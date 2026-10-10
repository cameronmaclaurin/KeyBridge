import CryptoKit
import Foundation
import Network

/// KBP2 server (docs/PROTOCOL.md §1, §1a, §2, §4–§6) on Network.framework.
///
/// Everything runs on the main queue: the listener, every connection, the timers and the
/// event-tap callback all fire there, so a keystroke goes tap → seal → send with no thread
/// hop and all state is touched from one thread. Used unchanged by the selftest build.
final class KBP2Server {
    struct Options {
        var port: UInt16 = KBP2.port
        /// Bind 127.0.0.1 only (selftest). Otherwise listen on all interfaces.
        var loopbackOnly = false
        /// Stop listening after this many accepted connections (selftest: 1).
        var acceptLimit: Int?
        /// Send PING every 2 s while authenticated (off in the selftest, which pings once).
        var autoPing = true
    }

    enum ListenerEvent {
        case ready
        case failed(String)
    }

    var onListenerEvent: ((ListenerEvent) -> Void)?
    /// A session authenticated. `replacedHost` is set if it replaced an existing session.
    var onAuthenticated: ((_ host: String, _ replacedHost: String?) -> Void)?
    /// The authenticated session closed (peer left, liveness timeout, decrypt failure, ...).
    var onSessionEnded: (() -> Void)?
    var onHandshakeFailed: ((KBP2HandshakeError) -> Void)?
    var onPong: (() -> Void)?

    enum PairingEvent {
        /// A PC sent a valid PairHello; PairCommit is on its way.
        case started(pcName: String)
        /// MacNonce sent: show `sas` and ask the user to compare (§2.3).
        case compare(pcName: String, sas: UInt32)
        /// The Mac user confirmed and the PcConfirm verified: store `ltk` (§2.4).
        case paired(ltk: SymmetricKey, pcName: String)
        case failed(KBP2PairingError)
    }

    var onPairingEvent: ((PairingEvent) -> Void)?
    /// A pairing connection has finished closing (after `.paired` or `.failed`).
    var onPairingConnectionClosed: (() -> Void)?

    var isAuthenticated: Bool { session != nil }
    var peerHost: String? { session?.host }
    var isPairing: Bool { pairing != nil }

    /// §2.1: accept "KBPR" connections only while true. Turning it off doesn't end a pairing
    /// already in progress; use `cancelPairing()` for that.
    var pairingModeEnabled = false
    /// The name sent in PairCommit (§2.2).
    var macDisplayName = "Mac"

    private let options: Options
    private var psk: SymmetricKey?
    private var listener: NWListener?
    private var pending: [Pending] = []
    private var session: Session?
    private var pairing: Pairing?
    private var acceptedCount = 0
    private var serviceName: String?

    /// `psk` is the long-term key from pairing; nil = not paired (every "KBR2" is closed).
    init(psk: SymmetricKey?, options: Options = Options()) {
        self.psk = psk
        self.options = options
    }

    // MARK: Listener

    func start() {
        guard listener == nil else { return }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true  // each 20-byte record goes out immediately
        let params = NWParameters(tls: nil, tcp: tcp)
        params.allowLocalEndpointReuse = true

        let l: NWListener
        do {
            guard let port = NWEndpoint.Port(rawValue: options.port) else {
                onListenerEvent?(.failed("Invalid port \(options.port)"))
                return
            }
            if options.loopbackOnly {
                params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: port)
                l = try NWListener(using: params)
            } else {
                l = try NWListener(using: params, on: port)
            }
        } catch {
            onListenerEvent?(.failed(error.localizedDescription))
            return
        }

        l.stateUpdateHandler = { [weak self, weak l] state in
            guard let self, let l, self.listener === l else { return }
            switch state {
            case .ready:
                self.onListenerEvent?(.ready)
            case .failed(let err):
                l.cancel()
                self.listener = nil
                self.onListenerEvent?(.failed(err.localizedDescription))
            default:
                break
            }
        }
        l.newConnectionHandler = { [weak self] c in self?.accept(c) }
        l.service = serviceName.map(Self.bonjourService)
        listener = l
        l.start(queue: .main)
    }

    /// §1a: advertise `_keybridge._tcp` under `name` (nil = don't advertise). Takes effect
    /// immediately on a running listener, so it can follow computer-name changes.
    func setServiceName(_ name: String?) {
        guard name != serviceName else { return }
        serviceName = name
        listener?.service = name.map(Self.bonjourService)
    }

    private static func bonjourService(_ name: String) -> NWListener.Service {
        NWListener.Service(name: name, type: "_keybridge._tcp", domain: nil,
                           txtRecord: NWTXTRecord(["v": "2"]))
    }

    /// Stops listening and closes everything. `completion` runs once the session (if any)
    /// has closed gracefully, at most ~1 s later.
    func stop(completion: (() -> Void)? = nil) {
        listener?.cancel()
        listener = nil
        for p in pending { abort(p) }
        pending.removeAll()
        if let pr = pairing {
            pairing = nil
            stopPairingTimer(pr)
            pr.conn.stateUpdateHandler = nil
            pr.conn.cancel()
        }
        disconnectSession(completion: completion)
    }

    /// New pairing (or Forget): drop everything that was authenticated (or authenticating)
    /// with the old key. A pairing connection in progress is left alone.
    func setPSK(_ newPSK: SymmetricKey?) {
        psk = newPSK
        for p in pending { abort(p) }
        pending.removeAll()
        disconnectSession()
    }

    /// Graceful close (§5): records already queued (e.g. RELEASE_ALL) are delivered first.
    func disconnectSession(completion: (() -> Void)? = nil) {
        if let s = session {
            end(s, graceful: true, completion: completion)
        } else {
            completion?()
        }
    }

    // MARK: Sending (Mac → PC)

    /// Hot path: called from the event tap on the main thread.
    func sendKey(isDown: Bool, isExtended: Bool, vk: UInt16) {
        let f = KBP2RecordChannel.keyFields(isDown: isDown, isExtended: isExtended, vk: vk)
        send(KBP2.RecordType.key.rawValue, f.0, f.1, f.2)
    }

    func sendPing() { send(KBP2.RecordType.ping.rawValue) }

    func sendReleaseAll() { send(KBP2.RecordType.releaseAll.rawValue) }

    private func send(_ type: UInt8, _ b1: UInt8 = 0, _ b2: UInt8 = 0, _ b3: UInt8 = 0) {
        guard let s = session else { return }
        guard let rec = s.channel.seal(type, b1, b2, b3) else { end(s); return }
        s.conn.send(content: rec, completion: .idempotent)
    }

    // MARK: Handshake (§4)

    private final class Pending {
        let conn: NWConnection
        let acceptedAt = DispatchTime.now()
        var timeout: DispatchWorkItem?
        init(_ conn: NWConnection) { self.conn = conn }
    }

    private func accept(_ c: NWConnection) {
        if let limit = options.acceptLimit {
            guard acceptedCount < limit else { c.cancel(); return }
            acceptedCount += 1
            if acceptedCount >= limit {
                listener?.cancel()
                listener = nil
            }
        }
        // At most 4 unauthenticated connections; extras are closed immediately.
        guard pending.count < KBP2.maxUnauthenticated else { c.cancel(); return }

        let p = Pending(c)
        pending.append(p)

        c.stateUpdateHandler = { [weak self, weak p] state in
            guard let self, let p else { return }
            switch state {
            case .failed, .cancelled: self.fail(p, .closed)
            default: break
            }
        }
        let timeout = DispatchWorkItem { [weak self, weak p] in
            guard let self, let p else { return }
            self.fail(p, .timeout)
        }
        p.timeout = timeout
        DispatchQueue.main.asyncAfter(deadline: .now() + KBP2.handshakeTimeout, execute: timeout)
        c.start(queue: .main)

        // §1: read the 4-byte magic and dispatch.
        c.receive(minimumIncompleteLength: KBP2.magicLength,
                  maximumLength: KBP2.magicLength) { [weak self, weak p] data, _, _, _ in
            guard let self, let p, self.isPending(p) else { return }
            guard let data, data.count == KBP2.magicLength else { self.fail(p, .closed); return }
            if data.elementsEqual(KBP2.magic) {
                // Not paired: there is no key to authenticate with, so close at once.
                guard let psk = self.psk else { self.fail(p, .notPaired); return }
                self.receiveClientHello(p, magic: data, psk: psk)
            } else if data.elementsEqual(KBP2.pairingMagic) {
                guard self.pairingModeEnabled, self.pairing == nil else {
                    self.fail(p, .pairingNotAllowed)
                    return
                }
                self.remove(p)
                self.startPairing(p.conn, acceptedAt: p.acceptedAt)
            } else {
                self.fail(p, .badMagic)
            }
        }
    }

    private func receiveClientHello(_ p: Pending, magic: Data, psk: SymmetricKey) {
        let rest = KBP2.clientHelloLength - KBP2.magicLength
        p.conn.receive(minimumIncompleteLength: rest, maximumLength: rest) { [weak self, weak p] data, _, _, _ in
            guard let self, let p, self.isPending(p) else { return }
            guard let data, data.count == rest else { self.fail(p, .closed); return }
            let hs: KBP2ServerHandshake
            do {
                hs = try KBP2ServerHandshake(clientHello: magic + data, psk: psk)
            } catch {
                self.fail(p, error as? KBP2HandshakeError ?? .closed)
                return
            }
            p.conn.send(content: hs.serverHello, completion: .idempotent)
            self.receiveClientFinished(p, hs)
        }
    }

    private func receiveClientFinished(_ p: Pending, _ hs: KBP2ServerHandshake) {
        p.conn.receive(minimumIncompleteLength: KBP2.clientFinishedLength,
                       maximumLength: KBP2.clientFinishedLength) { [weak self, weak p] data, _, _, _ in
            guard let self, let p, self.isPending(p) else { return }
            guard let data, data.count == KBP2.clientFinishedLength else { self.fail(p, .closed); return }
            do {
                let channel = try hs.finish(clientFinished: data)
                self.promote(p, channel)
            } catch {
                self.fail(p, .badFinished)
            }
        }
    }

    private func isPending(_ p: Pending) -> Bool { pending.contains { $0 === p } }

    private func remove(_ p: Pending) {
        pending.removeAll { $0 === p }
        p.timeout?.cancel()
        p.timeout = nil
        p.conn.stateUpdateHandler = nil
    }

    /// Close silently; nothing is sent to an unauthenticated peer.
    private func abort(_ p: Pending) {
        p.timeout?.cancel()
        p.timeout = nil
        p.conn.stateUpdateHandler = nil
        p.conn.cancel()
    }

    private func fail(_ p: Pending, _ reason: KBP2HandshakeError) {
        guard isPending(p) else { return }
        remove(p)
        p.conn.cancel()
        onHandshakeFailed?(reason)
    }

    // MARK: Pairing (§2), responder

    private final class Pairing {
        let conn: NWConnection
        var responder: KBP2PairingResponder?
        var keys: KBP2PairingKeys?
        var timer: DispatchWorkItem?
        var macConfirmed = false     // our user clicked Confirm and MacConfirm was sent
        var pcConfirmed = false      // PcConfirm arrived and verified
        var receiving = false        // a receive is outstanding
        var closing = false
        var closed = false
        init(_ conn: NWConnection) { self.conn = conn }
    }

    /// The Mac user clicked Confirm: send MacConfirm; done once PcConfirm has verified too.
    func confirmPairing() {
        guard let pr = pairing, let keys = pr.keys, !pr.macConfirmed else { return }
        pr.macConfirmed = true
        pr.conn.send(content: keys.macConfirm, completion: .idempotent)
        if pr.pcConfirmed { pairingSucceeded(pr) }
    }

    /// Cancel any pairing in progress (reported as `.failed(.cancelled)`).
    func cancelPairing() {
        if let pr = pairing { pairingFailed(pr, .cancelled) }
    }

    private func startPairing(_ conn: NWConnection, acceptedAt: DispatchTime) {
        let pr = Pairing(conn)
        pairing = pr
        conn.stateUpdateHandler = { [weak self, weak pr] state in
            guard let self, let pr else { return }
            switch state {
            case .failed, .cancelled: self.pairingFailed(pr, .closed)
            default: break
            }
        }
        // PairHello through MacNonce within 10 s of connecting.
        schedulePairingTimer(pr, deadline: acceptedAt + KBP2Pairing.exchangeTimeout)

        let rest = KBP2Pairing.pairHelloLength - KBP2.magicLength
        pairingReceive(pr, exactly: rest) { [weak self] pr, data in
            guard let self else { return }
            let responder: KBP2PairingResponder
            do {
                responder = try KBP2PairingResponder(pairHello: Data(KBP2.pairingMagic) + data,
                                                     macName: self.macDisplayName)
            } catch {
                self.pairingFailed(pr, error as? KBP2PairingError ?? .closed)
                return
            }
            pr.responder = responder
            pr.conn.send(content: responder.pairCommit, completion: .idempotent)
            self.onPairingEvent?(.started(pcName: responder.pcName))
            guard self.pairing === pr else { return }
            self.receivePcNonce(pr)
        }
    }

    private func receivePcNonce(_ pr: Pairing) {
        pairingReceive(pr, exactly: KBP2Pairing.nonceLength) { [weak self] pr, pcNonce in
            guard let self, let responder = pr.responder else { return }
            let keys: KBP2PairingKeys
            do {
                keys = try responder.finish(pcNonce: pcNonce)
            } catch {
                self.pairingFailed(pr, error as? KBP2PairingError ?? .closed)
                return
            }
            pr.keys = keys
            // mac_nonce goes out only now, after pc_nonce arrived (§2.2).
            pr.conn.send(content: responder.macNonce, completion: .idempotent)
            self.schedulePairingTimer(pr, deadline: .now() + KBP2Pairing.confirmTimeout)
            self.receivePcConfirm(pr)
            self.onPairingEvent?(.compare(pcName: responder.pcName, sas: keys.sas))
        }
    }

    private func receivePcConfirm(_ pr: Pairing) {
        pairingReceive(pr, exactly: KBP2Pairing.confirmLength) { [weak self] pr, value in
            guard let self, let keys = pr.keys else { return }
            guard KBP2Crypto.constantTimeEqual(value, keys.expectedPcConfirm) else {
                self.pairingFailed(pr, .badConfirm)
                return
            }
            pr.pcConfirmed = true
            if pr.macConfirmed {
                self.pairingSucceeded(pr)
            } else {
                self.watchForPairingClose(pr)
            }
        }
    }

    /// While waiting for our user: the PC has nothing more to send, so data or EOF = abort.
    private func watchForPairingClose(_ pr: Pairing) {
        pr.receiving = true
        pr.conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self, weak pr] data, _, isComplete, error in
            guard let self, let pr else { return }
            pr.receiving = false
            if pr.closing { self.drainPairing(pr, data: data, isComplete: isComplete, error: error); return }
            guard self.pairing === pr else { return }
            self.pairingFailed(pr, .closed)
        }
    }

    /// Reads exactly `n` bytes, then calls `next` (only while this pairing is still running).
    /// Once the pairing is closing, the outstanding receive becomes part of the drain.
    private func pairingReceive(_ pr: Pairing, exactly n: Int,
                                _ next: @escaping (Pairing, Data) -> Void) {
        pr.receiving = true
        pr.conn.receive(minimumIncompleteLength: n, maximumLength: n) { [weak self, weak pr] data, _, isComplete, error in
            guard let self, let pr else { return }
            pr.receiving = false
            if pr.closing { self.drainPairing(pr, data: data, isComplete: isComplete, error: error); return }
            guard self.pairing === pr else { return }
            guard let data, data.count == n else { self.pairingFailed(pr, .closed); return }
            next(pr, Data(data))
        }
    }

    private func schedulePairingTimer(_ pr: Pairing, deadline: DispatchTime) {
        pr.timer?.cancel()
        let t = DispatchWorkItem { [weak self, weak pr] in
            guard let self, let pr else { return }
            self.pairingFailed(pr, .timeout)
        }
        pr.timer = t
        DispatchQueue.main.asyncAfter(deadline: deadline, execute: t)
    }

    private func stopPairingTimer(_ pr: Pairing) {
        pr.timer?.cancel()
        pr.timer = nil
    }

    private func pairingSucceeded(_ pr: Pairing) {
        guard pairing === pr, let keys = pr.keys, let responder = pr.responder else { return }
        pairing = nil
        stopPairingTimer(pr)
        onPairingEvent?(.paired(ltk: keys.ltk, pcName: responder.pcName))
        closePairing(pr)
    }

    private func pairingFailed(_ pr: Pairing, _ reason: KBP2PairingError) {
        guard pairing === pr else { return }
        pairing = nil
        stopPairingTimer(pr)
        onPairingEvent?(.failed(reason))
        closePairing(pr)
    }

    /// §5-style graceful close: half-close, read and discard until EOF or 1 s, then cancel.
    private func closePairing(_ pr: Pairing) {
        guard !pr.closing else { return }
        pr.closing = true
        pr.conn.stateUpdateHandler = nil
        pr.conn.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            self?.finishPairingClose(pr)
        }
        if !pr.receiving { drainPairing(pr, data: nil, isComplete: false, error: nil) }
    }

    private func drainPairing(_ pr: Pairing, data: Data?, isComplete: Bool, error: NWError?) {
        guard !pr.closed else { return }
        if isComplete || error != nil { finishPairingClose(pr); return }
        pr.receiving = true
        pr.conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self, weak pr] data, _, isComplete, error in
            guard let self, let pr else { return }
            pr.receiving = false
            self.drainPairing(pr, data: data, isComplete: isComplete, error: error)
        }
    }

    private func finishPairingClose(_ pr: Pairing) {
        guard !pr.closed else { return }
        pr.closed = true
        pr.conn.cancel()
        onPairingConnectionClosed?()
    }

    // MARK: Session (§5, §6)

    private final class Session {
        let conn: NWConnection
        let host: String
        var channel: KBP2RecordChannel
        var pingTimer: DispatchSourceTimer?
        var livenessTimer: DispatchSourceTimer?

        init(conn: NWConnection, host: String, channel: KBP2RecordChannel) {
            self.conn = conn
            self.host = host
            self.channel = channel
        }
    }

    private func promote(_ p: Pending, _ channel: KBP2RecordChannel) {
        remove(p)
        let s = Session(conn: p.conn, host: Self.hostString(p.conn.endpoint), channel: channel)

        // A newly authenticated session replaces the old one (closed gracefully, no callback).
        let replacedHost = session?.host
        if let old = session {
            session = nil
            stopTimers(old)
            Self.closeGracefully(old.conn, completion: nil)
        }
        session = s

        s.conn.stateUpdateHandler = { [weak self, weak s] state in
            guard let self, let s else { return }
            switch state {
            case .failed, .cancelled: self.end(s)
            default: break
            }
        }

        let live = DispatchSource.makeTimerSource(queue: .main)
        live.schedule(deadline: .now() + KBP2.livenessTimeout)
        live.setEventHandler { [weak self, weak s] in
            guard let self, let s else { return }
            self.end(s)
        }
        live.resume()
        s.livenessTimer = live

        if options.autoPing {
            let ping = DispatchSource.makeTimerSource(queue: .main)
            ping.schedule(deadline: .now() + KBP2.pingInterval, repeating: KBP2.pingInterval,
                          leeway: .milliseconds(100))
            ping.setEventHandler { [weak self, weak s] in
                guard let self, let s, self.session === s else { return }
                self.sendPing()
            }
            ping.resume()
            s.pingTimer = ping
        }

        receiveRecord(s)
        onAuthenticated?(s.host, replacedHost)
    }

    private func receiveRecord(_ s: Session) {
        s.conn.receive(minimumIncompleteLength: KBP2.recordLength,
                       maximumLength: KBP2.recordLength) { [weak self, weak s] data, _, isComplete, error in
            guard let self, let s, self.session === s else { return }
            if let data, !data.isEmpty {
                // Any authentication failure (or a short record) closes the connection.
                guard data.count == KBP2.recordLength, let pt = s.channel.open(data) else {
                    self.end(s)
                    return
                }
                s.livenessTimer?.schedule(deadline: .now() + KBP2.livenessTimeout)
                if pt[0] == KBP2.RecordType.pong.rawValue { self.onPong?() }
                // Unknown types are ignored (forward compatibility).
            }
            guard self.session === s else { return }
            if isComplete || error != nil { self.end(s); return }
            self.receiveRecord(s)
        }
    }

    private func stopTimers(_ s: Session) {
        s.pingTimer?.cancel()
        s.pingTimer = nil
        s.livenessTimer?.cancel()
        s.livenessTimer = nil
    }

    /// `graceful: false` is for a dead or misbehaving peer (closed, liveness timeout,
    /// decrypt failure), where §5 says to close immediately.
    private func end(_ s: Session, graceful: Bool = false, completion: (() -> Void)? = nil) {
        guard session === s else { completion?(); return }
        session = nil
        stopTimers(s)
        if graceful {
            Self.closeGracefully(s.conn, completion: completion)
        } else {
            s.conn.stateUpdateHandler = nil
            s.conn.cancel()
            completion?()
        }
        onSessionEnded?()
    }

    /// §5 graceful close: half-close our write side (after everything already queued),
    /// read and discard until EOF or 1 s, then cancel. Cancelling with unread data would
    /// make TCP send an RST that can destroy records still in flight.
    private static func closeGracefully(_ conn: NWConnection, completion: (() -> Void)?) {
        conn.stateUpdateHandler = nil
        conn.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)

        var done = false
        func finish() {
            guard !done else { return }
            done = true
            conn.cancel()
            completion?()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { finish() }
        func drain() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, isComplete, error in
                if done { return }
                if isComplete || error != nil { finish() } else { drain() }
            }
        }
        drain()
    }

    static func hostString(_ endpoint: NWEndpoint) -> String {
        guard case .hostPort(let host, _) = endpoint else { return "unknown" }
        var str: String
        switch host {
        case .ipv4(let a): str = "\(a)"
        case .ipv6(let a): str = "\(a)"
        case .name(let n, _): str = n
        @unknown default: str = "\(host)"
        }
        if let pct = str.firstIndex(of: "%") { str = String(str[..<pct]) }   // drop scope id
        if str.lowercased().hasPrefix("::ffff:") { str = String(str.dropFirst(7)) }  // v4-mapped
        return str
    }
}
