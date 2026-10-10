import Foundation
import Network

// Binary frame, 4 bytes:
//   [0] flags  bit0=isDown, bit1=isExtended
//   [1] vk low byte
//   [2] vk high byte
//   [3] reserved (0)
private func makeFrame(_ evt: KeyEvent) -> Data {
    var flags: UInt8 = 0
    if evt.isDown     { flags |= 0x01 }
    if evt.isExtended { flags |= 0x02 }
    return Data([flags, UInt8(evt.vk & 0xFF), UInt8(evt.vk >> 8), 0])
}

/// Runs on the main queue: the event tap already fires there, so sends need no thread hop
/// and `conn` is only ever touched from one thread.
final class NetworkServer {
    var onClientConnected: ((String) -> Void)?
    var onClientDisconnected: (() -> Void)?

    private var listener: NWListener?
    private var conn: NWConnection?

    var isConnected: Bool { conn != nil }

    func start(port: UInt16) {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true  // disable Nagle so each 4-byte frame goes out immediately
        let params = NWParameters(tls: nil, tcp: tcp)
        params.allowLocalEndpointReuse = true

        guard let l = try? NWListener(using: params, on: NWEndpoint.Port(rawValue: port)!) else {
            NSLog("[KeyBridge] Could not listen on port \(port)")
            return
        }
        l.newConnectionHandler = { [weak self] c in self?.accept(c) }
        l.start(queue: .main)
        listener = l
    }

    private func accept(_ c: NWConnection) {
        conn?.cancel()
        conn = c
        c.stateUpdateHandler = { [weak self, weak c] state in
            guard let self, let c else { return }
            switch state {
            case .ready:
                var host = "unknown"
                if case .hostPort(let h, _) = c.endpoint { host = "\(h)" }
                self.onClientConnected?(host)
            case .failed, .cancelled:
                // A replaced connection reports .cancelled after the new one is installed.
                guard self.conn === c else { return }
                self.conn = nil
                self.onClientDisconnected?()
            default:
                break
            }
        }
        c.start(queue: .main)
    }

    func send(_ evt: KeyEvent) {
        conn?.send(content: makeFrame(evt), completion: .idempotent)
    }
}
