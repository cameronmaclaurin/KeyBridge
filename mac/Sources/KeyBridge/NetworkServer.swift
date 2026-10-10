import Foundation
import Network

// Binary frame: 4 bytes
//   [0]   flags  bit0=isDown, bit1=isExtended
//   [1]   vk low byte
//   [2]   vk high byte
//   [3]   0x00 reserved

private func makeFrame(_ evt: KeyEvent) -> Data {
    var flags: UInt8 = 0
    if evt.isDown     { flags |= 0x01 }
    if evt.isExtended { flags |= 0x02 }
    return Data([flags, UInt8(evt.vk & 0xFF), UInt8(evt.vk >> 8), 0x00])
}

final class NetworkServer {
    var onClientConnected: ((String) -> Void)?
    var onClientDisconnected: (() -> Void)?

    private var listener: NWListener?
    private var conn: NWConnection?
    private let queue = DispatchQueue(label: "keybridge.net", qos: .userInteractive)

    func start(port: UInt16) {
        let p = NWEndpoint.Port(rawValue: port)!
        listener = try? NWListener(using: .tcp, on: p)
        listener?.newConnectionHandler = { [weak self] c in self?.accept(c) }
        listener?.start(queue: queue)
    }

    private func accept(_ c: NWConnection) {
        conn?.cancel()
        conn = c
        let params = c.parameters
        // Disable Nagle – key to low latency
        params.defaultProtocolStack.internetProtocol.map {
            if let tcp = $0 as? NWProtocolTCP.Options { tcp.noDelay = true }
        }
        c.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                if case .hostPort(let h, _) = c.endpoint {
                    DispatchQueue.main.async { self?.onClientConnected?(h.debugDescription) }
                }
            case .failed, .cancelled:
                DispatchQueue.main.async { self?.onClientDisconnected?() }
                self?.conn = nil
            default: break
            }
        }
        c.start(queue: queue)
    }

    func send(_ evt: KeyEvent) {
        guard let c = conn else { return }
        let frame = makeFrame(evt)
        c.send(content: frame, completion: .idempotent)
    }

    var isConnected: Bool { conn != nil }
}
