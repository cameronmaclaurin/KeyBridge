import Darwin
import Foundation
import SystemConfiguration

enum NetworkInfo {
    /// Bonjour name, e.g. `Camerons-MacBook-Pro.local`.
    static func localHostName() -> String? {
        guard let name = SCDynamicStoreCopyLocalHostName(nil) as String?, !name.isEmpty else { return nil }
        return name + ".local"
    }

    /// IPv4 addresses of active, non-loopback, non-VPN interfaces (en0 first).
    static func ipv4Addresses() -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var found: [(iface: String, addr: String)] = []
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let p = cur {
            defer { cur = p.pointee.ifa_next }
            let flags = Int32(p.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_RUNNING != 0,
                  flags & IFF_LOOPBACK == 0, flags & IFF_POINTOPOINT == 0,
                  let sa = p.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET)
            else { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count),
                              nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let addr = String(cString: host)
            if addr.hasPrefix("169.254.") { continue }  // link-local: not reachable from the PC
            let iface = String(cString: p.pointee.ifa_name)
            if !found.contains(where: { $0.addr == addr }) { found.append((iface, addr)) }
        }
        return found
            .sorted { a, b in
                let ra = a.iface == "en0" ? 0 : a.iface.hasPrefix("en") ? 1 : 2
                let rb = b.iface == "en0" ? 0 : b.iface.hasPrefix("en") ? 1 : 2
                return ra != rb ? ra < rb : a.iface < b.iface
            }
            .map(\.addr)
    }
}
