import CryptoKit
import Foundation

// docs/UPDATES.md: signed update manifest → verify → parse strictly → compare versions → download
// with size and SHA-256 checks. Everything here is free of AppKit and shared with the selftest.

/// `MAJOR.MINOR.PATCH`, decimal, no leading zeros except a lone `0` (§2).
struct UpdateVersion: Comparable, CustomStringConvertible {
    let major: Int, minor: Int, patch: Int

    static let zero = UpdateVersion(major: 0, minor: 0, patch: 0)

    init(major: Int, minor: Int, patch: Int) {
        self.major = major; self.minor = minor; self.patch = patch
    }

    init?(_ s: some StringProtocol) {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }
        var nums = [Int]()
        for p in parts {
            let b = Array(p.utf8)
            guard !b.isEmpty, b.count <= 18, b.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
                  b.count == 1 || b[0] != 0x30, let n = Int(p) else { return nil }
            nums.append(n)
        }
        self.init(major: nums[0], minor: nums[1], patch: nums[2])
    }

    static func < (a: UpdateVersion, b: UpdateVersion) -> Bool {
        (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch)
    }

    var description: String { "\(major).\(minor).\(patch)" }

    /// The running app's version; anything that doesn't parse (local builds, "1.2.3-beta") is 0.0.0.
    static var running: UpdateVersion {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
            .flatMap { UpdateVersion($0) } ?? .zero
    }
}

struct UpdateAsset: Equatable {
    let url: URL
    let sha256: String   // 64 lowercase hex
    let size: Int64      // 1 ... 200,000,000
}

struct UpdateManifest {
    let version: UpdateVersion
    let notesURL: URL
    let mac: UpdateAsset
    let windows: UpdateAsset
}

enum UpdateDecision {
    case update(UpdateManifest)
    case current
}

enum UpdateVerifier {
    /// Must equal tools/update_pubkey.txt exactly (CI checks). Uncompressed X9.63 P-256 point.
    static let embeddedPublicKeyHex =
        "04290216611bac006bab98e63c0a3fa68f3c6bb49293fd65cec42c7b323f2caea9cbe542a9b238561284afe444746c091ab8cfc37aa50a01c40cf3477968d8df33"

    static let manifestURL = URL(string: "https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/update-manifest.txt")!
    static let signatureURL = URL(string: "https://github.com/cameronmaclaurin/KeyBridge/releases/latest/download/update-manifest.sig")!

    static let assetURLPrefix = "https://github.com/cameronmaclaurin/KeyBridge/releases/download/"
    /// notes-url points at the release page (`…/releases/tag/vX.Y.Z`), so it can't satisfy the
    /// download prefix; it's held to the same repository's releases instead.
    static let notesURLPrefix = "https://github.com/cameronmaclaurin/KeyBridge/releases/"
    static let maxResponseBytes: Int64 = 16 * 1024
    static let maxAssetSize: Int64 = 200_000_000

    private static let header = "keybridge-update-manifest 1"

    // MARK: Signature

    /// 130 hex characters (either case) → public key.
    static func publicKey(hex: String) -> P256.Signing.PublicKey? {
        guard let bytes = hexBytes(hex), bytes.count == 65 else { return nil }
        return try? P256.Signing.PublicKey(x963Representation: bytes)
    }

    /// ECDSA P-256 / SHA-256 over the exact manifest bytes; `sig` is base64 of raw r||s (88 chars,
    /// one optional trailing LF).
    static func verifySignature(manifest: Data, signature sig: Data, publicKey: P256.Signing.PublicKey) -> Bool {
        var b64 = sig
        if b64.last == 0x0A { b64.removeLast() }
        guard b64.count == 88, let text = String(data: b64, encoding: .ascii),
              let raw = Data(base64Encoded: text), raw.count == 64,
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
        return publicKey.isValidSignature(signature, for: manifest)
    }

    // MARK: Parsing

    /// Strict parse of an already-verified manifest (§2). nil = bad format or a bad URL.
    static func parse(_ data: Data) -> UpdateManifest? {
        guard data.count <= maxResponseBytes, String(data: data, encoding: .utf8) != nil,
              !data.contains(0x0D), !data.contains(0x00) else { return nil }
        var lines = Array(data).split(separator: 0x0A, omittingEmptySubsequences: false)
        if lines.last?.isEmpty == true { lines.removeLast() }   // the final LF
        guard let first = lines.first, String(decoding: first, as: UTF8.self) == header else { return nil }

        let known: Set<String> = ["version", "notes-url", "mac-url", "mac-sha256", "mac-size",
                                  "windows-url", "windows-sha256", "windows-size"]
        var fields = [String: String]()
        for line in lines.dropFirst() {
            guard let sp = line.firstIndex(of: 0x20), sp > line.startIndex else { return nil }
            let key = String(decoding: line[line.startIndex..<sp], as: UTF8.self)
            let value = String(decoding: line[line.index(after: sp)...], as: UTF8.self)
            if key == "keybridge-update-manifest" { return nil }   // header only once, first
            guard known.contains(key) else { continue }             // unknown keys are ignored
            guard fields[key] == nil else { return nil }            // each key exactly once
            fields[key] = value
        }
        guard fields.count == known.count,
              let version = UpdateVersion(fields["version"]!),
              let notes = url(fields["notes-url"]!, prefix: notesURLPrefix),
              let mac = asset(fields, "mac"),
              let windows = asset(fields, "windows") else { return nil }
        return UpdateManifest(version: version, notesURL: notes, mac: mac, windows: windows)
    }

    /// Signature first, then the strict parse.
    static func verifyAndParse(manifest: Data, signature: Data, publicKey: P256.Signing.PublicKey) -> UpdateManifest? {
        guard manifest.count <= maxResponseBytes, signature.count <= maxResponseBytes,
              verifySignature(manifest: manifest, signature: signature, publicKey: publicKey) else { return nil }
        return parse(manifest)
    }

    /// Offer only a strictly newer version: equal or older (a replayed old manifest) is current.
    static func decide(_ m: UpdateManifest, running: UpdateVersion) -> UpdateDecision {
        m.version > running ? .update(m) : .current
    }

    private static func asset(_ f: [String: String], _ platform: String) -> UpdateAsset? {
        guard let u = url(f["\(platform)-url"]!, prefix: assetURLPrefix),
              let sha = f["\(platform)-sha256"], isLowerHex64(sha),
              let size = decimalSize(f["\(platform)-size"]!) else { return nil }
        return UpdateAsset(url: u, sha256: sha, size: size)
    }

    /// Prefix match plus a conservative character set (no whitespace, query, fragment, escapes
    /// or dot segments), so what's checked is what's fetched.
    private static func url(_ s: String, prefix: String) -> URL? {
        guard s.hasPrefix(prefix), s.count > prefix.count else { return nil }
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/:+".utf8)
        guard s.utf8.allSatisfy({ allowed.contains($0) }) else { return nil }
        let path = s.dropFirst(prefix.count).split(separator: "/", omittingEmptySubsequences: false)
        guard !path.contains(where: { $0 == "." || $0 == ".." || $0.isEmpty }) else { return nil }
        guard let u = URL(string: s), u.scheme == "https", u.host == "github.com" else { return nil }
        return u
    }

    private static func isLowerHex64(_ s: String) -> Bool {
        let b = Array(s.utf8)
        return b.count == 64 && b.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    private static func decimalSize(_ s: String) -> Int64? {
        let b = Array(s.utf8)
        guard !b.isEmpty, b.count <= 9, b[0] != 0x30, b.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              let n = Int64(s), n >= 1, n <= maxAssetSize else { return nil }
        return n
    }

    static func hexBytes(_ hex: String) -> [UInt8]? {
        let c = Array(hex.utf8)
        guard c.count % 2 == 0 else { return nil }
        func nibble(_ x: UInt8) -> UInt8? {
            switch x {
            case 0x30...0x39: return x - 0x30
            case 0x61...0x66: return x - 0x61 + 10
            case 0x41...0x46: return x - 0x41 + 10
            default: return nil
            }
        }
        var out = [UInt8]()
        out.reserveCapacity(c.count / 2)
        for i in stride(from: 0, to: c.count, by: 2) {
            guard let hi = nibble(c[i]), let lo = nibble(c[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
        }
        return out
    }

    static func hex(_ digest: some Sequence<UInt8>) -> String {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: – Fetching

/// One HTTPS GET with a hard byte limit, streamed either into memory or into a file while
/// computing SHA-256. Ephemeral session, no caching, HTTPS-only redirects, normal TLS validation.
/// The completion handler runs on the main queue.
final class UpdateFetch: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    enum Failure: Error {
        case network(Error)
        case http(Int)
        case tooLarge
        case insecureRedirect
        case io(Error)
        case cancelled

        var message: String {
            switch self {
            case .network(let e): return e.localizedDescription
            case .http(let code): return "the server responded with an error (HTTP \(code))."
            case .tooLarge: return "the download was larger than expected."
            case .insecureRedirect: return "the server redirected to an insecure address."
            case .io(let e): return e.localizedDescription
            case .cancelled: return "cancelled."
            }
        }
    }

    struct Result {
        let data: Data        // memory mode only
        let size: Int64
        let sha256: String    // lowercase hex
    }

    private let limit: Int64
    private let fileURL: URL?
    private let onProgress: ((Int64) -> Void)?
    private var onDone: ((Swift.Result<Result, Failure>) -> Void)?

    // Touched only on the session's serial delegate queue.
    private var buffer = Data()
    private var handle: FileHandle?
    private var hasher = SHA256()
    private var received: Int64 = 0
    private var failure: Failure?
    private var lastProgress = Date.distantPast

    private var session: URLSession?
    private var task: URLSessionDataTask?

    /// `fileURL` nil → collect in memory. The file is created fresh with mode 0600.
    init(url: URL, limit: Int64, timeout: TimeInterval, resourceTimeout: TimeInterval, fileURL: URL? = nil,
         onProgress: ((Int64) -> Void)? = nil, onDone: @escaping (Swift.Result<Result, Failure>) -> Void) {
        self.limit = limit
        self.fileURL = fileURL
        self.onProgress = onProgress
        self.onDone = onDone
        super.init()

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = resourceTimeout
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.waitsForConnectivity = false
        config.httpAdditionalHeaders = ["User-Agent": "KeyBridge/\(UpdateVersion.running)"]
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        queue.name = "KeyBridge.UpdateFetch"
        let s = URLSession(configuration: config, delegate: self, delegateQueue: queue)
        session = s
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        task = s.dataTask(with: req)
    }

    func start() {
        guard task?.state == .suspended else { return }
        task?.resume()
    }

    func cancel() { task?.cancel() }

    private func fail(_ f: Failure, _ dataTask: URLSessionTask) {
        if failure == nil { failure = f }
        dataTask.cancel()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        guard request.url?.scheme?.lowercased() == "https" else {
            fail(.insecureRedirect, task)
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            failure = failure ?? .http((response as? HTTPURLResponse)?.statusCode ?? 0)
            completionHandler(.cancel)
            return
        }
        if response.expectedContentLength > limit {
            failure = .tooLarge
            completionHandler(.cancel)
            return
        }
        if let fileURL {
            guard FileManager.default.createFile(atPath: fileURL.path, contents: nil,
                                                 attributes: [.posixPermissions: 0o600]),
                  let h = try? FileHandle(forWritingTo: fileURL) else {
                failure = .io(CocoaError(.fileWriteUnknown))
                completionHandler(.cancel)
                return
            }
            handle = h
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard failure == nil else { return }
        received += Int64(data.count)
        guard received <= limit else { return fail(.tooLarge, dataTask) }
        hasher.update(data: data)
        if let handle {
            do { try handle.write(contentsOf: data) } catch { return fail(.io(error), dataTask) }
        } else {
            buffer.append(data)
        }
        if let onProgress, Date().timeIntervalSince(lastProgress) > 0.1 {
            lastProgress = Date()
            let n = received
            DispatchQueue.main.async { onProgress(n) }
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let handle {
            do { try handle.close() } catch { failure = failure ?? .io(error) }
            self.handle = nil
        }
        let result: Swift.Result<Result, Failure>
        if let failure {
            result = .failure(failure)
        } else if let error {
            let ns = error as NSError
            result = .failure(ns.domain == NSURLErrorDomain && ns.code == NSURLErrorCancelled ? .cancelled : .network(error))
        } else {
            result = .success(Result(data: buffer, size: received, sha256: UpdateVerifier.hex(hasher.finalize())))
        }
        if case .failure = result, let fileURL { try? FileManager.default.removeItem(at: fileURL) }
        session.invalidateAndCancel()   // the session retains its delegate until invalidated
        let n = received
        let done = onDone
        onDone = nil
        DispatchQueue.main.async {
            self.onProgress?(n)
            done?(result)
        }
    }
}
