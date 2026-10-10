import AppKit
import CryptoKit

/// docs/UPDATES.md §2–§4 on macOS: schedule, prompt, download, verify, hand the .pkg to Installer.
/// At most one check, prompt or download runs at a time.
@MainActor
final class UpdateController: NSObject {
    private let settings = AppSettings.shared
    private let publicKey = UpdateVerifier.publicKey(hex: UpdateVerifier.embeddedPublicKeyHex)!

    private var started = false
    private var scheduled = false
    private var launchTimer: Timer?
    private var dailyTimer: Timer?

    private enum State { case idle, checking, prompting, downloading }
    private var state = State.idle
    private var manualCheck = false
    private var fetch: UpdateFetch?
    private var progress: UpdateProgressWindow?

    private static let tempPrefix = "KeyBridge-Update-"

    /// Call once the app has finished launching.
    func start() {
        guard !started else { return }
        started = true
        removeOldDownloads()
        applySchedule()
    }

    /// Follows the "Automatically check for updates" setting: 10 s after it's on, then every 24 h.
    func applySchedule() {
        guard started else { return }
        let on = settings.autoCheckUpdates
        guard on != scheduled else { return }
        scheduled = on
        launchTimer?.invalidate()
        dailyTimer?.invalidate()
        launchTimer = nil
        dailyTimer = nil
        guard on else { return }
        launchTimer = Timer.scheduledTimer(timeInterval: 10, target: self, selector: #selector(automaticCheck),
                                           userInfo: nil, repeats: false)
        let daily = Timer.scheduledTimer(timeInterval: 24 * 60 * 60, target: self, selector: #selector(automaticCheck),
                                         userInfo: nil, repeats: true)
        daily.tolerance = 10 * 60
        dailyTimer = daily
    }

    @objc private func automaticCheck() {
        guard settings.autoCheckUpdates else { return }
        check(manual: false)
    }

    /// Menu item "Check for Updates…".
    func checkNow() {
        switch state {
        case .idle: check(manual: true)
        case .checking: manualCheck = true      // report the result of the check already running
        case .prompting: break                  // the update alert is already up
        case .downloading: progress?.show()
        }
    }

    // MARK: – Checking

    private func check(manual: Bool) {
        guard state == .idle else { return }
        state = .checking
        manualCheck = manual
        get(UpdateVerifier.manifestURL) { [weak self] r in
            guard let self else { return }
            switch r {
            case .failure(let f): self.checkFailed(f.message)
            case .success(let manifest):
                self.get(UpdateVerifier.signatureURL) { [weak self] r in
                    guard let self else { return }
                    switch r {
                    case .failure(let f): self.checkFailed(f.message)
                    case .success(let sig): self.checked(manifest: manifest.data, signature: sig.data)
                    }
                }
            }
        }
    }

    private func get(_ url: URL, _ done: @escaping (Result<UpdateFetch.Result, UpdateFetch.Failure>) -> Void) {
        let f = UpdateFetch(url: url, limit: UpdateVerifier.maxResponseBytes, timeout: 15, resourceTimeout: 15,
                            onDone: { [weak self] r in
                                self?.fetch = nil
                                done(r)
                            })
        fetch = f
        f.start()
    }

    private func checkFailed(_ why: String) {
        let manual = manualCheck
        state = .idle
        NSLog("[KeyBridge] Update check failed: \(why)")
        if manual { showAlert("Couldn’t check for updates", Self.sentence(why)) }
    }

    private func checked(manifest: Data, signature: Data) {
        guard let m = UpdateVerifier.verifyAndParse(manifest: manifest, signature: signature, publicKey: publicKey) else {
            checkFailed("the update information isn’t valid.")
            return
        }
        settings.lastUpdateCheck = Date()
        let running = UpdateVersion.running
        switch UpdateVerifier.decide(m, running: running) {
        case .current:
            let manual = manualCheck
            state = .idle
            if manual {
                showAlert("You’re up to date",
                          "KeyBridge \(running) is the latest version.")
            }
        case .update(let m):
            if !manualCheck && settings.skippedUpdateVersion == m.version.description {
                state = .idle
                return
            }
            prompt(m, running: running)
        }
    }

    // MARK: – Prompt

    private func prompt(_ m: UpdateManifest, running: UpdateVersion) {
        state = .prompting
        activate()
        let alert = NSAlert()
        alert.icon = NSApp.applicationIconImage
        alert.messageText = "KeyBridge \(m.version) is available"
        var info = "You have version \(running). KeyBridge quits while the update installs and opens again afterwards."
        if !Self.runningFromApplications {
            info += " The update installs KeyBridge into your Applications folder."
        }
        alert.informativeText = info
        alert.addButton(withTitle: "Install Update")
        alert.addButton(withTitle: "Later")
        alert.addButton(withTitle: "Skip This Version")
        alert.accessoryView = ReleaseNotesLink(url: m.notesURL)
        let reply = alert.runModal()
        switch reply {
        case .alertFirstButtonReturn:
            download(m)
        case .alertThirdButtonReturn:
            settings.skippedUpdateVersion = m.version.description
            state = .idle
        default:
            state = .idle
        }
    }

    private static var runningFromApplications: Bool {
        Bundle.main.bundleURL.standardizedFileURL.deletingLastPathComponent().path == "/Applications"
    }

    // MARK: – Download and install (§3)

    private func download(_ m: UpdateManifest) {
        state = .downloading
        let asset = m.mac
        let dir: URL
        do {
            dir = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
                .appendingPathComponent(Self.tempPrefix + UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
        } catch {
            downloadFailed("Couldn’t download the update: \(error.localizedDescription)", dir: nil)
            return
        }
        let file = dir.appendingPathComponent("KeyBridge-\(m.version).pkg")

        let window = UpdateProgressWindow(total: asset.size)
        window.onCancel = { [weak self] in self?.fetch?.cancel() }
        progress = window
        window.show()

        let f = UpdateFetch(url: asset.url, limit: asset.size, timeout: 15, resourceTimeout: 60 * 60, fileURL: file,
                            onProgress: { [weak window] n in window?.setReceived(n) },
                            onDone: { [weak self] r in
                                guard let self else { return }
                                self.fetch = nil
                                switch r {
                                case .failure(.cancelled):
                                    self.downloadFailed(nil, dir: dir)
                                case .failure(let f):
                                    self.downloadFailed("Couldn’t download the update: \(f.message)", dir: dir)
                                case .success(let got):
                                    guard got.size == asset.size, got.sha256 == asset.sha256 else {
                                        self.downloadFailed("The update was damaged or tampered with", dir: dir,
                                                            detail: "Nothing was installed. Try again later.")
                                        return
                                    }
                                    self.install(file, dir: dir)
                                }
                            })
        fetch = f
        f.start()
    }

    private func downloadFailed(_ message: String?, dir: URL?, detail: String = "") {
        if let dir { try? FileManager.default.removeItem(at: dir) }
        progress?.close()
        progress = nil
        state = .idle
        if let message { showAlert(message, detail) }
    }

    private func install(_ pkg: URL, dir: URL) {
        progress?.setInstalling()
        // §3.4: verified above, so no quarantine flag (URLSession doesn't add one; be sure).
        removexattr(pkg.path, "com.apple.quarantine", 0)

        let done: @Sendable (Error?) -> Void = { [weak self] error in
            DispatchQueue.main.async { self?.installerOpened(error, dir: dir) }
        }
        let installer = URL(fileURLWithPath: "/System/Library/CoreServices/Installer.app", isDirectory: true)
        let config = NSWorkspace.OpenConfiguration()
        config.activates = true
        if FileManager.default.fileExists(atPath: installer.path) {
            NSWorkspace.shared.open([pkg], withApplicationAt: installer, configuration: config) { _, e in done(e) }
        } else {
            NSWorkspace.shared.open(pkg, configuration: config) { _, e in done(e) }
        }
    }

    private func installerOpened(_ error: Error?, dir: URL) {
        if let error {
            downloadFailed("Couldn’t open the installer: \(error.localizedDescription)", dir: dir)
            return
        }
        // Installer reads the package from `dir`; the package's preinstall quits KeyBridge and the
        // next launch removes the folder.
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self else { return }
            self.progress?.close()
            self.progress = nil
            self.state = .idle
        }
    }

    /// Leftovers from earlier updates (Installer was done with them once KeyBridge relaunched).
    private func removeOldDownloads() {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        guard let items = try? FileManager.default.contentsOfDirectory(at: tmp, includingPropertiesForKeys: nil) else { return }
        for item in items where item.lastPathComponent.hasPrefix(Self.tempPrefix) {
            try? FileManager.default.removeItem(at: item)
        }
    }

    // MARK: – Helpers

    private func showAlert(_ title: String, _ text: String) {
        activate()
        let alert = NSAlert()
        alert.icon = NSApp.applicationIconImage
        alert.messageText = title
        alert.informativeText = text
        alert.runModal()
    }

    /// "the server responded…" → "The server responded…".
    private static func sentence(_ s: String) -> String {
        guard let first = s.first else { return s }
        let out = first.uppercased() + s.dropFirst()
        return out.hasSuffix(".") ? out : out + "."
    }

    private func activate() {
        if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
    }
}

// MARK: – UI pieces

/// "Release notes" link under the update alert's text; opens notes-url without closing the alert.
@MainActor
private final class ReleaseNotesLink: NSButton {
    private var url: URL?

    convenience init(url: URL) {
        self.init(frame: .zero)
        self.url = url
        isBordered = false
        setButtonType(.momentaryChange)
        attributedTitle = NSAttributedString(string: "Release notes", attributes: [
            .foregroundColor: NSColor.linkColor,
            .underlineStyle: NSUnderlineStyle.single.rawValue,
            .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
        ])
        target = self
        action = #selector(openNotes)
        sizeToFit()
    }

    override func resetCursorRects() { addCursorRect(bounds, cursor: .pointingHand) }

    @objc private func openNotes() {
        if let url { NSWorkspace.shared.open(url) }
    }
}

/// Small window: the app icon beside "Downloading update…", a determinate bar and Cancel,
/// then "Installing…".
@MainActor
final class UpdateProgressWindow: NSWindowController {
    var onCancel: (() -> Void)?

    private let total: Int64
    private let title = NSTextField(labelWithString: "Downloading update…")
    private let detail = NSTextField(labelWithString: "")
    private let bar = NSProgressIndicator()
    private let cancelButton = NSButton(title: "Cancel", target: nil, action: nil)

    init(total: Int64) {
        self.total = total
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 420, height: 120),
                            styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
        panel.title = "KeyBridge Update"
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        super.init(window: panel)

        let icon = NSImageView()
        icon.image = NSApp.applicationIconImage
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.setAccessibilityElement(false)
        title.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .semibold)
        detail.font = .monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
        detail.textColor = .secondaryLabelColor
        bar.isIndeterminate = false
        bar.minValue = 0
        bar.maxValue = Double(max(total, 1))
        bar.style = .bar
        cancelButton.bezelStyle = .rounded
        cancelButton.keyEquivalent = "\u{1b}"
        cancelButton.target = self
        cancelButton.action = #selector(cancelTapped)

        let column = NSStackView(views: [title, bar, detail])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 8
        let content = NSView()
        for v in [icon, column, cancelButton] {
            v.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(v)
        }
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 64),
            icon.heightAnchor.constraint(equalToConstant: 64),
            icon.topAnchor.constraint(equalTo: content.topAnchor, constant: 32),
            icon.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            column.topAnchor.constraint(equalTo: icon.topAnchor, constant: 6),
            column.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 16),
            column.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            bar.widthAnchor.constraint(equalTo: column.widthAnchor),
            bar.widthAnchor.constraint(equalToConstant: 300),
            cancelButton.topAnchor.constraint(greaterThanOrEqualTo: column.bottomAnchor, constant: 16),
            cancelButton.topAnchor.constraint(greaterThanOrEqualTo: icon.bottomAnchor, constant: 8),
            cancelButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            cancelButton.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
            cancelButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 90),
        ])
        panel.contentView = content
        panel.setContentSize(content.fittingSize)
        panel.center()
        setReceived(0)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    func show() {
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
    }

    func setReceived(_ n: Int64) {
        bar.doubleValue = Double(n)
        let f = ByteCountFormatter()
        f.countStyle = .file
        detail.stringValue = "\(f.string(fromByteCount: n)) of \(f.string(fromByteCount: total))"
    }

    func setInstalling() {
        title.stringValue = "Installing…"
        detail.stringValue = "Follow the steps in Installer."
        bar.isIndeterminate = true
        bar.startAnimation(nil)
        cancelButton.isEnabled = false
    }

    @objc private func cancelTapped() {
        cancelButton.isEnabled = false
        onCancel?()
    }
}
