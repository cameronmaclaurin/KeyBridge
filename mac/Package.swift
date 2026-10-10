// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "KeyBridge",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "KeyBridge",
            path: "Sources/KeyBridge",
            resources: [.copy("../../Resources/Info.plist")],
            swiftSettings: [.unsafeFlags(["-strict-concurrency=minimal"])]
        )
    ]
)
