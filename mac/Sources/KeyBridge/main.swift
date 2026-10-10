import AppKit

// Entry point: run entirely on the main actor to satisfy Swift 6 concurrency.
NSApplication.shared.delegate = AppDelegate()
NSApplication.shared.run()
