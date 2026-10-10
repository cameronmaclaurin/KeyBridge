// make_icons.swift - generates every KeyBridge icon from code.
//
//   swift assets/src/make_icons.swift          (run from the repository root)
//
// Writes:
//   assets/AppIcon.icns      macOS app icon (16 ... 512@2x)
//   assets/keybridge.ico     Windows app icon (16, 20, 24, 32, 40, 48, 64, 256)
//   assets/tray-on.ico       Windows tray icon, connected (16, 20, 24, 32, 48)
//   assets/tray-off.ico      Windows tray icon, disconnected (16, 20, 24, 32, 48)
//   assets/logo.png          512 px logo for the README
//
// Set KEYBRIDGE_ICON_PREVIEW=/some/dir to also dump every rendered size plus
// magnified contact sheets (light and dark backgrounds) for review.
//
// Design: a brand-gradient rounded square holding two white keycaps joined by
// a bridge-shaped arrow (keys travel from one computer to the other). No SF
// Symbols, no platform logos. Small sizes use bolder, simplified geometry.
//
// Dependencies: CoreGraphics, ImageIO and /usr/bin/iconutil (all ship with macOS).

import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

// MARK: - Colour

let sRGB = CGColorSpace(name: CGColorSpace.sRGB)!

func rgb(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: sRGB, components: [
        CGFloat((hex >> 16) & 0xFF) / 255,
        CGFloat((hex >> 8) & 0xFF) / 255,
        CGFloat(hex & 0xFF) / 255,
        alpha,
    ])!
}

func gradient(_ stops: [(CGFloat, CGColor)]) -> CGGradient {
    CGGradient(colorsSpace: sRGB,
               colors: stops.map { $0.1 } as CFArray,
               locations: stops.map { $0.0 })!
}

/// Brand plate: violet -> blue -> cyan, lit from the top.
let brandPlate = gradient([(0.0, rgb(0x9B6BFF)), (0.48, rgb(0x5468FF)), (1.0, rgb(0x16BDEB))])
/// Disconnected tray plate: neutral mid-grey that reads on light and dark taskbars.
let grayPlate = gradient([(0.0, rgb(0xA3A9B3)), (1.0, rgb(0x6C727C))])

let keyTopFace = gradient([(0.0, rgb(0xFFFFFF)), (1.0, rgb(0xEEF1FB))])
let keySkirt = gradient([(0.0, rgb(0xDCE2F6)), (1.0, rgb(0xB9C3E6))])

// MARK: - Bitmaps

func makeContext(_ w: Int, _ h: Int) -> CGContext {
    let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8,
                        bytesPerRow: w * 4, space: sRGB,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.setShouldAntialias(true)
    ctx.setAllowsAntialiasing(true)
    ctx.interpolationQuality = .high
    return ctx
}

func pngData(_ image: CGImage) -> Data {
    let data = NSMutableData()
    let dest = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, image, nil)
    precondition(CGImageDestinationFinalize(dest), "PNG encoding failed")
    return data as Data
}

func writePNG(_ image: CGImage, to url: URL) throws {
    try pngData(image).write(to: url)
}

// MARK: - Shapes

/// Rounded square with continuous ("squircle") corners: each corner is a
/// superellipse quadrant, so curvature eases into the straight edges the way
/// macOS icon plates do. `radius` is the equivalent circular corner radius.
func continuousRect(_ r: CGRect, radius: CGFloat) -> CGPath {
    let n: CGFloat = 3.2                                   // superellipse exponent
    let extent = min(radius * 1.5, min(r.width, r.height) / 2) // corner reach along each edge
    let path = CGMutablePath()
    let steps = 48
    // Corner centres (inner) and the quadrant each corner spans, counter-clockwise from bottom-right.
    let corners: [(CGPoint, CGFloat)] = [
        (CGPoint(x: r.maxX - extent, y: r.minY + extent), -.pi / 2), // bottom-right: -90 deg -> 0
        (CGPoint(x: r.maxX - extent, y: r.maxY - extent), 0),         // top-right: 0 -> 90
        (CGPoint(x: r.minX + extent, y: r.maxY - extent), .pi / 2),   // top-left: 90 -> 180
        (CGPoint(x: r.minX + extent, y: r.minY + extent), .pi),       // bottom-left: 180 -> 270
    ]
    for (i, (c, start)) in corners.enumerated() {
        for s in 0...steps {
            let t = start + (.pi / 2) * CGFloat(s) / CGFloat(steps)
            let ct = cos(t), st = sin(t)
            let x = c.x + extent * copysign(pow(abs(ct), 2 / n), ct)
            let y = c.y + extent * copysign(pow(abs(st), 2 / n), st)
            if i == 0 && s == 0 { path.move(to: CGPoint(x: x, y: y)) } else { path.addLine(to: CGPoint(x: x, y: y)) }
        }
    }
    path.closeSubpath()
    return path
}

// MARK: - Glyph geometry

enum Detail { case tiny, small, full }

/// All values are fractions of the plate's side length.
struct Geometry {
    var keyW: CGFloat       // keycap width
    var keyH: CGFloat       // keycap height
    var keyCX: CGFloat      // centre x of the left keycap (the right one is mirrored)
    var keyR: CGFloat       // keycap corner radius
    var skirt: CGFloat      // visible keycap side below the top face
    var gap: CGFloat        // space between keycap tops and the bridge
    var arrowLen: CGFloat
    var arrowW: CGFloat
    var stroke: CGFloat     // bridge line width
    var breakLen: CGFloat   // visible gap cut into the bridge for the "disconnected" glyph

    static func forDetail(_ d: Detail) -> Geometry {
        switch d {
        case .full:
            return Geometry(keyW: 0.30, keyH: 0.235, keyCX: 0.285, keyR: 0.055, skirt: 0.048,
                            gap: 0.04, arrowLen: 0.125, arrowW: 0.20, stroke: 0.074, breakLen: 0.10)
        case .small:
            return Geometry(keyW: 0.28, keyH: 0.235, keyCX: 0.26, keyR: 0.05, skirt: 0.05,
                            gap: 0.05, arrowLen: 0.16, arrowW: 0.31, stroke: 0.10, breakLen: 0.12)
        case .tiny:
            return Geometry(keyW: 0.25, keyH: 0.22, keyCX: 0.25, keyR: 0.05, skirt: 0.0625,
                            gap: 0.0625, arrowLen: 0.19, arrowW: 0.40, stroke: 0.125, breakLen: 0.14)
        }
    }
}

func detail(forPlate side: CGFloat) -> Detail {
    if side < 30 { return .tiny }
    if side < 70 { return .small }
    return .full
}

/// Draws the keycaps + bridge arrow inside `plate` (pixel coordinates, y up).
/// Below `.full` detail every edge is snapped to the pixel grid so 16-48 px renders stay crisp
/// (the plate origin must then be integral, which `render` guarantees).
func drawGlyph(_ ctx: CGContext, plate: CGRect, detail d: Detail, broken: Bool, shadowed: Bool) {
    let g = Geometry.forDetail(d)
    let P = plate.width
    let snap = d != .full
    func q(_ v: CGFloat) -> CGFloat { snap ? v.rounded() : v }
    func q1(_ v: CGFloat) -> CGFloat { snap ? max(1, v.rounded()) : v }

    // Everything below is in pixels relative to the plate's bottom-left corner.
    let stroke = q1(g.stroke * P)
    var keyW = q(g.keyW * P)
    if snap && Int(keyW) % 2 != Int(stroke) % 2 { keyW += 1 } // keeps the legs' edges on whole pixels
    let keyH = q(g.keyH * P)
    let keyMinX = q((g.keyCX - g.keyW / 2) * P)
    let lx = keyMinX + keyW / 2                   // left leg / left key centre
    let rx = P - lx                               // right leg / right key centre
    let archR = P / 2 - lx                        // bridge centre-line radius
    let gap = q1(g.gap * P)
    let arrowLen = q(g.arrowLen * P)
    let skirt = q1(g.skirt * P)
    let keyR = g.keyR * P
    // Centre the glyph vertically: keys + gap + arrow + arch + half the stroke.
    let total = keyH + gap + arrowLen + archR + stroke / 2
    let keyY = q((P - total) / 2)
    let keyTop = keyY + keyH
    let base = keyTop + gap + arrowLen            // where the arch meets its legs

    func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: plate.minX + x, y: plate.minY + y) }

    if shadowed {
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -0.014 * P), blur: 0.035 * P,
                      color: rgb(0x1A0F5C, 0.38))
        ctx.beginTransparencyLayer(auxiliaryInfo: nil)
    }

    // Keycaps
    for minX in [keyMinX, P - keyMinX - keyW] {
        let body = CGRect(origin: pt(minX, keyY), size: CGSize(width: keyW, height: keyH))
        let bodyPath = CGPath(roundedRect: body, cornerWidth: keyR, cornerHeight: keyR, transform: nil)
        if d == .tiny {
            // Flat two-tone key: white face over a one-pixel lavender skirt.
            let face = CGRect(x: body.minX, y: body.minY + skirt, width: keyW, height: keyH - skirt)
            ctx.addPath(bodyPath); ctx.setFillColor(rgb(0xC5CDF0)); ctx.fillPath()
            ctx.addPath(CGPath(roundedRect: face, cornerWidth: keyR, cornerHeight: keyR, transform: nil))
            ctx.setFillColor(rgb(0xFFFFFF)); ctx.fillPath()
        } else {
            let inset = q(skirt * 0.42)
            let face = CGRect(x: body.minX + inset, y: body.minY + skirt,
                              width: keyW - 2 * inset, height: keyH - skirt - q(inset * 0.5))
            let faceR = max(0, keyR - inset * 0.6)
            ctx.saveGState(); ctx.addPath(bodyPath); ctx.clip()
            ctx.drawLinearGradient(keySkirt, start: CGPoint(x: 0, y: body.maxY), end: CGPoint(x: 0, y: body.minY), options: [])
            ctx.restoreGState()
            ctx.saveGState()
            ctx.addPath(CGPath(roundedRect: face, cornerWidth: faceR, cornerHeight: faceR, transform: nil)); ctx.clip()
            ctx.drawLinearGradient(keyTopFace, start: CGPoint(x: 0, y: face.maxY), end: CGPoint(x: 0, y: face.minY), options: [])
            ctx.restoreGState()
        }
    }

    // Bridge: the left leg rises from the left key, arches over and lands as an arrow on the right key.
    ctx.setStrokeColor(rgb(0xFFFFFF))
    ctx.setFillColor(rgb(0xFFFFFF))
    ctx.setLineWidth(stroke)
    ctx.setLineJoin(.round)
    ctx.setLineCap(.butt)

    let center = pt(P / 2, base)
    let foot = pt(lx, keyTop + gap + stroke / 2)  // centre of the round cap on the left leg
    let overlap = max(1, 0.02 * P)                // tuck the arch into the arrowhead so there is no seam
    func dot(_ c: CGPoint) {
        ctx.fillEllipse(in: CGRect(x: c.x - stroke / 2, y: c.y - stroke / 2, width: stroke, height: stroke))
    }

    let leftHalf = CGMutablePath()
    leftHalf.move(to: foot)
    leftHalf.addLine(to: pt(lx, base))
    let rightHalf = CGMutablePath()
    if broken {
        // Cut the apex; the cut ends are rounded, so widen the angle by a stroke's width.
        let half = (g.breakLen * P / 2 + stroke / 2) / archR
        leftHalf.addArc(center: center, radius: archR, startAngle: .pi, endAngle: .pi / 2 + half, clockwise: true)
        rightHalf.addArc(center: center, radius: archR, startAngle: .pi / 2 - half, endAngle: 0, clockwise: true)
        for a in [CGFloat.pi / 2 + half, .pi / 2 - half] {
            dot(CGPoint(x: center.x + archR * cos(a), y: center.y + archR * sin(a)))
        }
    } else {
        leftHalf.addArc(center: center, radius: archR, startAngle: .pi, endAngle: .pi / 2, clockwise: true)
        rightHalf.addArc(center: center, radius: archR, startAngle: .pi / 2, endAngle: 0, clockwise: true)
    }
    rightHalf.addLine(to: pt(rx, base - overlap))
    ctx.addPath(leftHalf); ctx.addPath(rightHalf); ctx.strokePath()
    dot(foot)

    // Arrowhead (corners softened on larger renders)
    let head = CGMutablePath()
    head.move(to: pt(rx - g.arrowW * P / 2, base))
    head.addLine(to: pt(rx + g.arrowW * P / 2, base))
    head.addLine(to: pt(rx, base - arrowLen))
    head.closeSubpath()
    ctx.addPath(head); ctx.fillPath()
    if d == .full {
        ctx.setLineWidth(0.018 * P)
        ctx.addPath(head); ctx.strokePath()
    }

    if shadowed {
        ctx.endTransparencyLayer()
        ctx.restoreGState()
    }
}

// MARK: - Plate

func drawPlate(_ ctx: CGContext, rect: CGRect, radius: CGFloat, fill: CGGradient,
               dropShadow: Bool, gloss: Bool) {
    let path = continuousRect(rect, radius: radius)
    let S = rect.width

    if dropShadow {
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -0.012 * S), blur: 0.030 * S, color: rgb(0x000000, 0.32))
        ctx.addPath(path); ctx.setFillColor(rgb(0x5468FF)); ctx.fillPath()
        ctx.restoreGState()
    }

    ctx.saveGState()
    ctx.addPath(path); ctx.clip()
    // Diagonal fill, top-left to bottom-right.
    ctx.drawLinearGradient(fill,
                           start: CGPoint(x: rect.minX + 0.20 * S, y: rect.maxY),
                           end: CGPoint(x: rect.minX + 0.80 * S, y: rect.minY),
                           options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
    if gloss {
        // Soft top light and a faint darkening toward the bottom edge.
        let light = gradient([(0, rgb(0xFFFFFF, 0.22)), (1, rgb(0xFFFFFF, 0))])
        ctx.drawRadialGradient(light, startCenter: CGPoint(x: rect.midX, y: rect.maxY + 0.15 * S), startRadius: 0,
                               endCenter: CGPoint(x: rect.midX, y: rect.maxY + 0.15 * S), endRadius: 0.85 * S, options: [])
        let dark = gradient([(0, rgb(0x0B0A3A, 0)), (1, rgb(0x0B0A3A, 0.16))])
        ctx.drawLinearGradient(dark, start: CGPoint(x: 0, y: rect.minY + 0.35 * S), end: CGPoint(x: 0, y: rect.minY), options: [])
    }
    ctx.restoreGState()

    if gloss {
        // Hairline inner highlight along the top edge.
        ctx.saveGState()
        ctx.addPath(path); ctx.clip()
        ctx.addPath(path)
        ctx.setLineWidth(max(1, 0.006 * S) * 2)
        ctx.setStrokeColor(rgb(0xFFFFFF, 0.28))
        ctx.clip(to: CGRect(x: rect.minX, y: rect.midY, width: S, height: S / 2))
        ctx.strokePath()
        ctx.restoreGState()
    }
}

// MARK: - Variants

enum Variant { case mac, windows, trayOn, trayOff }

func render(_ px: Int, _ variant: Variant) -> CGImage {
    let ctx = makeContext(px, px)
    let S = CGFloat(px)
    let plate: CGRect
    let radius: CGFloat
    switch variant {
    case .mac:
        // Apple's macOS grid: 824 px body centred on a 1024 canvas, ~185 px corners.
        // At 16 px a one-pixel margin keeps the glyph legible; small sizes snap to whole pixels.
        let m = px == 16 ? 1 : (px < 128 ? (S * 100 / 1024).rounded() : S * 100 / 1024)
        plate = CGRect(x: m, y: m, width: S - 2 * m, height: S - 2 * m)
        radius = plate.width * 185.4 / 824
    case .windows:
        // Windows icons run nearly edge to edge.
        let m = px >= 32 ? (S / 32).rounded() : 0
        plate = CGRect(x: m, y: m, width: S - 2 * m, height: S - 2 * m)
        radius = plate.width * 0.20
    case .trayOn, .trayOff:
        plate = CGRect(x: 0, y: 0, width: S, height: S)
        radius = S * 0.22
    }
    let d = detail(forPlate: plate.width)
    let isTray = variant == .trayOn || variant == .trayOff
    drawPlate(ctx, rect: plate, radius: radius,
              fill: variant == .trayOff ? grayPlate : brandPlate,
              dropShadow: variant == .mac && px >= 64,
              gloss: !isTray && d != .tiny)
    drawGlyph(ctx, plate: plate, detail: d, broken: variant == .trayOff,
              shadowed: !isTray && d != .tiny)
    return ctx.makeImage()!
}

// MARK: - ICO writer

extension Data {
    mutating func le16(_ v: Int) { var x = UInt16(truncatingIfNeeded: v).littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func le32(_ v: Int) { var x = UInt32(truncatingIfNeeded: v).littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
}

/// Straight (non-premultiplied) RGBA bytes, top row first.
func straightRGBA(_ image: CGImage) -> [UInt8] {
    let w = image.width, h = image.height
    let ctx = makeContext(w, h)
    ctx.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
    let p = ctx.data!.bindMemory(to: UInt8.self, capacity: w * h * 4)
    var out = [UInt8](repeating: 0, count: w * h * 4)
    for i in 0..<(w * h) {
        let a = Int(p[i * 4 + 3])
        out[i * 4 + 3] = UInt8(a)
        guard a > 0 else { continue }
        for c in 0..<3 { out[i * 4 + c] = UInt8(min(255, (Int(p[i * 4 + c]) * 255 + a / 2) / a)) }
    }
    return out
}

/// Classic 32-bit DIB entry (BITMAPINFOHEADER + BGRA rows bottom-up + 1-bit AND mask).
/// Used for sizes below 256 because every Windows toolchain (rc, windres, Inno Setup) accepts it.
func dibEntry(_ image: CGImage) -> Data {
    let w = image.width, h = image.height
    let rgba = straightRGBA(image)
    let maskStride = ((w + 31) / 32) * 4
    var d = Data()
    d.le32(40); d.le32(w); d.le32(h * 2); d.le16(1); d.le16(32); d.le32(0)
    d.le32(w * h * 4 + maskStride * h); d.le32(0); d.le32(0); d.le32(0); d.le32(0)
    for y in stride(from: h - 1, through: 0, by: -1) {
        for x in 0..<w {
            let i = (y * w + x) * 4
            d.append(contentsOf: [rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]])
        }
    }
    for y in stride(from: h - 1, through: 0, by: -1) {
        var row = [UInt8](repeating: 0, count: maskStride)
        for x in 0..<w where rgba[(y * w + x) * 4 + 3] == 0 { row[x / 8] |= 0x80 >> UInt8(x % 8) }
        d.append(contentsOf: row)
    }
    return d
}

/// Packs images into an .ico. 256 px entries are PNG-compressed (Vista+), smaller ones are DIBs.
func icoData(_ images: [CGImage]) -> Data {
    let payloads = images.map { $0.width >= 256 ? pngData($0) : dibEntry($0) }
    var d = Data()
    d.le16(0); d.le16(1); d.le16(images.count)
    var offset = 6 + 16 * images.count
    for (img, payload) in zip(images, payloads) {
        d.append(UInt8(img.width >= 256 ? 0 : img.width))
        d.append(UInt8(img.height >= 256 ? 0 : img.height))
        d.append(0); d.append(0)          // palette colours, reserved
        d.le16(1); d.le16(32)              // planes, bits per pixel
        d.le32(payload.count); d.le32(offset)
        offset += payload.count
    }
    for payload in payloads { d.append(payload) }
    return d
}

// MARK: - Preview sheets

func contactSheet(_ images: [CGImage], zoom: Int, background: UInt32) -> CGImage {
    let pad = 16
    let width = images.reduce(pad) { $0 + $1.width * zoom + pad } + images.reduce(0) { $0 + $1.width + pad }
    let height = (images.map(\.height).max() ?? 0) * zoom + 2 * pad
    let ctx = makeContext(width, height)
    ctx.setFillColor(rgb(background)); ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))
    var x = pad
    ctx.interpolationQuality = .none
    for img in images { // magnified, nearest-neighbour
        ctx.draw(img, in: CGRect(x: x, y: pad, width: img.width * zoom, height: img.height * zoom))
        x += img.width * zoom + pad
    }
    for img in images { // actual size
        ctx.draw(img, in: CGRect(x: x, y: pad, width: img.width, height: img.height))
        x += img.width + pad
    }
    return ctx.makeImage()!
}

// MARK: - Main

let fm = FileManager.default
let root = URL(fileURLWithPath: fm.currentDirectoryPath)
let assets = root.appendingPathComponent("assets")
guard fm.fileExists(atPath: assets.appendingPathComponent("src/make_icons.swift").path) else {
    FileHandle.standardError.write("Run from the repository root: swift assets/src/make_icons.swift\n".data(using: .utf8)!)
    exit(1)
}
let preview: URL? = ProcessInfo.processInfo.environment["KEYBRIDGE_ICON_PREVIEW"].map { URL(fileURLWithPath: $0) }
if let preview { try fm.createDirectory(at: preview, withIntermediateDirectories: true) }

// macOS .icns via a temporary .iconset
let iconset = fm.temporaryDirectory.appendingPathComponent("KeyBridge-\(UUID().uuidString).iconset")
try fm.createDirectory(at: iconset, withIntermediateDirectories: true)
defer { try? fm.removeItem(at: iconset) }
var macRenders: [Int: CGImage] = [:]
for base in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let px = base * scale
        let img = macRenders[px] ?? render(px, .mac)
        macRenders[px] = img
        let name = scale == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        try writePNG(img, to: iconset.appendingPathComponent(name))
    }
}
let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", assets.appendingPathComponent("AppIcon.icns").path]
try iconutil.run(); iconutil.waitUntilExit()
guard iconutil.terminationStatus == 0 else { print("iconutil failed"); exit(1) }
print("wrote assets/AppIcon.icns")

try writePNG(macRenders[512]!, to: assets.appendingPathComponent("logo.png"))
print("wrote assets/logo.png")

let windowsSizes = [16, 20, 24, 32, 40, 48, 64, 256]
let traySizes = [16, 20, 24, 32, 48]
let windows = windowsSizes.map { render($0, .windows) }
let trayOn = traySizes.map { render($0, .trayOn) }
let trayOff = traySizes.map { render($0, .trayOff) }
try icoData(windows).write(to: assets.appendingPathComponent("keybridge.ico"))
print("wrote assets/keybridge.ico")
try icoData(trayOn).write(to: assets.appendingPathComponent("tray-on.ico"))
print("wrote assets/tray-on.ico")
try icoData(trayOff).write(to: assets.appendingPathComponent("tray-off.ico"))
print("wrote assets/tray-off.ico")

if let preview {
    for (px, img) in macRenders { try writePNG(img, to: preview.appendingPathComponent("mac-\(px).png")) }
    for img in windows { try writePNG(img, to: preview.appendingPathComponent("win-\(img.width).png")) }
    for (i, px) in traySizes.enumerated() {
        try writePNG(trayOn[i], to: preview.appendingPathComponent("tray-on-\(px).png"))
        try writePNG(trayOff[i], to: preview.appendingPathComponent("tray-off-\(px).png"))
    }
    let macSmall = [16, 32, 64].map { macRenders[$0]! }
    for (name, bg) in [("light", UInt32(0xF3F3F3)), ("dark", UInt32(0x202020))] {
        try writePNG(contactSheet(macSmall, zoom: 8, background: bg), to: preview.appendingPathComponent("sheet-mac-\(name).png"))
        try writePNG(contactSheet(Array(windows.prefix(6)), zoom: 6, background: bg), to: preview.appendingPathComponent("sheet-win-\(name).png"))
        try writePNG(contactSheet(trayOn + trayOff, zoom: 6, background: bg), to: preview.appendingPathComponent("sheet-tray-\(name).png"))
    }
    print("previews in \(preview.path)")
}
