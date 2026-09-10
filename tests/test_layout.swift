import AppKit

@main enum LayoutTests {
    static func main() {
        let screens = [NSRect(x: 0, y: 0, width: 1440, height: 875),
                       NSRect(x: 0, y: 0, width: 1024, height: 560),
                       NSRect(x: -1920, y: 200, width: 1920, height: 1055),
                       NSRect(x: 1440, y: -400, width: 1280, height: 695)]
        for visible in screens {
            let content = PanelGeometry.contentSize(in: visible)
            // Reproduce a popover initially placed above the screen with full chrome.
            let badFrame = NSRect(x: visible.maxX - 80, y: visible.maxY - 90,
                                  width: content.width + 4, height: content.height + 24)
            let fixed = NSRect(origin: PanelGeometry.origin(for: badFrame, in: visible), size: badFrame.size)
            precondition(visible.contains(fixed), "Panel extends beyond display: \(fixed)")
            precondition(content.height <= 700, "Panel must stay bounded")
        }
        print("PASS: offscreen panel placement corrected on four screen sizes/origins.")
    }
}
