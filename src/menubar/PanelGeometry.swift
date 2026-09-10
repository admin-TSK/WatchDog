import AppKit

enum PanelGeometry {
    static func contentSize(in visible: NSRect) -> NSSize {
        // Leave room for the popover's arrow, border, and display-edge margins.
        NSSize(width: min(410, max(1, visible.width - 24)),
               height: min(820, max(1, visible.height - 48)))
    }
    static func origin(for frame: NSRect, in visible: NSRect) -> NSPoint {
        let bounds = visible.insetBy(dx: 6, dy: 6)
        return NSPoint(x: max(bounds.minX, min(frame.minX, bounds.maxX - frame.width)),
                       y: max(bounds.minY, min(frame.minY, bounds.maxY - frame.height)))
    }
}
