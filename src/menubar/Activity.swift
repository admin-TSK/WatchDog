import Foundation

struct Activity: Decodable, Identifiable {
    let id: String
    let timestamp: Double?
    let kind: String
    let title: String
    let detail: String
    let resolved_at: Double?

    var isResolved: Bool { resolved_at != nil }
    var displayTitle: String { isResolved ? "Resolved · \(title)" : title }
    var symbol: String {
        if isResolved { return "checkmark.circle" }
        switch kind {
        case "process": return "hand.raised.fill"
        case "permission": return "lock.fill"
        case "job": return "gearshape.fill"
        case "shield": return "switch.2"
        case "warning": return "clock.badge.exclamationmark"
        default: return "exclamationmark.triangle.fill"
        }
    }
    func countsAsUnread(since timestamp: Double) -> Bool {
        !isResolved && (self.timestamp ?? 0) > timestamp
    }
    /// Banners are for protection actions and real faults, not shield toggles or expected gaps.
    var notifiesUser: Bool {
        if isResolved { return false }
        if title == "Network hostname partial" { return false }
        switch kind {
        case "process", "permission", "job", "error", "warning": return true
        default: return false
        }
    }
    static func visible(_ events: [Activity], showResolved: Bool) -> [Activity] {
        events.filter { showResolved || !$0.isResolved }
    }
}
