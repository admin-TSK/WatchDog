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
    static func visible(_ events: [Activity], showResolved: Bool) -> [Activity] {
        events.filter { showResolved || !$0.isResolved }
    }
}
