import Foundation

@main struct ActivityTests {
    static func main() throws {
        let data = #"[{"id":"old","timestamp":20,"kind":"warning","title":"Session check timed out","detail":"Original detail","resolved_at":30},{"id":"new","timestamp":40,"kind":"warning","title":"New warning","detail":"Check failed"},{"id":"action","timestamp":50,"kind":"permission","title":"Blocked","detail":"jamf"}]"#.data(using: .utf8)!
        let events = try JSONDecoder().decode([Activity].self, from: data)
        precondition(Activity.visible(events, showResolved: false).map(\.id) == ["new", "action"])
        precondition(Activity.visible(events, showResolved: true).count == 3)
        precondition(!events[0].countsAsUnread(since: 0))
        precondition(events[1].countsAsUnread(since: 0))
        precondition(!events[1].countsAsUnread(since: 45))
        precondition(events[0].displayTitle.hasPrefix("Resolved"))
        precondition(events[0].detail == "Original detail")
        precondition(!events[1].isResolved) // Older feeds omit the optional field.
        print("PASS: resolved history stays available; new warnings remain visible and unread.")
    }
}
