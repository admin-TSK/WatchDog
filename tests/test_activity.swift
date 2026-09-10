import Foundation

@main struct ActivityTests {
    static func main() throws {
        let data = #"[{"id":"old","timestamp":20,"kind":"warning","title":"Session check timed out","detail":"Original detail","resolved_at":30},{"id":"new","timestamp":40,"kind":"warning","title":"New warning","detail":"Check failed"},{"id":"action","timestamp":50,"kind":"permission","title":"Blocked","detail":"jamf"},{"id":"toggle","timestamp":60,"kind":"shield","title":"Permissions shield off","detail":"Local control updated from Shields."}]"#.data(using: .utf8)!
        let events = try JSONDecoder().decode([Activity].self, from: data)
        precondition(Activity.visible(events, showResolved: false).map(\.id) == ["new", "action", "toggle"])
        precondition(Activity.visible(events, showResolved: true).count == 4)
        precondition(!events[0].countsAsUnread(since: 0))
        precondition(events[1].countsAsUnread(since: 0))
        precondition(!events[1].countsAsUnread(since: 45))
        precondition(events[0].displayTitle.hasPrefix("Resolved"))
        precondition(events[0].detail == "Original detail")
        precondition(!events[1].isResolved) // Older feeds omit the optional field.
        precondition(events[3].symbol == "switch.2")
        precondition(!events[3].notifiesUser)
        precondition(events[1].notifiesUser)
        precondition(!events[0].notifiesUser)
        let partialData = #"{"id":"p","timestamp":70,"kind":"warning","title":"Network hostname partial","detail":"A wildcard could not be expanded; IP approximation is incomplete."}"#.data(using: .utf8)!
        let partial = try JSONDecoder().decode(Activity.self, from: partialData)
        precondition(!partial.notifiesUser)
        let loadedData = #"{"id":"r","timestamp":71,"kind":"shield","title":"Network rules loaded","detail":"A loaded rule is not a confirmed deny."}"#.data(using: .utf8)!
        let loaded = try JSONDecoder().decode(Activity.self, from: loadedData)
        precondition(!loaded.notifiesUser)
        precondition([partial, loaded].filter(\.notifiesUser).isEmpty)
        print("PASS: resolved history stays available; new warnings remain visible and unread.")
    }
}
