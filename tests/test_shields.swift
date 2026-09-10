import Foundation

@main struct ShieldDecodeTests {
    static func main() throws {
        let full = #"{"permissions":false,"jobs":true,"monitor":true,"sticky":true,"signatures":false,"connect":false}"#.data(using: .utf8)!
        let state = try JSONDecoder().decode(ShieldState.self, from: full)
        precondition(!state.permissions)
        precondition(state.jobs)
        precondition(state.sticky)
        precondition(!state.connect)
        precondition(state.network == "off")
        precondition(!state.enabled("permissions"))
        precondition(state.enabled("sticky"))
        let empty = try JSONDecoder().decode(ShieldState.self, from: Data("{}".utf8))
        precondition(empty.permissions && empty.jobs && empty.monitor)
        precondition(!empty.sticky && !empty.signatures && !empty.connect)
        precondition(empty.network == "off")
        print("PASS: shield state defaults and toggles decode.")
    }
}
