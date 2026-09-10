import SwiftUI

struct NetworkStatus: Decodable, Equatable {
    var mode: String
    var anchorLoaded: Bool
    var resolvedCount: Int
    var partial: [String]
    var stale: [String]
    var pfEnabled: Bool

    enum CodingKeys: String, CodingKey {
        case mode, partial, stale
        case anchorLoaded = "anchor_loaded"
        case resolvedCount = "resolved_count"
        case pfEnabled = "pf_enabled"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mode = try container.decodeIfPresent(String.self, forKey: .mode) ?? "off"
        anchorLoaded = try container.decodeIfPresent(Bool.self, forKey: .anchorLoaded) ?? false
        resolvedCount = try container.decodeIfPresent(Int.self, forKey: .resolvedCount) ?? 0
        partial = try container.decodeIfPresent([String].self, forKey: .partial) ?? []
        stale = try container.decodeIfPresent([String].self, forKey: .stale) ?? []
        pfEnabled = try container.decodeIfPresent(Bool.self, forKey: .pfEnabled) ?? false
    }
}

struct ShieldState: Decodable, Equatable {
    var permissions: Bool
    var jobs: Bool
    var monitor: Bool
    var sticky: Bool
    var signatures: Bool
    var connect: Bool
    var network: String

    static let coreOn = ShieldState(permissions: true, jobs: true, monitor: true,
                                    sticky: false, signatures: false, connect: false, network: "off")

    enum CodingKeys: String, CodingKey {
        case permissions, jobs, monitor, sticky, signatures, connect, network
    }

    init(permissions: Bool, jobs: Bool, monitor: Bool, sticky: Bool, signatures: Bool, connect: Bool, network: String) {
        self.permissions = permissions
        self.jobs = jobs
        self.monitor = monitor
        self.sticky = sticky
        self.signatures = signatures
        self.connect = connect
        self.network = network
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        permissions = try container.decodeIfPresent(Bool.self, forKey: .permissions) ?? true
        jobs = try container.decodeIfPresent(Bool.self, forKey: .jobs) ?? true
        monitor = try container.decodeIfPresent(Bool.self, forKey: .monitor) ?? true
        sticky = try container.decodeIfPresent(Bool.self, forKey: .sticky) ?? false
        signatures = try container.decodeIfPresent(Bool.self, forKey: .signatures) ?? false
        connect = try container.decodeIfPresent(Bool.self, forKey: .connect) ?? false
        network = try container.decodeIfPresent(String.self, forKey: .network) ?? "off"
    }

    func enabled(_ id: String) -> Bool {
        switch id {
        case "permissions": return permissions
        case "jobs": return jobs
        case "monitor": return monitor
        case "sticky": return sticky
        case "signatures": return signatures
        case "connect": return connect
        default: return false
        }
    }
}

struct ShieldSpec: Identifiable {
    let id: String
    let title: String
    let detail: String
    let symbol: String
}

let shieldCatalog: [ShieldSpec] = [
    ShieldSpec(id: "permissions", title: "Permissions", detail: "Strip execute bits on Jamf binaries", symbol: "lock.fill"),
    ShieldSpec(id: "jobs", title: "Launch jobs", detail: "Disable and unload matching jobs", symbol: "gearshape.fill"),
    ShieldSpec(id: "monitor", title: "Process monitor", detail: "Pause and kill matching processes", symbol: "hand.raised.fill"),
    ShieldSpec(id: "sticky", title: "Sticky block", detail: "Resist a naive chmod +x", symbol: "pin.fill"),
    ShieldSpec(id: "signatures", title: "Signatures", detail: "Match Jamf code-signing IDs", symbol: "signature"),
    ShieldSpec(id: "connect", title: "Jamf Connect", detail: "Optional; can lock the login window", symbol: "person.crop.circle.fill"),
]
