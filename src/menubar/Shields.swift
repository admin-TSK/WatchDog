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
    var ddmChannel: Bool
    var ddmPush: Bool
    var ddmUpdate: Bool
    var ddmInstalls: Bool
    var ddmAssets: Bool
    var network: String

    static let coreOn = ShieldState(permissions: true, jobs: true, monitor: true,
                                    sticky: false, signatures: false, connect: false,
                                    ddmChannel: false, ddmPush: false, ddmUpdate: false,
                                    ddmInstalls: false, ddmAssets: false, network: "off")

    enum CodingKeys: String, CodingKey {
        case permissions, jobs, monitor, sticky, signatures, connect, network
        case ddmChannel = "ddm-channel"
        case ddmPush = "ddm-push"
        case ddmUpdate = "ddm-update"
        case ddmInstalls = "ddm-installs"
        case ddmAssets = "ddm-assets"
    }

    init(permissions: Bool, jobs: Bool, monitor: Bool, sticky: Bool, signatures: Bool, connect: Bool,
         ddmChannel: Bool, ddmPush: Bool, ddmUpdate: Bool, ddmInstalls: Bool, ddmAssets: Bool, network: String) {
        self.permissions = permissions
        self.jobs = jobs
        self.monitor = monitor
        self.sticky = sticky
        self.signatures = signatures
        self.connect = connect
        self.ddmChannel = ddmChannel
        self.ddmPush = ddmPush
        self.ddmUpdate = ddmUpdate
        self.ddmInstalls = ddmInstalls
        self.ddmAssets = ddmAssets
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
        ddmChannel = try container.decodeIfPresent(Bool.self, forKey: .ddmChannel) ?? false
        ddmPush = try container.decodeIfPresent(Bool.self, forKey: .ddmPush) ?? false
        ddmUpdate = try container.decodeIfPresent(Bool.self, forKey: .ddmUpdate) ?? false
        ddmInstalls = try container.decodeIfPresent(Bool.self, forKey: .ddmInstalls) ?? false
        ddmAssets = try container.decodeIfPresent(Bool.self, forKey: .ddmAssets) ?? false
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
        case "ddm-channel": return ddmChannel
        case "ddm-push": return ddmPush
        case "ddm-update": return ddmUpdate
        case "ddm-installs": return ddmInstalls
        case "ddm-assets": return ddmAssets
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
    ShieldSpec(id: "ddm-channel", title: "Management channel", detail: "Pause new declarations and status reports", symbol: "antenna.radiowaves.left.and.right"),
    ShieldSpec(id: "ddm-push", title: "Management wake", detail: "Block the push that wakes management", symbol: "bell.slash"),
    ShieldSpec(id: "ddm-update", title: "Software update", detail: "Pause an enforced OS update and remove its applied state", symbol: "arrow.down.circle"),
    ShieldSpec(id: "ddm-installs", title: "Installs", detail: "Pause blueprint app and package downloads. Installed apps stay.", symbol: "square.and.arrow.down"),
    ShieldSpec(id: "ddm-assets", title: "Declaration assets", detail: "Pause credential and data asset downloads", symbol: "doc.badge.ellipsis"),
]
