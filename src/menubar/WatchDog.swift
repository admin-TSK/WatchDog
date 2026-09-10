import AppKit
import SwiftUI
import UserNotifications

struct Snapshot: Decodable {
    let schema: Int
    let updated_at: Double
    let guard_running: Bool
    let monitor_running: Bool
    let execution_blocked: Bool
    let executable_count: Int
    let job_count: Int
    let process_total: Int
    let action_total: Int
    let events: [Activity]
    let shields: ShieldState?
}

@MainActor final class ActivityStore: ObservableObject {
    @Published var snapshot: Snapshot?
    @Published var showResolved = false
    @Published var now = Date()
    @Published var readFailure = false
    @Published var lastViewed = UserDefaults.standard.object(forKey: "lastViewed") as? Date ?? Date()
    @Published var notifications = UserDefaults.standard.bool(forKey: "notifications")
    @Published var notificationNote = ""
    @Published var launchAtLogin = false
    @Published var tab = "shields"
    @Published var pending: [String: Bool] = [:]
    var onChange: (() -> Void)?
    private var timer: Timer?
    private var previousIDs: Set<String>?
    let feedURL: URL
    let demo: Bool
    var loginURL: URL { FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/local.watchdog.menubar.plist") }
    var fresh: Bool { !readFailure && snapshot.map { now.timeIntervalSince1970 - $0.updated_at < 12 && now.timeIntervalSince1970 >= $0.updated_at - 5 } == true }
    var shields: ShieldState {
        var value = snapshot?.shields ?? .coreOn
        if let enabled = pending["permissions"] { value.permissions = enabled }
        if let enabled = pending["jobs"] { value.jobs = enabled }
        if let enabled = pending["monitor"] { value.monitor = enabled }
        if let enabled = pending["sticky"] { value.sticky = enabled }
        if let enabled = pending["signatures"] { value.signatures = enabled }
        if let enabled = pending["connect"] { value.connect = enabled }
        return value
    }
    var active: Bool {
        guard fresh, let snap = snapshot else { return false }
        if !snap.guard_running { return false }
        let flags = shields
        if flags.monitor && !snap.monitor_running { return false }
        if flags.permissions && !snap.execution_blocked { return false }
        return flags.permissions || flags.jobs || flags.monitor
    }
    var paused: Bool {
        fresh && snapshot?.guard_running == true && !shields.permissions && !shields.jobs && !shields.monitor
    }
    var status: String {
        if paused { return "Core shields paused" }
        if active { return "Local protection active" }
        if fresh { return "Protection needs attention" }
        return "Activity feed unavailable"
    }
    var unread: Int { snapshot?.events.filter { $0.countsAsUnread(since: lastViewed.timeIntervalSince1970) }.count ?? 0 }
    var resolvedCount: Int { snapshot?.events.filter { $0.isResolved }.count ?? 0 }
    var visibleEvents: [Activity] { Activity.visible(snapshot?.events ?? [], showResolved: showResolved) }

    init() {
        let args = ProcessInfo.processInfo.arguments
        demo = args.contains("--demo")
        if let index = args.firstIndex(of: "--feed"), args.count > index + 1 {
            feedURL = URL(fileURLWithPath: args[index + 1])
        } else {
            feedURL = URL(fileURLWithPath: "/Library/Application Support/WatchDog Status/events.json")
        }
        launchAtLogin = FileManager.default.fileExists(atPath: loginURL.path)
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }
    func refresh() {
        now = Date()
        do {
            let data = try Data(contentsOf: feedURL)
            let value = try JSONDecoder().decode(Snapshot.self, from: data)
            guard value.schema == 1 else { throw CocoaError(.coderReadCorrupt) }
            if let previousIDs, notifications, !demo {
                let new = value.events.filter { !previousIDs.contains($0.id) && $0.countsAsUnread(since: Date().timeIntervalSince1970 - 15) }
                if let latest = new.first { notify(latest, count: new.count) }
            }
            previousIDs = Set(value.events.map(\.id))
            snapshot = value
            readFailure = false
            if let live = value.shields {
                pending = pending.filter { live.enabled($0.key) != $0.value }
            }
        } catch { readFailure = true }
        onChange?()
    }
    func markRead() {
        lastViewed = Date()
        UserDefaults.standard.set(lastViewed, forKey: "lastViewed")
        onChange?()
    }
    func setNotifications(_ enabled: Bool) {
        if !enabled { notifications = false; UserDefaults.standard.set(false, forKey: "notifications"); return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
            Task { @MainActor in
                self.notifications = granted
                UserDefaults.standard.set(granted, forKey: "notifications")
                self.notificationNote = granted ? "" : "Allow WatchDog alerts in System Settings → Notifications."
            }
        }
    }
    private func notify(_ event: Activity, count: Int) {
        let content = UNMutableNotificationContent()
        content.title = count > 1 ? "WatchDog recorded \(count) actions" : "WatchDog · \(event.title)"
        content.body = event.detail
        if let attachment = Self.logoAttachment() {
            content.attachments = [attachment]
        }
        let request = UNNotificationRequest(identifier: event.id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { _ in }
    }
    fileprivate static func logoAttachment() -> UNNotificationAttachment? {
        let names = ["AppIcon@2x", "AppIcon", "Logo@3x", "Logo"]
        guard let source = names.compactMap({ Bundle.main.url(forResource: $0, withExtension: "png") }).first else { return nil }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("WatchDogNotify", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let copy = folder.appendingPathComponent("logo-\(UUID().uuidString).png")
            try FileManager.default.copyItem(at: source, to: copy)
            return try UNNotificationAttachment(identifier: "logo", url: copy, options: [UNNotificationAttachmentOptionsTypeHintKey: "public.png"])
        } catch {
            return nil
        }
    }
    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try FileManager.default.createDirectory(at: loginURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                let value: [String: Any] = ["Label": "local.watchdog.menubar", "ProgramArguments": [Bundle.main.executableURL!.path], "RunAtLoad": true]
                let data = try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
                try data.write(to: loginURL, options: .atomic)
            } else if FileManager.default.fileExists(atPath: loginURL.path) { try FileManager.default.removeItem(at: loginURL) }
            launchAtLogin = enabled
        } catch { notificationNote = "Couldn’t update the login setting: \(error.localizedDescription)" }
    }
    func setShield(_ id: String, enabled: Bool) {
        if id == "connect" && enabled && !confirmConnect() { return }
        pending[id] = enabled
        if demo { onChange?(); return }
        let directory = feedURL.deletingLastPathComponent().appendingPathComponent("requests")
        do {
            let payload: [String: Any] = ["id": id, "enabled": enabled, "at": Date().timeIntervalSince1970]
            let data = try JSONSerialization.data(withJSONObject: payload)
            let url = directory.appendingPathComponent(UUID().uuidString + ".json")
            try data.write(to: url, options: .atomic)
        } catch {
            pending[id] = nil
            notificationNote = "Couldn’t update that shield. Reinstall WatchDog if Shields is missing."
        }
        onChange?()
    }
    private func confirmConnect() -> Bool {
        let alert = NSAlert()
        alert.messageText = "Enable Jamf Connect blocking?"
        alert.informativeText = "If this Mac uses Jamf Connect at the login window, users can be locked out until WatchDog is uninstalled. WatchDog never rewrites authorizationdb."
        alert.addButton(withTitle: "Enable")
        alert.addButton(withTitle: "Cancel")
        alert.alertStyle = .warning
        return alert.runModal() == .alertFirstButtonReturn
    }
    func exportActivity() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "WatchDog-activity.json"
        panel.canCreateDirectories = true
        NSApp.activate(ignoringOtherApps: true)
        if panel.runModal() == .OK, let url = panel.url {
            do { try Data(contentsOf: feedURL).write(to: url, options: .atomic) }
            catch { notificationNote = "Couldn’t export activity." }
        }
    }
}

private let accent = Color(red: 0.68, green: 0.92, blue: 0.38)

struct WatchDogLogo: View {
    var size: CGFloat
    var body: some View {
        Group {
            if let image = NSImage(named: "Logo") {
                Image(nsImage: image)
                    .resizable()
                    .interpolation(.high)
                    .aspectRatio(contentMode: .fit)
            } else {
                Image(systemName: "shield.fill").foregroundStyle(accent)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

func menuBarLogo() -> NSImage? {
    guard let base = NSImage(named: "MenuBarIcon") ?? NSImage(named: "Logo") else { return nil }
    let image = base.copy() as? NSImage ?? base
    image.size = NSSize(width: 18, height: 18)
    image.isTemplate = false
    image.accessibilityDescription = "WatchDog"
    return image
}

struct ActivityPanel: View {
    @ObservedObject var store: ActivityStore
    var panelSize = CGSize(width: 410, height: 700)
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                WatchDogLogo(size: 34)
                VStack(alignment: .leading, spacing: 3) {
                    Text("WatchDog").font(.system(size: 23, weight: .bold, design: .rounded))
                    Text(store.demo ? "DEMO · SAMPLE ACTIVITY" : "LOCAL FRAMEWORK MONITOR").font(.system(size: 9, weight: .semibold)).tracking(1.3).foregroundStyle(.secondary)
                }
                Spacer()
                Circle().fill(store.active ? accent : store.paused ? Color.secondary : .orange).frame(width: 8, height: 8)
            }.padding(22)
            VStack(alignment: .leading, spacing: 7) {
                Label(store.status, systemImage: store.active ? "checkmark.shield.fill" : store.paused ? "pause.circle.fill" : "exclamationmark.shield.fill")
                    .font(.system(size: 13, weight: .semibold)).foregroundStyle(store.active ? accent : store.paused ? Color.secondary : .orange)
                Text(store.fresh ? "Toggle each control independently." : "The guard may still be running. Check WatchDog’s status.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                if store.tab != "shields" {
                    HStack(spacing: 0) {
                        metric("PROCESSES STOPPED", value: store.snapshot?.process_total ?? 0)
                        Divider().frame(height: 34).padding(.horizontal, 15)
                        metric("EXECUTION CONTROLS", value: store.snapshot?.executable_count ?? 0)
                    }.padding(.top, 9)
                }
            }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.white.opacity(0.045), in: RoundedRectangle(cornerRadius: 12)).padding(.horizontal, 18)
            Picker("View", selection: $store.tab) {
                Text("Shields").tag("shields")
                Text("Activity").tag("activity")
            }.pickerStyle(.segmented).labelsHidden().padding(.horizontal, 18).padding(.top, 12)
            if store.tab == "shields" {
                ScrollView {
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 8) {
                        ForEach(shieldCatalog) { spec in shieldTile(spec) }
                    }.padding(.horizontal, 18).padding(.vertical, 12)
                }.frame(minHeight: 40, maxHeight: .infinity)
            } else {
                VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("RECENT ACTIVITY").font(.system(size: 10, weight: .semibold)).tracking(1.1).foregroundStyle(.secondary)
                Spacer()
                if store.unread > 0 { Text("\(store.unread) new").font(.system(size: 10, weight: .medium)).foregroundStyle(accent) }
            }.padding(.horizontal, 22).padding(.top, 12).padding(.bottom, 9)
            if store.resolvedCount > 0 {
                Button {
                    store.showResolved.toggle()
                } label: {
                    Label("\(store.resolvedCount) past warnings resolved · \(store.showResolved ? "Hide" : "Show")", systemImage: "checkmark.circle")
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                }.buttonStyle(.plain).padding(.horizontal, 22).padding(.bottom, 8)
            }
            ScrollView {
                LazyVStack(spacing: 0) {
                    if !store.visibleEvents.isEmpty {
                        ForEach(store.visibleEvents.prefix(100)) { event in
                            HStack(alignment: .top, spacing: 11) {
                                Image(systemName: event.symbol).font(.system(size: 12)).foregroundStyle(event.isResolved ? .gray : ["error", "warning"].contains(event.kind) ? .orange : accent)
                                    .frame(width: 28, height: 28).background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack(alignment: .firstTextBaseline) {
                                        Text(event.displayTitle).font(.system(size: 12, weight: .semibold))
                                        Spacer(minLength: 5)
                                        Text(event.timestamp.map { Date(timeIntervalSince1970: $0).formatted(date: .omitted, time: .standard) } ?? "Earlier")
                                            .font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
                                    }
                                    Text(event.detail).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
                                }
                            }.padding(.horizontal, 20).padding(.vertical, 10)
                            Divider().padding(.leading, 59).opacity(0.4)
                        }
                    } else {
                        VStack(spacing: 8) {
                            WatchDogLogo(size: 28).opacity(0.7)
                            Text("No activity recorded yet").font(.system(size: 12, weight: .medium))
                            Text("Confirmed actions will appear here.").font(.system(size: 11)).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity).padding(.vertical, 38)
                    }
                }
            }.frame(minHeight: 40, maxHeight: .infinity)
                }
            }
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                Toggle("Notify me about new actions", isOn: Binding(get: { store.notifications }, set: store.setNotifications)).toggleStyle(.switch).controlSize(.mini)
                Toggle("Open at login", isOn: Binding(get: { store.launchAtLogin }, set: store.setLaunchAtLogin)).toggleStyle(.switch).controlSize(.mini)
                if !store.notificationNote.isEmpty { Text(store.notificationNote).font(.caption2).foregroundStyle(.orange) }
                HStack {
                    Button("Export activity…") { store.exportActivity() }
                    Spacer()
                    Button("Quit menu bar") { NSApp.terminate(nil) }.help("Closes this app. Protection keeps running.")
                }.buttonStyle(.plain).font(.system(size: 11)).foregroundStyle(.secondary)
            }.font(.system(size: 11)).padding(.horizontal, 18).padding(.vertical, 14)
        }.frame(width: panelSize.width, height: panelSize.height).background(Color(red: 0.065, green: 0.09, blue: 0.12)).environment(\.colorScheme, .dark)
    }
    func shieldTile(_ spec: ShieldSpec) -> some View {
        let on = store.shields.enabled(spec.id)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .center) {
                Image(systemName: spec.symbol).font(.system(size: 13, weight: .semibold)).foregroundStyle(on ? accent : .secondary)
                    .frame(width: 26, height: 26)
                    .background(on ? accent.opacity(0.18) : Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 7))
                Spacer(minLength: 8)
                Toggle(spec.title, isOn: Binding(
                    get: { store.shields.enabled(spec.id) },
                    set: { store.setShield(spec.id, enabled: $0) }
                )).toggleStyle(.switch).controlSize(.mini).labelsHidden()
                    .accessibilityLabel(spec.title)
            }
            Text(spec.title).font(.system(size: 12, weight: .semibold))
            Text(spec.detail).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(2).fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, minHeight: 86, alignment: .topLeading)
        .background(Color.white.opacity(on ? 0.07 : 0.04), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(on ? accent.opacity(0.5) : Color.white.opacity(0.06), lineWidth: 1))
    }
    func metric(_ label: String, value: Int) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("\(value)").font(.system(size: 24, weight: .semibold, design: .rounded)).monospacedDigit()
            Text(label).font(.system(size: 8, weight: .medium)).tracking(0.6).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private var item: NSStatusItem!
    private let popover = NSPopover()
    private let store = ActivityStore()
    private var previewWindow: NSWindow?
    func applicationDidFinishLaunching(_ notification: Notification) {
        if let icon = NSImage(named: "WatchDog") ?? NSImage(named: "AppIcon") ?? NSImage(named: "Logo") {
            NSApp.applicationIconImage = icon
        }
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.target = self
        item.button?.action = #selector(toggle)
        item.button?.setAccessibilityLabel("WatchDog")
        popover.behavior = .transient
        popover.delegate = self
        popover.animates = false
        configurePanel(for: NSScreen.main)
        store.onChange = { [weak self] in self?.updateButton() }
        updateButton()
        if ProcessInfo.processInfo.arguments.contains("--show-panel") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { self.toggle() }
        }
        if ProcessInfo.processInfo.arguments.contains("--preview") {
            let size = PanelGeometry.contentSize(in: NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1024, height: 768))
            let controller = NSHostingController(rootView: ActivityPanel(store: store, panelSize: size))
            controller.sizingOptions = []
            controller.preferredContentSize = size
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: size.width, height: size.height),
                styleMask: [.titled, .closable],
                backing: .buffered,
                defer: false
            )
            window.contentViewController = controller
            window.title = store.demo ? "WatchDog — Demo" : "WatchDog Activity"
            window.setContentSize(size)
            window.center()
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            previewWindow = window
        }
    }
    func updateButton() {
        item.button?.image = menuBarLogo()
        item.button?.image?.isTemplate = false
        item.button?.alphaValue = store.active ? 1 : store.paused ? 0.45 : 0.8
        item.button?.title = store.unread > 0 ? " \(min(store.unread, 99))" : ""
        item.button?.toolTip = "WatchDog · \(store.status)"
    }
    @objc func toggle() {
        guard let button = item.button else { return }
        if popover.isShown { popover.performClose(nil) }
        else {
            store.refresh()
            configurePanel(for: button.window?.screen)
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }
    private func configurePanel(for screen: NSScreen?) {
        let visible = screen?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1024, height: 768)
        let size = PanelGeometry.contentSize(in: visible)
        let controller = NSHostingController(rootView: ActivityPanel(store: store, panelSize: size))
        // Explicit bounds prevent SwiftUI's live content from changing the popover's
        // size after AppKit has already positioned it against the menu bar.
        controller.sizingOptions = []
        controller.preferredContentSize = size
        controller.view.frame = NSRect(origin: .zero, size: size)
        popover.contentViewController = controller
        popover.contentSize = size
    }
    func popoverDidShow(_ notification: Notification) {
        guard let window = popover.contentViewController?.view.window,
              let screen = item.button?.window?.screen ?? window.screen else { return }
        // Clamp as a fallback for unusual menu-bar placement / multiple displays.
        let frame = window.frame
        let origin = PanelGeometry.origin(for: frame, in: screen.visibleFrame)
        if origin != frame.origin { window.setFrameOrigin(origin) }
        UserDefaults.standard.set(["fitsScreen": screen.frame.contains(window.frame),
                                   "windowFrame": NSStringFromRect(window.frame),
                                   "visibleFrame": NSStringFromRect(screen.visibleFrame)], forKey: "lastPanelGeometry")
    }
    func popoverDidClose(_ notification: Notification) { store.markRead() }
}

@main enum WatchDogMain {
    @MainActor static func main() {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        application.delegate = delegate
        application.run()
        withExtendedLifetime(delegate) {}
    }
}
