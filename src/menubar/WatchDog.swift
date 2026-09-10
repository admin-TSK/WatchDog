import AppKit
import SwiftUI
import UserNotifications

struct Activity: Decodable, Identifiable {
    let id: String
    let timestamp: Double?
    let kind: String
    let title: String
    let detail: String
    var symbol: String {
        switch kind { case "process": return "hand.raised.fill"; case "permission": return "lock.fill"; case "job": return "gearshape.fill"; case "warning": return "clock.badge.exclamationmark"; default: return "exclamationmark.triangle.fill" }
    }
}
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
}

@MainActor final class ActivityStore: ObservableObject {
    @Published var snapshot: Snapshot?
    @Published var now = Date()
    @Published var readFailure = false
    @Published var lastViewed = UserDefaults.standard.object(forKey: "lastViewed") as? Date ?? Date()
    @Published var notifications = UserDefaults.standard.bool(forKey: "notifications")
    @Published var notificationNote = ""
    @Published var launchAtLogin = false
    var onChange: (() -> Void)?
    private var timer: Timer?
    private var previousIDs: Set<String>?
    let feedURL: URL
    let demo: Bool
    var loginURL: URL { FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/local.watchdog.menubar.plist") }
    var fresh: Bool { !readFailure && snapshot.map { now.timeIntervalSince1970 - $0.updated_at < 12 && now.timeIntervalSince1970 >= $0.updated_at - 5 } == true }
    var active: Bool { fresh && snapshot.map { $0.guard_running && $0.monitor_running && $0.execution_blocked } == true }
    var status: String { active ? "Local protection active" : fresh ? "Protection needs attention" : "Activity feed unavailable" }
    var unread: Int { snapshot?.events.filter { ($0.timestamp ?? 0) > lastViewed.timeIntervalSince1970 }.count ?? 0 }

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
                let new = value.events.filter { !previousIDs.contains($0.id) && ($0.timestamp ?? 0) > Date().timeIntervalSince1970 - 15 }
                if let latest = new.first { notify(latest, count: new.count) }
            }
            previousIDs = Set(value.events.map(\.id))
            snapshot = value
            readFailure = false
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
        let request = UNNotificationRequest(identifier: event.id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { _ in }
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
struct ActivityPanel: View {
    @ObservedObject var store: ActivityStore
    var panelSize = CGSize(width: 410, height: 620)
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "shield.lefthalf.filled").font(.system(size: 30, weight: .medium)).foregroundStyle(accent)
                VStack(alignment: .leading, spacing: 3) {
                    Text("WatchDog").font(.system(size: 23, weight: .bold, design: .rounded))
                    Text(store.demo ? "DEMO · SAMPLE ACTIVITY" : "LOCAL FRAMEWORK MONITOR").font(.system(size: 9, weight: .semibold)).tracking(1.3).foregroundStyle(.secondary)
                }
                Spacer()
                Circle().fill(store.active ? accent : .orange).frame(width: 8, height: 8)
            }.padding(22)
            VStack(alignment: .leading, spacing: 7) {
                Label(store.status, systemImage: store.active ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .font(.system(size: 13, weight: .semibold)).foregroundStyle(store.active ? accent : .orange)
                Text(store.fresh ? "Watching for Jamf framework activity." : "The guard may still be running. Check WatchDog’s status.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                HStack(spacing: 0) {
                    metric("PROCESSES STOPPED", value: store.snapshot?.process_total ?? 0)
                    Divider().frame(height: 34).padding(.horizontal, 15)
                    metric("EXECUTION CONTROLS", value: store.snapshot?.executable_count ?? 0)
                }.padding(.top, 9)
            }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.white.opacity(0.045), in: RoundedRectangle(cornerRadius: 12)).padding(.horizontal, 18)
            HStack {
                Text("RECENT ACTIVITY").font(.system(size: 10, weight: .semibold)).tracking(1.1).foregroundStyle(.secondary)
                Spacer()
                if store.unread > 0 { Text("\(store.unread) new").font(.system(size: 10, weight: .medium)).foregroundStyle(accent) }
            }.padding(.horizontal, 22).padding(.top, 19).padding(.bottom, 9)
            ScrollView {
                LazyVStack(spacing: 0) {
                    if let events = store.snapshot?.events, !events.isEmpty {
                        ForEach(events.prefix(100)) { event in
                            HStack(alignment: .top, spacing: 11) {
                                Image(systemName: event.symbol).font(.system(size: 12)).foregroundStyle(["error", "warning"].contains(event.kind) ? .orange : accent)
                                    .frame(width: 28, height: 28).background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack(alignment: .firstTextBaseline) {
                                        Text(event.title).font(.system(size: 12, weight: .semibold))
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
                            Image(systemName: "shield.checkered").font(.system(size: 24)).foregroundStyle(.secondary)
                            Text("No activity recorded yet").font(.system(size: 12, weight: .medium))
                            Text("Confirmed actions will appear here.").font(.system(size: 11)).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity).padding(.vertical, 38)
                    }
                }
            }.frame(minHeight: 40, maxHeight: .infinity)
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                Toggle("Notify me about new actions", isOn: Binding(get: { store.notifications }, set: store.setNotifications)).toggleStyle(.switch).controlSize(.mini)
                Toggle("Open at login", isOn: Binding(get: { store.launchAtLogin }, set: store.setLaunchAtLogin)).toggleStyle(.switch).controlSize(.mini)
                if !store.notificationNote.isEmpty { Text(store.notificationNote).font(.caption2).foregroundStyle(.orange) }
                Text("Shows WatchDog actions, not every denied attempt. MDM remains outside its scope.").font(.system(size: 10)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Export activity…") { store.exportActivity() }
                    Spacer()
                    Button("Quit menu bar") { NSApp.terminate(nil) }.help("Closes this app. Protection keeps running.")
                }.buttonStyle(.plain).font(.system(size: 11)).foregroundStyle(.secondary)
            }.font(.system(size: 11)).padding(18)
        }.frame(width: panelSize.width, height: panelSize.height).background(Color(red: 0.065, green: 0.09, blue: 0.12)).environment(\.colorScheme, .dark)
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
            let controller = NSHostingController(rootView: ActivityPanel(store: store))
            let window = NSWindow(contentViewController: controller)
            window.title = store.demo ? "WatchDog — Demo" : "WatchDog Activity"
            window.styleMask = [.titled, .closable]
            window.center()
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            previewWindow = window
        }
    }
    func updateButton() {
        let name = store.active ? (store.unread > 0 ? "shield.fill" : "shield.lefthalf.filled") : "exclamationmark.shield"
        item.button?.image = NSImage(systemSymbolName: name, accessibilityDescription: "WatchDog")
        item.button?.image?.isTemplate = true
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
