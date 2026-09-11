# Changelog

## Unreleased

- Network On also denies Apple enrollment/profile-fetch HTTPS. Yeet still uniquely blocks APNs. Installed profiles stay.
- Discovered JSS URLs honor a non-443 port. Live Network On/Yeet also reads MDM ServerURL hosts from `profiles show` (host only; never logged).
- PF state-kill is unicast-only and management-first. A management kill timeout is a warning, not a failed rule load. After reboot, an empty running anchor reloads `pf.conf`; a disabled filter is re-enabled even if a token was stored.
- Launch jobs match `com.jamf.management.*`, scan per-user `~/Library/LaunchAgents`, and still disable known labels when `print` times out. Self Service+ is in the path lists.

## 0.4.0 — 2026-09-10

- Added a **Network** shield with Off / On / Yeet. Off is the default. On denies outbound Jamf/MDM/JCDS destinations. Yeet also denies published APNs ranges and Apple enrollment hosts (iMessage/push will break).
- Network Off stores and passes the `pfctl -E` enable token to `pfctl -X`. A missing token is reported as **Packet filter token missing**; WatchDog never calls bare `pfctl -X`.
- Enforcement is a dedicated PF anchor (`local.watchdog`), reversible on Off or uninstall. Hostname matching is IP approximation; wildcards without CIDRs (Jamf Remote Assist) are recorded as partial and are not a load failure. VPN/proxy can bypass.
- Enrollment and profiles stay. A loaded rule is not a confirmed deny.

## 0.3.1 — 2026-09-10

- Added a **Shields** tab: one tile per local control, each independently toggleable from the menu bar.
- Core shields (permissions, launch jobs, process monitor) default on. Sticky block, signature matching, and Jamf Connect default off.
- Turning a core shield off reverses that layer (restore modes, restore jobs, or stop the monitor). Enabling Jamf Connect asks for confirmation.
- Menu bar writes `{id, enabled}` JSON into a `1777` drop folder; the root event reader applies accepted keys to `shields.json`. The activity feed stays read-only.
- Menu bar status item, panel header, and notification banners use the WatchDog shield mark.

## 0.3.0 — 2026-09-10

- Unified path, launch-job, and signing matches in `src/targets.py`, kept in parity with the native monitor.
- Widened coverage from `Jamf.app/` to `/Library/Application Support/JAMF/` so `jamfHelper` and Management Action are blocked, plus Self Service and App Installers.
- Optional Jamf Connect blocking (`WATCHDOG_BLOCK_CONNECT`) with a login-lockout warning; never rewrites authorizationdb or login-window plugins.
- Optional sticky `UF_IMMUTABLE` block (`WATCHDOG_STICKY_BLOCK`) and signature-aware process matching (`WATCHDOG_MATCH_SIGNATURE`), both off by default.
- Process monitor also selects observed process-group members after a parent is paused, catching reparented helpers. Only a group whose leader is the matched process is followed, so an inherited parent group (shells, the test runner) is left alone.
- Default permission polling 100 ms and monitor polling 50 ms, configurable in `installation.json`.
- Interpreter fallback runner so a missing install-time Python does not silently disable the LaunchDaemon after reboot.
- Guard monitor spawn backs off on failure instead of crash-looping; event reader can re-bootstrap a down guard at most once per minute.
- Status reports the monitor, event reader, menu bar, every tracked path, and activity-snapshot age.
- Log rotation via `/etc/newsyslog.d/local.watchdog.conf`.
- Replaced Finder `.command` wrappers with `./install.sh` and `./uninstall.sh`. The menu bar companion installs and removes with those scripts.

## 0.2.2 — 2026-09-10

- Resolve historical session timeouts only after the guard confirms a successful native session lookup.
- Keep resolved warnings in expandable history and exports, excluding them from unread counts and notifications.
- Added recovery, restart, and activity-filter regression tests.

## 0.2.1 — 2026-09-10

- Replaced recurring system-wide ps commands with native macOS process metadata queries in the guard and activity reader.
- Corrected historical session-scan timeout labels without deleting events or replaying notifications.
- Extended live health checks to every tracked executable.
- Reduced permission checks to 200 ms and separated slow component discovery and launch-job checks from the permission loop.
- Added regression coverage for restored permissions and binary replacement while background checks stall.

## 0.2.0 — 2026-09-10

- Bounded the menu panel to the visible display and made the activity list adapt to available height.
- Added layout regression tests for small and offset displays.
- Added a native Swift menu bar app with live status, recent actions, and an unread badge.
- Added optional notifications, login startup, and activity export.
- Added a separate event reader that publishes a restricted read-only feed.
- Added standalone companion installation for existing legacy guards, without restarting protection.
- Added event parsing, redaction, incomplete-line, restart, and log-rotation tests.

## 0.1.0 — 2026-09-10

- Introduced WatchDog branding and a structured source repository.
- Added a universal native process monitor and reversible Python guard.
- Added portable build, install, status, and uninstall entry points.
- Added legacy installation detection and compatible restoration.
- Removed machine-specific Python paths from the source installer.
- Added isolated regression tests and macOS GitHub Actions checks.
- Documented polling limits, MDM boundaries, and legacy restoration behavior.
