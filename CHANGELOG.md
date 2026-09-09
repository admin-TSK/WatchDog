# Changelog

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
