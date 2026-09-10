# Testing and release preparation

Run `./scripts/test.sh` on macOS with Python 3.10+ and Xcode command-line tools. It builds the monitor for Apple Silicon and Intel, verifies the ad hoc code signature, checks script syntax, builds the native Swift menu bar app, and runs isolated checks.

The tests cover permission removal, permission reapplication after a simulated updater, restoration, v1-to-v2 undo migration, sticky immutable flags, disabled-state parsing, process termination, descendant and process-group termination, unrelated-process survival, repeated launches, monitor shutdown, target-list parity with the C monitor, signing allow/deny, installation collision detection, legacy detection, interpreter fallbacks, expanded status output, retention of recovery files after restoration failure, event allowlisting/redaction, partial log lines, cursor restart, log rotation, bounded guard self-heal, shield defaults and drop-folder apply, network policy/PF generation with mocked pfctl, and Swift shield-state decoding.

Lifecycle tests use simulated launchctl responses and temporary directories. They do not validate privileged installation or boot behavior on the GitHub runner. The native tests execute only temporary fixtures under `--test-target`; they never target the live Jamf binary. Network tests never call live `pfctl -E`.

Before a release that changes privileged lifecycle behavior, validate fresh `./install.sh`, `./scripts/status.sh`, reboot, and `./uninstall.sh` on a disposable enrolled test Mac. Confirm the undo record and MDM enrollment separately. For Network, confirm iMessage in On vs Yeet, an unrelated HTTPS site, and rollback of only the WatchDog PF anchor. Do not use a production Mac as an automated integration-test runner.

Update VERSION and CHANGELOG.md together. Keep generated binaries, runtime records, local notes, and logs out of Git. Choose a distribution license before inviting third-party reuse. The repository includes no automatic publishing or release-upload workflow.

Menu layout regression checks reproduce an offscreen popover on small and offset displays. The app uses explicit hosting bounds, sizes its content to the visible display, and clamps the final window position. For a local layout check, launch the app with `--show-panel`; the last measured bounds are recorded in its `lastPanelGeometry` preference.
