![WatchDog — Local control for macOS testing](assets/watchdog.svg)

# WatchDog

A reversible macOS test utility that blocks the **local Jamf Pro framework** through launch-job controls, executable permissions, and a native process monitor. MDM enrollment stays intact.

**WatchDog is experimental.** It interrupts inventory reporting, policies, and Self Service workflows that depend on the local framework. It does not make the Mac read-only or prevent commands delivered through MDM.

## How it works

| Layer | Action | Frequency |
| --- | --- | --- |
| Launch jobs | Disable and unload matching Jamf Pro jobs | Approximately every 2 seconds |
| Executable permissions | Remove execution permission from the main binary and declared executables inside Jamf.app | Approximately every 2 seconds |
| Process monitor | Pause and kill matching processes and observable descendants | Approximately every 100 ms |
| Recovery | Record original file modes and effective job states before modification | Before each first change |
| Supervision | Restart the monitor if it exits; start the guard at boot | Managed by the guard and launchd |

Polling intervals are targets, not hard deadlines. A process can act before detection. MDM and other root processes can reverse WatchDog’s controls. [Read the boundaries and architecture](docs/architecture.md).

## Requirements

- macOS 14 or later, Apple Silicon or Intel.
- Python 3.10 or later; only the standard library is used.
- Xcode Command Line Tools or Xcode for compiling the native monitor.
- Administrator access to install and remove the service.

The installer records the selected Python executable’s absolute path. That interpreter and its standard library must remain installed for the service to start after reboot. Choose a trusted runtime appropriate for a root service; WatchDog does not bundle Python.

## Quick start

From a clone or extracted source folder:

```sh
./scripts/test.sh
./Install.command
./Status.command
```

You can also double-click the `.command` files in Finder. Installation builds the native executable before requesting administrator authentication. Build artifacts are ad hoc signed locally; they are not notarized.

To select a particular Python interpreter:

```sh
WATCHDOG_PYTHON=/absolute/path/to/python3 ./Install.command
```

An existing WatchDog or legacy installation is detected and left in place. The installer refuses to create a second service.

## Remove and restore

```sh
./Uninstall.command
```

Uninstall stops the guard and monitor, restores recorded file modes and effective launch-job states, and preserves an audit copy of the undo record in `/var/log`. If restoration fails, recovery files remain available for another attempt.

The uninstall command also recognizes the original “Jamf Test Blocker” installation. Old state records marked `original_override_unverified` produce a restoration notice; the recorded fallback is used for those jobs. See [restoration details](docs/architecture.md#restoration).

## Installed files

| Item | Location |
| --- | --- |
| Service label | `local.watchdog.guard` |
| Installed code and undo record | `/Library/Application Support/WatchDog/` |
| LaunchDaemon | `/Library/LaunchDaemons/local.watchdog.guard.plist` |
| Log | `/var/log/watchdog.log` |

The repository can be moved after installation. The running service uses its own installed copy. Changes to source do not update an existing service automatically.

## Development

```sh
./scripts/build.sh  # Universal native executable in build/watchdog
./scripts/test.sh   # Isolated tests; no administrator access
```

Tests use disposable executables, temporary files, and simulated launchctl responses. They never install WatchDog or intentionally change the real Jamf framework. The GitHub Actions workflow runs these checks on macOS. [Testing and release notes](docs/testing.md).

```text
WatchDog/
├── src/          # Python guard/lifecycle commands and native C monitor
├── scripts/      # Build, test, install, uninstall, and status entry points
├── tests/        # Isolated process and restoration checks
├── assets/       # WatchDog branding
├── docs/         # Architecture, limits, and testing
└── .github/      # macOS CI and contribution templates
```

Runtime state, logs, build products, and local migration notes are excluded from Git. No credentials or server configuration are needed in this repository.

## Project status

Version **0.1.0**. This project is independent of Jamf and is not a Jamf-supported management mode. See [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).

No open-source license has been selected. See [LICENSE-NOTICE.md](LICENSE-NOTICE.md).
