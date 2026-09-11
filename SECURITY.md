# Security boundaries

WatchDog runs with root privileges and intentionally interrupts local Jamf activity: the Jamf Pro framework, Self Service, App Installers, and — only when `WATCHDOG_BLOCK_CONNECT=1` — Jamf Connect agents and app binaries. Its controls can be reversed by another privileged process. It is not an isolation boundary against MDM or a hostile administrator.

Jamf Connect blocking can lock users out of the login window on Macs that use Connect as the login mechanism. WatchDog never rewrites `authorizationdb` and never changes login-window SecurityAgentPlugins. Uninstall restores recorded execute bits and re-enables recorded launch jobs. Do not enable Connect blocking on a production Mac or on a Mac whose only admin login is Connect. The menu bar asks for confirmation before turning that shield on.

Runtime shield changes use a world-writable drop folder under `/Library/Application Support/WatchDog Status/requests/`. The event reader accepts only known shield keys. Any local account that can write that folder can toggle WatchDog's local controls.

Network Off / On / Yeet loads a dedicated PF anchor. On denies outbound HTTPS to the discovered Jamf host (including a non-443 JSS port), Jamf cloud/JCDS destinations, and Apple enrollment/profile-fetch hosts. Yeet also blocks Apple Push and will break iMessage. Enrollment records and already-installed configuration profiles stay. Hostname matching is IP approximation. VPN or a proxy can bypass it. Uninstall removes only WatchDog’s PF rules.

Jamf Protect, MDM enrollment, and configuration profiles stay out of scope. Network On interrupts Jamf and Apple HTTPS check-in and profile download. Yeet also interrupts APNs. Installed profiles keep applying locally.

To report a defect involving unintended process termination, privilege handling, file access, restoration, or login lockout, use GitHub’s private vulnerability reporting when the repository owner has enabled it. Otherwise contact the repository owner privately before sharing sensitive details. Do not place credentials, device records, or unredacted logs in a public issue.

Only the current development version is maintained. No independent security audit has been performed.
