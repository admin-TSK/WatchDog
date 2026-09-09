# Security boundaries

WatchDog runs with root privileges and intentionally interrupts local management activity. Its controls can be reversed by another privileged process. It is not an isolation boundary against MDM or a hostile administrator.

To report a defect involving unintended process termination, privilege handling, file access, or restoration, use GitHub’s private vulnerability reporting when the repository owner has enabled it. Otherwise contact the repository owner privately before sharing sensitive details. Do not place credentials, device records, or unredacted logs in a public issue.

Only the current development version is maintained. No independent security audit has been performed.
