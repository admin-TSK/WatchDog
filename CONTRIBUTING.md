# Contributing to WatchDog

Discuss substantial changes in an issue before changing matching rules or privileged behavior. Explain the concrete behavior, expected result, and compatibility with existing undo records.

Run `./scripts/test.sh` before proposing a change. Keep automated tests isolated from installed management tools. Add a regression check when modifying process selection, installation, restoration, or the format of saved state.

Use plain language in logs and documentation. Preserve the distinction between local framework blocking and MDM control. Do not add claims of zero-write protection or guaranteed real-time interception.

Do not commit logs, enrollment details, device identifiers, credentials, or local state. No open-source license has been selected yet; discuss contribution terms with the repository owner before submitting third-party code.
