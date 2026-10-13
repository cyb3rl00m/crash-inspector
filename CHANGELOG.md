# Changelog

## 1.2.0 - 2026-10-13
- First public release.
- Copied/exported reports hide personal info by default (computer name, user name,
  boot IDs, IP/MAC addresses). Terminal: `--private`.
- About dialog with links to the project page and issue tracker.
- Installer explains how to use the terminal command and removes files from earlier versions.

## 1.1.0
- Normal startup messages (MCE/EDAC/AER initialisation) are no longer reported as hardware errors.
- Known-harmless messages are listed as "harmless" and don't count as problems.
- Boots stopped within 90 seconds are labelled as interrupted startups, not crashes.
- A CPU Machine Check logged at the next boot is linked to the crash that caused it.

## 1.0.0
- Initial version.
