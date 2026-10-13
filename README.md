# Crash Inspector

**Every crash and error on your Linux PC, in one window, explained in plain words.**

Did your computer freeze, reboot by itself, or show a black screen? Instead of typing
dozens of `journalctl` commands, open Crash Inspector. It reads all the system logs in
a few seconds, sorts everything into clear categories, and tells you what the findings
probably mean.

Made for **Ubuntu 26.04 LTS**. Works on any systemd-based distro with GTK 4 + libadwaita.

<!-- Screenshots: put images in a "screenshots" folder and uncomment these lines
![Overview](screenshots/overview.png)
![Unexpected shutdowns](screenshots/shutdowns.png)
-->

## What it finds

| Area | What it checks |
|---|---|
| **Unexpected shutdowns & freezes** | Previous boots that ended without a clean shutdown (hard freeze, kernel panic, power loss, failed wake-up from sleep), with the last log lines before the PC died. If the CPU reported a hardware error (Machine Check) on the next boot, it's linked to that crash. |
| **Kernel panics, oopses & lockups** | Panics, Oops/BUG reports, kernel WARNING traces with the responsible driver, soft/hard lockups, hung tasks, saved pstore panic logs |
| **Program crashes** | Segfaults reported by the kernel, systemd-coredump, Apport reports in `/var/crash` |
| **Out of memory** | Kernel OOM killer, systemd-oomd, earlyoom |
| **Graphics / GPU** | amdgpu, i915/xe, nouveau and NVIDIA errors, ring timeouts, GPU resets |
| **Disks & filesystems** | I/O errors, SATA/NVMe problems, ext4/btrfs/xfs errors, read-only remounts |
| **Hardware & firmware** | Machine Check Exceptions, memory (EDAC) and PCIe errors, BIOS/ACPI and firmware problems, overheating, USB faults |
| **System services** | Services that crashed or failed |
| **Desktop session** | GNOME Shell, Xwayland, PipeWire, GDM… |
| **Other errors** | Everything else logged as an error |

Other features:

- **Plain-language hints:** the Overview page explains what the findings probably mean and what to try.
- **Harmless messages marked:** well-known harmless messages (webcam, keyring, Bluetooth…) are still shown but don't count as problems.
- **Duplicates merged:** repeated messages appear once, with a counter.
- **Time ranges:** this boot, the previous boot (use this right after a crash), or the last 24 hours, 7 days or 30 days.
- **Shows its commands:** every section lists the exact commands it ran, so you can learn and run them yourself.
- **Copy / Export the full report**, with personal info (computer name, user name, IDs, IP/MAC addresses) hidden by default, so you can paste it on a forum safely.
- **Terminal mode** for when the desktop won't start.

## Install

1. Download the latest zip from the [Releases page](https://github.com/cyb3rl00m/crash-inspector/releases) and unzip it.
2. Open a terminal in the unzipped folder and run:

```bash
./install.sh
```

Then open **Crash Inspector** from the app grid. Run `./install.sh` again to update, or `./install.sh --uninstall` to remove it.

For complete results your user needs permission to read the system logs (the first user
on Ubuntu has it by default). If the app shows a yellow banner, run
`sudo usermod -aG adm $USER`, then log out and back in.

## Terminal mode

If the desktop won't start, switch to a text console (Ctrl+Alt+F3), log in, and run:

```bash
crash-inspector --text --range boot1 | less              # what happened in the previous boot
crash-inspector --text --range 7d --private > report.txt  # last 7 days, personal info hidden
```

Ranges: `boot0` (this boot), `boot1` (previous boot), `24h`, `7d`, `30d`.

## Optional extras

- `sudo apt install systemd-coredump` records a full stack trace for every program crash.
- `sudo apt install smartmontools` lets you check disk health (`sudo smartctl -a /dev/nvme0n1`).

## Privacy

Crash Inspector runs entirely on your computer. It sends nothing anywhere. Reports leave
your PC only if you copy or export them yourself. When you do, personal details are
removed by default (the shield button in the header bar toggles this).

## Contributing

Bug reports and ideas are very welcome. The most helpful contributions:

- **False alarms:** a harmless message shown as a problem? [Open an issue](https://github.com/cyb3rl00m/crash-inspector/issues/new/choose) with the message text.
- **Missed problems:** a crash the app didn't catch? Send the exported report (with "hide personal info" on).
- **Testing on other hardware and distros:** NVIDIA, Intel, laptops, Fedora, Arch…

## About this project

Crash Inspector was built by me [cyb3rl00m](https://github.com/cyb3rl00m) and with the help of
Claude, an AI assistant by Anthropic, while tracking down random freezes on a Ryzen PC.
It found the cause: a CPU Machine Check right after each freeze.

## License

[MIT](LICENSE): free to use, change and share.
