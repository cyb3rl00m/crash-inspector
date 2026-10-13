#!/usr/bin/env python3
"""
Crash Inspector - every crash and error on this computer, in one window.

For Ubuntu 26.04 LTS (works on any systemd distro with GTK 4 + libadwaita).
"""

import argparse
import getpass
import datetime as dt
import glob
import grp
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field

APP_ID = "io.github.cyb3rl00m.CrashInspector"
PROJECT_URL = "https://github.com/cyb3rl00m/crash-inspector"
ISSUES_URL = PROJECT_URL + "/issues"
APP_NAME = "Crash Inspector"
VERSION = "1.2.0"

ENV = dict(os.environ, LC_ALL="C.UTF-8", SYSTEMD_COLORS="0",
           SYSTEMD_PAGER="", PAGER="cat", SYSTEMD_LESS="")

RANGES = [
    ("boot0", "This boot"),
    ("boot1", "Previous boot"),
    ("24h", "Last 24 hours"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
]
RANGE_ARGS = {
    "boot0": ["-b", "0"],
    "boot1": ["-b", "-1"],
    "24h": ["--since=-24h"],
    "7d": ["--since=-7d"],
    "30d": ["--since=-30d"],
}

SEV_RANK = {"critical": 0, "error": 1, "warning": 2, "info": 3}
COREDUMP_MSGID = "fc2e22bc6ee647b6b90729ab34a250b1"
KERNEL_LOG_LIMIT = 40000


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, env=ENV)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{' '.join(cmd)}: timed out"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def have(prog):
    return shutil.which(prog) is not None


def read_file(path, default="", limit=None):
    try:
        with open(path, errors="replace") as f:
            return (f.read(limit) if limit else f.read()).strip()
    except OSError:
        return default


def fmt_time(ts):
    if not ts:
        return "-"
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def human_duration(sec):
    sec = int(max(0, sec))
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d} d")
    if h or d:
        parts.append(f"{h} h")
    parts.append(f"{m} min")
    return " ".join(parts)


def one_line(text, cap=240):
    for line in (text or "").splitlines():
        line = " ".join(line.split())
        if line:
            return line if len(line) <= cap else line[: cap - 1] + "…"
    return "(empty message)"


def prio_sev(prio):
    if prio <= 2:
        return "critical"
    if prio == 3:
        return "error"
    if prio == 4:
        return "warning"
    return "info"


def _decode(v):
    if v is None:
        return ""
    if isinstance(v, list):
        if v and all(isinstance(x, int) for x in v):
            return bytes(v).decode("utf-8", "replace")
        return "\n".join(_decode(x) for x in v)
    return str(v)


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------

@dataclass
class Event:
    ts: float
    severity: str
    source: str
    summary: str
    details: str = ""
    count: int = 1
    first_ts: float = 0.0

    def __post_init__(self):
        if not self.first_ts:
            self.first_ts = self.ts
        self.summary = one_line(self.summary)

    def search_text(self):
        return f"{self.summary}\n{self.source}\n{self.details}".lower()

    def full_text(self):
        head = [f"Time:      {fmt_time(self.ts)}",
                f"Source:    {self.source}",
                f"Severity:  {self.severity}"]
        if self.count > 1:
            head.append(f"Occurred:  {self.count} times "
                        f"(first {fmt_time(self.first_ts)}, last {fmt_time(self.ts)})")
        return "\n".join(head) + "\n\n" + (self.details or self.summary)


@dataclass
class Category:
    id: str
    title: str
    icon: str
    description: str
    events: list = field(default_factory=list)
    commands: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    dedupe: bool = True

    def add(self, ev):
        self.events.append(ev)

    @property
    def issues(self):
        """Events that are real problems (known-harmless 'info' entries excluded)."""
        return [e for e in self.events if e.severity != "info"]

    @property
    def harmless(self):
        return len(self.events) - len(self.issues)

    @property
    def worst(self):
        iss = self.issues
        if not iss:
            return None
        return min((e.severity for e in iss), key=lambda s: SEV_RANK[s])

    @property
    def occurrences(self):
        return sum(e.count for e in self.events)


@dataclass
class Report:
    range_key: str
    range_label: str
    generated: float
    categories: list
    info: list
    facts: dict
    notes: list
    duration: float
    hints: list = field(default_factory=list)

    def cat(self, cid):
        for c in self.categories:
            if c.id == cid:
                return c
        raise KeyError(cid)


CATEGORY_DEFS = [
    ("unclean", "Unexpected shutdowns & freezes", "system-shutdown-symbolic",
     "Previous boots that ended without a clean shutdown - what you see after a hard "
     "freeze, a kernel panic, power loss or holding the power button. Always checks the "
     "last 10 boots, whatever range is selected."),
    ("kernel", "Kernel panics, oopses & lockups", "dialog-error-symbolic",
     "Kernel panics, Oops / BUG reports, kernel WARNING traces, soft and hard lockups, "
     "hung tasks and RCU stalls, plus panic logs the kernel saved to pstore before a reboot."),
    ("apps", "Program crashes", "application-x-executable-symbolic",
     "Programs that crashed: segfaults and traps reported by the kernel, core dumps "
     "(systemd-coredump) and Apport crash reports in /var/crash."),
    ("oom", "Out of memory", "utilities-system-monitor-symbolic",
     "Processes killed because the system ran out of RAM (kernel OOM killer, "
     "systemd-oomd, earlyoom)."),
    ("gpu", "Graphics / GPU", "video-display-symbolic",
     "GPU driver errors, ring timeouts, GPU hangs and resets (amdgpu, i915/xe, nouveau, NVIDIA)."),
    ("disk", "Disks & filesystems", "drive-harddisk-symbolic",
     "I/O errors, SATA / NVMe link problems and timeouts, filesystem errors and "
     "read-only remounts."),
    ("hardware", "Hardware & firmware", "computer-symbolic",
     "Machine Check Exceptions, memory (EDAC) and PCIe errors, ACPI / BIOS errors, "
     "firmware loading failures, thermal events and USB faults."),
    ("services", "System services", "emblem-system-symbolic",
     "systemd services that crashed, failed to start, or are in a failed state right now."),
    ("desktop", "Desktop session", "user-desktop-symbolic",
     "Errors from GNOME Shell, the display server (Wayland / Xwayland), audio (PipeWire) "
     "and other desktop components."),
    ("other", "Other errors", "dialog-warning-symbolic",
     "Everything else that was logged at error level or higher."),
]


def category_commands(r):
    return {
        "unclean": ["journalctl --list-boots",
                    "journalctl -b -1 -n 60          # last lines of the previous boot"],
        "kernel": [f"journalctl -k {r} | grep -iE 'panic|oops|BUG:|WARNING: CPU|lockup|blocked for more than|rcu.*stall'",
                   "ls -l /var/lib/systemd/pstore",
                   "cat /proc/sys/kernel/tainted"],
        "apps": [f"journalctl -k {r} | grep -E 'segfault|traps:'",
                 "coredumpctl list",
                 "ls -l /var/crash"],
        "oom": [f"journalctl -k {r} | grep -iE 'oom|out of memory'",
                f"journalctl {r} -t systemd-oomd -t earlyoom"],
        "gpu": [f"journalctl -k {r} | grep -iE 'amdgpu|i915|xe |nouveau|NVRM|drm'"],
        "disk": [f"journalctl -k {r} | grep -iE 'I/O error|EXT4-fs|BTRFS|XFS|ata[0-9]|nvme'",
                 "sudo smartctl -a /dev/nvme0n1   # disk health (package smartmontools)"],
        "hardware": [f"journalctl -k {r} | grep -iE 'mce|hardware error|EDAC|AER|ACPI|firmware|thermal|usb'"],
        "services": ["systemctl --failed",
                     "systemctl --user --failed",
                     f"journalctl {r} -t systemd -p warning | grep -i fail"],
        "desktop": [f"journalctl {r} -p err      # gnome-shell, Xwayland, pipewire, gdm…"],
        "other": [f"journalctl {r} -p err"],
    }


def make_categories(range_key):
    pretty = " ".join(RANGE_ARGS[range_key])
    cmds = category_commands(pretty)
    cats = {}
    for cid, title, icon, desc in CATEGORY_DEFS:
        cats[cid] = Category(cid, title, icon, desc, commands=list(cmds[cid]),
                             dedupe=(cid != "unclean"))
    return cats


# --------------------------------------------------------------------------
# journal access
# --------------------------------------------------------------------------

@dataclass
class JEntry:
    ts: float
    prio: int
    ident: str
    msg: str
    raw: dict

    @property
    def kernel(self):
        return self.raw.get("_TRANSPORT") == "kernel"


def parse_journal_json(text):
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        try:
            ts = int(d.get("__REALTIME_TIMESTAMP", "0")) / 1e6
        except (TypeError, ValueError):
            ts = 0.0
        try:
            prio = int(_decode(d.get("PRIORITY")) or 6)
        except ValueError:
            prio = 6
        ident = (_decode(d.get("SYSLOG_IDENTIFIER")) or _decode(d.get("_COMM"))
                 or ("kernel" if d.get("_TRANSPORT") == "kernel" else "?"))
        if ident.endswith("]") and "[" not in ident:  # e.g. "gdm-password]"
            ident = _decode(d.get("_COMM")) or ident.rstrip("]")
        entries.append(JEntry(ts, prio, ident, _decode(d.get("MESSAGE")), d))
    return entries


def journal(args, limit=5000, timeout=120):
    cmd = ["journalctl", "--no-pager", "-q", "-o", "json", "-n", str(limit)] + list(args)
    rc, out, err = run(cmd, timeout)
    entries = parse_journal_json(out)
    problem = ""
    if rc == 127:
        problem = "journalctl is not available."
    elif rc not in (0, 1) and not entries and err.strip():
        problem = err.strip().splitlines()[0]
    return entries, problem


@dataclass
class Boot:
    index: int
    boot_id: str
    first: float
    last: float


def list_boots():
    rc, out, _ = run(["journalctl", "--list-boots", "-o", "json", "--no-pager", "-q"])
    boots = []
    try:
        for b in json.loads(out):
            boots.append(Boot(int(b.get("index", 0)), b.get("boot_id", ""),
                              (b.get("first_entry") or 0) / 1e6,
                              (b.get("last_entry") or 0) / 1e6))
    except (ValueError, TypeError, AttributeError):
        for line in out.splitlines():
            parts = line.split()
            if (len(parts) >= 2 and re.fullmatch(r"-?\d+", parts[0])
                    and re.fullmatch(r"[0-9a-f]{32}", parts[1])):
                boots.append(Boot(int(parts[0]), parts[1], 0, 0))
    boots.sort(key=lambda b: b.index)
    return boots


def boot_time():
    for line in read_file("/proc/stat").splitlines():
        if line.startswith("btime"):
            return float(line.split()[1])
    return 0.0


def time_window(key, boots):
    """(start, end) epoch seconds; end None = open ended."""
    by = {b.index: b for b in boots}
    if key == "boot0":
        b = by.get(0)
        return ((b.first if b and b.first else boot_time()), None)
    if key == "boot1":
        b = by.get(-1)
        if b and b.first:
            return (b.first, b.last + 120)
        return (1.0, 0.0)  # matches nothing
    hours = {"24h": 24, "7d": 168, "30d": 720}[key]
    return (time.time() - hours * 3600, None)


def in_window(ts, w):
    start, end = w
    return ts >= start and (end is None or ts <= end)


def journal_access():
    if os.geteuid() == 0:
        return True
    names = set()
    for g in os.getgroups():
        try:
            names.add(grp.getgrgid(g).gr_name)
        except KeyError:
            pass
    return bool(names & {"adm", "systemd-journal", "wheel", "root"})


# --------------------------------------------------------------------------
# kernel log analysis
# --------------------------------------------------------------------------

RX_SEGV = re.compile(r"(?:^|\s)([^\s\[]+)\[(\d+)\]: segfault at|^traps: ([^\s\[]+)\[(\d+)\] (.+?) ip:")
RX_SEGV_LIB = re.compile(r" in ([^\s\[]+)\[")
RX_OOM_START = re.compile(r"invoked oom-killer|Memory cgroup out of memory|oom-kill:|Out of memory: Kill", re.I)
RX_OOM_END = re.compile(r"Killed process|oom_reaper: reaped")
RX_OOM_KILLED = re.compile(r"Killed process (\d+) \(([^)]+)\)")
RX_KCRASH = re.compile(
    r"Kernel panic|Oops:|\bBUG: |kernel BUG at|general protection fault(?!.* ip:)|"
    r"WARNING: CPU: \d+ PID|soft lockup|hard LOCKUP|blocked for more than \d+ seconds|"
    r"rcu.*(self-detected stall|detected stalls)|Unable to handle kernel|"
    r"stack-protector|double fault|watchdog: BUG", re.I)
RX_KCRASH_CRIT = re.compile(r"panic|Oops|BUG|lockup|LOCKUP|protection fault|double fault|"
                            r"Unable to handle", re.I)
RX_KCRASH_END = re.compile(r"---\[ end (trace|Kernel panic)")
RX_RIP = re.compile(r"RIP: [0-9a-f]+:([\w.]+)\+0x[0-9a-f]+/0x[0-9a-f]+(?: \[(\w+)\])?")

RX_GPU = re.compile(
    r"amdgpu.*(error|fail|timeout|fault|reset|hang)|\*ERROR\*|NVRM: Xid|"
    r"nouveau.*(error|fail|fault)|\b(i915|xe)\b.*(hang|error|fail)|GPU (hang|reset|fault)|"
    r"ring \S+ timeout|\[drm\].*(error|fail)", re.I)
RX_GPU_CRIT = re.compile(r"timeout|GPU (reset|hang)|Xid|hang", re.I)

RX_DISK = re.compile(
    r"I/O error|EXT4-fs (error|warning)|BTRFS (error|warning|critical)|XFS .*(error|corrupt|shutdown)|"
    r"blk_update_request|critical medium error|Medium Error|"
    r"ata\d+(\.\d+)?: (exception|failed command|error|SError|hard resetting link)|"
    r"nvme\d*.*(timeout|I/O|reset|error|failed)|remounting filesystem read-only|"
    r"FAT-fs.*error|SQUASHFS error|Aborting journal|journal commit I/O error", re.I)
RX_DISK_CRIT = re.compile(r"read-only|Aborting journal|critical", re.I)

RX_HW = re.compile(
    r"mce: |Machine check|Hardware Error|EDAC|PCIe Bus Error|AER: |ACPI (BIOS )?Error|"
    r"ACPI Exception|temperature above threshold|clock throttled|thermal.*critical|"
    r"usb \S+: (device descriptor read|device not accepting address|unable to enumerate)|"
    r"Firmware Bug|firmware: failed|Direct firmware load .* failed|Corrected error|Uncorrected", re.I)
# informational boot messages that merely mention MCE / EDAC / AER / ACPI
RX_BENIGN = re.compile(
    r"MCE decoding enabled|AER: enabled with IRQ|EDAC MC: Ver|EDAC .*Giving out device|"
    r"_OSI\(Linux\) query ignored|mce: Using \d+ MCE banks|ACPI: .*Added _OSI|"
    r"Firmware Bug\]: TSC_DEADLINE disabled", re.I)
# patterns that are real problems even when logged at a low priority
RX_STRONG = re.compile(
    r"Hardware Error|Machine check events|I/O error|ring \S+ timeout|GPU (reset|hang)|"
    r"NVRM: Xid|EXT4-fs error|BTRFS (error|critical)|read-only|Uncorrected", re.I)
RX_HW_ERR = re.compile(r"Hardware Error|Machine check|Uncorrected|Fatal|EDAC .*UE|"
                       r"temperature above|thermal.*critical", re.I)


def group_lines(entries, i, end_rx=None, max_lines=150, window=3.0):
    first = entries[i]
    out = [first.msg]
    j = i + 1
    while j < len(entries) and len(out) < max_lines:
        e = entries[j]
        if e.ts - first.ts > window:
            break
        if RX_SEGV.search(e.msg):
            break
        out.append(e.msg)
        j += 1
        if end_rx and end_rx.search(e.msg):
            break
    return "\n".join(out), j


def segv_summary(msg):
    m = RX_SEGV.search(msg)
    if not m:
        return one_line(msg)
    if m.group(1):
        name, pid, kind = m.group(1), m.group(2), "segmentation fault"
    else:
        name, pid, kind = m.group(3), m.group(4), m.group(5)
    lib = RX_SEGV_LIB.search(msg)
    where = f" in {lib.group(1)}" if lib else ""
    return f"{name} (PID {pid}) crashed - {kind}{where}"


def analyze_kernel(entries, cats):
    i, n = 0, len(entries)
    while i < n:
        e = entries[i]
        m = e.msg
        if RX_SEGV.search(m):
            details = m
            j = i + 1
            if j < n and entries[j].msg.lstrip().startswith("Code:"):
                details += "\n" + entries[j].msg
                j += 1
            details += ("\n\nThe kernel stopped this program because it accessed memory it "
                        "does not own (or executed an invalid instruction). The library named "
                        "after 'in' is where it happened.")
            cats["apps"].add(Event(e.ts, "error", "kernel", segv_summary(m), details))
            i = j
            continue
        if RX_OOM_START.search(m):
            details, j = group_lines(entries, i, RX_OOM_END, max_lines=250, window=5.0)
            k = RX_OOM_KILLED.search(details)
            summary = (f"Out of memory - kernel killed {k.group(2)} (PID {k.group(1)})"
                       if k else "Out-of-memory killer invoked")
            cats["oom"].add(Event(e.ts, "error", "kernel OOM killer", summary, details))
            i = j
            continue
        if RX_KCRASH.search(m):
            details, j = group_lines(entries, i, RX_KCRASH_END)
            sev = "critical" if RX_KCRASH_CRIT.search(m) else "error"
            summary = one_line(m)
            rip = RX_RIP.search(details)
            if rip:
                summary += f" - in {rip.group(1)}" + (f" [{rip.group(2)}]" if rip.group(2) else "")
            cats["kernel"].add(Event(e.ts, sev, "kernel", summary, details))
            i = j
            continue
        if RX_BENIGN.search(m) or (e.prio > 4 and not RX_STRONG.search(m)):
            i += 1
            continue
        if RX_GPU.search(m):
            sev = "critical" if RX_GPU_CRIT.search(m) else "error"
            cats["gpu"].add(Event(e.ts, sev, "kernel", m, m))
        elif RX_DISK.search(m):
            sev = "critical" if RX_DISK_CRIT.search(m) else (
                "warning" if "warning" in m.lower() else "error")
            cats["disk"].add(Event(e.ts, sev, "kernel", m, m))
        elif RX_HW.search(m):
            sev = "error" if RX_HW_ERR.search(m) else "warning"
            cats["hardware"].add(Event(e.ts, sev, "kernel", m, m))
        elif e.prio <= 3:
            cats["other"].add(Event(e.ts, prio_sev(e.prio), "kernel", m, m))
        i += 1


# --------------------------------------------------------------------------
# user space analysis
# --------------------------------------------------------------------------

RX_DESKTOP = re.compile(
    r"^(gnome-|gdm|gsd-|org\.gnome\.|Xwayland|Xorg|mutter|pipewire|wireplumber|pulseaudio|"
    r"xdg-desktop-portal|nautilus|tracker-|ibus|kwin|plasmashell|kded|cosmic|at-spi|"
    r"evolution|gvfs|goa-|gjs|/usr/libexec/gdm|/usr/libexec/gsd|/usr/bin/gnome)", re.I)

RX_SVC = re.compile(
    r"Failed with result|Main process exited, code=(dumped|killed)|Failed to start|"
    r"Start request repeated too quickly|start operation timed out|Watchdog timeout|"
    r"Processes still around after|State 'stop-sigterm' timed out", re.I)
RX_SVC_STATUS = re.compile(r"status=(\S+)")


def entry_details(e):
    extra = []
    for key, label in (("_SYSTEMD_UNIT", "Unit"), ("_SYSTEMD_USER_UNIT", "User unit"),
                       ("UNIT", "Unit"), ("USER_UNIT", "User unit"),
                       ("_EXE", "Executable"), ("_PID", "PID"), ("_CMDLINE", "Command line"),
                       ("CODE_FILE", "Code file")):
        v = _decode(e.raw.get(key))
        if v and not any(x.startswith(label + ":") for x in extra):
            extra.append(f"{label}: {v}")
    return e.msg + ("\n\n" + "\n".join(extra) if extra else "")


def analyze_errors(entries, cats):
    for e in entries:
        if e.kernel or e.ident in ("systemd", "systemd-coredump"):
            continue
        if _decode(e.raw.get("MESSAGE_ID")) == COREDUMP_MSGID:
            continue
        cid = "desktop" if RX_DESKTOP.match(e.ident) else "other"
        cats[cid].add(Event(e.ts, prio_sev(e.prio), e.ident, e.msg, entry_details(e)))


def analyze_services(entries, cats):
    for e in entries:
        if e.kernel:
            continue
        if not RX_SVC.search(e.msg):
            if e.prio <= 3:
                cats["other"].add(Event(e.ts, prio_sev(e.prio), e.ident, e.msg, entry_details(e)))
            continue
        unit = (_decode(e.raw.get("UNIT")) or _decode(e.raw.get("USER_UNIT"))
                or e.msg.split(":")[0])
        if re.search(r"code=(dumped|killed)", e.msg):
            st = RX_SVC_STATUS.search(e.msg)
            summary = f"{unit} crashed ({st.group(1) if st else 'killed'})"
            sev = "critical" if "dumped" in e.msg else "error"
        else:
            summary = e.msg
            sev = "error" if re.search(r"Failed|timed out|Watchdog", e.msg, re.I) else "warning"
        src = "systemd (user)" if e.raw.get("USER_UNIT") else "systemd"
        details = entry_details(e) + f"\n\nInspect with:  journalctl -u {unit} -b"
        cats["services"].add(Event(e.ts, sev, src, summary, details))


def current_failed_units(cats):
    now = time.time()
    for user in (False, True):
        flag = ["--user"] if user else []
        rc, out, _ = run(["systemctl"] + flag + ["--failed", "--no-legend", "--plain", "--no-pager"], 20)
        if rc == 127:
            return
        for line in out.splitlines()[:20]:
            parts = line.split()
            if not parts:
                continue
            unit = parts[0].lstrip("●* ")
            if not unit:
                continue
            _, status, _ = run(["systemctl"] + flag + ["status", unit, "-n", "25",
                                                       "--no-pager", "-l"], 20)
            utag = "--user " if user else ""
            details = (status.strip() or f"{unit} is failed.") + (
                f"\n\nRetry:    systemctl {utag}restart {unit}"
                f"\nLogs:     journalctl {'--user-unit' if user else '-u'} {unit} -b")
            cats["services"].add(Event(now, "error", "systemd (user)" if user else "systemd",
                                       f"{unit} is in a FAILED state right now", details))


SIGNALS = {3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS",
           8: "SIGFPE", 11: "SIGSEGV", 31: "SIGSYS"}
SIG_DESC = {"SIGSEGV": "segmentation fault", "SIGABRT": "aborted", "SIGBUS": "bus error",
            "SIGILL": "illegal instruction", "SIGFPE": "arithmetic error",
            "SIGTRAP": "trap / breakpoint", "SIGSYS": "bad system call", "SIGQUIT": "quit"}


def sig_name(raw):
    name = _decode(raw.get("COREDUMP_SIGNAL_NAME"))
    if name:
        return name
    try:
        return SIGNALS.get(int(_decode(raw.get("COREDUMP_SIGNAL"))), "signal")
    except ValueError:
        return "signal"


def collect_coredumps(rargs, cats):
    entries, _ = journal(rargs + [f"MESSAGE_ID={COREDUMP_MSGID}"], limit=500)
    for e in entries:
        r = e.raw
        comm = _decode(r.get("COREDUMP_COMM")) or "?"
        pid = _decode(r.get("COREDUMP_PID"))
        sig = sig_name(r)
        lines = [f"Executable:   {_decode(r.get('COREDUMP_EXE'))}",
                 f"PID:          {pid}",
                 f"Signal:       {sig} ({SIG_DESC.get(sig, '')})",
                 f"User ID:      {_decode(r.get('COREDUMP_UID'))}",
                 f"Command line: {_decode(r.get('COREDUMP_CMDLINE'))}"]
        pkg = _decode(r.get("COREDUMP_PACKAGE_NAME"))
        if pkg:
            lines.append(f"Package:      {pkg} {_decode(r.get('COREDUMP_PACKAGE_VERSION'))}")
        details = "\n".join(lines) + "\n\n" + e.msg + (
            f"\n\nMore info:  coredumpctl info {pid}\nDebug:      coredumpctl debug {pid}")
        cats["apps"].add(Event(e.ts, "error", "systemd-coredump",
                               f"{comm} crashed - {SIG_DESC.get(sig, sig)} ({sig})", details))
    if not have("coredumpctl"):
        cats["apps"].notes.append(
            "systemd-coredump is not installed (Ubuntu uses Apport by default), so crashes "
            "are taken from the kernel log and /var/crash. For full stack traces of every "
            "crash you can install it: sudo apt install systemd-coredump")


APPORT_KEYS = ["ProblemType", "Title", "Date", "ExecutablePath", "Package", "SourcePackage",
               "Signal", "SignalName", "ProcCmdline", "CrashCounter", "DistroRelease",
               "Uname", "Architecture", "DuplicateSignature", "StacktraceTop",
               "Stacktrace", "ThreadStacktrace", "Traceback", "OopsText", "Failure"]


def parse_apport(path, maxbytes=1024 * 1024):
    with open(path, "r", errors="replace") as f:
        data = f.read(maxbytes)
    fields, key, skip = {}, None, False
    for line in data.splitlines():
        if line.startswith(" ") and key:
            if not skip:
                fields[key] += "\n" + line[1:]
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+):\s?(.*)$", line)
        if m:
            key = m.group(1)
            val = m.group(2)
            skip = val.strip() == "base64"
            fields[key] = "" if skip else val
    return fields


def collect_apport(window, cats):
    files = sorted(glob.glob("/var/crash/*.crash"))
    for path in files:
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if not in_window(mtime, window):
            continue
        guess = os.path.basename(path).split(".")[0].replace("_", "/")
        try:
            f = parse_apport(path)
        except PermissionError:
            cats["apps"].add(Event(mtime, "error", "apport",
                                   f"{guess} crashed (Apport report, readable by root only)",
                                   f"Report: {path}\n\nView it with:  sudo less {path}\n"
                                   f"Open in the crash reporter:  ubuntu-bug {path}"))
            continue
        except OSError:
            continue
        ptype = f.get("ProblemType", "Crash")
        exe = f.get("ExecutablePath") or guess
        sig = f.get("SignalName", "")
        if not sig and f.get("Signal", "").strip().isdigit():
            sig = SIGNALS.get(int(f["Signal"]), "")
        title = f.get("Title") or (f"{os.path.basename(exe)} crashed"
                                   + (f" - {SIG_DESC.get(sig, sig)} ({sig})" if sig else ""))
        body = [f"Report file: {path}"]
        for k in APPORT_KEYS:
            v = f.get(k)
            if v:
                body.append(f"{k}:" + ("\n" + v if "\n" in v else " " + v))
        body.append(f"\nOpen in the Ubuntu crash reporter:  ubuntu-bug {path}")
        if ptype in ("KernelCrash", "KernelOops"):
            cats["kernel"].add(Event(mtime, "critical", "apport", title, "\n".join(body)))
        else:
            cats["apps"].add(Event(mtime, "error", "apport", title, "\n".join(body)))


def collect_pstore(cats):
    base = "/var/lib/systemd/pstore"
    if not os.path.isdir(base):
        return
    try:
        items = sorted(os.listdir(base))
    except PermissionError:
        cats["kernel"].notes.append(f"{base} is not readable without root - saved kernel panic "
                                    f"logs (if any) are not shown. Check: sudo ls -l {base}")
        return
    for name in items:
        path = os.path.join(base, name)
        try:
            mtime = os.path.getmtime(path)
            if os.path.isdir(path):
                txt = read_file(os.path.join(path, "dmesg.txt"))
                if not txt:
                    txt = "\n".join(read_file(p, limit=200000)
                                    for p in sorted(glob.glob(path + "/*")))
            else:
                txt = read_file(path, limit=200000)
        except OSError:
            continue
        hit = next((ln for ln in txt.splitlines() if RX_KCRASH.search(ln)), "")
        summary = "Saved crash log from before a reboot" + (f": {one_line(hit, 160)}" if hit else "")
        cats["kernel"].add(Event(mtime, "critical", "pstore (saved before reboot)", summary,
                                 f"Saved in: {path}\n\n{txt[-30000:]}"))


def collect_oomd(rargs, cats):
    entries, _ = journal(rargs + ["-t", "systemd-oomd", "-t", "earlyoom"], limit=500)
    for e in entries:
        if re.search(r"kill|sending SIG", e.msg, re.I):
            cats["oom"].add(Event(e.ts, "error", e.ident, e.msg, entry_details(e)))


RX_CLEAN = re.compile(
    r"Journal stopped|Reached target (System )?(Power-?Off|Reboot|Shutdown|Halt|Kexec)|"
    r"reboot: (Restarting system|Power down)|systemd-shutdown|Shutting down\.|"
    r"System is (powering down|rebooting)|Stopped target Graphical Interface", re.I)
RX_SUSPEND = re.compile(r"PM: suspend entry|PM: hibernation entry|Reached target Sleep|"
                        r"Suspending system|Entering sleep state", re.I)


def collect_unclean(boots, cats):
    prev = sorted([b for b in boots if b.index < 0], key=lambda b: -b.index)[:10]
    if not prev:
        cats["unclean"].notes.append(
            "No previous boots are stored in the journal, so earlier shutdowns can't be checked. "
            "Either this is the first boot or persistent logging is off (see Overview → hints).")
        return
    by_index = {x.index: x for x in boots}
    for b in prev:
        ref = b.boot_id or str(b.index)
        rc, out, _ = run(["journalctl", "--no-pager", "-q", "-b", ref, "-n", "80",
                          "-o", "short-iso"], 30)
        lines = [ln for ln in out.splitlines() if ln.strip()]
        if not lines or RX_CLEAN.search("\n".join(lines)):
            continue
        tail = "\n".join(lines[-15:])
        started = fmt_time(b.first) if b.first else f"boot {b.index}"
        ran = (b.last - b.first) if b.first and b.last else None
        sev = "critical"
        if ran is not None and ran < 90:
            summary = f"Stopped {int(ran)} s after power-on, still starting up ({started})"
            why = ("The computer was reset or switched off while it was still booting. Usually "
                   "that is you pressing reset / power (for example to get into the BIOS), but "
                   "it can also be a crash very early in startup.")
            sev = "warning"
        elif RX_SUSPEND.search(tail):
            summary = f"Never woke up from suspend (boot started {started})"
            why = ("The last thing logged was the system going to sleep. Resume failed - "
                   "often a GPU driver or firmware (BIOS) resume problem.")
        else:
            summary = f"Boot ended abruptly - no clean shutdown (started {started})"
            why = ("Nothing was logged about shutting down. Typical causes: hard freeze "
                   "(GPU / CPU hang), kernel panic, power loss or unstable PSU, overheating, "
                   "overclock / XMP instability, or the power button being held. If the last "
                   "lines show normal activity and no error, suspect hardware or power.")
        # A CPU Machine Check that caused the crash is only written at the NEXT boot
        mce_lines = []
        nxt = by_index.get(b.index + 1)
        if nxt:
            _, kout, _ = run(["journalctl", "--no-pager", "-q", "-k", "-b",
                              nxt.boot_id or str(nxt.index), "-o", "cat"], 30)
            mce_lines = [ln for ln in kout.splitlines()
                         if re.search(r"\[Hardware Error\]|Machine check events", ln)][:40]
        if mce_lines:
            summary += " - CPU Machine Check reported afterwards"
            sev = "critical"
            why += ("\n\nIMPORTANT: when the computer started again, the CPU reported a Machine "
                    "Check Exception (MCE) from this crash. That means the crash was a HARDWARE-"
                    "level fault seen by the CPU itself (CPU, RAM, power delivery, or unstable "
                    "BIOS / power-saving settings), not a normal software bug.")
        dur = human_duration(b.last - b.first) if b.first and b.last else "?"
        details = (f"Boot index: {b.index}\nBoot ID:    {b.boot_id}\n"
                   f"Started:    {started}\nLast log:   {fmt_time(b.last)}\nRan for:    {dur}\n\n"
                   f"{why}\n\nLast {len(lines)} messages before the system stopped:\n"
                   f"{'-' * 60}\n" + "\n".join(lines) +
                   f"\n{'-' * 60}\nSee more:  journalctl -b {b.index} -n 300")
        if mce_lines:
            details += ("\n\nMachine Check reported at the next boot:\n" + "\n".join(mce_lines) +
                        f"\nSee:  journalctl -k -b {nxt.index} | grep -i 'hardware error'")
        cats["unclean"].add(Event(b.last or b.first or 0, sev, "journal", summary, details))


# --------------------------------------------------------------------------
# known harmless noise: still shown (marked "harmless"), never counted as a problem
# --------------------------------------------------------------------------

KNOWN_HARMLESS = [
    (r"gkr-pam: unable to locate daemon control file",
     "GNOME Keyring message at login. Harmless and logged on almost every Ubuntu system."),
    (r"uvcvideo.*Failed to query .*UVC control",
     "Your webcam doesn't support an optional setting the driver asked about. Harmless."),
    (r"bluetoothd.*Failed to set mode: Failed \(0x03\)",
     "Bluetooth adapter rejected an optional setting at startup. Harmless if Bluetooth works."),
    (r"snapd-desktop-integration.*Failed with result",
     "A Snap helper that often fails at login. Harmless; Snap apps still work."),
    (r"mpris-proxy\.service.*Failed with result",
     "Bluetooth media-button helper; fails when no Bluetooth headset is connected. Harmless."),
    (r"thermald.*Unsupported cpu model",
     "thermald only supports Intel CPUs. Harmless on AMD."),
    (r"Unknown username \"malcontent",
     "Parental-controls service users not created yet. Harmless."),
    (r"Failed to (query|set) .* (aspm|ASPM)",
     "PCIe power-saving feature not available. Harmless."),
]
KNOWN_HARMLESS = [(re.compile(rx, re.I), why) for rx, why in KNOWN_HARMLESS]


def mark_known_harmless(cats):
    for cat in cats.values():
        if cat.id == "unclean":
            continue
        for ev in cat.events:
            text = f"{ev.source} {ev.summary}"
            for rx, why in KNOWN_HARMLESS:
                if rx.search(text):
                    ev.severity = "info"
                    ev.details = f"KNOWN HARMLESS: {why}\n\n{ev.details or ev.summary}"
                    break


# --------------------------------------------------------------------------
# system info
# --------------------------------------------------------------------------

TAINT_FLAGS = [
    ("P", "proprietary module loaded (e.g. NVIDIA)"), ("F", "module force-loaded"),
    ("S", "CPU out of spec"), ("R", "module force-unloaded"),
    ("M", "machine check (hardware error) occurred"), ("B", "bad memory page found"),
    ("U", "taint requested by user"), ("D", "kernel crashed (OOPS/BUG) in this boot"),
    ("A", "ACPI table overridden"), ("W", "kernel warning issued"),
    ("C", "staging driver loaded"), ("I", "firmware bug workaround active"),
    ("O", "out-of-tree module loaded"), ("E", "unsigned module loaded"),
    ("L", "soft lockup occurred"), ("K", "kernel live-patched"),
    ("X", "auxiliary taint"), ("T", "built with struct randomization"), ("N", "test taint"),
]


def os_name():
    for line in read_file("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return platform.system()


def meminfo():
    vals = {}
    for line in read_file("/proc/meminfo").splitlines():
        parts = line.replace(":", "").split()
        if len(parts) >= 2 and parts[1].isdigit():
            vals[parts[0]] = int(parts[1]) / 1048576  # GiB
    return vals


def read_temps():
    temps = []
    for hw in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
        name = read_file(hw + "/name") or os.path.basename(hw)
        best = None
        for inp in glob.glob(hw + "/temp*_input"):
            v = read_file(inp)
            if not v.lstrip("-").isdigit():
                continue
            t = int(v) / 1000
            label = read_file(inp.replace("_input", "_label")) or "temp"
            if best is None or t > best[1]:
                best = (f"{name} {label}", t)
        if best and -30 < best[1] < 150:
            temps.append(best)
    return temps


def system_info(boots):
    info, facts = [], {}
    info.append(("Computer", platform.node()))
    info.append(("Operating system", os_name()))
    info.append(("Kernel", platform.release()))
    de, st = os.environ.get("XDG_CURRENT_DESKTOP", ""), os.environ.get("XDG_SESSION_TYPE", "")
    if de or st:
        info.append(("Desktop session", f"{de} ({st})" if de and st else de or st))
    board = " ".join(filter(None, [read_file("/sys/class/dmi/id/board_vendor"),
                                   read_file("/sys/class/dmi/id/board_name")]))
    if board:
        info.append(("Motherboard", board))
    bios = read_file("/sys/class/dmi/id/bios_version")
    if bios:
        info.append(("BIOS", f"{bios} ({read_file('/sys/class/dmi/id/bios_date')})"))
    cpu = next((ln.split(":", 1)[1].strip() for ln in read_file("/proc/cpuinfo").splitlines()
                if ln.startswith("model name")), platform.processor())
    info.append(("CPU", f"{cpu} - {os.cpu_count()} threads"))
    mi = meminfo()
    if mi:
        info.append(("Memory", f"{mi.get('MemTotal', 0):.1f} GiB total, "
                               f"{mi.get('MemAvailable', 0):.1f} GiB available, swap "
                               f"{mi.get('SwapTotal', 0):.1f} GiB ({mi.get('SwapFree', 0):.1f} free)"))
    facts["swap"] = mi.get("SwapTotal", 0)
    gpus = []
    rc, out, _ = run(["lspci"], 10)
    for ln in out.splitlines():
        m = re.search(r"(VGA compatible controller|3D controller|Display controller): (.+)", ln)
        if m:
            gpus.append(m.group(2).strip())
    drivers = set()
    for p in glob.glob("/sys/class/drm/card[0-9]*/device/driver"):
        try:
            drivers.add(os.path.basename(os.readlink(p)))
        except OSError:
            pass
    if gpus or drivers:
        info.append(("Graphics", "; ".join(gpus) + (f"  [driver: {', '.join(sorted(drivers))}]"
                                                    if drivers else "")))
    try:
        up = float(read_file("/proc/uptime", "0").split()[0])
        info.append(("Uptime", f"{human_duration(up)} (since {fmt_time(time.time() - up)})"))
    except (ValueError, IndexError):
        pass
    try:
        du = shutil.disk_usage("/")
        facts["root_free_pct"] = du.free / du.total * 100
        info.append(("Root filesystem", f"{du.free / 1e9:.1f} GB free of {du.total / 1e9:.1f} GB"))
    except OSError:
        facts["root_free_pct"] = 100
    temps = read_temps()
    facts["temps"] = temps
    if temps:
        info.append(("Temperatures now", ",  ".join(f"{l}: {t:.0f} °C" for l, t in temps)))
    taint_val = read_file("/proc/sys/kernel/tainted", "0")
    letters = []
    try:
        tv = int(taint_val)
        for bit, (letter, desc) in enumerate(TAINT_FLAGS):
            if tv & (1 << bit):
                letters.append((letter, desc))
    except ValueError:
        tv = 0
    facts["taint"] = "".join(l for l, _ in letters)
    info.append(("Kernel taint", "not tainted" if not letters else
                 f"{tv} - " + "; ".join(f"{l}: {d}" for l, d in letters)))
    persistent = os.path.isdir("/var/log/journal")
    facts["persistent"] = persistent
    facts["boots"] = len(boots)
    info.append(("System journal", f"{'persistent' if persistent else 'NOT persistent (lost on reboot)'}"
                                   f", {len(boots)} boot(s) stored"))
    acc = journal_access()
    facts["access"] = acc
    info.append(("Log access", "full (adm / systemd-journal group or root)" if acc else
                 "limited - only your own user's logs are visible"))
    return info, facts


# --------------------------------------------------------------------------
# hints
# --------------------------------------------------------------------------

def build_hints(rep):
    h = []
    c = {cat.id: cat for cat in rep.categories}
    f = rep.facts
    n = lambda i: len(c[i].issues)  # noqa: E731
    crashes = [e for e in c["unclean"].events if e.severity == "critical"]
    if crashes:
        h.append(f"The computer stopped abruptly {len(crashes)} time(s) in the last boots. Open "
                 "'Unexpected shutdowns' and read the last lines of each: a GPU error or kernel "
                 "trace just before points to a driver; nothing at all points to power, "
                 "overheating or unstable hardware settings (overclock, XMP/EXPO, undervolt).")
    if n("kernel"):
        h.append("The kernel reported crashes or warnings. The module in [brackets] after the "
                 "function name is usually the driver responsible - try a different kernel "
                 "version (choose it under 'Advanced options' in GRUB) to confirm.")
    if "D" in f.get("taint", ""):
        h.append("The kernel has already crashed during this boot - the system may behave "
                 "strangely until you reboot.")
    if n("gpu"):
        h.append("GPU errors were logged. GPU hangs cause frozen screens and black-screen "
                 "crashes: update Mesa / the NVIDIA driver (Software & Updates → Additional "
                 "Drivers), and test with a different kernel.")
    if (any(RX_HW_ERR.search(e.summary) for e in c["hardware"].issues)
            or any("Machine Check" in e.summary for e in c["unclean"].events)
            or "M" in f.get("taint", "")):
        h.append("Machine Check / memory errors point at hardware: RAM, CPU or overclock "
                 "instability. Reset BIOS to defaults (disable XMP/EXPO and PBO), and test RAM "
                 "with memtest86+ from the GRUB menu.")
    if n("disk"):
        h.append("Disk or filesystem errors were found. Back up your data, then check the disk: "
                 "sudo apt install smartmontools && sudo smartctl -a /dev/sdX (or /dev/nvme0n1).")
    if n("oom"):
        swap = f.get("swap", 0)
        h.append("Programs were killed because RAM ran out." +
                 (" You have no swap - adding a swap file helps a lot." if swap < 0.5 else
                  " Close memory-hungry programs or add more swap."))
    if n("apps"):
        h.append("Program crashes: open an entry to see the library it crashed in. Repeated "
                 "crashes in the same library after an update usually mean a bug in that "
                 "update - check for newer updates or try the Flatpak / Snap version.")
    if n("services"):
        h.append("Some services failed. Open the entry for the exact error and the "
                 "commands to restart or inspect it.")
    hot = [(l, t) for l, t in f.get("temps", []) if t >= 90]
    if hot:
        h.append("High temperature right now: " + ", ".join(f"{l} {t:.0f} °C" for l, t in hot) +
                 ". Overheating causes sudden shutdowns - check fans and cooling.")
    if f.get("root_free_pct", 100) < 5:
        h.append("Your root filesystem is almost full - this alone breaks updates, logins and apps.")
    if not f.get("persistent", True):
        h.append("The journal is not persistent, so logs from before the last reboot are lost. "
                 "Enable it: sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald")
    if not f.get("access", True):
        h.append("You can only read your own logs, so system crashes may be missing. Run "
                 "'sudo usermod -aG adm $USER', log out and back in, then scan again.")
    harmless = sum(cat.harmless for cat in rep.categories)
    if not h:
        h.append("No crashes or problems were found in this range.")
    if harmless:
        h.append(f"{harmless} logged error(s) are known to be harmless (webcam, keyring, "
                 "Bluetooth and similar). They are still listed, marked 'harmless'.")
    return h


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------

def normalize(text):
    return re.sub(r"0x[0-9a-fA-F]+|\b[0-9a-fA-F]{8,}\b|\d+", "#", text)


def dedupe(events):
    groups = {}
    for ev in sorted(events, key=lambda e: e.ts):
        key = (ev.source, normalize(ev.summary))
        g = groups.get(key)
        if g is None:
            groups[key] = Event(ev.ts, ev.severity, ev.source, ev.summary, ev.details,
                                ev.count, ev.first_ts)
        else:
            g.count += ev.count
            g.first_ts = min(g.first_ts, ev.first_ts)
            g.ts, g.summary, g.details = ev.ts, ev.summary, ev.details
            if SEV_RANK[ev.severity] < SEV_RANK[g.severity]:
                g.severity = ev.severity
    return list(groups.values())


def collect(range_key="boot0", progress=lambda s: None):
    t0 = time.time()
    notes = []
    cats = make_categories(range_key)
    rargs = RANGE_ARGS[range_key]

    if not have("journalctl"):
        notes.append("journalctl was not found - this tool needs systemd's journal.")

    progress("Listing boots…")
    boots = list_boots()
    window = time_window(range_key, boots)

    progress("Reading the kernel log…")
    kern, prob = journal(rargs + ["-k"], limit=KERNEL_LOG_LIMIT)
    if prob:
        notes.append(f"Kernel log: {prob}")
    if len(kern) >= KERNEL_LOG_LIMIT:
        notes.append(f"Only the newest {KERNEL_LOG_LIMIT} kernel messages were analysed.")
    analyze_kernel(kern, cats)

    progress("Reading system errors…")
    errs, prob = journal(rargs + ["-p", "3"], limit=10000)
    if prob:
        notes.append(f"System log: {prob}")
    analyze_errors(errs, cats)

    progress("Checking services…")
    svc, _ = journal(rargs + ["-t", "systemd", "-p", "4"], limit=6000)
    analyze_services(svc, cats)
    current_failed_units(cats)

    progress("Looking for core dumps and crash reports…")
    collect_coredumps(rargs, cats)
    collect_apport(window, cats)
    collect_pstore(cats)
    collect_oomd(rargs, cats)

    progress("Checking how previous boots ended…")
    collect_unclean(boots, cats)

    progress("Reading system information…")
    info, facts = system_info(boots)
    mark_known_harmless(cats)

    for cat in cats.values():
        if cat.dedupe:
            cat.events = dedupe(cat.events)
        cat.events.sort(key=lambda e: e.ts, reverse=True)

    label = dict(RANGES)[range_key]
    rep = Report(range_key, label, time.time(), list(cats.values()), info, facts, notes,
                 time.time() - t0)
    rep.hints = build_hints(rep)
    return rep


# --------------------------------------------------------------------------
# text report
# --------------------------------------------------------------------------

def anonymize(text):
    """Remove details that identify this computer or person before a report is shared."""
    subs = []
    host = platform.node()
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = ""
    home = os.path.expanduser("~")
    if home and home not in ("/", "/root"):
        subs.append((home, "/home/<user>"))
    if host and len(host) >= 3:
        subs.append((host, "<computer>"))
    if user and len(user) >= 3:
        subs.append((user, "<user>"))
    for old, new in subs:
        text = re.sub(re.escape(old), new, text)
    text = re.sub(r"\b[0-9a-f]{32}\b", "<id>", text)                                # boot / machine IDs
    text = re.sub(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", "<mac>", text)        # MAC addresses
    text = re.sub(r"\b(?!127\.)(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", text)            # IPv4
    text = re.sub(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b", "<ip6>", text)  # IPv6
    text = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "<email>", text)                    # e-mail
    text = re.sub(r"(?i)(serial[ _-]?(?:number|no)?[:=]\s*)\S+", r"\1<serial>", text)
    return text


def report_to_text(rep, detail_lines=80, private=False):
    out = [f"{APP_NAME} {VERSION} - crash & error report   ({PROJECT_URL})",
           f"Generated: {fmt_time(rep.generated)}",
           f"Range:     {rep.range_label}", ""]
    out.append("=== SYSTEM ===")
    w = max(len(k) for k, _ in rep.info) if rep.info else 10
    out += [f"{k.ljust(w)} : {v}" for k, v in rep.info]
    out += ["", "=== WHAT THIS MIGHT MEAN ==="]
    out += [f"* {h}" for h in rep.hints]
    if rep.notes:
        out += ["", "=== SCAN NOTES ==="] + [f"! {n}" for n in rep.notes]
    out += ["", "=== SUMMARY ==="]
    for c in rep.categories:
        cnt = len(c.issues)
        extra = f" (+{c.harmless} harmless)" if c.harmless else ""
        out.append(f"{c.title.ljust(34)} {'OK' if not cnt else f'{cnt} issue(s)'}{extra}")
    for c in rep.categories:
        if not c.events and not c.notes:
            continue
        out += ["", "=" * 78, f"=== {c.title.upper()} ({len(c.events)}) ===", "=" * 78]
        out += [f"! {n}" for n in c.notes]
        for ev in c.events:
            cnt = f"  (x{ev.count}, first {fmt_time(ev.first_ts)})" if ev.count > 1 else ""
            tag = "HARMLESS" if ev.severity == "info" else ev.severity.upper()
            out += ["", f"[{tag}] {fmt_time(ev.ts)}  {ev.source}{cnt}",
                    f"  {ev.summary}"]
            lines = (ev.details or "").splitlines()
            if lines and not (len(lines) == 1 and lines[0].strip() == ev.summary):
                shown = lines[:detail_lines]
                out += ["    | " + ln for ln in shown]
                if len(lines) > detail_lines:
                    out.append(f"    | … {len(lines) - detail_lines} more lines")
    text = "\n".join(out) + "\n"
    if private:
        text = "(Personal details such as computer name, user name, IDs and addresses were removed.)\n" + anonymize(text)
    return text


# --------------------------------------------------------------------------
# GUI (GTK 4 + libadwaita)
# --------------------------------------------------------------------------

GTK_ERROR = ""
try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango
    HAVE_GTK = True
except (ImportError, ValueError) as _e:
    HAVE_GTK = False
    GTK_ERROR = str(_e)

CSS = """
.ci-badge { border-radius: 999px; padding: 1px 9px; font-weight: bold; font-size: 0.85em; }
.ci-badge-critical, .ci-badge-error { background-color: @error_bg_color; color: @error_fg_color; }
.ci-badge-warning { background-color: @warning_bg_color; color: @warning_fg_color; }
.ci-badge-ok { background-color: alpha(@success_color, 0.18); color: @success_color; }
.ci-sev-critical, .ci-sev-error { color: @error_color; }
.ci-sev-warning { color: @warning_color; }
.ci-sev-info { color: @accent_color; }
textview.ci-detail { font-family: monospace; font-size: 0.9em; border-radius: 8px;
                     padding: 10px; background-color: alpha(@view_fg_color, 0.05); }
textview.ci-detail text { background-color: transparent; }
.ci-cmd { font-family: monospace; font-size: 0.9em; }
.ci-note { padding: 10px 14px; }
"""

MAX_ROWS = 400
SEV_ICON = {"critical": "dialog-error-symbolic", "error": "dialog-error-symbolic",
            "warning": "dialog-warning-symbolic", "info": "dialog-information-symbolic"}

if HAVE_GTK:

    def _margins(w, n):
        w.set_margin_top(n)
        w.set_margin_bottom(n)
        w.set_margin_start(n)
        w.set_margin_end(n)
        return w

    def _label(text, css=(), wrap=True, xalign=0.0, selectable=False):
        lbl = Gtk.Label(label=text, xalign=xalign, wrap=wrap, selectable=selectable)
        if wrap:
            lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        for c in css:
            lbl.add_css_class(c)
        return lbl

    def _badge(cat):
        n = len(cat.issues)
        lbl = Gtk.Label(label=str(n) if n else "✓", valign=Gtk.Align.CENTER)
        lbl.add_css_class("ci-badge")
        lbl.add_css_class(f"ci-badge-{cat.worst}" if n else "ci-badge-ok")
        return lbl

    class SidebarRow(Gtk.ListBoxRow):
        def __init__(self, cat_id, title, icon, cat=None):
            super().__init__()
            self.cat_id = cat_id
            box = Gtk.Box(spacing=10)
            _margins(box, 6)
            img = Gtk.Image.new_from_icon_name(icon)
            if cat is not None and cat.issues:
                img.add_css_class(f"ci-sev-{cat.worst}")
            box.append(img)
            lbl = Gtk.Label(label=title, xalign=0, hexpand=True,
                            ellipsize=Pango.EllipsizeMode.END)
            box.append(lbl)
            if cat is not None:
                box.append(_badge(cat))
            self.set_child(box)

    class DetailBox(Gtk.Box):
        def __init__(self, ev, win):
            super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            _margins(self, 12)
            text = ev.full_text()
            tv = Gtk.TextView(editable=False, cursor_visible=False, monospace=True,
                              wrap_mode=Gtk.WrapMode.WORD_CHAR)
            tv.add_css_class("ci-detail")
            tv.get_buffer().set_text(text)
            self.append(tv)
            btn = Gtk.Button(label="Copy details", halign=Gtk.Align.END)
            btn.connect("clicked", lambda *_: win.copy(text, "Details copied"))
            self.append(btn)

    class EventRow(Adw.ExpanderRow):
        def __init__(self, ev, win):
            super().__init__()
            self.ev, self.win, self._filled = ev, win, False
            try:
                self.set_use_markup(False)
            except AttributeError:
                pass
            self.set_title(ev.summary)
            try:
                self.set_title_lines(2)
                self.set_subtitle_lines(1)
            except AttributeError:
                pass
            sub = f"{fmt_time(ev.ts)}   ·   {ev.source}"
            if ev.count > 1:
                sub += f"   ·   {ev.count}× since {fmt_time(ev.first_ts)}"
            if ev.severity == "info":
                sub += "   ·   known harmless"
            self.set_subtitle(sub)
            icon = Gtk.Image.new_from_icon_name(SEV_ICON.get(ev.severity, SEV_ICON["info"]))
            icon.add_css_class(f"ci-sev-{ev.severity}")
            self.add_prefix(icon)
            self.connect("notify::expanded", self._on_expanded)

        def _on_expanded(self, *_):
            if self.get_expanded() and not self._filled:
                self._filled = True
                self.add_row(DetailBox(self.ev, self.win))

    class MainWindow(Adw.ApplicationWindow):
        def __init__(self, app, range_key):
            super().__init__(application=app, title=APP_NAME)
            self.set_default_size(1180, 800)
            self.report = None
            self.loading = False
            self.selected_id = "overview"
            self.rows = {}

            self.toasts = Adw.ToastOverlay()
            tv = Adw.ToolbarView()
            hb = Adw.HeaderBar()

            self.refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic",
                                          tooltip_text="Scan again (F5)")
            self.refresh_btn.connect("clicked", lambda *_: self.refresh())
            hb.pack_start(self.refresh_btn)
            self.range_dd = Gtk.DropDown.new_from_strings([l for _, l in RANGES])
            self.range_dd.set_tooltip_text("Time range to scan")
            self.range_dd.set_selected([k for k, _ in RANGES].index(range_key))
            self.range_dd.connect("notify::selected", lambda *_: self.refresh())
            hb.pack_start(self.range_dd)

            self.export_btn = Gtk.Button(icon_name="document-save-symbolic",
                                         tooltip_text="Export the full report to a text file")
            self.export_btn.connect("clicked", lambda *_: self.export())
            self.copy_btn = Gtk.Button(icon_name="edit-copy-symbolic",
                                       tooltip_text="Copy the full report (for a forum post or bug report)")
            self.copy_btn.connect("clicked", lambda *_: self.report and
                                  self.copy(report_to_text(self.report, private=self.private_btn.get_active()),
                                            "Full report copied"))
            self.private_btn = Gtk.ToggleButton(icon_name="security-high-symbolic", active=True,
                                                tooltip_text="Hide personal info (computer name, user name, "
                                                             "IDs, addresses) when copying or exporting")
            self.private_btn.connect("toggled", lambda b: self.toast(
                "Personal info will be hidden in copied/exported reports" if b.get_active()
                else "Copied/exported reports will include personal info"))
            about_btn = Gtk.Button(icon_name="help-about-symbolic", tooltip_text="About Crash Inspector")
            about_btn.connect("clicked", lambda *_: self.show_about())
            hb.pack_end(self.export_btn)
            hb.pack_end(about_btn)
            hb.pack_end(self.copy_btn)
            hb.pack_end(self.private_btn)
            tv.add_top_bar(hb)

            self.banner = Adw.Banner()
            self.banner.set_revealed(False)
            self.banner.connect("button-clicked", lambda *_: self.copy(
                "sudo usermod -aG adm $USER", "Command copied - run it, then log out and back in"))
            tv.add_top_bar(self.banner)

            self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
            loading = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14,
                              valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER)
            sp = Gtk.Spinner(spinning=True)
            sp.set_size_request(48, 48)
            loading.append(sp)
            loading.append(_label("Scanning system logs", ("title-2",), xalign=0.5))
            self.status_lbl = _label("Starting…", ("dim-label",), xalign=0.5)
            loading.append(self.status_lbl)
            self.stack.add_named(loading, "loading")

            paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
            paned.set_position(310)
            paned.set_resize_start_child(False)
            paned.set_shrink_start_child(False)
            self.sidebar = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
            self.sidebar.add_css_class("navigation-sidebar")
            self.sidebar.connect("row-selected", self.on_row_selected)
            ss = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
            ss.set_size_request(260, -1)
            ss.set_child(self.sidebar)
            paned.set_start_child(ss)
            self.content = Adw.Bin()
            paned.set_end_child(self.content)
            self.stack.add_named(paned, "content")

            err = Adw.StatusPage(icon_name="dialog-error-symbolic", title="The scan failed")
            self.err_lbl = _label("", ("ci-cmd",), selectable=True)
            err.set_child(self.err_lbl)
            self.stack.add_named(err, "error")

            tv.set_content(self.stack)
            self.toasts.set_child(tv)
            self.set_content(self.toasts)

            ctrl = Gtk.ShortcutController()
            ctrl.add_shortcut(Gtk.Shortcut.new(
                Gtk.ShortcutTrigger.parse_string("F5"),
                Gtk.CallbackAction.new(lambda *_: (self.refresh(), True)[1])))
            ctrl.add_shortcut(Gtk.Shortcut.new(
                Gtk.ShortcutTrigger.parse_string("<Control>r"),
                Gtk.CallbackAction.new(lambda *_: (self.refresh(), True)[1])))
            self.add_controller(ctrl)
            GLib.idle_add(self.refresh)

        # ---- actions
        def toast(self, text):
            self.toasts.add_toast(Adw.Toast.new(text))

        def copy(self, text, msg="Copied"):
            cb = self.get_clipboard()
            try:
                cb.set(text)
            except Exception:  # noqa: BLE001
                try:
                    cb.set_content(Gdk.ContentProvider.new_for_value(text))
                except Exception as e:  # noqa: BLE001
                    self.toast(f"Copy failed: {e}")
                    return
            self.toast(msg)

        def show_about(self):
            kw = dict(application_name=APP_NAME, application_icon=APP_ID, version=VERSION,
                      developer_name="cyb3rl00m", website=PROJECT_URL, issue_url=ISSUES_URL,
                      license_type=Gtk.License.MIT_X11, copyright="© 2026 cyb3rl00m",
                      comments="Every crash and error on this computer, in one window.")
            try:
                Adw.AboutDialog(**kw).present(self)
            except (AttributeError, TypeError):
                win = Adw.AboutWindow(transient_for=self, **kw)
                win.present()

        def export(self):
            if not self.report:
                return
            dlg = Gtk.FileDialog()
            dlg.set_title("Export crash report")
            dlg.set_initial_name(f"crash-report-{dt.datetime.now():%Y-%m-%d_%H%M}.txt")
            dlg.save(self, None, self._export_done)

        def _export_done(self, dlg, res):
            try:
                gfile = dlg.save_finish(res)
            except GLib.Error:
                return
            if not gfile:
                return
            path = gfile.get_path()
            try:
                with open(path, "w") as f:
                    f.write(report_to_text(self.report, detail_lines=400,
                                           private=self.private_btn.get_active()))
                self.toast(f"Report saved to {path}")
            except OSError as e:
                self.toast(f"Could not save: {e}")

        def refresh(self):
            if self.loading:
                return False
            self.loading = True
            for w in (self.refresh_btn, self.range_dd, self.export_btn, self.copy_btn):
                w.set_sensitive(False)
            key = RANGES[self.range_dd.get_selected()][0]
            self.status_lbl.set_text("Starting…")
            self.stack.set_visible_child_name("loading")

            def worker():
                try:
                    rep = collect(key, lambda s: GLib.idle_add(self.status_lbl.set_text, s))
                    err = None
                except Exception:  # noqa: BLE001
                    rep, err = None, traceback.format_exc()
                GLib.idle_add(self.on_done, rep, err)

            threading.Thread(target=worker, daemon=True).start()
            return False

        def on_done(self, rep, err):
            self.loading = False
            for w in (self.refresh_btn, self.range_dd, self.export_btn, self.copy_btn):
                w.set_sensitive(True)
            if err:
                self.err_lbl.set_text(err)
                self.stack.set_visible_child_name("error")
                return False
            self.report = rep
            if not rep.facts.get("access", True):
                self.banner.set_title("Only your own logs are visible - system crashes may be "
                                      "missing. Add yourself to the 'adm' group.")
                self.banner.set_button_label("Copy command")
                self.banner.set_revealed(True)
            else:
                self.banner.set_revealed(False)
            self.populate_sidebar()
            self.stack.set_visible_child_name("content")
            return False

        # ---- navigation
        def populate_sidebar(self):
            child = self.sidebar.get_first_child()
            while child:
                nxt = child.get_next_sibling()
                self.sidebar.remove(child)
                child = nxt
            self.rows = {}
            row = SidebarRow("overview", "Overview", "view-grid-symbolic")
            self.sidebar.append(row)
            self.rows["overview"] = row
            for cat in self.report.categories:
                row = SidebarRow(cat.id, cat.title, cat.icon, cat)
                self.sidebar.append(row)
                self.rows[cat.id] = row
            self.sidebar.select_row(self.rows.get(self.selected_id, self.rows["overview"]))

        def select(self, cid):
            if cid in self.rows:
                self.sidebar.select_row(self.rows[cid])

        def on_row_selected(self, _lb, row):
            if row is None or not self.report:
                return
            self.selected_id = row.cat_id
            if row.cat_id == "overview":
                self.content.set_child(self.build_overview())
            else:
                self.content.set_child(self.build_category(self.report.cat(row.cat_id)))

        # ---- pages
        def _page(self):
            sw = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
            clamp = Adw.Clamp(maximum_size=1100)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
            _margins(box, 24)
            clamp.set_child(box)
            sw.set_child(clamp)
            return sw, box

        def build_overview(self):
            rep = self.report
            sw, box = self._page()
            problem = [c for c in rep.categories if c.issues]
            worst = min((SEV_RANK[c.worst] for c in problem), default=9)
            issues = sum(len(c.issues) for c in problem)
            if worst == 0:
                icon, title = "dialog-error-symbolic", "Crashes found"
            elif worst <= 2:
                icon, title = "dialog-warning-symbolic", "Some problems found"
            else:
                icon, title = "emblem-ok-symbolic", "No problems found"
            status = Adw.StatusPage(icon_name=icon, title=title)
            status.set_description(
                f"{issues} distinct issue(s) in {len(problem)} area(s)  ·  {rep.range_label}  ·  "
                f"scanned {fmt_time(rep.generated)} in {rep.duration:.1f} s")
            status.add_css_class("compact")
            box.append(status)

            hints = Adw.PreferencesGroup(title="What this might mean")
            for h in rep.hints:
                r = Adw.ActionRow(title=h)
                try:
                    r.set_use_markup(False)
                    r.set_title_lines(0)
                except AttributeError:
                    pass
                r.add_prefix(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
                hints.add(r)
            box.append(hints)

            for note in rep.notes:
                box.append(self._note(note))

            areas = Adw.PreferencesGroup(title="Problem areas",
                                         description="Click an area to see every entry with full details.")
            for c in rep.categories:
                r = Adw.ActionRow(title=c.title, activatable=True)
                try:
                    r.set_use_markup(False)
                except AttributeError:
                    pass
                sub = f"{len(c.issues)} issue(s)" if c.issues else "No problems"
                if c.harmless:
                    sub += f"  ·  {c.harmless} known harmless"
                r.set_subtitle(sub)
                img = Gtk.Image.new_from_icon_name(c.icon)
                if c.issues:
                    img.add_css_class(f"ci-sev-{c.worst}")
                r.add_prefix(img)
                r.add_suffix(_badge(c))
                r.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
                r.connect("activated", lambda _r, cid=c.id: self.select(cid))
                areas.add(r)
            box.append(areas)

            sysg = Adw.PreferencesGroup(title="This computer")
            for k, v in rep.info:
                r = Adw.ActionRow(title=k, subtitle=v)
                try:
                    r.set_use_markup(False)
                    r.set_subtitle_selectable(True)
                except AttributeError:
                    pass
                sysg.add(r)
            box.append(sysg)
            return sw

        def _note(self, text):
            b = Gtk.Box(spacing=10)
            b.add_css_class("card")
            b.add_css_class("ci-note")
            img = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            img.add_css_class("ci-sev-warning")
            b.append(img)
            b.append(_label(text, selectable=True))
            return b

        def build_category(self, cat):
            sw, box = self._page()
            head = Gtk.Box(spacing=14)
            img = Gtk.Image.new_from_icon_name(cat.icon)
            img.set_pixel_size(40)
            if cat.issues:
                img.add_css_class(f"ci-sev-{cat.worst}")
            head.append(img)
            tbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, hexpand=True)
            tbox.append(_label(cat.title, ("title-2",)))
            tbox.append(_label(cat.description, ("dim-label",)))
            head.append(tbox)
            box.append(head)

            for note in cat.notes:
                box.append(self._note(note))

            if cat.events:
                search = Gtk.SearchEntry(placeholder_text=f"Filter {len(cat.events)} entries…")
                box.append(search)
                lb = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
                lb.add_css_class("boxed-list")
                info = _label("", ("dim-label", "caption"))

                def fill(query=""):
                    child = lb.get_first_child()
                    while child:
                        nxt = child.get_next_sibling()
                        lb.remove(child)
                        child = nxt
                    q = query.lower().strip()
                    matched = [e for e in cat.events if not q or q in e.search_text()]
                    for ev in matched[:MAX_ROWS]:
                        lb.append(EventRow(ev, self))
                    txt = f"{len(matched)} of {len(cat.events)} entries"
                    if len(matched) > MAX_ROWS:
                        txt += f" - showing the newest {MAX_ROWS}; filter or export to see all"
                    info.set_text(txt + ". Click an entry for full details.")

                search.connect("search-changed", lambda s: fill(s.get_text()))
                fill()
                box.append(lb)
                box.append(info)
            else:
                st = Adw.StatusPage(icon_name="emblem-ok-symbolic", title="Nothing found",
                                    description=f"No problems of this kind in: {self.report.range_label}.")
                st.add_css_class("compact")
                box.append(st)

            exp = Gtk.Expander(label="How this was checked - commands you can run yourself")
            exp.set_child(_margins(_label("\n".join(cat.commands), ("ci-cmd",), selectable=True), 8))
            box.append(exp)
            return sw

    class CrashInspectorApp(Adw.Application):
        def __init__(self, range_key):
            super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
            self.range_key = range_key

        def do_startup(self):
            Adw.Application.do_startup(self)
            provider = Gtk.CssProvider()
            try:
                provider.load_from_string(CSS)
            except (AttributeError, TypeError):
                provider.load_from_data(CSS, -1)
            Gtk.StyleContext.add_provider_for_display(
                Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        def do_activate(self):
            win = self.props.active_window or MainWindow(self, self.range_key)
            win.present()


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(prog="crash-inspector",
                                description="Show every crash and error on this computer.")
    p.add_argument("--text", action="store_true",
                   help="print the report in the terminal instead of opening a window "
                        "(works on a TTY or over SSH)")
    p.add_argument("--range", choices=[k for k, _ in RANGES], default="boot0",
                   help="time range: boot0 (this boot), boot1 (previous boot), 24h, 7d, 30d")
    p.add_argument("--private", action="store_true",
                   help="hide computer name, user name, IDs and addresses (for posting online)")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    a = p.parse_args()

    has_display = bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))
    if a.text or not HAVE_GTK or not has_display:
        if not a.text and not HAVE_GTK:
            print(f"GTK 4 / libadwaita not available ({GTK_ERROR}).\n"
                  "Install: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1\n"
                  "Showing the text report instead.\n", file=sys.stderr)
        tty = sys.stderr.isatty()
        rep = collect(a.range, lambda s: tty and print(f"  {s}", file=sys.stderr))
        sys.stdout.write(report_to_text(rep, private=a.private))
        return 0
    return CrashInspectorApp(a.range).run([sys.argv[0]])


if __name__ == "__main__":
    sys.exit(main())
