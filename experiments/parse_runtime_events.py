#!/usr/bin/env python3
"""Extract minimal Android process, DEC activity, and native-crash chronology.

Purely offline, read-only. No ADB calls or app changes. Never prints full log
message bodies, intent extras, tokens, paths, or device identifiers.

Inputs: adb logcat -d -v threadtime -b main -b system -b events -b crash
Usage: python experiments/parse_runtime_events.py raw-logcat.txt
"""
import argparse
import json
import re
from pathlib import Path

PACKAGE = "com.greenpoint.android.mc10086.activity"
THREADTIME = re.compile(
    r"^\s*(?P<clock>\d\d-\d\d \d\d:\d\d:\d\d\.\d{3,6})\s+"
    r"(?P<logger_pid>\d+)\s+(?P<tid>\d+)\s+\S+\s+"
    r"(?P<tag>[^:]+):\s*(?P<message>.*)$")
SIGNAL = re.compile(
    r"Fatal signal\s+(?P<signal>\d+)\s+\((?P<name>[^)]+)\)", re.I)
SIGNAL_ADDR = re.compile(r"\bfault addr\s+(0x[0-9a-fA-F]+)", re.I)
SIGNAL_PID = re.compile(r"\bpid\s+(\d+)", re.I)
DEBUG_SIGNAL = re.compile(
    r"signal\s+(?P<signal>\d+)\s+\((?P<name>[^)]+)\).*?"
    r"fault addr\s+(?P<addr>0x[0-9a-fA-F]+)", re.I)
PID_FIELD = re.compile(r"\bpid:\s*(\d+)")
ACTIVITY = re.compile(r"\bDECMsgDialog\b")
PROC_TAGS = {"am_proc_start", "am_proc_died", "am_kill", "am_crash"}


def parse(line_iter, package=PACKAGE):
    events = []
    # Keep the last debug process PID only while reading one contiguous DEBUG block.
    debug_pid = None
    potential_signals = []
    runtime_starts = []
    app_context_pids = set()
    for line in line_iter:
        match = THREADTIME.match(line)
        if not match:
            continue
        clock, tag, msg = (match.group("clock"),
                           match.group("tag").strip(), match.group("message"))
        event = None
        # SELinux audit entries can establish which app owns a given PID.
        # Avoid treating ADB log lines containing /proc/<pid>/maps as identity.
        if re.search(r"\bapp=" + re.escape(package) + r"(?=\s|$)", msg):
            app_context_pids.add(int(match.group("logger_pid")))
        if (tag == "AndroidRuntime" and
                "START com.android.internal.os.RuntimeInit uid" in msg):
            uid = re.search(r"\buid\s+(\d+)", msg)
            if uid:
                runtime_starts.append({
                    "clock": clock, "kind": "app_process_runtime_init",
                    "pid": int(match.group("logger_pid")),
                    "uid": int(uid.group(1))})
        if tag in PROC_TAGS and msg.startswith("[") and msg.endswith("]"):
            parts = [part.strip() for part in msg[1:-1].split(",")]
            # Android event-log buffer convention: [user,pid,uid,process,...]
            if tag == "am_crash":
                # am_crash first field can be system PID; do not mislabel it as app PID.
                name = parts[2] if len(parts) > 2 else ""
                if name == package:
                    event = {"kind": "native_crash_report"
                             if "Native crash" in msg else "crash_report"}
            elif len(parts) >= 3 and (parts[2] == package or
                                        parts[2].startswith(package + ":")):
                # Some versions log [user,pid,process,...]
                if parts[1].isdigit():
                    event = {"kind": tag, "pid": int(parts[1])}
            elif len(parts) >= 4 and (parts[3] == package or
                                        parts[3].startswith(package + ":")):
                if parts[1].isdigit():
                    event = {"kind": tag, "pid": int(parts[1])}
        elif tag == "ActivityTaskManager" and ACTIVITY.search(msg) and package in msg:
            kind = ("dec_launch" if "START u" in msg else
                    "dec_displayed" if "Displayed " in msg else
                    "dec_force_finish" if "Force finishing " in msg else None)
            if kind:
                event = {"kind": kind}
        elif tag == "libc" and "Fatal signal" in msg:
            sig = SIGNAL.search(msg)
            pid = SIGNAL_PID.search(msg)
            addr = SIGNAL_ADDR.search(msg)
            if sig and pid:
                potential_signals.append(
                    {"clock": clock, "kind": "fatal_signal",
                     "pid": int(pid.group(1)), "signal": sig.group("name"),
                     "fault_addr": addr.group(1) if addr else None,
                     "explicit_package": package in msg})
        # DEBUG signal records lack the process name on the signal line. Only
        # attribute to package if that specific block states the cmdline name.
        elif tag == "DEBUG" and msg.startswith("Cmdline:"):
            debug_pid = None
        elif tag == "DEBUG" and msg.startswith("pid:") and package in msg:
            m = PID_FIELD.search(msg)
            debug_pid = int(m.group(1)) if m else None
        elif tag == "DEBUG" and debug_pid is not None and msg.startswith("signal "):
            sig = DEBUG_SIGNAL.search(msg)
            if sig:
                event = {"kind": "tombstone_signal", "pid": debug_pid,
                         "signal": sig.group("name"), "fault_addr": sig.group("addr")}
                debug_pid = None
        if event is not None:
            events.append({"clock": clock, **event})
    # Native fatal lines often abbreviate process names. Retain them only
    # when target PID is independently identified by Android process events.
    target_pids = {ev["pid"] for ev in events if "pid" in ev}
    for fatal in potential_signals:
        if fatal.pop("explicit_package") or fatal["pid"] in target_pids:
            events.append(fatal)
    for worker in runtime_starts:
        if worker["pid"] in app_context_pids:
            events.append(worker)
    # De-duplicate exact log lines that can appear across multiple log buffers.
    events.sort(key=lambda ev: ev["clock"])
    seen = set()
    result = []
    for event in events:
        key = tuple(sorted(event.items()))
        if key not in seen:
            seen.add(key)
            result.append(event)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logcat", type=Path, help="local threadtime logcat text")
    parser.add_argument("--package", default=PACKAGE)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+", args.package):
        parser.error("invalid Android package name")
    with args.logcat.open("r", encoding="utf-8-sig", errors="replace") as fh:
        result = parse(fh, args.package)
    print(json.dumps({"package": args.package, "events": result,
                      "note": ("Times are device-local logcat clocks. "
                               "Earlier ADB module timeline contains only "
                               "host-relative seconds; exact alignment "
                               "requires an independent shared time anchor.")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
