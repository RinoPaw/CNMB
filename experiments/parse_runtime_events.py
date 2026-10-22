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
    r"Fatal signal\s+(?P<signal>\d+)\s+\((?P<name>[^)]+)\)"
    r".*?(?:fault addr\s+(?P<addr>0x[0-9a-fA-F]+))?"
    r".*?\bpid\s+(?P<pid>\d+)", re.I)
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
    for line in line_iter:
        match = THREADTIME.match(line)
        if not match:
            continue
        clock, tag, msg = (match.group("clock"),
                           match.group("tag").strip(), match.group("message"))
        event = None
        if tag in PROC_TAGS and msg.startswith("[") and msg.endswith("]"):
            parts = [part.strip() for part in msg[1:-1].split(",")]
            # Android event-log buffer convention: [user,pid,uid,process,...]
            if tag == "am_crash":
                # am_crash first field can be system PID; do not mislabel it as app PID.
                name = parts[2] if len(parts) > 2 else ""
                if name == package:
                    event = {"kind": "native_crash_report"
                             if "Native crash" in msg else "crash_report"}
            elif len(parts) >= 3 and parts[2].startswith(package):
                # Some versions log [user,pid,process,...]
                if parts[1].isdigit():
                    event = {"kind": tag, "pid": int(parts[1])}
            elif len(parts) >= 4 and parts[3].startswith(package):
                if parts[1].isdigit():
                    event = {"kind": tag, "pid": int(parts[1])}
        elif tag == "ActivityTaskManager" and ACTIVITY.search(msg):
            kind = ("dec_launch" if "START u" in msg else
                    "dec_displayed" if "Displayed " in msg else
                    "dec_force_finish" if "Force finishing " in msg else None)
            if kind:
                event = {"kind": kind}
        elif tag == "libc" and "Fatal signal" in msg:
            sig = SIGNAL.search(msg)
            if sig and package in msg:
                event = {"kind": "fatal_signal", "pid": int(sig.group("pid")),
                         "signal": sig.group("name"),
                         "fault_addr": sig.group("addr")}
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
    # De-duplicate exact log lines that can appear across multiple log buffers.
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
