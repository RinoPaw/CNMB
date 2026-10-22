#!/usr/bin/env python3
"""Read-only, privacy-limited chronology of one Android app_process PID.

This scans a previously captured threadtime logcat. Raw log message bodies,
device paths, command-line arguments, and unrecognized data are never emitted.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

from parse_runtime_events import PACKAGE, THREADTIME

MAIN_ENTRY = re.compile(r"\bCalling main entry\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)")
LOAD_LIBRARY = re.compile(r"\bLoad\s+(lib[A-Za-z0-9_@.\-]+\.so)\s+using\b")
MAX_EVENTS = 100


def profile(lines, pid, package=PACKAGE):
    first = last = None
    count = 0
    tags = Counter()
    events = []
    seen = set()
    def add(clock, kind, **data):
        identity = (clock, kind, tuple(sorted(data.items())))
        if identity not in seen and len(events) < MAX_EVENTS:
            seen.add(identity)
            events.append({"clock": clock, "kind": kind, **data})

    for line in lines:
        match = THREADTIME.match(line)
        if not match or int(match.group("logger_pid")) != pid:
            continue
        clock, tag, msg = (match.group("clock"),
                           match.group("tag").strip(),
                           match.group("message"))
        first = first or clock
        last = clock
        count += 1
        tags[tag] += 1
        if tag == "AndroidRuntime" and "START com.android.internal.os.RuntimeInit uid" in msg:
            add(clock, "runtime_init")
        if tag in {"auditd", "zygote"} and re.search(
                r"\bapp=" + re.escape(package) + r"(?=\s|$)", msg):
            add(clock, "selinux_target_package_context")
        if tag == "app_process" and "createInstance(64bit)" in msg:
            add(clock, "app_process_extensions_init")
        if tag == "app_process" and "Could not create image space" in msg:
            add(clock, "art_boot_image_fallback")
        if tag == "nativeloader":
            lib = LOAD_LIBRARY.search(msg)
            if lib:
                add(clock, "native_library_load", library=lib.group(1))
        if tag == "AndroidRuntime":
            main = MAIN_ENTRY.search(msg)
            if main:
                add(clock, "explicit_main_entry_log", class_name=main.group(1))
        if tag == "libc" and "Fatal signal" in msg:
            add(clock, "native_fatal_signal")
    return {
        "pid": pid, "lines": count,
        "first_message_clock": first,
        "last_message_clock": last,
        "tags": dict(sorted(tags.items())),
        "events": events,
        "has_explicit_main_entry_log": any(
            e["kind"] == "explicit_main_entry_log" for e in events),
        "note": ("Only exact logger-PID messages. An absent main entry is "
                 "not evidence that no Java main was executed. "
                 "PPID and original command line are not present in this input.")
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logcat", type=Path)
    p.add_argument("--pid", type=int, required=True, help="specific observed worker PID")
    p.add_argument("--package", default=PACKAGE)
    args = p.parse_args()
    if args.pid <= 0:
        p.error("pid must be positive")
    with args.logcat.open("r", encoding="utf-8-sig", errors="replace") as stream:
        result = profile(stream, args.pid, args.package)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
