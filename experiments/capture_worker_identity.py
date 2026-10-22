#!/usr/bin/env python3
"""Sample target-named Android processes without hooking or dumping memory.

Only PPID, sanitized process type and allowlisted Java main-class candidates
leave the process. NEVER save full /proc/PID/cmdline or its extra arguments.
App_process can overwrite argv, so an empty entry does not prove no Java main.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time

from capture_loaded_modules import (
    PACKAGE, SAFE_PACKAGE, process_parentage, require_ready_device, run_adb
)

# Whitelist avoids accidentally emitting arbitrary command-line parameters.
ENTRY_PREFIXES = (
    "com.secneo.", "com.a.b.c.", "com.greenpoint.", "com.mc10086.",
    "com.android.internal."
)
CLASS_NAME = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+\.[A-Z_$][A-Za-z0-9_$]*$"
)


def sanitize_cmdline(raw, package=PACKAGE):
    """Accept NUL-separated /proc cmdline, never return argv or unknown values."""
    if not raw or not raw.strip("\x00"):
        return {"cmdline_state": "empty_or_exited"}
    argv = raw.split("\x00")
    argv = [arg for arg in argv if arg]
    if not argv:
        return {"cmdline_state": "empty_or_exited"}
    argv0 = argv[0].rsplit("/", 1)[-1]
    if "app_process" in argv0:
        kind = "app_process"
    elif argv0 == package:
        kind = "renamed_to_target_package"
    else:
        kind = "other_or_overwritten"
    entry = next(
        (arg for arg in argv[1:]
         if CLASS_NAME.fullmatch(arg) and
         any(arg.startswith(prefix) for prefix in ENTRY_PREFIXES)
         and not arg.startswith(package + ":")), None
    )
    return {"cmdline_state": "readable",
            "argv0_kind": kind,
            "allowlisted_java_entry_candidate": entry}


def observe(package, seconds, interval, launch=False):
    if launch:
        run_adb("shell", "am", "force-stop", package, timeout=8)
        run_adb("shell", "monkey", "-p", package, "1", timeout=10)
    anchor_host_utc = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    previous = {}
    events = []
    errors = []
    while (t := time.monotonic() - start) < seconds:
        try:
            parents = process_parentage(
                run_adb("shell", "ps", "-A", "-o", "PID,PPID,NAME"), package)
        except Exception:
            errors.append({"t": round(t, 2), "kind": "ps_unavailable"})
            time.sleep(interval)
            continue
        for pid in sorted(previous.keys() - parents.keys()):
            events.append({"t": round(t, 2), "pid": pid, "state": "not_in_ps"})
        next_state = {}
        for pid, ppid in sorted(parents.items()):
            try:
                cmdline = run_adb("shell", "su", "-c",
                                  f"cat /proc/{pid}/cmdline", timeout=3)
                clean = sanitize_cmdline(cmdline, package)
            except Exception:
                clean = {"cmdline_state": "unavailable"}
            state = {"ppid": ppid, **clean}
            next_state[pid] = state
            if previous.get(pid) != state:
                events.append({"t": round(time.monotonic() - start, 2),
                               "pid": pid, **state})
        previous = next_state
        time.sleep(interval)
    for pid in sorted(previous):
        events.append({"t": round(time.monotonic() - start, 2),
                       "pid": pid, "state": "present_at_end"})
    return {
        "package": package, "host_utc_anchor": anchor_host_utc,
        "anchor_notice": ("Host wall-clock at start of sampling; "
                          "not a device/Logcat synchronization anchor."),
        "seconds": seconds, "poll_interval_seconds": interval,
        "launched_by_script": launch, "events": events, "errors": errors,
        "limits": ("Only exact package process names are sampled. "
                   "PPID may change after reparenting. /proc/PID/cmdline "
                   "may be overwritten. No raw cmdline arguments recorded.")
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--package", default=PACKAGE)
    p.add_argument("--seconds", type=float, default=18)
    p.add_argument("--poll-seconds", type=float, default=0.25)
    p.add_argument("--launch", action="store_true", help="restart the target application")
    p.add_argument("--output", type=Path, help="save sanitized observations locally")
    args = p.parse_args()
    if not SAFE_PACKAGE.fullmatch(args.package):
        p.error("invalid package")
    if args.seconds <= 0 or not 0.1 <= args.poll_seconds <= 10:
        p.error("invalid sampling interval")
    try:
        require_ready_device()
    except Exception as exc:
        p.exit(2, f"ADB precheck failed: {type(exc).__name__}\n")
    result = observe(args.package, args.seconds, args.poll_seconds, args.launch)
    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
