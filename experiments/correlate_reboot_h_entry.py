#!/usr/bin/env python3
"""Correlate an observed SecNeo H Java entry with one DEC launch in an offline logcat.

Read-only and privacy-minimized: never returns raw log messages, paths, extra
intent data, process argv or device identifiers. The result proves chronology
and process identity within the log, not fork ancestry or DEC causation.
"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re

PACKAGE = "com.greenpoint.android.mc10086.activity"
H_ENTRY = "com.secneo.apkwrapper.H"
THREADTIME = re.compile(
    r"^\s*(?P<clock>\d\d-\d\d \d\d:\d\d:\d\d\.\d{3,6})\s+"
    r"(?P<pid>\d+)\s+\d+\s+\S+\s+(?P<tag>[^:]+):\s*(?P<msg>.*)$")
START_PROC = re.compile(
    r"\bStart proc (?P<pid>\d+):(?P<package>[\w.]+)/u"
    r"(?P<user>\d+)a(?P<app>\d+)\b")
RUNTIME = re.compile(
    r"\bSTART com\.android\.internal\.os\.RuntimeInit uid (?P<uid>\d+)")
ENTRY = re.compile(
    r"\bCalling main entry\s+(?P<class>[A-Za-z_$][\w$]*(?:[./][A-Za-z_$][\w$]*)+)")
CALLING_UID = re.compile(r"\bmCallingUid=(?P<uid>\d+)\b")
VENDOR_PID = re.compile(r"\bcallingPid:\s*(?P<pid>\d+)\b")
VM_SHUTDOWN = "Shutting down VM"


def at(clock):
    # A leap-year anchor permits Feb 29. Comparisons are allowed only when
    # the entire session shares a single device-local calendar day.
    return datetime.strptime("2000-" + clock, "%Y-%m-%d %H:%M:%S.%f")


def seconds(later, earlier):
    if later.date() != earlier.date():
        return None
    return round((later - earlier).total_seconds(), 3)


def correlate(lines, package=PACKAGE, window_seconds=30.0):
    starts, runtime, audits, entries = [], [], {}, []
    shutdowns, dec_starts, vendor = {}, [], []
    for line in lines:
        m = THREADTIME.match(line)
        if not m:
            continue
        clock, pid = m.group("clock"), int(m.group("pid"))
        tag, msg = m.group("tag").strip(), m.group("msg")
        moment = at(clock)
        if tag == "ActivityManager":
            p = START_PROC.search(msg)
            if p and p.group("package") == package:
                uid = int(p.group("user")) * 100000 + 10000 + int(p.group("app"))
                starts.append((moment, pid if pid == int(p.group("pid")) else int(p.group("pid")), uid, clock))
        if tag == "AndroidRuntime":
            r = RUNTIME.search(msg)
            if r:
                runtime.setdefault(pid, []).append((moment, int(r.group("uid")), clock))
            e = ENTRY.search(msg)
            if e and e.group("class").replace("/", ".") == H_ENTRY:
                entries.append((moment, pid, clock))
            if VM_SHUTDOWN in msg:
                shutdowns.setdefault(pid, []).append((moment, clock))
        if tag in {"auditd", "zygote"} and re.search(
                r"\bapp=" + re.escape(package) + r"(?=\s|$)", msg):
            audits.setdefault(pid, []).append(moment)
        if tag == "ActivityTaskManager" and "START u" in msg and (
                "cmp=" + package + "/com.a.b.c.DECMsgDialog") in msg:
            u = CALLING_UID.search(msg)
            if u:
                dec_starts.append((moment, int(u.group("uid")), clock))
        if tag == "OplusZoomWindowManagerService" and (
                package in msg and "sourceStack:" in msg):
            v = VENDOR_PID.search(msg)
            if v:
                vendor.append((moment, int(v.group("pid"))))

    # Repeated messages across log buffers must not create false ambiguity.
    starts = sorted(set(starts))
    entries = sorted(set(entries))
    dec_starts = sorted(set(dec_starts))
    candidates = []
    for start, main_pid, uid, start_clock in starts:
        for dec, dec_uid, dec_clock in dec_starts:
            duration = seconds(dec, start)
            if dec_uid != uid or duration is None or not 0 <= duration <= window_seconds:
                continue
            for entry, worker_pid, entry_clock in entries:
                h_elapsed = seconds(entry, start)
                dec_after_h = seconds(dec, entry)
                if (worker_pid == main_pid or h_elapsed is None or
                        dec_after_h is None or h_elapsed < 0 or dec_after_h < 0):
                    continue
                rt = [(ts, c) for ts, rt_uid, c in runtime.get(worker_pid, [])
                      if rt_uid == uid and seconds(entry, ts) is not None
                      and 0 <= seconds(entry, ts) <= window_seconds]
                av = [ts for ts in audits.get(worker_pid, [])
                      if seconds(entry, ts) is not None
                      and 0 <= seconds(entry, ts) <= window_seconds]
                if not rt or not av:
                    continue
                runtime_at, runtime_clock = min(rt)
                # The vendor field is corroboration about launch routing,
                # not a kernel-validated creator or an IPC call trace.
                vendor_match = any(
                    vendor_pid == main_pid and
                    seconds(ts, dec) is not None and
                    0 <= seconds(ts, dec) <= 0.5
                    for ts, vendor_pid in vendor)
                ended = [s for s, c in shutdowns.get(worker_pid, [])
                         if seconds(s, entry) is not None and
                         0 <= seconds(s, entry) <= window_seconds]
                ended_clock = min((c for s, c in shutdowns.get(worker_pid, [])
                                  if s in ended), default=None)
                candidates.append({
                    "main_pid": main_pid, "worker_pid": worker_pid,
                    "main_uid": uid,
                    "main_start_clock": start_clock,
                    "runtime_init_clock": runtime_clock,
                    "h_entry_clock": entry_clock,
                    "worker_vm_shutdown_clock": ended_clock,
                    "dec_launch_clock": dec_clock,
                    "vendor_window_log_names_main_pid": vendor_match,
                    "intervals_seconds": {
                        "main_start_to_runtime_init": seconds(runtime_at, start),
                        "main_start_to_h_entry": h_elapsed,
                        "h_entry_to_dec_launch": dec_after_h,
                        "main_start_to_dec_launch": duration,
                        "worker_shutdown_to_dec_launch":
                            seconds(dec, min(ended)) if ended else None,
                    },
                })
    # Distinct candidate sessions are meaningful ambiguity; duplicative
    # same-session lines are not.
    unique = {(
        c["main_pid"], c["worker_pid"], c["main_start_clock"],
        c["h_entry_clock"], c["dec_launch_clock"]): c for c in candidates}
    if len(unique) != 1:
        return {
            "status": "insufficient" if not unique else "ambiguous",
            "matching_sessions": len(unique),
            "reason": ("One uniquely matched main start, H entry, same-PID RuntimeInit "
                       "and app-context audit, and DEC launch are required."),
        }
    return {
        "status": "correlated",
        "session": next(iter(unique.values())),
        "interpretation": (
            "H Java entry observed in a separate PID under the app UID before "
            "DEC launch; vendor callingPid may corroborate main-process routing. "
            "No fork/exec parentage, interprocess message, detection function "
            "or causal relationship is established."),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logcat", type=Path)
    p.add_argument("--window-seconds", type=float, default=30.0)
    args = p.parse_args()
    if not 1 <= args.window_seconds <= 120:
        p.error("window must be 1..120 seconds")
    with args.logcat.open("r", encoding="utf-8-sig", errors="replace") as source:
        result = correlate(source, window_seconds=args.window_seconds)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
