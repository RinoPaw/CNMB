#!/usr/bin/env python3
"""Correlate an existing worker-identity JSON with an offline Android logcat.

Read-only. The captured host UTC timestamp is NOT used to align device time.
Requires a device-log am_proc_start for the observed main PID to select one
experiment window; otherwise it refuses to attribute historical DEC events.
Only sanitized summaries are emitted. No full log lines, paths or arguments.
"""
import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path

from parse_runtime_events import parse, THREADTIME
from profile_runtime_worker import profile

WINDOW_SECONDS = 35


def device_time(clock):
    return datetime.strptime("2026-" + clock, "%Y-%m-%d %H:%M:%S.%f")


def summarize_identity(capture):
    if not isinstance(capture.get("events"), list):
        raise ValueError("invalid worker identity capture")
    snapshots = {}
    finished = {}
    for event in capture["events"]:
        pid = event.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            continue
        if "ppid" in event and isinstance(event["ppid"], int):
            if pid not in snapshots:
                snapshots[pid] = {
                    "pid": pid, "ppid_at_first_snapshot": event["ppid"],
                    "first_seen_relative_seconds": event.get("t"),
                    "argv0_kind": event.get("argv0_kind"),
                    "entry_candidate": event.get("allowlisted_java_entry_candidate"),
                }
            else:
                if snapshots[pid]["ppid_at_first_snapshot"] != event["ppid"]:
                    snapshots[pid]["observed_parent_change"] = True
        if event.get("state") == "not_in_ps":
            finished[pid] = event.get("t")
    if not snapshots:
        raise ValueError("no PID/PPID observations")
    main = min(snapshots.values(),
               key=lambda row: (float(row["first_seen_relative_seconds"]), row["pid"]))
    main_pid = main["pid"]
    for pid, snapshot in snapshots.items():
        if pid in finished:
            snapshot["first_not_in_ps_relative_seconds"] = finished[pid]
    direct_children = sorted(pid for pid, item in snapshots.items()
                             if item["ppid_at_first_snapshot"] == main_pid)
    init_children = sorted(pid for pid, item in snapshots.items()
                           if item["ppid_at_first_snapshot"] == 1)
    return {"main_pid_candidate": main_pid,
            "direct_children_of_main_at_snapshot": direct_children,
            "ppid_1_at_first_snapshot": init_children,
            "processes": [snapshots[pid] for pid in sorted(snapshots)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", type=Path, required=True,
                        help="local worker-identity JSON")
    parser.add_argument("--logcat", type=Path, required=True,
                        help="local threadtime logcat collected after that run")
    parser.add_argument("--window-seconds", type=float, default=WINDOW_SECONDS)
    args = parser.parse_args()
    if not 5 <= args.window_seconds <= 120:
        parser.error("window must be 5..120 seconds")
    capture = json.loads(args.identity.read_text(encoding="utf-8-sig"))
    # First pass obtains start/death/DEC events; second pass profiles exact PIDs.
    with args.logcat.open("r", encoding="utf-8-sig", errors="replace") as input_file:
        events_only = parse(input_file, capture.get("package"))
    # Supply compact parsed events to the second pass for PID-specific profiling.
    with args.logcat.open("r", encoding="utf-8-sig", errors="replace") as input_file:
        output = correlate_with_events(capture, events_only, input_file,
                                       args.window_seconds)
    print(json.dumps(output, ensure_ascii=False, indent=2))


def correlate_with_events(capture, events, lines, window_seconds=WINDOW_SECONDS):
    """Streaming-friendly variant that accepts already parsed logcat events."""
    identity = summarize_identity(capture)
    pids = {p["pid"] for p in identity["processes"]}
    anchors = [e for e in events if e.get("kind") == "am_proc_start"
               and e.get("pid") == identity["main_pid_candidate"]]
    if len(anchors) != 1:
        return {"identity": identity, "device_log_anchor": None,
                "logcat_events": [], "process_log_profiles": [],
                "status": "No unique matching main PID start: session not correlated"}
    start = device_time(anchors[0]["clock"]) - timedelta(seconds=2)
    end = device_time(anchors[0]["clock"]) + timedelta(seconds=window_seconds)
    session_events = [e for e in events if start <= device_time(e["clock"]) <= end]
    workers = {pid: [] for pid in pids}
    for line in lines:
        m = THREADTIME.match(line)
        if m is None:
            continue
        pid = int(m.group("logger_pid"))
        if pid in pids and start <= device_time(m.group("clock")) <= end:
            workers[pid].append(line)
    return {
        "identity": identity,
        "device_log_anchor": anchors[0]["clock"],
        "logcat_events": session_events,
        "process_log_profiles": [profile(workers[pid], pid, capture.get("package"))
                                 for pid in sorted(pids)],
        "status": ("Match based on exact main PID and device-clock window. "
                   "Host-relative seconds are not synchronized. PPID=1 "
                   "does not reveal original parent or Java entry.")
    }


if __name__ == "__main__":
    main()
