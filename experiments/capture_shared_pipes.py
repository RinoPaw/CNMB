#!/usr/bin/env python3
"""Sample shared anonymous pipe FDs among exact-named target processes.

ADB + root only; no Frida, hooks, file contents, packet capture or app changes
unless --launch is explicitly provided. Only pipes observed in TWO OR MORE
target-named PIDs are reported. Pipe inode numbers never enter JSON output.
The kernel may reparent processes, reuse pipe inode numbers or close a pipe
between samples. A match is FD sharing, not proof of who created the pipe or
what payload it carried.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time

from capture_loaded_modules import (
    PACKAGE, SAFE_PACKAGE, process_parentage, require_ready_device, run_adb
)

PIPE_ROW = re.compile(r"^(?P<pid>\d+)\s+(?P<fd>\d+)\s+(?P<inode>\d+)\s+(?P<flags>[0-7]+|-)$")
MAX_PID_COUNT = 20

# PIDs are coerced to positive integers and cannot inject shell syntax.
# Only 'pipe:[inode]' links are printed. No sockets, names, paths or content.
READ_PIPES = """
for pid in %(pids)s; do
  for path in /proc/$pid/fd/*; do
    target=$(readlink "$path" 2>/dev/null) || continue
    case "$target" in
      pipe:\[*\])
        fd=${path##*/}
        inode=${target#pipe:[}
        inode=${inode%%]}
        flags=$(sed -n 's/^flags:[[:space:]]*//p' "/proc/$pid/fdinfo/$fd" 2>/dev/null)
        [ -n "$flags" ] || flags=-
        printf '%%s %%s %%s %%s\\n' "$pid" "$fd" "$inode" "$flags"
        ;;
    esac
  done
done
"""


def access_mode(flags):
    """Linux /proc/<pid>/fdinfo flags are octal, O_ACCMODE occupies bits 0-1."""
    if flags == "-":
        return "unknown"
    try:
        bits = int(flags, 8) & 3
    except ValueError:
        return "unknown"
    return {0: "read", 1: "write", 2: "read_write"}.get(bits, "unknown")


def parse_fd_rows(raw, allowed_pids):
    """Discard every row not belonging to a known target PID or valid pipe."""
    pipes = {}
    for line in raw.splitlines():
        m = PIPE_ROW.fullmatch(line.strip())
        if not m:
            continue
        pid, fd, inode = (int(m.group(part)) for part in ("pid", "fd", "inode"))
        if pid not in allowed_pids or fd < 0 or inode <= 0:
            continue
        member = {"pid": pid, "fd": fd, "access_mode": access_mode(m.group("flags"))}
        pipes.setdefault(inode, []).append(member)
    # Only same-pipe FDs in DIFFERENT target PIDs can form a candidate link.
    return {inode: sorted(members, key=lambda x: (x["pid"], x["fd"]))
            for inode, members in pipes.items()
            if len({member["pid"] for member in members}) >= 2}


def shared_links(raw, parents, tags):
    """Anonymize inode numbers with local capture-scoped sequential labels."""
    pipes = parse_fd_rows(raw, set(parents))
    links = []
    for inode, members in sorted(pipes.items()):
        if inode not in tags:
            tags[inode] = f"pipe_{len(tags) + 1}"
        participants = [
            {**m, "ppid_at_sample": parents[m["pid"]]} for m in members
        ]
        links.append({"pipe": tags[inode], "members": participants,
                      "opposite_access_modes_observed":
                      any(m["access_mode"] == "read" for m in participants) and
                      any(m["access_mode"] == "write" for m in participants)})
    return sorted(links, key=lambda x: x["pipe"])


def read_pipe_fds(pids):
    if not pids or len(pids) > MAX_PID_COUNT:
        raise ValueError("invalid number of matching process IDs")
    numbers = " ".join(str(int(pid)) for pid in sorted(set(pids)))
    if any(int(pid) <= 0 for pid in pids):
        raise ValueError("invalid process ID")
    return run_adb("shell", "su", "-c", READ_PIPES % {"pids": numbers},
                   timeout=6)


def observe(package, seconds, interval, launch=False):
    # Fail on unavailable root BEFORE force-stopping any application.
    if run_adb("shell", "su", "-c", "id -u", timeout=5).strip() != "0":
        raise RuntimeError("root permission required to inspect target /proc/PID/fd")
    if launch:
        run_adb("shell", "am", "force-stop", package, timeout=8)
        run_adb("shell", "monkey", "-p", package, "1", timeout=10)

    started = time.monotonic()
    tags = {}
    previously = None
    events = []
    errors = []
    polls = 0
    while (now := time.monotonic() - started) < seconds:
        polls += 1
        try:
            ps = run_adb("shell", "ps", "-A", "-o", "PID,PPID,NAME", timeout=5)
            parents = process_parentage(ps, package)
            if len(parents) > MAX_PID_COUNT:
                errors.append({"t": round(now, 3), "kind": "too_many_target_pids"})
            elif len(parents) >= 2:
                raw = read_pipe_fds(parents.keys())
                links = shared_links(raw, parents, tags)
                if links != previously:
                    events.append({"t": round(time.monotonic() - started, 3),
                                   "shared_links": links})
                    previously = links
            else:
                if previously:
                    events.append({"t": round(time.monotonic() - started, 3),
                                   "shared_links": []})
                previously = []
        except (RuntimeError, subprocess.TimeoutExpired, ValueError):
            errors.append({"t": round(time.monotonic() - started, 3),
                           "kind": "process_or_fd_unavailable"})
        time.sleep(interval)
    return {
        "package": package,
        "seconds": seconds, "poll_interval_seconds": interval,
        "launched_by_script": launch, "polls": polls,
        "events": events, "errors": errors,
        "notes": [
            "Capture only includes shared pipe FDs across distinct matching PIDs.",
            "Pipe names are per-capture labels. Raw inode values and path strings are not exported.",
            "Matching inode is not evidence of original parent, contents or DEC causality.",
            "No match can mean transient close, missed window, unavailable permissions or alternate IPC.",
            "PPID is only the value at the sampling instant. FD flag bits indicate descriptor access mode."
        ]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", default=PACKAGE)
    parser.add_argument("--seconds", type=float, default=18)
    parser.add_argument("--poll-seconds", type=float, default=0.2)
    parser.add_argument("--launch", action="store_true",
                        help="force-stop and relaunch target app (opt-in)")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not SAFE_PACKAGE.fullmatch(args.package):
        parser.error("invalid package name")
    if not 0 < args.seconds <= 120 or not 0.1 <= args.poll_seconds <= 10:
        parser.error("seconds must be 0..120, poll-seconds 0.1..10")
    try:
        require_ready_device()
        result = observe(args.package, args.seconds, args.poll_seconds, args.launch)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        parser.exit(2, f"ADB/root precheck failed: {type(exc).__name__}: {exc}\n")
    out = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        # Store local evidence under ignored captures/ by default in examples.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(out + "\n", encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
