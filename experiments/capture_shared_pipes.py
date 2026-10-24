#!/usr/bin/env python3
"""Sample shared anonymous pipe FDs across processes with the target app UID.

ADB + root only; no Frida, hooks, file contents, packet capture or app changes
unless --launch is explicitly provided. Only pipes observed in TWO OR MORE
same-UID PIDs are reported. Pipe inode numbers never enter JSON output.
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
    PACKAGE, SAFE_PACKAGE, require_ready_device, run_adb
)

PIPE_ROW = re.compile(r"^(?P<pid>\d+)\s+(?P<fd>\d+)\s+(?P<inode>\d+)\s+(?P<flags>[0-7]+|-)$")
MAX_PID_COUNT = 20
PROBE_ROW = re.compile(
    r"^STAT (?P<pid>\d+) (?P<exists>[01]) (?P<readable>[01]) "
    r"(?P<searchable>[01]) (?P<globs>\d+) (?P<links>\d+) "
    r"(?P<resolved>\d+) (?P<pipes>\d+)$")
PS_UID_ROW = re.compile(r"^\s*(?P<pid>\d+)\s+(?P<ppid>\d+)\s+(?P<uid>\d+)\s+(?P<name>\S+)\s*$")

# PIDs are coerced to positive integers and cannot inject shell syntax.
# Only 'pipe:[inode]' links are printed. No sockets, names, paths or content.
READ_PIPES = r"""
for pid in %(pids)s; do
  fd_dir=/proc/$pid/fd
  exists=0
  readable=0
  searchable=0
  globs=0
  links=0
  resolved=0
  pipes=0
  [ -d "$fd_dir" ] && exists=1
  [ -r "$fd_dir" ] && readable=1
  [ -x "$fd_dir" ] && searchable=1
  for path in "$fd_dir"/*; do
    # With an inaccessible/empty directory, POSIX sh leaves '*' literal.
    [ "$path" = "$fd_dir/*" ] && continue
    globs=$((globs + 1))
    [ -L "$path" ] && links=$((links + 1))
    # Do not gate readlink on 'test -L': Android toybox / procfs may
    # disagree with the desktop shell, so distinguish both outcomes.
    target=$(readlink "$path" 2>/dev/null) || continue
    resolved=$((resolved + 1))
    case "$target" in
      pipe:\[*\])
        pipes=$((pipes + 1))
        fd=${path##*/}
        inode=${target#pipe:[}
        inode=${inode%%]}
        flags=$(sed -n 's/^flags:[[:space:]]*//p' "/proc/$pid/fdinfo/$fd" 2>/dev/null)
        [ -n "$flags" ] || flags=-
        printf '%%s %%s %%s %%s\n' "$pid" "$fd" "$inode" "$flags"
        ;;
    esac
  done
  printf 'STAT %%s %%s %%s %%s %%s %%s %%s %%s %%s\n' "$pid" "$exists" "$readable" "$searchable" "$globs" "$links" "$resolved" "$pipes"
done
"""



def select_app_uid_processes(ps_output, package, known_uid=None):
    """Select all numeric-UID peers of a confirmed target-named process.

    The initial UID MUST come from an exact package process name. A UID
    already seen in this run may be reused during a gap in that name's
    lifetime. NAME is never retained or emitted for unrelated processes.
    """
    rows = []
    for line in ps_output.splitlines():
        matched = PS_UID_ROW.fullmatch(line.strip())
        if not matched:
            continue
        pid = int(matched.group("pid"))
        ppid = int(matched.group("ppid"))
        uid = int(matched.group("uid"))
        if pid <= 0 or uid <= 0:
            continue
        rows.append((pid, ppid, uid, matched.group("name")))
    if not rows:
        raise ValueError("ps did not return numeric UID rows")
    present_app_uids = {uid for pid, ppid, uid, name in rows if name == package}
    if len(present_app_uids) > 1 or (present_app_uids and known_uid is not None
                                     and present_app_uids != {known_uid}):
        raise ValueError("ambiguous or changing app UID")
    uid = next(iter(present_app_uids), known_uid)
    if uid is None:
        return {}, {}, None
    parents = {pid: ppid for pid, ppid, row_uid, name in rows if row_uid == uid}
    identities = {pid: ("target_package" if name == package
                         else "same_uid_other_name")
                  for pid, ppid, row_uid, name in rows if row_uid == uid}
    return parents, identities, uid


def parse_probe_stats(raw, pids):
    """Return aggregate shell/procfs coverage with no names, paths or inodes.

    Counters emitted by the shell demonstrate that its loop finished, but
    only glob and readlink successes prove FD enumeration actually happened.
    """
    expected = set(pids)
    samples = {}
    for line in raw.splitlines():
        match = PROBE_ROW.fullmatch(line.strip())
        if not match:
            continue
        pid = int(match.group("pid"))
        if pid not in expected or pid in samples:
            continue
        exists, readable, searchable = (
            int(match.group(field))
            for field in ("exists", "readable", "searchable"))
        globs, links, resolved, pipes = (
            int(match.group(field))
            for field in ("globs", "links", "resolved", "pipes"))
        if (links > globs or resolved > globs or pipes > resolved
                or (not exists and (links or resolved or pipes))):
            continue
        samples[pid] = (exists, readable, searchable, globs, links, resolved, pipes)
    return {
        "probe_pid_count": len(samples),
        "probes_complete": len(samples) == len(expected),
        "fd_dir_exists_count": sum(x[0] for x in samples.values()),
        "fd_dir_readable_count": sum(x[1] for x in samples.values()),
        "fd_dir_searchable_count": sum(x[2] for x in samples.values()),
        "fd_glob_match_count": sum(x[3] for x in samples.values()),
        "fd_symlink_count": sum(x[4] for x in samples.values()),
        "fd_readlink_success_count": sum(x[5] for x in samples.values()),
        "pipe_target_count": sum(x[6] for x in samples.values()),
    }


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


def shared_links(raw, parents, tags, identities=None):
    """Anonymize inode numbers with local capture-scoped sequential labels."""
    pipes = parse_fd_rows(raw, set(parents))
    links = []
    for inode, members in sorted(pipes.items()):
        if inode not in tags:
            tags[inode] = f"pipe_{len(tags) + 1}"
        participants = [
            {**m, "ppid_at_sample": parents[m["pid"]],
             **({"name_class": identities.get(m["pid"], "unclassified")}
                if identities is not None else {})} for m in members
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
    known_uid = None
    previously = None
    events = []
    errors = []
    polls = 0
    stats = {
        "polls_with_confirmed_uid": 0,
        "polls_with_same_uid_other_name": 0,
        "polls_with_two_or_more_candidates": 0,
        "fd_queries": 0,
        "fd_queries_with_pipe_rows": 0,
        "total_pipe_fd_rows": 0,
        "verified_fd_probe_polls": 0,
        "incomplete_fd_probe_polls": 0,
        "total_fd_dir_exists": 0,
        "total_fd_dir_readable": 0,
        "total_fd_dir_searchable": 0,
        "total_fd_glob_matches": 0,
        "fd_probes_without_glob_matches": 0,
        "fd_probes_without_readlink_success": 0,
        "total_fd_symlinks_seen": 0,
        "total_fd_readlinks_succeeded": 0,
        "total_pipe_symlinks_seen": 0,
        "max_candidate_pids": 0,
        "max_pipe_fd_rows_in_one_poll": 0
    }
    while (now := time.monotonic() - started) < seconds:
        polls += 1
        try:
            # Android toybox ps supports numeric UID as a documented field.
            ps = run_adb("shell", "ps", "-A", "-o", "PID,PPID,UID,NAME", timeout=5)
            parents, identities, known_uid = select_app_uid_processes(
                ps, package, known_uid)
            count = len(parents)
            if known_uid is not None:
                stats["polls_with_confirmed_uid"] += 1
            if any(value == "same_uid_other_name" for value in identities.values()):
                stats["polls_with_same_uid_other_name"] += 1
            stats["max_candidate_pids"] = max(stats["max_candidate_pids"], count)
            if count > MAX_PID_COUNT:
                errors.append({"t": round(now, 3), "kind": "too_many_same_uid_pids"})
                continue
            if count >= 2:
                stats["polls_with_two_or_more_candidates"] += 1
                raw = read_pipe_fds(parents.keys())
                stats["fd_queries"] += 1
                probe = parse_probe_stats(raw, parents.keys())
                if probe["probes_complete"] and probe["fd_readlink_success_count"] > 0:
                    stats["verified_fd_probe_polls"] += 1
                else:
                    stats["incomplete_fd_probe_polls"] += 1
                    errors.append({"t": round(now, 3),
                                   "kind": ("fd_probe_no_access" if probe["probes_complete"]
                                            else "fd_probe_incomplete")})
                stats["total_fd_dir_exists"] += probe["fd_dir_exists_count"]
                stats["total_fd_dir_readable"] += probe["fd_dir_readable_count"]
                stats["total_fd_dir_searchable"] += probe["fd_dir_searchable_count"]
                stats["total_fd_glob_matches"] += probe["fd_glob_match_count"]
                if probe["fd_glob_match_count"] == 0:
                    stats["fd_probes_without_glob_matches"] += 1
                if probe["fd_readlink_success_count"] == 0:
                    stats["fd_probes_without_readlink_success"] += 1
                stats["total_fd_symlinks_seen"] += probe["fd_symlink_count"]
                stats["total_fd_readlinks_succeeded"] += probe["fd_readlink_success_count"]
                stats["total_pipe_symlinks_seen"] += probe["pipe_target_count"]
                row_count = sum(1 for line in raw.splitlines()
                                if PIPE_ROW.fullmatch(line.strip()))
                stats["total_pipe_fd_rows"] += row_count
                stats["max_pipe_fd_rows_in_one_poll"] = max(
                    stats["max_pipe_fd_rows_in_one_poll"], row_count)
                if row_count:
                    stats["fd_queries_with_pipe_rows"] += 1
                links = shared_links(raw, parents, tags, identities)
            else:
                links = []
            if links != previously:
                events.append({"t": round(time.monotonic() - started, 3),
                               "candidate_process_count": count,
                               "shared_links": links})
                previously = links
        except (RuntimeError, subprocess.TimeoutExpired, ValueError):
            errors.append({"t": round(time.monotonic() - started, 3),
                           "kind": "process_or_fd_unavailable"})
        time.sleep(interval)
    return {
        "package": package,
        "seconds": seconds, "poll_interval_seconds": interval,
        "launched_by_script": launch, "polls": polls,
        "statistics": stats,
        "events": events, "errors": errors,
        "notes": [
            "Capture selects exact package PIDs plus any peers sharing their confirmed numeric UID.",
            "An equal UID is an identity candidate, not proof a process belongs to SecNeo.",
            "The statistics count scans even when shared_links did not change.",
            "Each scanned PID emits STAT status, but only successful FD readlink proves enumeration.",
            "An FD query returning zero accessible links is flagged as a failed coverage probe.",
            "A zero pipe row result is inconclusive if FD symlink enumeration/readlink failed.",
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
