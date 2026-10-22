#!/usr/bin/env python3
"""Time-stamped, non-invasive Android process-lifetime / Frida attach test.

Run with the matching Frida 17.5.2 Python environment. This script does not
change SELinux, root settings, app files, or any detection return values.
"""
import argparse
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import frida

PACKAGE = 'com.greenpoint.android.mc10086.activity'


def adb(*args, timeout=3):
    try:
        return subprocess.run(['adb', *args], capture_output=True, text=True,
                              errors='replace', timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None


def ps_snapshot():
    """Get exact app-main PIDs without su -c quoting or process-name guessing."""
    p = adb('shell', 'ps', '-A', '-o', 'PID,NAME')
    if p is None or p.returncode != 0:
        return None
    seen = set()
    for line in p.stdout.splitlines():
        m = re.match(r'^\s*(\d+)\s+(\S+)\s*$', line)
        if m and m.group(2) == PACKAGE:
            seen.add(int(m.group(1)))
    return seen


class Watcher:
    """An independent sampling thread active during blocking device.attach()."""
    def __init__(self):
        self.t0 = time.monotonic()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.observed = set()
        self.current = set()
        self.started = {}
        self.exited = {}
        self.count = 0
        self.failed = 0
        self.last_good_at = None
        self.worker = threading.Thread(target=self.run, daemon=True)

    def now(self):
        return time.monotonic() - self.t0

    def log(self, message):
        print(f'[+{self.now():6.2f}s] {message}', flush=True)

    def start(self):
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        self.worker.join(timeout=4)

    def run(self):
        next_heartbeat = time.monotonic() + 5
        while not self.stop_event.is_set():
            snapshot = ps_snapshot()
            elapsed = self.now()
            if snapshot is None:
                with self.lock:
                    self.failed += 1
            else:
                with self.lock:
                    newly_started = sorted(snapshot - self.current)
                    newly_exited = sorted(self.current - snapshot)
                    for pid in newly_started:
                        self.started[pid] = elapsed
                    for pid in newly_exited:
                        self.exited[pid] = elapsed
                    self.observed.update(snapshot)
                    self.current = snapshot
                    self.count += 1
                    self.last_good_at = elapsed
                for pid in newly_started:
                    self.log(f'MAIN_STARTED pid={pid}')
                for pid in newly_exited:
                    self.log(f'MAIN_DISAPPEARED pid={pid}')
            if time.monotonic() >= next_heartbeat:
                with self.lock:
                    current = sorted(self.current)
                    samples = self.count
                    failed = self.failed
                self.log(f'WATCH_HEARTBEAT current={current} samples={samples} ps_errors={failed}')
                next_heartbeat += 5
            self.stop_event.wait(0.12)

    def first_pid(self):
        with self.lock:
            return min(self.started, key=self.started.get) if self.started else None

    def describe(self, pid):
        with self.lock:
            alive = pid in self.current
            birth = self.started.get(pid)
            death = self.exited.get(pid)
            checks = self.count
            errors = self.failed
        state = 'ALIVE_AT_LAST_SAMPLE' if alive else ('DISAPPEARED' if death is not None else 'NOT_SEEN')
        return (f'{state}, first_seen=+{birth:.2f}s' if birth is not None else state) + \
               (f', disappeared=+{death:.2f}s' if death is not None else '') + \
               f', ps_samples={checks}, ps_errors={errors}'


def main():
    parser = argparse.ArgumentParser(description='Observe China Mobile main process while Frida attaches')
    parser.add_argument('--monitor-only', action='store_true',
                        help='Only measure launch and process lifetime; do not connect Frida or attach')
    parser.add_argument('--observe-seconds', type=float, default=20,
                        help='How long to monitor in --monitor-only mode (default: 20s)')
    parser.add_argument('--trace', action='store_true', help='Load CNMB-DEC-Trace.js after attach')
    parser.add_argument('--script', type=Path, help='Load a specified Frida JavaScript file')
    args = parser.parse_args()
    script_file = args.script or (Path('CNMB-DEC-Trace.js') if args.trace else None)
    if args.monitor_only and script_file:
        parser.error('--monitor-only cannot be combined with --trace or --script')
    if script_file and not script_file.is_file():
        parser.error(f'JS file not found: {script_file}')

    print('Frida / ADB main-process lifetime test (v2)', flush=True)
    device = None
    if args.monitor_only:
        print('[1/4] ADB-only control: Frida will not connect or attach.', flush=True)
    else:
        print('[1/4] Connecting to Frida before launching target...', flush=True)
        try:
            device = frida.get_usb_device(timeout=10)
            print(f'Device: {device.name}', flush=True)
        except Exception as exc:
            print(f'FRIDA_CONNECTION_FAILED: {type(exc).__name__}: {exc}', flush=True)
            return 2

    stopped = adb('shell', 'am', 'force-stop', PACKAGE, timeout=8)
    if stopped is None or stopped.returncode != 0:
        print('ADB_FORCE_STOP_FAILED', flush=True)
        return 3
    # Ensure no old main-process PID remains from a previous run.
    for attempt in range(16):
        current = ps_snapshot()
        if current == set():
            break
        time.sleep(0.15)
    else:
        print('ADB_BASELINE_FAILED: main PID still present after force-stop, '
              'or adb ps repeatedly failed.', flush=True)
        return 3
    watcher = Watcher()
    watcher.log('[2/4] Launching via adb monkey...')
    try:
        launcher = subprocess.Popen(['adb', 'shell', 'monkey', '-p', PACKAGE, '1'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        print(f'ADB_LAUNCH_FAILED: {exc}', flush=True)
        return 3
    watcher.start()

    session = None
    script = None
    try:
        deadline = time.monotonic() + 12
        pid = None
        while time.monotonic() < deadline:
            pid = watcher.first_pid()
            if pid is not None:
                break
            if launcher.poll() not in (None, 0):
                watcher.log(f'WARNING: monkey exited with code {launcher.returncode}')
                break
            time.sleep(0.06)
        if pid is None:
            watcher.log('MAIN_NOT_DETECTED within observation window')
            return 4

        if args.monitor_only:
            watcher.log(f'[3/4] BASELINE_MONITORING for {args.observe_seconds:g}s; no Frida injection')
            until = watcher.t0 + max(1, args.observe_seconds)
            while time.monotonic() < until:
                time.sleep(0.2)
            watcher.log(f'[4/4] BASELINE_DONE: {watcher.describe(pid)}')
            return 0

        watcher.log(f'[3/4] ATTACH_BEGIN pid={pid} (no JS loaded yet)')
        attach_start = time.monotonic()
        try:
            session = device.attach(pid)
        except Exception as exc:
            watcher.log(f'ATTACH_FAILED after {time.monotonic()-attach_start:.2f}s: '
                        f'{type(exc).__name__}: {exc}')
            watcher.log(f'PID_{pid}_TIMELINE: {watcher.describe(pid)}')
            watcher.log('NOTE: A disappeared PID does not by itself explain why it exited.')
            return 5

        watcher.log(f'[4/4] ATTACHED pid={pid} after {time.monotonic()-attach_start:.2f}s')
        detached_event = threading.Event()

        def on_detached(reason, crash=None):
            watcher.log(f'SESSION_DETACHED reason={reason} crash={crash}')
            detached_event.set()
        session.on('detached', on_detached)

        if script_file:
            watcher.log(f'Loading JS: {script_file}')
            try:
                source = script_file.read_text(encoding='utf-8-sig')
                script = session.create_script(source)
                def on_message(msg, data):
                    if msg.get('type') == 'send':
                        print(f'[JS] {msg.get("payload")}', flush=True)
                    else:
                        print(f'[JS] {msg}', flush=True)
                script.on('message', on_message)
                script.load()
                watcher.log('SCRIPT_LOADED')
            except Exception as exc:
                watcher.log(f'SCRIPT_LOAD_FAILED: {type(exc).__name__}: {exc}')
                return 6
        else:
            watcher.log('No JavaScript loaded: baseline instrumentation only')
        watcher.log('Observing session; Ctrl+C to stop')
        while not detached_event.wait(0.3):
            pass
        return 0
    except KeyboardInterrupt:
        watcher.log('Stopped by Ctrl+C')
        return 130
    finally:
        watcher.stop()
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        state = adb('shell', 'ps', '-A', '-o', 'PID,NAME')
        if state and state.returncode == 0:
            servers = [x.strip() for x in state.stdout.splitlines() if 'frida' in x.lower()]
            print('FRIDA_PROCESSES_AT_END: ' + str(servers[:12]), flush=True)
        else:
            print('FRIDA_PROCESSES_AT_END: UNKNOWN (adb ps failed)', flush=True)
        print('Tip: Review crash buffer separately: adb logcat -d -b crash -v threadtime', flush=True)


if __name__ == '__main__':
    sys.exit(main())