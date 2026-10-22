#!/usr/bin/env python3
"""ADB-only runtime module census; no Frida, no hooks, no memory dumps.

A rooted device is needed to read another application's /proc/PID/maps.
Only sanitized module BASENAMES, counts and relative seconds are recorded.
Only use --launch when you intend to restart the target app.
"""
import argparse
import json
import re
import subprocess
import time
from pathlib import Path

PACKAGE = 'com.greenpoint.android.mc10086.activity'
PS_LINE = re.compile(r'^\s*(\d+)\s+(\S+)\s*
MAP_LINE = re.compile(r'^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+\S+\s+\S+\s+\d+\s*(.*)$')
SAFE_PACKAGE = re.compile(r'^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+$')
WATCH_LIBS = ('libDexHelper.so', 'libdatajar.so', 'libdexjni.so',
              'libdexvmp.so')


def run_adb(*arguments, timeout=6):
    result = subprocess.run(['adb',*arguments],capture_output=True,
                            timeout=timeout, check=False)
    if result.returncode:
        err = result.stderr.decode('utf-8','replace').strip()
        raise RuntimeError(f'adb command failed ({result.returncode}): {err[:180]}')
    return result.stdout.decode('utf-8','replace')


def parse_adb_devices(output):
    """Return [(serial, state)] from `adb devices -l` output."""
    devices = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] in {
            'device', 'unauthorized', 'offline', 'recovery',
            'sideload', 'bootloader', 'no',
        }:
            devices.append((fields[0], fields[1]))
    return devices


def require_ready_device():
    """Fail before changing app state if ADB lacks exactly one ready device."""
    try:
        devices = parse_adb_devices(run_adb('devices', '-l', timeout=10))
    except FileNotFoundError as exc:
        raise RuntimeError('找不到 adb 命令，请先安装 Android platform-tools 并配置 PATH。') from exc
    ready = [serial for serial, state in devices if state == 'device']
    if len(devices) == 1 and len(ready) == 1:
        return ready[0]
    if not devices:
        raise RuntimeError(
            'ADB 未发现手机。先运行 adb devices -l，确认 USB/无线 ADB 已连接；'
            'USB 调试已启用，必要时执行 adb kill-server、adb start-server。'
        )
    if any(state == 'unauthorized' for _, state in devices):
        raise RuntimeError(
            'ADB 设备未授权。请解锁手机并确认「允许 USB 调试」弹窗，'
            '然后运行 adb devices -l。'
        )
    if any(state == 'offline' for _, state in devices):
        raise RuntimeError(
            'ADB 设备 offline。请等待手机完成启动，重新连接，再运行 adb devices -l。'
        )
    raise RuntimeError(
        'ADB 当前设备状态不符合要求或连接了多台设备：'
        + ', '.join(f'{serial}={state}' for serial, state in devices)
        + '。本脚本要求恰好一台处于 device 状态的设备。'
    )


def process_ids(ps_output, package):
    return sorted({int(m[1]) for line in ps_output.splitlines()
                   if (m:=PS_LINE.match(line)) and m[2]==package})


def process_parentage(ps_output, package):
    """Map target PIDs to observed PPIDs; names must match exactly."""
    return {int(m[1]): int(m[2]) for line in ps_output.splitlines()
            if (m := PS_PPID_LINE.match(line)) and m[3] == package}


def summarize_maps(raw):
    mapped=set()
    anon_exec_count=0
    anon_rwx_count=0
    anon_rwx_bytes=0
    memfd_count=0
    for line in raw.splitlines():
        m=MAP_LINE.match(line)
        if not m:continue
        start,end=int(m[1],16),int(m[2],16)
        perms=m[3]
        path=m[4].strip()
        if path.startswith('/memfd:') or path.startswith('/dev/ashmem'):
            memfd_count+=1
        if not path and 'x' in perms:
            anon_exec_count+=1
            if perms.startswith('rwx'):
                anon_rwx_count+=1
                anon_rwx_bytes+=end-start
        if path.startswith('/'):
            basename=path.rsplit('/',1)[-1].split(' (deleted)')[0]
            if basename.endswith(('.so','.dex','.odex','.vdex')) or basename=='base.apk':
                mapped.add(basename)
    return {'native_and_dex_files':sorted(mapped),
            'anonymous_executable_regions':anon_exec_count,
            'anonymous_rwx_regions':anon_rwx_count,
            'anonymous_rwx_bytes':anon_rwx_bytes,
            'memfd_or_ashmem_entries':memfd_count}


def read_pid_maps(pid):
    return run_adb('shell','su','-c',f'cat /proc/{pid}/maps',timeout=5)


def observe(package, duration, interval, launch=False, parentage=False):
    if launch:
        run_adb('shell','am','force-stop',package,timeout=8)
        run_adb('shell','monkey','-p',package,'1',timeout=10)
    start=time.monotonic()
    history=[]
    last={}
    maps_empty_seen=set()
    errors=[]
    while (elapsed:=time.monotonic()-start)<duration:
        try:
            columns='PID,PPID,NAME' if parentage else 'PID,NAME'
            snapshot=run_adb('shell','ps','-A','-o',columns)
            parents=process_parentage(snapshot,package) if parentage else {}
            pids=sorted(parents) if parentage else process_ids(snapshot,package)
        except (RuntimeError,subprocess.TimeoutExpired) as error:
            errors.append({'elapsed_seconds':round(elapsed,2),'kind':type(error).__name__})
            time.sleep(interval)
            continue
        for old_pid in list(last):
            if old_pid not in pids:
                history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                'pid':old_pid,'state':'not_in_ps'})
                del last[old_pid]
                maps_empty_seen.discard(old_pid)
        for pid in pids:
            try:
                raw=read_pid_maps(pid)
                if not raw.strip():
                    if pid not in maps_empty_seen:
                        errors.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                       'kind':'maps-empty','pid':pid})
                        maps_empty_seen.add(pid)
                    continue
                maps_empty_seen.discard(pid)
                summary=summarize_maps(raw)
                if parentage:
                    summary['ppid']=parents[pid]
            except (RuntimeError,subprocess.TimeoutExpired):
                errors.append({'elapsed_seconds':round(elapsed,2),
                               'kind':'maps-unavailable','pid':pid})
                continue
            if last.get(pid)!=summary:
                history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                'pid':pid,**summary})
                last[pid]=summary
        time.sleep(interval)
    for pid in sorted(last):
        history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                        'pid':pid,'state':'present_at_end'})
    return {'package':package,'duration_seconds':duration,'poll_seconds':interval,
            'launched_by_script':launch,'includes_parentage':parentage,
            'events':history,'errors':errors,
            'note':('ADB map snapshots only. Empty maps are treated as unreadable. '
                    'Absence of a module from snapshots does not prove never loaded.')}


def concise_report(result):
    """Avoid printing hundreds of system libraries; keep full events in --output."""
    rows=[]
    for event in result['events']:
        state=event.get('state')
        if state:
            rows.append({'t':event['elapsed_seconds'],'pid':event['pid'],
                         'state':state})
            continue
        files=event.get('native_and_dex_files',[])
        if (not files and event.get('anonymous_executable_regions') == 0
                and event.get('anonymous_rwx_regions') == 0
                and event.get('memfd_or_ashmem_entries') == 0):
            # Legacy captures may include a zero-byte /proc/PID/maps read.
            # A normal Android process has many mappings; classify as invalid.
            rows.append({'t':event['elapsed_seconds'],'pid':event['pid'],
                         'state':'invalid_empty_maps_legacy_capture'})
            continue
        interesting=[name for name in files
                     if name in WATCH_LIBS or 'ZWRisk' in name]
        row={'t':event['elapsed_seconds'],'pid':event['pid'],
             'mapped_research_libraries':interesting,
             'anonymous_rwx_regions':event.get('anonymous_rwx_regions'),
             'anonymous_rwx_bytes':event.get('anonymous_rwx_bytes'),
             'memfd_or_ashmem_entries':event.get('memfd_or_ashmem_entries')}
        if 'ppid' in event:
            row['ppid']=event['ppid']
        rows.append(row)
    return {'package':result['package'],'duration_seconds':result['duration_seconds'],
            'events':rows,'errors':result['errors'],
            'note':result['note']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',default=PACKAGE)
    p.add_argument('--seconds',type=float,default=18.0)
    p.add_argument('--poll-seconds',type=float,default=0.5)
    p.add_argument('--launch',action='store_true',help='force-stop then launch via adb monkey')
    p.add_argument('--parentage',action='store_true',
                   help='also sample PPID from adb ps -A -o PID,PPID,NAME')
    p.add_argument('--output',type=Path,help='save detailed sanitized JSON locally')
    p.add_argument('--from-json',type=Path,
                   help='summarize an existing capture, without ADB or relaunch')
    p.add_argument('--full-stdout',action='store_true',
                   help='print detailed JSON instead of a compact summary')
    args=p.parse_args()
    if args.from_json:
        if args.output:
            p.error('--output cannot be combined with --from-json')
        stored=json.loads(args.from_json.read_text(encoding='utf-8'))
        print(json.dumps(stored if args.full_stdout else concise_report(stored),
                         ensure_ascii=False,indent=2))
        return
    if not SAFE_PACKAGE.fullmatch(args.package):
        p.error('Invalid package name')
    if args.seconds<=0 or not 0.1<=args.poll_seconds<=10:
        p.error('Invalid duration / polling interval')
    try:
        serial = require_ready_device()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        p.exit(2, f"ADB 预检查失败：{error}\n")
    print(f"ADB connected: {serial}", flush=True)
    result=observe(args.package,args.seconds,args.poll_seconds,
                   args.launch,args.parentage)
    encoded=json.dumps(result,ensure_ascii=False,indent=2)
    if args.output:
        args.output.write_text(encoded+'\n',encoding='utf-8')
    print(encoded if args.full_stdout else
          json.dumps(concise_report(result),ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
)
PS_PPID_LINE = re.compile(r'^\s*(\d+)\s+(\d+)\s+(\S+)\s*
MAP_LINE = re.compile(r'^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+\S+\s+\S+\s+\d+\s*(.*)$')
SAFE_PACKAGE = re.compile(r'^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+$')
WATCH_LIBS = ('libDexHelper.so', 'libdatajar.so', 'libdexjni.so',
              'libdexvmp.so')


def run_adb(*arguments, timeout=6):
    result = subprocess.run(['adb',*arguments],capture_output=True,
                            timeout=timeout, check=False)
    if result.returncode:
        err = result.stderr.decode('utf-8','replace').strip()
        raise RuntimeError(f'adb command failed ({result.returncode}): {err[:180]}')
    return result.stdout.decode('utf-8','replace')


def parse_adb_devices(output):
    """Return [(serial, state)] from `adb devices -l` output."""
    devices = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] in {
            'device', 'unauthorized', 'offline', 'recovery',
            'sideload', 'bootloader', 'no',
        }:
            devices.append((fields[0], fields[1]))
    return devices


def require_ready_device():
    """Fail before changing app state if ADB lacks exactly one ready device."""
    try:
        devices = parse_adb_devices(run_adb('devices', '-l', timeout=10))
    except FileNotFoundError as exc:
        raise RuntimeError('找不到 adb 命令，请先安装 Android platform-tools 并配置 PATH。') from exc
    ready = [serial for serial, state in devices if state == 'device']
    if len(devices) == 1 and len(ready) == 1:
        return ready[0]
    if not devices:
        raise RuntimeError(
            'ADB 未发现手机。先运行 adb devices -l，确认 USB/无线 ADB 已连接；'
            'USB 调试已启用，必要时执行 adb kill-server、adb start-server。'
        )
    if any(state == 'unauthorized' for _, state in devices):
        raise RuntimeError(
            'ADB 设备未授权。请解锁手机并确认「允许 USB 调试」弹窗，'
            '然后运行 adb devices -l。'
        )
    if any(state == 'offline' for _, state in devices):
        raise RuntimeError(
            'ADB 设备 offline。请等待手机完成启动，重新连接，再运行 adb devices -l。'
        )
    raise RuntimeError(
        'ADB 当前设备状态不符合要求或连接了多台设备：'
        + ', '.join(f'{serial}={state}' for serial, state in devices)
        + '。本脚本要求恰好一台处于 device 状态的设备。'
    )


def process_ids(ps_output, package):
    return sorted({int(m[1]) for line in ps_output.splitlines()
                   if (m:=PS_LINE.match(line)) and m[2]==package})


def summarize_maps(raw):
    mapped=set()
    anon_exec_count=0
    anon_rwx_count=0
    anon_rwx_bytes=0
    memfd_count=0
    for line in raw.splitlines():
        m=MAP_LINE.match(line)
        if not m:continue
        start,end=int(m[1],16),int(m[2],16)
        perms=m[3]
        path=m[4].strip()
        if path.startswith('/memfd:') or path.startswith('/dev/ashmem'):
            memfd_count+=1
        if not path and 'x' in perms:
            anon_exec_count+=1
            if perms.startswith('rwx'):
                anon_rwx_count+=1
                anon_rwx_bytes+=end-start
        if path.startswith('/'):
            basename=path.rsplit('/',1)[-1].split(' (deleted)')[0]
            if basename.endswith(('.so','.dex','.odex','.vdex')) or basename=='base.apk':
                mapped.add(basename)
    return {'native_and_dex_files':sorted(mapped),
            'anonymous_executable_regions':anon_exec_count,
            'anonymous_rwx_regions':anon_rwx_count,
            'anonymous_rwx_bytes':anon_rwx_bytes,
            'memfd_or_ashmem_entries':memfd_count}


def read_pid_maps(pid):
    return run_adb('shell','su','-c',f'cat /proc/{pid}/maps',timeout=5)


def observe(package, duration, interval, launch=False):
    if launch:
        run_adb('shell','am','force-stop',package,timeout=8)
        run_adb('shell','monkey','-p',package,'1',timeout=10)
    start=time.monotonic()
    history=[]
    last={}
    maps_empty_seen=set()
    errors=[]
    while (elapsed:=time.monotonic()-start)<duration:
        try:
            pids=process_ids(run_adb('shell','ps','-A','-o','PID,NAME'),package)
        except (RuntimeError,subprocess.TimeoutExpired) as error:
            errors.append({'elapsed_seconds':round(elapsed,2),'kind':type(error).__name__})
            time.sleep(interval)
            continue
        for old_pid in list(last):
            if old_pid not in pids:
                history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                'pid':old_pid,'state':'not_in_ps'})
                del last[old_pid]
                maps_empty_seen.discard(old_pid)
        for pid in pids:
            try:
                raw=read_pid_maps(pid)
                if not raw.strip():
                    if pid not in maps_empty_seen:
                        errors.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                       'kind':'maps-empty','pid':pid})
                        maps_empty_seen.add(pid)
                    continue
                maps_empty_seen.discard(pid)
                summary=summarize_maps(raw)
            except (RuntimeError,subprocess.TimeoutExpired):
                errors.append({'elapsed_seconds':round(elapsed,2),
                               'kind':'maps-unavailable','pid':pid})
                continue
            if last.get(pid)!=summary:
                history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                'pid':pid,**summary})
                last[pid]=summary
        time.sleep(interval)
    for pid in sorted(last):
        history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                        'pid':pid,'state':'present_at_end'})
    return {'package':package,'duration_seconds':duration,'poll_seconds':interval,
            'launched_by_script':launch,'events':history,'errors':errors,
            'note':('ADB map snapshots only. Empty maps are treated as unreadable. '
                    'Absence of a module from snapshots does not prove never loaded.')}


def concise_report(result):
    """Avoid printing hundreds of system libraries; keep full events in --output."""
    rows=[]
    for event in result['events']:
        state=event.get('state')
        if state:
            rows.append({'t':event['elapsed_seconds'],'pid':event['pid'],
                         'state':state})
            continue
        files=event.get('native_and_dex_files',[])
        if (not files and event.get('anonymous_executable_regions') == 0
                and event.get('anonymous_rwx_regions') == 0
                and event.get('memfd_or_ashmem_entries') == 0):
            # Legacy captures may include a zero-byte /proc/PID/maps read.
            # A normal Android process has many mappings; classify as invalid.
            rows.append({'t':event['elapsed_seconds'],'pid':event['pid'],
                         'state':'invalid_empty_maps_legacy_capture'})
            continue
        interesting=[name for name in files
                     if name in WATCH_LIBS or 'ZWRisk' in name]
        rows.append({'t':event['elapsed_seconds'],'pid':event['pid'],
                     'mapped_research_libraries':interesting,
                     'anonymous_rwx_regions':event.get('anonymous_rwx_regions'),
                     'anonymous_rwx_bytes':event.get('anonymous_rwx_bytes'),
                     'memfd_or_ashmem_entries':event.get('memfd_or_ashmem_entries')})
    return {'package':result['package'],'duration_seconds':result['duration_seconds'],
            'events':rows,'errors':result['errors'],
            'note':result['note']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',default=PACKAGE)
    p.add_argument('--seconds',type=float,default=18.0)
    p.add_argument('--poll-seconds',type=float,default=0.5)
    p.add_argument('--launch',action='store_true',help='force-stop then launch via adb monkey')
    p.add_argument('--output',type=Path,help='save detailed sanitized JSON locally')
    p.add_argument('--from-json',type=Path,
                   help='summarize an existing capture, without ADB or relaunch')
    p.add_argument('--full-stdout',action='store_true',
                   help='print detailed JSON instead of a compact summary')
    args=p.parse_args()
    if args.from_json:
        if args.output:
            p.error('--output cannot be combined with --from-json')
        stored=json.loads(args.from_json.read_text(encoding='utf-8'))
        print(json.dumps(stored if args.full_stdout else concise_report(stored),
                         ensure_ascii=False,indent=2))
        return
    if not SAFE_PACKAGE.fullmatch(args.package):
        p.error('Invalid package name')
    if args.seconds<=0 or not 0.1<=args.poll_seconds<=10:
        p.error('Invalid duration / polling interval')
    try:
        serial = require_ready_device()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        p.exit(2, f"ADB 预检查失败：{error}\n")
    print(f"ADB connected: {serial}", flush=True)
    result=observe(args.package,args.seconds,args.poll_seconds,args.launch)
    encoded=json.dumps(result,ensure_ascii=False,indent=2)
    if args.output:
        args.output.write_text(encoded+'\n',encoding='utf-8')
    print(encoded if args.full_stdout else
          json.dumps(concise_report(result),ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
)
MAP_LINE = re.compile(r'^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+\S+\s+\S+\s+\d+\s*(.*)$')
SAFE_PACKAGE = re.compile(r'^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+$')
WATCH_LIBS = ('libDexHelper.so', 'libdatajar.so', 'libdexjni.so',
              'libdexvmp.so')


def run_adb(*arguments, timeout=6):
    result = subprocess.run(['adb',*arguments],capture_output=True,
                            timeout=timeout, check=False)
    if result.returncode:
        err = result.stderr.decode('utf-8','replace').strip()
        raise RuntimeError(f'adb command failed ({result.returncode}): {err[:180]}')
    return result.stdout.decode('utf-8','replace')


def parse_adb_devices(output):
    """Return [(serial, state)] from `adb devices -l` output."""
    devices = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] in {
            'device', 'unauthorized', 'offline', 'recovery',
            'sideload', 'bootloader', 'no',
        }:
            devices.append((fields[0], fields[1]))
    return devices


def require_ready_device():
    """Fail before changing app state if ADB lacks exactly one ready device."""
    try:
        devices = parse_adb_devices(run_adb('devices', '-l', timeout=10))
    except FileNotFoundError as exc:
        raise RuntimeError('找不到 adb 命令，请先安装 Android platform-tools 并配置 PATH。') from exc
    ready = [serial for serial, state in devices if state == 'device']
    if len(devices) == 1 and len(ready) == 1:
        return ready[0]
    if not devices:
        raise RuntimeError(
            'ADB 未发现手机。先运行 adb devices -l，确认 USB/无线 ADB 已连接；'
            'USB 调试已启用，必要时执行 adb kill-server、adb start-server。'
        )
    if any(state == 'unauthorized' for _, state in devices):
        raise RuntimeError(
            'ADB 设备未授权。请解锁手机并确认「允许 USB 调试」弹窗，'
            '然后运行 adb devices -l。'
        )
    if any(state == 'offline' for _, state in devices):
        raise RuntimeError(
            'ADB 设备 offline。请等待手机完成启动，重新连接，再运行 adb devices -l。'
        )
    raise RuntimeError(
        'ADB 当前设备状态不符合要求或连接了多台设备：'
        + ', '.join(f'{serial}={state}' for serial, state in devices)
        + '。本脚本要求恰好一台处于 device 状态的设备。'
    )


def process_ids(ps_output, package):
    return sorted({int(m[1]) for line in ps_output.splitlines()
                   if (m:=PS_LINE.match(line)) and m[2]==package})


def summarize_maps(raw):
    mapped=set()
    anon_exec_count=0
    anon_rwx_count=0
    anon_rwx_bytes=0
    memfd_count=0
    for line in raw.splitlines():
        m=MAP_LINE.match(line)
        if not m:continue
        start,end=int(m[1],16),int(m[2],16)
        perms=m[3]
        path=m[4].strip()
        if path.startswith('/memfd:') or path.startswith('/dev/ashmem'):
            memfd_count+=1
        if not path and 'x' in perms:
            anon_exec_count+=1
            if perms.startswith('rwx'):
                anon_rwx_count+=1
                anon_rwx_bytes+=end-start
        if path.startswith('/'):
            basename=path.rsplit('/',1)[-1].split(' (deleted)')[0]
            if basename.endswith(('.so','.dex','.odex','.vdex')) or basename=='base.apk':
                mapped.add(basename)
    return {'native_and_dex_files':sorted(mapped),
            'anonymous_executable_regions':anon_exec_count,
            'anonymous_rwx_regions':anon_rwx_count,
            'anonymous_rwx_bytes':anon_rwx_bytes,
            'memfd_or_ashmem_entries':memfd_count}


def read_pid_maps(pid):
    return run_adb('shell','su','-c',f'cat /proc/{pid}/maps',timeout=5)


def observe(package, duration, interval, launch=False):
    if launch:
        run_adb('shell','am','force-stop',package,timeout=8)
        run_adb('shell','monkey','-p',package,'1',timeout=10)
    start=time.monotonic()
    history=[]
    last={}
    maps_empty_seen=set()
    errors=[]
    while (elapsed:=time.monotonic()-start)<duration:
        try:
            pids=process_ids(run_adb('shell','ps','-A','-o','PID,NAME'),package)
        except (RuntimeError,subprocess.TimeoutExpired) as error:
            errors.append({'elapsed_seconds':round(elapsed,2),'kind':type(error).__name__})
            time.sleep(interval)
            continue
        for old_pid in list(last):
            if old_pid not in pids:
                history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                'pid':old_pid,'state':'not_in_ps'})
                del last[old_pid]
                maps_empty_seen.discard(old_pid)
        for pid in pids:
            try:
                raw=read_pid_maps(pid)
                if not raw.strip():
                    if pid not in maps_empty_seen:
                        errors.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                       'kind':'maps-empty','pid':pid})
                        maps_empty_seen.add(pid)
                    continue
                maps_empty_seen.discard(pid)
                summary=summarize_maps(raw)
            except (RuntimeError,subprocess.TimeoutExpired):
                errors.append({'elapsed_seconds':round(elapsed,2),
                               'kind':'maps-unavailable','pid':pid})
                continue
            if last.get(pid)!=summary:
                history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                'pid':pid,**summary})
                last[pid]=summary
        time.sleep(interval)
    for pid in sorted(last):
        history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                        'pid':pid,'state':'present_at_end'})
    return {'package':package,'duration_seconds':duration,'poll_seconds':interval,
            'launched_by_script':launch,'events':history,'errors':errors,
            'note':('ADB map snapshots only. Empty maps are treated as unreadable. '
                    'Absence of a module from snapshots does not prove never loaded.')}


def concise_report(result):
    """Avoid printing hundreds of system libraries; keep full events in --output."""
    rows=[]
    for event in result['events']:
        state=event.get('state')
        if state:
            rows.append({'t':event['elapsed_seconds'],'pid':event['pid'],
                         'state':state})
            continue
        files=event.get('native_and_dex_files',[])
        if (not files and event.get('anonymous_executable_regions') == 0
                and event.get('anonymous_rwx_regions') == 0
                and event.get('memfd_or_ashmem_entries') == 0):
            # Legacy captures may include a zero-byte /proc/PID/maps read.
            # A normal Android process has many mappings; classify as invalid.
            rows.append({'t':event['elapsed_seconds'],'pid':event['pid'],
                         'state':'invalid_empty_maps_legacy_capture'})
            continue
        interesting=[name for name in files
                     if name in WATCH_LIBS or 'ZWRisk' in name]
        rows.append({'t':event['elapsed_seconds'],'pid':event['pid'],
                     'mapped_research_libraries':interesting,
                     'anonymous_rwx_regions':event.get('anonymous_rwx_regions'),
                     'anonymous_rwx_bytes':event.get('anonymous_rwx_bytes'),
                     'memfd_or_ashmem_entries':event.get('memfd_or_ashmem_entries')})
    return {'package':result['package'],'duration_seconds':result['duration_seconds'],
            'events':rows,'errors':result['errors'],
            'note':result['note']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',default=PACKAGE)
    p.add_argument('--seconds',type=float,default=18.0)
    p.add_argument('--poll-seconds',type=float,default=0.5)
    p.add_argument('--launch',action='store_true',help='force-stop then launch via adb monkey')
    p.add_argument('--output',type=Path,help='save detailed sanitized JSON locally')
    p.add_argument('--from-json',type=Path,
                   help='summarize an existing capture, without ADB or relaunch')
    p.add_argument('--full-stdout',action='store_true',
                   help='print detailed JSON instead of a compact summary')
    args=p.parse_args()
    if args.from_json:
        if args.output:
            p.error('--output cannot be combined with --from-json')
        stored=json.loads(args.from_json.read_text(encoding='utf-8'))
        print(json.dumps(stored if args.full_stdout else concise_report(stored),
                         ensure_ascii=False,indent=2))
        return
    if not SAFE_PACKAGE.fullmatch(args.package):
        p.error('Invalid package name')
    if args.seconds<=0 or not 0.1<=args.poll_seconds<=10:
        p.error('Invalid duration / polling interval')
    try:
        serial = require_ready_device()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        p.exit(2, f"ADB 预检查失败：{error}\n")
    print(f"ADB connected: {serial}", flush=True)
    result=observe(args.package,args.seconds,args.poll_seconds,args.launch)
    encoded=json.dumps(result,ensure_ascii=False,indent=2)
    if args.output:
        args.output.write_text(encoded+'\n',encoding='utf-8')
    print(encoded if args.full_stdout else
          json.dumps(concise_report(result),ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
