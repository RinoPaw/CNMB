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
PS_LINE = re.compile(r'^\s*(\d+)\s+(\S+)\s*$')
MAP_LINE = re.compile(r'^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+\S+\s+\S+\s+\d+\s*(.*)$')
SAFE_PACKAGE = re.compile(r'^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+$')


def run_adb(*arguments, timeout=6):
    result = subprocess.run(['adb',*arguments],capture_output=True,
                            timeout=timeout, check=False)
    if result.returncode:
        err = result.stderr.decode('utf-8','replace').strip()
        raise RuntimeError(f'adb command failed ({result.returncode}): {err[:180]}')
    return result.stdout.decode('utf-8','replace')


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
    errors=[]
    while (elapsed:=time.monotonic()-start)<duration:
        try:
            pids=process_ids(run_adb('shell','ps','-A','-o','PID,NAME'),package)
        except (RuntimeError,subprocess.TimeoutExpired) as error:
            errors.append({'elapsed_seconds':round(elapsed,2),'kind':type(error).__name__})
            time.sleep(interval)
            continue
        for pid in pids:
            try:
                summary=summarize_maps(read_pid_maps(pid))
            except (RuntimeError,subprocess.TimeoutExpired):
                errors.append({'elapsed_seconds':round(elapsed,2),
                               'kind':'maps-unavailable','pid':pid})
                continue
            if last.get(pid)!=summary:
                history.append({'elapsed_seconds':round(time.monotonic()-start,2),
                                'pid':pid,**summary})
                last[pid]=summary
        time.sleep(interval)
    return {'package':package,'duration_seconds':duration,'poll_seconds':interval,
            'launched_by_script':launch,'events':history,'errors':errors,
            'note':'ADB map observations only; absence from a snapshot does not prove never loaded'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',default=PACKAGE)
    p.add_argument('--seconds',type=float,default=18.0)
    p.add_argument('--poll-seconds',type=float,default=0.5)
    p.add_argument('--launch',action='store_true',help='force-stop then launch via adb monkey')
    p.add_argument('--output',type=Path,help='save sanitized JSON locally')
    args=p.parse_args()
    if not SAFE_PACKAGE.fullmatch(args.package):
        p.error('Invalid package name')
    if args.seconds<=0 or not 0.1<=args.poll_seconds<=10:
        p.error('Invalid duration / polling interval')
    result=observe(args.package,args.seconds,args.poll_seconds,args.launch)
    encoded=json.dumps(result,ensure_ascii=False,indent=2)
    if args.output:
        args.output.write_text(encoded+'\n',encoding='utf-8')
    print(encoded)


if __name__=='__main__':
    main()
