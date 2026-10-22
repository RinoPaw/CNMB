#!/usr/bin/env python3
"""Count ARM64 SVC instruction candidates in executable ELF LOAD segments.

Read-only original CNMB 12.5.5 APK. Counts static encoded instruction words,
not executed syscalls. Protected data and runtime-generated code are excluded.
"""
import argparse
from collections import Counter
import io
import struct
import zipfile
from pathlib import Path
from inspect_native_loader import read_apk

LIBS = ('libDexHelper.so', 'libdexjni.so', 'libdexvmp.so', 'libdatajar.so')
EXPECTED = {'libDexHelper.so': 0, 'libdexjni.so': 0,
            'libdexvmp.so': 34, 'libdatajar.so': 9}
SVC_MASK = 0xffe0001f
SVC_BASE = 0xd4000001


def svc_file_offsets(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('ARM64 little-endian ELF64 required')
    if struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('wrong ELF machine')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    entsize, entries = struct.unpack_from('<HH', data, 54)
    assert entsize == 56
    result = []
    for idx in range(entries):
        ph = phoff + entsize * idx
        kind, flags, offset, addr, _, size, memsz, alignment = (
            struct.unpack_from('<IIQQQQQQ', data, ph))
        if kind != 1 or not flags & 1:
            continue
        if offset + size > len(data):
            raise ValueError('executable segment escapes file')
        for cursor in range(offset, offset + size - 3, 4):
            insn = struct.unpack_from('<I', data, cursor)[0]
            if insn & SVC_MASK == SVC_BASE:
                result.append(cursor)
    return result


def check(apk):
    with zipfile.ZipFile(io.BytesIO(apk)) as z:
        observed = {}
        for name in LIBS:
            source = z.read('lib/arm64-v8a/' + name)
            offsets = svc_file_offsets(source)
            observed[name] = len(offsets)
            print(f'{name}: executable PT_LOAD SVC candidates={len(offsets)}; '
                  f'file offsets={[hex(x) for x in offsets]}')
        assert observed == EXPECTED, (observed, EXPECTED)
        print('NOTE: no claim about syscall numbers or code execution.')
        print('Masked/reconstructed memory code and libc wrappers not scanned.')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=Path, help='pinned original APK / diagnostic ZIP')
    args = ap.parse_args()
    check(read_apk(args.source))  # fixed APK SHA-256 enforced


if __name__ == '__main__':
    main()
