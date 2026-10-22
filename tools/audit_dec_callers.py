#!/usr/bin/env python3
"""Read-only complete callsite audit for the pinned China Mobile 12.5.5 Dex fragment.

The caller-search pattern is a conservative 16-bit-aligned *candidate* scan.
Its sole hit is additionally proven at a known Dalvik instruction boundary.
This does not decrypt the protected DeviceEnvironmentCheck implementation.
"""
import argparse
import struct
from pathlib import Path

from inspect_dec_tables import (
    BASE, CLASSES, METHOD_COUNT, STRING_COUNT, TYPE_COUNT, load, u32, uleb, validate
)

START_CHECK = 62496
DECAPP_INIT = 62487
DECAPP_HELPER = 62488
CALLBACK = {62479: (62494,), 62480: (62493, 62492),
            62482: (62495,), 62485: (62491, 62495)}


def class_methods(data, class_data_off):
    """Decode standard class_data_item, yielding method_id and code file offset."""
    at = BASE + class_data_off
    counts = []
    for _ in range(4):
        n, at = uleb(data, at)
        counts.append(n)
    if sum(counts) > 100_000:
        raise ValueError("implausible class_data item")
    for _ in range(counts[0] + counts[1]):
        _, at = uleb(data, at)  # field_idx_diff
        _, at = uleb(data, at)  # access_flags
    for method_count in counts[2:]:
        current = 0
        for _ in range(method_count):
            delta, at = uleb(data, at)
            _, at = uleb(data, at)  # access_flags
            code, at = uleb(data, at)
            current += delta
            if current >= METHOD_COUNT:
                raise ValueError("invalid method index")
            yield current, BASE + code if code else None


def decoded_code(data, offset):
    size = u32(data, offset + 12)  # code_item.insns_size
    if not 0 < size < 1_000_000 or offset + 16 + 2*size > len(data):
        raise ValueError(f"invalid code_item at {offset:#x}")
    return data[offset+16:offset+16+2*size]


def candidates(code, target, only_static=True):
    # Only a search for candidates. Does not claim to be a whole-Dex disassembler.
    needle = struct.pack('<H', target)
    return [(i,code[i]) for i in range(0,len(code)-5,2)
            if code[i] in ((0x71,0x77) if only_static
                           else (*range(0x6e,0x73),*range(0x74,0x79)))
            and code[i+2:i+4] == needle]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    args = p.parse_args()
    data = load(args.source)  # validates exact APK / SO hash
    validate(data)  # validates all surviving index tables

    method_bodies = {}
    valid_classes = 0
    encoded_methods = 0
    for i in range(TYPE_COUNT):
        pos = CLASSES+32*i
        cls, flags, parent, interfaces, source, annotations, class_data, static = (
            struct.unpack_from('<8I', data, pos))
        # Guard end of class_defs; sorting of class_idx is NOT required here.
        if not(cls < TYPE_COUNT and
               (parent < TYPE_COUNT or parent == 0xffffffff) and
               (source < STRING_COUNT or source == 0xffffffff)):
            break
        valid_classes += 1
        if class_data:
            for mid, offset in class_methods(data, class_data):
                encoded_methods += 1
                if offset:
                    if mid in method_bodies:
                        raise ValueError(f'duplicate class method {mid}')
                    method_bodies[mid] = offset

    hits = []
    for mid, pos in method_bodies.items():
        code = decoded_code(data, pos)
        for i, opcode in candidates(code, START_CHECK):
            hits.append((mid, pos+16+i, opcode))

    assert valid_classes == 16526, valid_classes
    assert encoded_methods == 57366, encoded_methods
    assert len(method_bodies) == 55713, len(method_bodies)
    assert hits == [(DECAPP_INIT, 0x1c20672, 0x71)], hits
    print(f'Validated class_defs: {valid_classes:,}')
    print(f'Encoded methods: {encoded_methods:,}; with code: {len(method_bodies):,}')
    print(f'startCheck candidate calls: {len(hits)}; {hits}')

    init = decoded_code(data, method_bodies[DECAPP_INIT])
    assert init[0:6] == bytes.fromhex('71 10 18 f4 03 00')
    assert init[84:90] == bytes.fromhex('39 00 03 00 0e 00')
    assert init[106:112] == bytes.fromhex('71 00 20 f4 00 00')
    print('DECApp.init: isMainProcess call, if-nez/return gate, startCheck call verified')

    maincheck = decoded_code(data, method_bodies[DECAPP_HELPER])
    expected = {1073: 'Process.myPid', 62603: 'File.<init>',
                62608: 'File.exists', 62623: 'FileReader.<init>',
                62596: 'BufferedReader.<init>', 62598: 'BufferedReader.readLine',
                62798: 'String.trim', 34: 'Application.getPackageName',
                62780: 'String.equals'}
    for method_id, name in expected.items():
        assert candidates(maincheck, method_id, only_static=False), (method_id, name)
    print('isMainProcess: readLine, trim, getPackageName, equals and PID refs verified')

    for caller, targets in CALLBACK.items():
        code = decoded_code(data, method_bodies[caller])
        for target in targets:
            assert candidates(code, target, only_static=False), (caller, target)
    print('DECApp$1: creation/save, destruction/remove, resumed/foreground, stopped/clear refs verified')
    # No definition is present for type 17421 in the 16,526 parsed class_defs.
    checker_defs = [i for i in range(valid_classes)
                    if u32(data, CLASSES+32*i) == 17421]
    assert checker_defs == [], checker_defs
    print('DeviceEnvironmentCheck.startCheck: referenced, definition absent in this fragment')


if __name__ == '__main__':
    main()
