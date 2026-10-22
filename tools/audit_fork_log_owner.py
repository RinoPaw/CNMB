#!/usr/bin/env python3
"""Prove ownership of two 'forked' strings in pinned CNMB 12.5.5.

Read-only. Both observations resolve to the Alipay CrashBridge method.
They do not establish who created Android worker processes observed via ADB.
"""
import argparse
import struct
from pathlib import Path

from carve_all_dex import carve, dex_string, u32
from inspect_dec_tables import load, uleb

VISIBLE = 0x729300c
EXPECTED_CLASSES = 7793
OWNER_TYPE = 6800
OWNER = 'Lcom/alipay/mobile/common/logging/CrashBridge;'
METHOD_ID = 46925
METHOD = 'isForkedCrashOnlyForTracing'
CODE = 0x79e8f88
REFERENCES = (
    (37635, 0x79e8fda, '[DEBUG] Current process is forked from'),
    (49851, 0x79e9022, 'forked from pid:'),
)


def decoded_methods(data, base, classdata):
    at = base + classdata
    counts = []
    for _ in range(4):
        count, at = uleb(data, at)
        counts.append(count)
    assert sum(counts) < 100000
    for _ in range(counts[0] + counts[1]):
        _, at = uleb(data, at)
        _, at = uleb(data, at)
    for count in counts[2:]:
        method = 0
        for _ in range(count):
            delta, at = uleb(data, at)
            _, at = uleb(data, at)
            code, at = uleb(data, at)
            method += delta
            yield method, base + code if code else None


def check(data):
    fragment = carve(data, VISIBLE, EXPECTED_CLASSES)
    base = fragment['base']
    pointers = fragment['pointers']
    descriptor_sid = fragment['types'][OWNER_TYPE]
    assert descriptor_sid == 23278
    assert dex_string(data, pointers[descriptor_sid]) == OWNER

    method_table = fragment['method_offset']
    owner, proto, name_sid = struct.unpack_from(
        '<HHI', data, method_table + METHOD_ID * 8)
    assert owner == OWNER_TYPE
    assert dex_string(data, pointers[name_sid]) == METHOD

    defs = []
    class_table = method_table + fragment['methods'] * 8
    for i in range(fragment['classes']):
        pos = class_table + i * 32
        if u32(data, pos) == OWNER_TYPE:
            defs.append((pos, u32(data, pos + 24)))
    assert len(defs) == 1
    class_pos, classdata = defs[0]
    assert class_pos == 0x73edab8
    methods = dict(decoded_methods(data, base, classdata))
    assert methods[METHOD_ID] == CODE
    code_units = u32(data, CODE + 12)
    instructions_begin = CODE + 16
    instructions_end = instructions_begin + code_units * 2
    assert code_units == 152

    for sid, position, phrase in REFERENCES:
        assert dex_string(data, pointers[sid]) == phrase
        assert instructions_begin <= position < instructions_end - 6
        assert (position - instructions_begin) % 2 == 0
        assert data[position] == 0x1b  # const-string/jumbo
        assert u32(data, position + 2) == sid
        print(f'string_id {sid}, const-string/jumbo @ {position:#x}: {phrase}')
    print('Class:', OWNER, f'class_def @ {class_pos:#x}')
    print('Method:', METHOD, f'ID {METHOD_ID}, code_item @ {CODE:#x}')
    print('CONCLUSION: strings belong to Alipay CrashBridge code.')
    print('LIMIT: this alone does not attribute the observed forked processes.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    check(load(args.source))  # pinned original APK/SO SHA-256


if __name__ == '__main__':
    main()
