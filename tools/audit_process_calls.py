#!/usr/bin/env python3
"""Audit process-operation Dalvik invoke candidates in 14 pinned CNMB 12.5.5 fragments.

16-bit aligned opcode hits are CANDIDATES; this is not a full disassembler.
Reflection, encrypted code and all native behavior remain outside scope.
"""
import argparse
from collections import Counter
import struct
from pathlib import Path
from carve_all_dex import STRING_TABLES, EXPECTED_CLASSES, carve, dex_string
from inspect_dec_tables import load, uleb

TARGETS = {
    ('Ljava/lang/Runtime;', 'exec'): 'Runtime.exec',
    ('Ljava/lang/Runtime;', 'exit'): 'Runtime.exit',
    ('Ljava/lang/ProcessBuilder;', 'start'): 'ProcessBuilder.start',
    ('Landroid/os/Process;', 'killProcess'): 'Process.killProcess',
}
EXPECTED = {'Runtime.exec': 61, 'Runtime.exit': 2,
            'ProcessBuilder.start': 12, 'Process.killProcess': 32}
INVOKES = frozenset((*range(0x6e, 0x73), *range(0x74, 0x79)))


def encoded_methods(data, base, class_data):
    pos = base + class_data
    counts = []
    for _ in range(4):
        n, pos = uleb(data, pos)
        counts.append(n)
    if sum(counts) > 100000:
        raise ValueError('unreasonable class method/field count')
    for _ in range(counts[0] + counts[1]):
        _, pos = uleb(data, pos)
        _, pos = uleb(data, pos)
    for amount in counts[2:]:
        mid = 0
        for _ in range(amount):
            diff, pos = uleb(data, pos)
            _, pos = uleb(data, pos)
            code, pos = uleb(data, pos)
            mid += diff
            yield mid, (base + code) if code else None


def call_candidates(code, targets):
    for i in range(0, len(code)-5, 2):
        if code[i] in INVOKES:
            mid = struct.unpack_from('<H', code, i+2)[0]
            if mid in targets:
                yield i, targets[mid]


def check(data):
    totals = Counter()
    target_owners = {owner for owner, method in TARGETS}
    for visible, expected_classes in zip(STRING_TABLES, EXPECTED_CLASSES):
        fragment = carve(data, visible, expected_classes)
        types, pointers = fragment['types'], fragment['pointers']
        table, total_methods, base = (
            fragment['method_offset'], fragment['methods'], fragment['base'])
        type_names = [dex_string(data, pointers[sid]) for sid in types]
        targets = {}
        for mid in range(total_methods):
            cls, proto, sid = struct.unpack_from('<HHI', data, table + 8*mid)
            if type_names[cls] in target_owners:
                key = (type_names[cls], dex_string(data, pointers[sid]))
                if key in TARGETS:
                    targets[mid] = TARGETS[key]
        counts = Counter()
        code_items = 0
        root_calls = 0
        for i in range(fragment['classes']):
            offset = table + 8 * total_methods + 32 * i
            cls, flags, parent, interfaces, src, anno, class_data, static = (
                struct.unpack_from('<8I', data, offset))
            if not class_data:
                continue
            for method_id, codepos in encoded_methods(data, base, class_data):
                if not codepos:
                    continue
                if method_id >= total_methods:
                    raise ValueError(f'invalid method at {offset:#x}')
                size = struct.unpack_from('<I', data, codepos+12)[0]
                if not 0 < size < 1_000_000 or codepos+16+size*2 > len(data):
                    raise ValueError(f'invalid code_item {codepos:#x}')
                body = data[codepos+16:codepos+16+size*2]
                code_items += 1
                for _, name in call_candidates(body, targets):
                    counts[name] += 1
                if visible == 0x84fe00c:
                    root_calls += sum(
                        1 for _ in call_candidates(body, {9038: 'OTS.checkRoot'}))
        if visible == 0x84fe00c:
            assert root_calls == 0, root_calls
        print(f'{visible:#x}: classes={fragment["classes"]:,} '
              f'code_items={code_items:,} candidate_calls={dict(counts)}')
        totals.update(counts)
    assert dict(totals) == EXPECTED, (dict(totals), EXPECTED)
    print('TOTAL process-op invoke CANDIDATES:', dict(totals))
    print('OTS DeviceInfoUtil.checkRoot: no direct caller candidate in its fragment.')
    print('DECApp fragment 0x2500c: no Runtime.exec / ProcessBuilder.start ref.')
    print('LIMIT: no native syscalls, reflection, hidden code or runtime-loaded DEX.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    check(load(args.source))


if __name__ == '__main__':
    main()
