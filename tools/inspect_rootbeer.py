#!/usr/bin/env python3
"""Verify RootBeer bytecode in a second recoverable Dex fragment of CNMB 12.5.5.

Read-only, fixed-offset and SHA-256 pinned. Distinguishes bundled root-check
code from evidence that the application's DEC entry actually calls it.
"""
import argparse
import struct
from pathlib import Path

from inspect_dec_tables import load, uleb

BASE = 0x381200c
STRING_IDS = 0x383200c
TYPE_IDS = 0x3861614
PROTO_IDS = 0x386b59c
FIELD_IDS = 0x3890a84
METHOD_IDS = 0x38f1354
CLASS_DEFS = 0x396f59c
FIRST_VISIBLE_ID = (STRING_IDS - (BASE + 0x70)) // 4
STRING_COUNT = FIRST_VISIBLE_ID + (TYPE_IDS - STRING_IDS) // 4
TYPE_COUNT = (PROTO_IDS - TYPE_IDS) // 4
METHOD_COUNT = (CLASS_DEFS - METHOD_IDS) // 8
ROOT_TYPE = 7235
ROOT_ID_FIRST = 47936
ROOT_ID_LAST = 47956


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def recover_strings(data):
    """Restore string_data offsets hidden by the first 128 KiB index mask."""
    first_visible_ptr = BASE + u32(data, STRING_IDS)
    assert first_visible_ptr == 0x3babf6a
    result = [0] * FIRST_VISIBLE_ID
    pos = first_visible_ptr
    for i in range(FIRST_VISIBLE_ID-1, -1, -1):
        assert data[pos-1] == 0, (i, pos)
        pos = data.rfind(b'\0', 0, pos-1) + 1
        assert pos > 0
        result[i] = pos
    assert result[0] == 0x39a79bd
    assert result[21946] == 0x3b0921e
    result.extend(BASE+u32(data, STRING_IDS+4*i)
                  for i in range((TYPE_IDS-STRING_IDS)//4))
    assert len(result) == STRING_COUNT == 81254
    assert all(a < b for a, b in zip(result, result[1:]))
    return result


def string(data, pointers, idx):
    _, at = uleb(data, pointers[idx])
    end = data.index(b'\0', at)
    return data[at:end].decode('utf-8', 'replace')


def class_methods(data, ptr):
    at = BASE+ptr
    counts = []
    for _ in range(4):
        n, at = uleb(data, at)
        counts.append(n)
    assert sum(counts) < 100000
    for _ in range(counts[0]+counts[1]):
        _, at = uleb(data, at)
        _, at = uleb(data, at)
    for amount in counts[2:]:
        idx = 0
        for _ in range(amount):
            delta, at = uleb(data, at)
            _, at = uleb(data, at)
            code, at = uleb(data, at)
            idx += delta
            assert idx < METHOD_COUNT
            yield idx, BASE+code if code else None


def code_item(data, off):
    size = u32(data, off+12)
    assert 0 < size < 1000000 and off+16+2*size < len(data)
    return data[off+16:off+16+2*size]


def invocations(code, target):
    needle = struct.pack('<H', target)
    return [i for i in range(0,len(code)-5,2)
            if code[i] in (*range(0x6e,0x73),*range(0x74,0x79))
            and code[i+2:i+4] == needle]


def string_literals(data, pointers, code):
    return [string(data, pointers, u32(code, i+2))
            for i in range(0,len(code)-5,2)
            if code[i] == 0x1b and u32(code,i+2) < STRING_COUNT]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    a = p.parse_args()
    data = load(a.source)
    pointers = recover_strings(data)
    type_ids = [u32(data,TYPE_IDS+4*i) for i in range(TYPE_COUNT)]
    assert all(0 <= sid < STRING_COUNT for sid in type_ids)
    assert type_ids[ROOT_TYPE] == 21946
    assert string(data, pointers, 21946) == 'Lcom/mc10086/lib/tools/root/RootBeer;'
    methods = {}
    class_count = 0
    encoded = 0
    root_class_off = None
    for i in range(TYPE_COUNT):
        off = CLASS_DEFS+32*i
        cl, flags, parent, interfaces, source, annotations, cdata, statics = (
            struct.unpack_from('<8I',data,off))
        if not(cl<TYPE_COUNT and (parent<TYPE_COUNT or parent==0xffffffff)
               and (source<STRING_COUNT or source==0xffffffff)):
            break
        class_count += 1
        if cl == ROOT_TYPE:
            assert root_class_off is None
            root_class_off = off
        if cdata:
            for method, code in class_methods(data, cdata):
                encoded += 1
                if code:
                    assert method not in methods
                    methods[method] = (code,cl)
    assert (class_count,encoded,len(methods)) == (7201,51514,50652)
    assert root_class_off == 0x399735c
    ids = [i for i in range(METHOD_COUNT)
           if struct.unpack_from('<H',data,METHOD_IDS+8*i)[0] == ROOT_TYPE]
    assert ids == list(range(ROOT_ID_FIRST,ROOT_ID_LAST+1))
    print('RootBeer Dex: 81,254 string IDs including 32,740 recovered hidden offsets')
    print('classes:',class_count,'encoded methods:',encoded,'code items:',len(methods))
    print('RootBeer type=7235 class_def=0x399735c; 21 method references')

    native_loader=code_item(data,methods[47938][0])
    assert native_loader == bytes.fromhex('12 10 0f 00')
    print('canLoadNativeLibrary(): constant true (const/4 v0, 1; return v0)')

    expected_literals = {
        47941: {'getprop','ro.debuggable','ro.secure','1','0'},
        47943: {'mount','rw'},
        47945: {'su'},
        47946: {'which','su'},
        47953: {'test-keys'},
        47955: {'su'},
    }
    for mid, expected in expected_literals.items():
        observed = set(string_literals(data,pointers,code_item(data,methods[mid][0])))
        assert expected.issubset(observed), (mid,expected,observed)
        print('RootBeer method',mid,'verified literals:',sorted(expected))

    expected_chain = (47951,47947,47939,47941,47943,47953,47946,47944)
    root_code=code_item(data,methods[47955][0])
    order = sorted([(offset,mid) for mid in expected_chain
                    for offset in invocations(root_code,mid)])
    assert tuple(mid for _,mid in order) == expected_chain
    print('isRooted() calls:', list(expected_chain))

    direct_calls=[]
    for mid,(off,cl) in methods.items():
        code=code_item(data,off)
        for callee in ids:
            for idx in invocations(code,callee):
                direct_calls.append((mid,cl,callee,off+16+idx))
    external=[c for c in direct_calls if c[1]!=ROOT_TYPE]
    assert not external,external
    assert len(direct_calls)==27, len(direct_calls)
    assert not [c for c in direct_calls if c[2] in (47955,47956)]
    print('RootBeer references: 27 candidate direct calls, all within RootBeer itself')
    print('isRooted/isRootedWithoutBusyBoxCheck callers: 0 in this Dex fragment')
    print('LIMIT: no evidence yet that DEC invokes this RootBeer class')


if __name__ == '__main__':
    main()
