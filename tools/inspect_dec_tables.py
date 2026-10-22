#!/usr/bin/env python3
"""Reproduce byte-level Dex-table and DEC-call observations for CNMB 12.5.5.

Read-only. Inputs: original base.apk, diagnostic ZIP, or extracted libdatajar.so.
The reported offsets are libdatajar.so file offsets. Only the pinned APK/SO
hashes are accepted, since this is a sample-specific partial parser.
"""
import argparse
import hashlib
import io
import struct
import zipfile
from pathlib import Path

APK_HASH = "6282d2cf05f76f37a60fff322bcf0d6f1d876829e5c9c4eae5cdd93b7a972a83"
SO_HASH = "8b0777aeeedb1d95041fb8b5a900735d607505f802255227a82c83225d8bbf81"
SO_NAME = "lib/arm64-v8a/libdatajar.so"
BASE = 0x500c
VISIBLE_STRINGS = 0x2500c
TYPES = 0x63d28
PROTOS = 0x75f20
FIELDS = 0x934a0
METHODS = 0xe9df0
CLASSES = 0x168990
TYPE_COUNT = 18558
PROTO_COUNT = 10016
FIELD_COUNT = 44330
METHOD_COUNT = 64884
FIRST_ID = (VISIBLE_STRINGS - (BASE + 0x70)) // 4
STRINGS_VISIBLE = (TYPES - VISIBLE_STRINGS) // 4
STRING_COUNT = FIRST_ID + STRINGS_VISIBLE


def load(path):
    raw = path.read_bytes()
    if raw.startswith(b"\x7fELF"):
        so = raw
    else:
        if not zipfile.is_zipfile(io.BytesIO(raw)):
            raise ValueError("Expected a .so, base APK, or diagnostic ZIP")
        with zipfile.ZipFile(io.BytesIO(raw)) as outer:
            if SO_NAME in outer.namelist():
                apk = raw
            else:
                apk = outer.read("apks/01-base.apk")
        if hashlib.sha256(apk).hexdigest() != APK_HASH:
            raise ValueError("APK SHA256 mismatch; refusing to apply fixed offsets")
        with zipfile.ZipFile(io.BytesIO(apk)) as archive:
            so = archive.read(SO_NAME)
    if hashlib.sha256(so).hexdigest() != SO_HASH:
        raise ValueError("SO SHA256 mismatch; this parser targets a specific binary")
    return so


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def uleb(data, offset):
    value = shift = 0
    for i in range(5):
        byte = data[offset+i]
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset+i+1
        shift += 7
    raise ValueError(f"Invalid ULEB128 at {offset:#x}")


def validate(data):
    strings = [u32(data, VISIBLE_STRINGS+4*i)+BASE
               for i in range(STRINGS_VISIBLE)]
    assert len(strings) == 64327
    for p, q in zip(strings, strings[1:]):
        assert 0 < p < q <= len(data), ("string offset", p, q)
        length, start = uleb(data, p)
        assert length < 1000000 and start < q
        assert data[q-1] == 0 and b"\x00" not in data[start:q-1]
    type_ids = [u32(data, TYPES+4*i) for i in range(TYPE_COUNT)]
    assert all(0 <= t < STRING_COUNT for t in type_ids)
    assert all(a < b for a, b in zip(type_ids, type_ids[1:]))
    for i in range(PROTO_COUNT):
        shorty, ret, params = struct.unpack_from("<III", data, PROTOS+12*i)
        assert shorty < STRING_COUNT and ret < TYPE_COUNT
        assert params == 0 or (params%4 == 0 and params+BASE < len(data))
    for start, count, limit in ((FIELDS, FIELD_COUNT, TYPE_COUNT),
                                (METHODS, METHOD_COUNT, PROTO_COUNT)):
        previous = -1
        for i in range(count):
            cls, typ, name = struct.unpack_from("<HHI", data, start+8*i)
            assert cls < TYPE_COUNT and typ < limit and name < STRING_COUNT
            assert cls >= previous
            previous = cls
    return strings, type_ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    data = load(args.source)
    strings, type_ids = validate(data)

    def text(i):
        if i < FIRST_ID:
            return f"<obscured string_id {i}>"
        if not FIRST_ID <= i < STRING_COUNT:
            raise ValueError(f"Invalid string_id {i}")
        _, off = uleb(data, strings[i-FIRST_ID])
        end = data.index(b"\x00", off)
        return data[off:end].decode("utf-8", "replace")

    def type_name(i):
        return text(type_ids[i])

    def method(i):
        c, proto, name = struct.unpack_from("<HHI", data, METHODS+8*i)
        return type_name(c), text(name), proto

    def type_index(descriptor):
        for i, sid in enumerate(type_ids):
            if sid >= FIRST_ID and text(sid) == descriptor:
                return i
        raise AssertionError("Missing descriptor: "+descriptor)

    def method_refs(type_id):
        return [i for i in range(METHOD_COUNT)
                if struct.unpack_from("<H", data, METHODS+8*i)[0] == type_id]

    def class_def(type_id):
        # SecNeo table is NOT strictly sorted by class_idx.
        for i in range(TYPE_COUNT):
            pos = CLASSES+32*i
            cl, flags, parent, interfaces, source, annotations, cdata, statics = (
                struct.unpack_from("<8I", data, pos))
            if not (cl < TYPE_COUNT and
                    (parent < TYPE_COUNT or parent == 0xffffffff) and
                    (source < STRING_COUNT or source == 0xffffffff)):
                break
            if cl == type_id:
                return pos, cdata
        return None

    def class_methods(cdata):
        off = BASE+cdata
        counts = []
        for _ in range(4):
            value, off = uleb(data, off)
            counts.append(value)
        assert sum(counts) < 10000
        for _ in range(counts[0]+counts[1]):
            _, off = uleb(data, off)
            _, off = uleb(data, off)
        methods = {}
        for count in counts[2:]:
            current = 0
            for _ in range(count):
                delta, off = uleb(data, off)
                flags, off = uleb(data, off)
                code, off = uleb(data, off)
                current += delta
                assert current < METHOD_COUNT
                methods[current] = code
        return methods

    def static_invokes(code, target):
        pos = BASE+code
        count = u32(data, pos+12)
        assert 0 < count < 100000
        insns = data[pos+16:pos+16+2*count]
        needle = struct.pack("<H", target)
        return [pos+16+i for i in range(0, len(insns)-5, 2)
                if insns[i] == 0x71 and insns[i+2:i+4] == needle]

    print("SO verified:", SO_HASH)
    print(f"Strings: {STRINGS_VISIBLE:,} visible; {FIRST_ID:,} inferred obscured; "
          f"{STRING_COUNT:,} inferred total")
    print(f"Types={TYPE_COUNT:,} Prototypes={PROTO_COUNT:,} "
          f"Fields={FIELD_COUNT:,} Methods={METHOD_COUNT:,}")
    dec = type_index("Lcom/a/b/c/DECApp;")
    checker = type_index("Lcom/a/b/c/DeviceEnvironmentCheck;")
    assert (dec, checker) == (17418, 17421)
    print("DECApp type_id", dec, "DeviceEnvironmentCheck type_id", checker)
    for cls in (dec, checker):
        print(type_name(cls), [(i, method(i)[1]) for i in method_refs(cls)])
        print("class_def", class_def(cls))
    definition = class_def(dec)
    assert definition is not None
    codes = class_methods(definition[1])
    for src, dst in ((62489, 62487), (62487, 62488), (62487, 62496)):
        hits = static_invokes(codes[src], dst)
        assert len(hits) == 1, ("invoke-static", src, dst, hits)
        print(f"{method(src)[1]} -> {type_name(checker) if dst==62496 else 'DECApp'}."
              f"{method(dst)[1]}: invoke-static @SO {hits[0]:#x}, method_id={dst}")
    # Confirm exact aligned Dalvik if-nez + return-void sequence.
    # It appears after the boolean-producing isMainProcessDECabc call.
    init_pos = BASE+codes[62487]
    insn_size = u32(data, init_pos+12)
    instrs = data[init_pos+16:init_pos+16+2*insn_size]
    gate = bytes.fromhex("39 00 03 00 0e 00")
    gate_positions = [i for i in range(0, len(instrs)-len(gate)+1, 2)
                      if instrs[i:i+len(gate)] == gate]
    assert gate_positions == [84], gate_positions
    print(f"DECApp main-process gate: if-nez v0, +3 / return-void"
          f" @SO {init_pos+16+gate_positions[0]:#x}")
    assert class_def(checker) is None
    print("No DeviceEnvironmentCheck class definition in this fragment; "
          "startCheck body and Root verdict remain unknown.")


if __name__ == "__main__":
    main()
