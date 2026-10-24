#!/usr/bin/env python3
"""Audit original SecNeo H guard's initialization, pointer alias and follow-up.

Pinned CNMB 12.5.5 original APK/diagnostic ZIP; no original binary or
unrelated configuration fields are emitted. Static analysis only.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, recover, bl_target
from audit_inner_app_process_argv import elf_file_offset

WORDS = {
    0x14a54:0xd00008b6, 0x14a58:0x911102d6,  # x22 = BSS 0x12a440
    0x14afc:0x900000a2, 0x14b08:0x91056c21,
    0x14b0c:0x911c3042, 0x14b28:0x9401c2dd,  # XOR reader callback
    0x14d80:0x9105f2c1, 0x14d88:0x9401c249,  # x22+0x17c, uint32
    0x151d0:0xd000086b, 0x151d4:0xf946e16b,
    0x151e8:0xf9000176,  # publish x22 through slot at 0x128000
    0x28758:0x4f05e580, 0x2878c:0x5280158a, 0x28798:0x4a0a016b,
    0x85748:0xb9000268, 0x85ce4:0x39000268,
    0x5ae44:0xb0000648, 0x5ae48:0xf946e108,
    0x5ae4c:0xf9400108, 0x5ae50:0x3945f108,
    0x5ae54:0x37000628,
    0x5af34:0x97ff2c8e, 0x5af38:0x340001a0,
    0x5af44:0x97ff2e3a, 0x5af4c:0x54000101,
    0x5af64:0x52800021, 0x5af68:0x97ff2f16,
    0x26930:0x97ffa3cc, 0x269b0:0x97ffa208,
    0x3af44:0xb000078c, 0x3af48:0x3905f189,
}
HELPERS = {0x85c9c:"bool", 0x856ac:"integer",
           0x85ec4:"binary_length", 0x85f54:"binary_payload"}
STREAM = 0x12415b
STATE = 0x12a440
GUARD = STATE + 0x17c


def word(elf, va):
    return struct.unpack_from("<I", elf, elf_file_offset(elf, va))[0]


def adrp_page(insn, pc):
    if insn & 0x9f000000 != 0x90000000:
        raise ValueError("expected AArch64 ADRP")
    imm = (((insn >> 5) & 0x7ffff) << 2) | ((insn >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xfff) + (imm << 12)


def relocation_target(elf, address):
    shoff = struct.unpack_from("<Q", elf, 40)[0]
    stride, count = struct.unpack_from("<HH", elf, 58)
    if stride != 64 or count > 200 or shoff + stride * count > len(elf):
        raise ValueError("invalid original section header table")
    found = []
    for idx in range(count):
        section = struct.unpack_from("<IIQQQQIIQQ", elf, shoff + idx*stride)
        if section[1] != 4:  # SHT_RELA
            continue
        start, size, width = section[4], section[5], section[9]
        if width != 24 or size % width or start + size > len(elf):
            raise ValueError("invalid original RELA section")
        for off in range(start, start+size, width):
            where, info, addend = struct.unpack_from("<QQq", elf, off)
            if where == address:
                if info & 0xffffffff != 1027:  # R_AARCH64_RELATIVE
                    raise ValueError("unexpected relocation type")
                found.append(addend)
    if len(found) != 1:
        raise ValueError("expected exactly one original GOT relocation")
    return found[0]


def msgpack_value(data, offset, kind):
    """Parse only the scalar types actually verified in the original stream."""
    if offset >= len(data):
        raise ValueError("truncated MessagePack scalar")
    tag = data[offset]
    if kind == "bool":
        if tag not in (0xc2,0xc3):
            raise ValueError("expected MessagePack boolean")
        return tag == 0xc3, offset+1
    if kind == "binary_length":
        if tag == 0xc4 and offset+2 <= len(data):
            return data[offset+1], offset+2
        if tag == 0xc5 and offset+3 <= len(data):
            return int.from_bytes(data[offset+1:offset+3], "big"), offset+3
        raise ValueError("unexpected binary header")
    if kind != "integer":
        raise ValueError("unexpected MessagePack kind")
    if tag < 0x80:
        return tag, offset+1
    if tag >= 0xe0:
        return tag-256, offset+1
    widths = {0xcc:(1,False),0xcd:(2,False),0xce:(4,False),
              0xd0:(1,True),0xd1:(2,True),0xd2:(4,True)}
    if tag not in widths:
        raise ValueError("unexpected original integer tag")
    width, signed = widths[tag]
    if offset + 1 + width > len(data):
        raise ValueError("truncated MessagePack integer")
    return (int.from_bytes(data[offset+1:offset+1+width],
                           "big", signed=signed), offset+1+width)


def decoder_calls(elf):
    records = []
    for pc in range(0x14b2c,0x14da4,4):
        insn = word(elf,pc)
        if insn >> 26 != 0b100101:
            continue
        target = bl_target(elf,pc)
        if target in HELPERS:
            records.append((pc,HELPERS[target]))
    if (len(records) != 48 or records[0] != (0x14b34,"bool")
            or records[45] != (0x14d88,"integer")
            or records[-1] != (0x14da0,"binary_length")
            or [pc for pc,kind in records if kind == "binary_length"]
            != [0x14bc8,0x14c00,0x14da0]
            or [pc for pc,kind in records if kind == "binary_payload"]
            != [0x14be8,0x14c20]):
        raise ValueError("original decoder call sequence changed")
    return records


def initial_guard(elf):
    start = elf_file_offset(elf, STREAM)
    encoded = elf[start:start+512]
    if len(encoded) != 512:
        raise ValueError("truncated original XOR stream")
    data = bytes(c ^ 0xac for c in encoded)
    offset = 0
    pending = None
    selected = None
    for pc,kind in decoder_calls(elf):
        if kind == "binary_payload":
            if pending is None or pending > 256 or offset+pending > len(data):
                raise ValueError("missing valid raw-byte length")
            offset += pending
            pending = None
            continue
        old = offset
        value,offset = msgpack_value(data,offset,kind)
        if kind == "binary_length":
            pending = value
        if pc == 0x14d88:
            selected = (old,value)
    if selected != (92,13) or pending != 0:
        raise ValueError("original guard field/stream alignment changed")
    return {"decoder_call":"0x14d88", "stream_offset":selected[0],
            "initial_value":selected[1], "bit_zero":selected[1]&1,
            "integer_storage_bytes":4}


def audit(elf):
    if hashlib.sha256(elf).hexdigest() != SAMPLES["libDexHelper.so"]["inner_sha"]:
        raise ValueError("original inner ELF SHA-256 mismatch")
    for at,expected in WORDS.items():
        if word(elf,at) != expected:
            raise ValueError("original instruction changed at "+hex(at))
    if (relocation_target(elf,0x123dc0) != 0x128000
            or adrp_page(word(elf,0x14a54),0x14a54) != 0x12a000
            or adrp_page(word(elf,0x151d0),0x151d0) != 0x123000
            or adrp_page(word(elf,0x3af44),0x3af44) != 0x12b000):
        raise ValueError("original global pointer or relocation changed")
    for pc,target in ((0x14b28,0x8569c),(0x14d88,0x856ac),
                      (0x5af34,0x2616c),(0x5af44,0x2682c),
                      (0x5af68,0x26bc0),(0x26930,0xf860),
                      (0x269b0,0xf1d0)):
        if bl_target(elf,pc) != target:
            raise ValueError("original branch call changed at "+hex(pc))
    guard = initial_guard(elf)
    return {
        "inner_elf_sha256":SAMPLES["libDexHelper.so"]["inner_sha"],
        "init_stream":{"va":"0x12415b","reader":"0x2870c",
                       "encoding":"XOR 0xac","verified_decoder_calls":48},
        "state_pointer":{"initial_object":"0x12a440",
                         "store":"0x151e8 -> [0x128000]",
                         "rela":"0x123dc0 -> 0x128000",
                         "read":"0x5ae44..0x5ae50: dereference slot and +0x17c",
                         "field_va":hex(GUARD)},
        "guard":guard,
        "at_initial_state_for_positive_result":"0x5af18 (bit 0 set)",
        "other_static_store":{"instruction":"0x3af48","va":"0x12b17c",
                              "same_field":False},
        "follow_up":{"0x5af34":"call 0x2616c; zero -> cleanup",
                     "0x5af44":"call 0x2682c; nonzero -> cleanup",
                     "0x5af68":"call 0x26bc0 with argument w1=1",
                     "0x2682c_io":"0x26930 fopen; 0x269b0 fgets"},
        "limits":"Initial value only; runtime mutations, device execution and DEC association unproven."
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source",type=Path)
    args=p.parse_args()
    data=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if "apks/01-base.apk" in z.namelist():
            data=z.read("apks/01-base.apk")
    if hashlib.sha256(data).hexdigest()!=APK_SHA:
        raise ValueError("original APK SHA mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        elf,_=recover(z.read("lib/arm64-v8a/libDexHelper.so"),
                      SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(elf),ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
