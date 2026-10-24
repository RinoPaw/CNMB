#!/usr/bin/env python3
"""Audit SecNeo H's pinned original 'root' -> envc.push record path.

Read-only. Recovers original inner DexHelper ELF in memory from original
12.5.5 APK or its diagnostic ZIP. Verifies ARM64 control flow, decoded ASCII
table and read/update file API calls. Never outputs private file contents or
original unpacked binaries.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, bl_target, recover
from audit_inner_app_process_argv import decode_table, elf_file_offset
from audit_inner_h_guard_config import relocation_target

ELF_SHA = SAMPLES["libDexHelper.so"]["inner_sha"]
# Addresses are VA within the pinned recovered ELF. PINNED includes input,
# branch, mode, formatting, file-write arguments and EOF/cleanup gates.
PINNED = {
    0x5af20: 0x52800020,  # mov w0,#1 (lookup selector)
    0x5af34: 0x97ff2c8e,  # call 0x2616c
    0x5af38: 0x340001a0,  # cbz -> do not update
    0x5af44: 0x97ff2e3a,  # call 0x2682c
    0x5af48: 0x72001c1f,  # tst w0,#255
    0x5af4c: 0x54000101,  # b.ne -> do not update
    0x5af50: 0x52903e29,  # mov w9,#0x81f1
    0x5af54: 0x52800148,  # mov w8,#0xa
    0x5af58: 0x72b6d449,  # movk w9,#0xb6a2,lsl16
    0x5af5c: 0x2a080122,  # orr w2,w9,w8
    0x5af60: 0x910343e0,  # x0 -> caller key buffer
    0x5af64: 0x52800021,  # mov w1,#1
    0x5af68: 0x97ff2f16,  # call 0x26bc0
    0x5b344: 0x370003e8,  # guard bit0 set -> 0x5b3c0
    0x5b3c8: 0x52800020,  # second root-key selector 1
    0x5b3dc: 0x97ff2b64,  # call 0x2616c
    0x5b3f0: 0x97ff2e0f,  # call 0x2682c
    0x5b3f4: 0x72001c1f,  # tst w0,#255
    0x5b3f8: 0x540000c1,  # b.ne skip second update
    0x5b3fc: 0x52903e22,  # mov w2,#0x81f1
    0x5b404: 0x52800021,  # mov w1,#1
    0x5b408: 0x72b6d442,  # movk w2,#0xb6a2,lsl16
    0x5b40c: 0x97ff2ae8,  # call 0x26bc0
    0x26188: 0xd00007e8,  # adrp x8,0x124000
    0x2618c: 0x9104d508,  # add x8,x8,#0x135 (ASCII+0x41)
    0x265cc: 0x51000408,  # selector-index = w0-1
    0x265d8: 0xd0000649,  # adrp x9,0xf0000
    0x265dc: 0x91026129,  # add x9,x9,#0x98 (branch table)
    0x265e0: 0x100000aa,  # adr x10,0x265f4
    0x265e4: 0x3868692b,  # ldrb jump-table index
    0x265ec: 0xd101b3a1,  # x1=x29-0x6c ('root')
    0x265f0: 0xd61f0140,  # br x10
    0x265f4: 0x9100a3e1,  # x1=sp+0x28 ('usb'), skipped for key 1
    0x265f8: 0x39400028,  # start of key length/copy logic
    0x26740: 0xaa1303e0,  # x0 = output buffer
    0x26744: 0xaa1403e2,  # x2 = key length
    0x26748: 0x97ffa42e,  # memcpy@plt
    0x26890: 0xd00007e8,  # reader ASCII origin
    0x26894: 0x91040908,  # ASCII+0xe
    0x26930: 0x97ffa3cc,  # fopen@plt
    0x269b0: 0x97ffa208,  # fgets@plt
    0x26c30: 0xd00007f6,  # writer ASCII origin
    0x26c34: 0x9103e6d6,  # ASCII+5
    0x26cc8: 0x97fff8c7,  # __snprintf_chk / formatter
    0x26d24: 0x97ffb077,  # vprintf wrapper (format '%s=%x%x')
    0x26d30: 0x97ffa0e4,  # access@plt
    0x26d44: 0x97ffa2c7,  # fopen@plt w+ if absent
    0x26d5c: 0x97ffa2c1,  # fopen@plt r+
    0x26d6c: 0x52800041,  # LOCK_EX 2
    0x26d70: 0x97ffa1ac,  # flock@plt
    0x26e04: 0x97ffa0f3,  # fgets@plt
    0x26e78: 0x940000cf,  # record parser
    0x26fe4: 0x91202442,  # fmt pointer %s%x%s
    0x270ec: 0x94000319,  # internal block transformation
    0x27130: 0x97ffa0b0,  # fseek@plt
    0x27138: 0x52800021,  # fwrite size=1
    0x27144: 0x97ffa1cf,  # fwrite@plt
}

ROOT_SITES = (0x26198, 0x261a8, 0x261b0, 0x261b8)
READER_FILE_SITES = (0x268b8, 0x268cc, 0x268e0, 0x268e8,
                     0x268f0, 0x268f8, 0x26900, 0x26908, 0x26910)
WRITER_FILE_SITES = (0x26c5c, 0x26c70, 0x26c84, 0x26c90,
                     0x26c98, 0x26ca0, 0x26ca8, 0x26cb0, 0x26cb8)
WRITER_FORMAT_SITES = (0x26ccc, 0x26ce0, 0x26cf4, 0x26d00,
                       0x26d08, 0x26d10, 0x26d18)


def insn(elf, va):
    return struct.unpack_from("<I", elf, elf_file_offset(elf, va))[0]


def decode_loads(elf, ascii_table, sites, base_index, base_reg, expected):
    """Decode only LDRB Wt,[Xn,#imm] verified to read original ASCII table.

    The actual text is reconstructed from the *original machine immediates*,
    not accepted merely because an expected string exists elsewhere.
    """
    decoded = bytearray()
    for site in sites:
        word = insn(elf, site)
        if ((word & 0xffc003e0) != (0x39400000 | (base_reg << 5))
                or ((word >> 10) & 0xfff) + base_index >= len(ascii_table)):
            raise ValueError("original indexed LDRB changed at " + hex(site))
        decoded.append(ascii_table[base_index + ((word >> 10) & 0xfff)])
    if decoded.decode("ascii") != expected:
        raise ValueError("original decoded indexed string changed")
    return expected


def nul_literal(elf, va, expected):
    off = elf_file_offset(elf, va)
    raw = elf[off:off+len(expected)+1]
    if raw != expected.encode() + b"\0":
        raise ValueError("original native C format/mode string changed")
    return expected


def branch_target_for_lookup_one(elf):
    # w0 = 1 => table index w8 = w0 - 1 = 0.
    # ADR x10,0x265f4; first table byte is 1, thus branch to 0x265f8,
    # skipping 'add x1,sp,#0x28' and preserving x1=x29-0x6c ('root').
    loc = elf_file_offset(elf, 0xf0098)
    jump_index = elf[loc]
    target = 0x265f4 + 4*jump_index
    if (jump_index, target) != (1, 0x265f8):
        raise ValueError("original selector 1 jump table changed")
    return target


def native_callsite_census(elf):
    """Scan entire ELF .text for aligned direct AArch64 BL instructions.

    Counts are static BL targets in the pinned original section. Control-flow
    reachability and actual execution are explicitly out of scope.
    """
    hdr = struct.unpack_from("<16sHHIQQQIHHHHHH", elf)
    shoff, stride, count = hdr[6], hdr[11], hdr[12]
    shstr = hdr[13]
    if stride != 64 or not 0 <= shstr < count or shoff + count*stride > len(elf):
        raise ValueError("invalid ELF section header metadata")
    def sh(i):
        return struct.unpack_from("<IIQQQQIIQQ", elf, shoff+i*stride)
    names = sh(shstr)
    name_data = elf[names[4]:names[4]+names[5]]
    matching = []
    for i in range(count):
        section = sh(i)
        name_offset = section[0]
        if name_offset >= len(name_data):
            raise ValueError("invalid original section name offset")
        tail = name_data[name_offset:].split(b"\0", 1)[0]
        if tail == b".text":
            matching.append(section)
    if len(matching) != 1:
        raise ValueError("original executable .text section missing")
    section = matching[0]
    start, filepos, size = section[3], section[4], section[5]
    if ((start, filepos, size) != (0xfa00, 0xfa00, 0xe0358)
            or not (section[2] & 4) or size % 4
            or filepos+size > len(elf)):
        raise ValueError("original .text layout changed")
    targets = {0x2616c: [], 0x2682c: [], 0x26bc0: []}
    for pos in range(filepos, filepos+size, 4):
        instruction = struct.unpack_from("<I", elf, pos)[0]
        if instruction >> 26 != 0b100101:
            continue
        pc = start + pos-filepos
        relative = instruction & 0x3ffffff
        if relative & (1 << 25):
            relative -= 1 << 26
        target = pc + relative*4
        if target in targets:
            targets[target].append(pc)
    totals = {hex(dest): len(sites) for dest,sites in targets.items()}
    if totals != {"0x2616c": 83, "0x2682c": 84, "0x26bc0": 48}:
        raise ValueError("original direct helper callsite census changed")
    for target,sites in (
        (0x2616c,(0x5af34,0x5b3dc)),
        (0x2682c,(0x5af44,0x5b3f0)),
        (0x26bc0,(0x5af68,0x5b40c)),
    ):
        if any(site not in targets[target] for site in sites):
            raise ValueError("required root recording callsites absent")
    return totals


def audit(elf):
    if hashlib.sha256(elf).hexdigest() != ELF_SHA:
        raise ValueError("original inner ELF SHA-256 mismatch")
    for va, expected in PINNED.items():
        if insn(elf, va) != expected:
            raise ValueError("original ARM64 instruction changed at " + hex(va))
    for pc, dest in (
        (0x5af34, 0x2616c), (0x5af44, 0x2682c), (0x5af68, 0x26bc0),
        (0x5b3dc, 0x2616c), (0x5b3f0, 0x2682c), (0x5b40c, 0x26bc0),
        (0x26748, 0xf800), (0x26930, 0xf860), (0x269b0, 0xf1d0),
        (0x26d24, 0x12f00), (0x26d30, 0xf0c0), (0x26d44, 0xf860),
        (0x26d5c, 0xf860), (0x26d70, 0xf420),
        (0x26e04, 0xf1d0), (0x27130, 0xf3f0),
        (0x27144, 0xf880),
    ):
        if bl_target(elf, pc) != dest:
            raise ValueError("original imported or helper call target changed "
                             + hex(pc))
    chars = decode_table(elf)
    key = decode_loads(elf, chars, ROOT_SITES, 0x41, 8, "root")
    chosen_branch = branch_target_for_lookup_one(elf)
    reader_filename = decode_loads(elf, chars, READER_FILE_SITES,
                                   0xe, 8, "envc.push")
    writer_filename = decode_loads(elf, chars, WRITER_FILE_SITES,
                                   5, 22, "envc.push")
    writer_format = decode_loads(elf, chars, WRITER_FORMAT_SITES,
                                 5, 22, "%s=%x%x")
    for va, expected in (
        (0xf0801, "%s%s"), (0xf0806, "w+"),
        (0xf0809, "%s%x%s"), (0xf0717, "r"), (0x101414, "r+"),
    ):
        nul_literal(elf, va, expected)

    # Reader and writer use the same relocated directory-prefix buffer.
    # Its value is runtime-owned; do not claim a concrete absolute path.
    if relocation_target(elf, 0x123f70) != 0x128010:
        raise ValueError("original runtime filename prefix relocation changed")
    # mov w9,#0x81f1; movk w9,#0xb6a2,lsl16; mov w8,#10; orr w2,w9,w8
    marker = ((0xb6a2 << 16) | 0x81f1) | 10
    if marker != 0xb6a281fb:
        raise ValueError("original record marker computation changed")
    census = native_callsite_census(elf)
    return {
        "inner_elf_sha256": ELF_SHA,
        "direct_BL_calls_in_entire_text": census,
        "positive_guard_followup": {
            "site": "0x5af18",
            "key_selector": "0x5af20 mov w0,#1",
            "selector_1_table_target": hex(chosen_branch),
            "selected_record_key": key,
            "lookup_call": "0x5af34 -> 0x2616c",
            "lookup_zero_skips": "0x5af38 -> cleanup",
            "read_call": "0x5af44 -> 0x2682c",
            "nonzero_reader_result_skips": "0x5af48..0x5af4c -> cleanup",
            "conditional_update_call": "0x5af68 -> 0x26bc0",
            "update_parameters": {
                "key": key, "numeric_flags": 1,
                "marker": hex(marker),
            },
            "second_root_update": {
                "entry": "0x5b3c0, guarded by 0x5b344 bit0",
                "key_selector": "0x5b3c8 w0=1, also root",
                "lookup_call": "0x5b3dc -> 0x2616c",
                "read_call": "0x5b3f0 -> 0x2682c",
                "conditional_update_call": "0x5b40c -> 0x26bc0",
                "marker": "0xb6a281f1",
                "difference_from_first_marker": "0x0a",
            },
        },
        "storage": {
            "reader_filename": reader_filename,
            "writer_filename": writer_filename,
            "dynamic_path_prefix_pointer": "0x123f70 -> 0x128010",
            "absolute_runtime_path_verified": False,
            "read_mode": "r",
            "update_mode": "r+",
            "create_if_absent_mode": "w+",
            "update_file_lock": "flock(...,LOCK_EX)",
            "writer_record_format": writer_format,
            "reader_calls": ["fopen", "fgets", "strtoul"],
            "writer_calls": [
                "access", "fopen", "flock", "fgets", "fseek",
                "fwrite", "fflush",
            ],
            "pre_write_processing": (
                "Internal parsing and block transformations at 0x26e78,"
                " 0x270ec; output is not proven plaintext"),
        },
        "scope": (
            "Proves original guarded native lookup/update of key 'root' in "
            "envc.push. No on-device file contents, actual write success, "
            "DECMsgDialog or DeviceEnvironmentCheck causality established."),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path,
                        help="pinned original APK or original diagnostic ZIP")
    args = parser.parse_args()
    payload = args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(payload)) as outer:
        if "apks/01-base.apk" in outer.namelist():
            payload = outer.read("apks/01-base.apk")
    if hashlib.sha256(payload).hexdigest() != APK_SHA:
        raise ValueError("original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        inner, _ = recover(archive.read("lib/arm64-v8a/libDexHelper.so"),
                           SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(inner), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
