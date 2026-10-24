#!/usr/bin/env python3
"""Original SecNeo H result label and shared envc.push file-mode audit.

Input: SHA-pinned CNMB 12.5.5 base APK or private diagnostics ZIP.
Only exposes strings built by original code; never exports APK/SO or FD data.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, recover, bl_target
from audit_inner_app_process_argv import decode_table, elf_file_offset
from audit_inner_h_guard_config import relocation_target

INNER_SHA = SAMPLES["libDexHelper.so"]["inner_sha"]
USB_LOADS = (0x261c4, 0x261cc, 0x261d4)
READ_FILE_LOADS = (0x268b8, 0x268cc, 0x268e0, 0x268e8, 0x268f0,
                   0x268f8, 0x26900, 0x26908, 0x26910)
WRITE_FILE_LOADS = (0x26c5c, 0x26c70, 0x26c84, 0x26c90, 0x26c98,
                    0x26ca0, 0x26ca8, 0x26cb0, 0x26cb8)
READ_LINE_LOADS = (0x2696c, 0x26980, 0x26990)
WRITE_LINE_LOADS = (0x26cdc, 0x26ce0, 0x26cf4, 0x26d00,
                    0x26d08, 0x26d10, 0x26d18)
WORDS = {
    0x5af20: 0x52800020,  # mov w0,#1 -> label selector
    0x265f4: 0x9100a3e1,  # source points to stack+0x28 ("usb")
    0x26740: 0xaa1303e0,  # memcpy destination
    0x26894: 0x91040908,  # read-side printable table base +0xe
    0x26c34: 0x9103e6d6,  # write-side printable table base +5
    0x26968: 0x9103e508,  # read line format printable base +5
    0x26928: 0x911c5c21,  # read-only "r" mode
    0x26d3c: 0x91201821,  # create "w+" mode
    0x26d54: 0x91105021,  # update "r+" mode
}
BL = {
    0x5af34: 0x2616c,  # label selector, not path construction
    0x26748: 0xf800,   # memcpy
    0x26920: 0x24fe4, # sprintf pathname
    0x2699c: 0x24fe4, # sprintf "usb=" line prefix
    0x26cc8: 0x24fe4,# sprintf pathname
    0x26d24: 0x12f00,# snprintf update record
    0x26930: 0xf860,  # fopen read-only
    0x26d44: 0xf860,  # fopen w+ if absent
    0x26d5c: 0xf860,  # fopen r+
    0x26d70: 0xf420,  # flock
    0x27144: 0xf880,  # fwrite
    0x2714c: 0xf190,  # fflush
}


def word(elf, address):
    return struct.unpack_from("<I", elf, elf_file_offset(elf, address))[0]


def bytes_at(elf, address, length):
    start = elf_file_offset(elf, address)
    return elf[start:start + length]


def decode_loads(elf, table, sites, base_index, base_reg, regs):
    """Validate ARM64 unsigned-offset LDRB and decode loaded bytes."""
    if len(sites) != len(regs):
        raise ValueError("mismatched original LDRB site count")
    output = []
    for pc, dst_reg in zip(sites, regs):
        instruction = word(elf, pc)
        if (instruction & 0xffc00000 != 0x39400000
                or (instruction >> 5) & 31 != base_reg
                or instruction & 31 != dst_reg):
            raise ValueError("original LDRB operand changed at " + hex(pc))
        idx = base_index + ((instruction >> 10) & 0xfff)
        if idx >= len(table):
            raise ValueError("original printable index out of bounds")
        output.append(table[idx])
    return bytes(output).decode("ascii")


def audit(elf):
    if hashlib.sha256(elf).hexdigest() != INNER_SHA:
        raise ValueError("original inner ELF SHA-256 mismatch")
    for pc, expected in WORDS.items():
        if word(elf, pc) != expected:
            raise ValueError("original ARM64 instruction changed at " + hex(pc))
    for pc, dest in BL.items():
        if bl_target(elf, pc) != dest:
            raise ValueError("original call target changed at " + hex(pc))
    table = decode_table(elf)
    label = decode_loads(elf, table, USB_LOADS, 0x41, 8, (9, 9, 9))
    read_file = decode_loads(elf, table, READ_FILE_LOADS, 0xe, 8,
                             (9, 9, 9, 9, 9, 9, 9, 9, 8))
    write_file = decode_loads(elf, table, WRITE_FILE_LOADS, 5, 22, (8,) * 9)
    read_line = decode_loads(elf, table, READ_LINE_LOADS, 5, 8, (9, 9, 8))
    write_line = decode_loads(elf, table, WRITE_LINE_LOADS, 5, 22, (8,) * 7)
    if (label, read_file, write_file, read_line, write_line) != (
            "usb", "envc.push", "envc.push", "%s=", "%s=%x%x"):
        raise ValueError("original decoded labels or file formats changed")
    if bytes_at(elf, 0xf0098, 2) != b"\x01\x00":
        raise ValueError("original label dispatch entry changed")
    # w0==1 -> jump table slot zero -> 0x265f8; 0x265f4 assigns SP+0x28.
    if bytes_at(elf, 0xf0801, 5) != b"%s%s\x00":
        raise ValueError("original shared path format changed")
    for at, mode in ((0xf0717, b"r\x00"),
                     (0xf0806, b"w+\x00"),
                     (0x101414, b"r+\x00")):
        if bytes_at(elf, at, len(mode)) != mode:
            raise ValueError("original fopen mode changed")
    if relocation_target(elf, 0x123f70) != 0x128010:
        raise ValueError("original runtime prefix pointer slot changed")
    return {
        "inner_elf_sha256": INNER_SHA,
        "positive_result_label": {
            "selector": 1, "name": label,
            "source": "0x5af34 -> 0x2616c -> 0x265f8",
            "other_label_capability_not_execution": True,
        },
        "shared_file": {
            "read_side": {"site": "0x2682c", "filename": read_file,
                          "mode": "r", "line_prefix": read_line.replace("%s", label)},
            "update_side": {"site": "0x26bc0", "filename": write_file,
                            "create_mode": "w+", "update_mode": "r+",
                            "record_format": write_line},
            "path_format": "%s%s",
            "runtime_prefix_pointer_slot": "0x128010",
            "full_absolute_path_observed": False,
        },
        "update_path": {
            "conditional_fwrite": "0x27144",
            "conditional_fflush": "0x2714c",
            "actual_written_bytes_observed": False,
        },
        "limit": ("Original static file names and modes are proven. Runtime prefix, "
                  "record values, actual writes and DEC causality remain unknown."),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    args = p.parse_args()
    data = args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if "apks/01-base.apk" in z.namelist():
            data = z.read("apks/01-base.apk")
    if hashlib.sha256(data).hexdigest() != APK_SHA:
        raise ValueError("original APK SHA mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        elf, _ = recover(z.read("lib/arm64-v8a/libDexHelper.so"),
                         SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(elf), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
