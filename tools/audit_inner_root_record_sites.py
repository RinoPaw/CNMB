#!/usr/bin/env python3
"""Verify five additional original root-key read-before-update callsite chains.

Original CNMB 12.5.5 nested DexHelper ELF, SHA-256 pinned. Static executable
code only; no device access, app mutation, or inferred DEC caller.
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
from audit_inner_h_envc_push import branch_target_for_lookup_one

# Independent static sites; several share a function and must not be counted
# as independent dynamic detector invocations.
# selector_mov, name BL, reader BL, writer BL, marker, instruction assertions
SITES = (
    ("0x1c1xx", 0x1c154, 0x1c178, 0x1c188, 0x1c1a4, 0xb6a281f3,
     {0x1c194:0x52903e62, 0x1c1a0:0x72b6d442, 0x1c19c:0x52800021}),
    ("0x329xx", 0x32970, 0x32984, 0x32994, 0x329b0, 0xb6a281f2,
     {0x329a0:0x52903e42, 0x329ac:0x72b6d442, 0x329a8:0x52800021}),
    ("0x371xx", 0x370e4, 0x370f8, 0x37108, 0x37124, 0xb6a281f8,
     {0x37114:0x52903f02, 0x37120:0x72b6d442, 0x3711c:0x52800021}),
    ("0x502xx", 0x5029c, 0x502c0, 0x502d0, 0x502f0, 0xb6a281f7,
     {0x502dc:0x52903ec8, 0x502e0:0x72b6d448, 0x502e4:0x32000102,
      0x502ec:0x52800021}),
    ("0x5a3xx", 0x5a330, 0x5a344, 0x5a354, 0x5a374, 0xb6a281f5,
     {0x5a360:0x52903e28, 0x5a364:0x72b6d448, 0x5a368:0x321e0102,
      0x5a370:0x52800021}),
)


def word(elf, addr):
    return struct.unpack_from("<I", elf, elf_file_offset(elf, addr))[0]


def checked(elf, addr, expected):
    if word(elf, addr) != expected:
        raise ValueError("original instruction mismatch at " + hex(addr))


def inspect_sites(elf):
    reports = []
    for label, mov, name, read, write, marker, extras in SITES:
        checked(elf, mov, 0x52800020)  # selector 1 => root
        for addr, expected in extras.items():
            checked(elf, addr, expected)
        for addr, target in ((name,0x2616c),
                             (read,0x2682c), (write,0x26bc0)):
            if bl_target(elf, addr) != target:
                raise ValueError("original direct BL changed at " + hex(addr))
        # Each of these linear snippets returns early when the existing
        # status is nonzero. This proves a local read-before-update gate.
        checked(elf, read + 4, 0x72001c1f)  # tst w0,#255
        if (word(elf, read + 8) & 0xff00001f) != 0x54000001:
            raise ValueError("expected B.NE after status read")
        reports.append({
            "region":label,
            "key_selector":1,
            "name_lookup":hex(name),
            "record_read":hex(read),
            "conditional_update":hex(write),
            "record_marker":hex(marker),
            "status_nonzero_skips_update":True,
        })
    if len({r["record_marker"] for r in reports}) != len(SITES):
        raise ValueError("unexpected repeated record marker")
    return reports


def audit(elf):
    if hashlib.sha256(elf).hexdigest() != SAMPLES["libDexHelper.so"]["inner_sha"]:
        raise ValueError("original inner ELF SHA-256 mismatch")
    if branch_target_for_lookup_one(elf) != 0x265f8:
        raise ValueError("original selector table changed")
    return {
        "inner_elf_sha256":SAMPLES["libDexHelper.so"]["inner_sha"],
        "key":"root",
        "additional_read_before_update_sites":inspect_sites(elf),
        "distinct_verified_markers":5,
        "limitations":(
            "Five static source locations, not five observed detections. "
            "No on-device writes, marker semantics, or DEC consumer demonstrated.")
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    args=p.parse_args()
    data=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if "apks/01-base.apk" in z.namelist():
            data=z.read("apks/01-base.apk")
    if hashlib.sha256(data).hexdigest()!=APK_SHA:
        raise ValueError("original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        elf,_=recover(z.read("lib/arm64-v8a/libDexHelper.so"),
                      SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(elf),ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
