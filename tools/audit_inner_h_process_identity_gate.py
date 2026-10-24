#!/usr/bin/env python3
"""Audit original SecNeo H sw/bs process-identity gates from pinned ARM64 ELF.

Uses the original CNMB 12.5.5 APK (or private diagnostics ZIP). The nested ELF
is recovered in memory, with fixed SHA-256 checks. No privileged device access.
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

SHA = SAMPLES["libDexHelper.so"]["inner_sha"]
# Each word is exact original ARM64 code from the SHA-pinned inner ELF.
WORDS = {
    0x2bf88:0xb00007c9, 0x2bf8c:0x91040d29,
    0x2c01c:0xd2801588, 0x2c020:0xd4000001, # SYS_getpid = 172
    0x2c194:0xd2800708, 0x2c198:0xd4000001, # SYS_openat = 56
    0x2c1dc:0xd28007e8, 0x2c1e0:0xd4000001, # SYS_read = 63
    0x2c2b8:0x52800020, # identity-check result 1
    0x2c400:0x52800060, # result 3
    0x2c42c:0x52800040, # result 2
    0x2c434:0x2a1f03e0, # result 0
    0x2c464:0xb4002242, 0x2c46c:0x37002203, # sw bit 0 early return
    0x2c47c:0x39403108, 0x2c480:0x34002168, # sw runtime byte at +0xc
    0x2c494:0x91010100, 0x2c498:0x97fffeb4, # sw identity helper
    0x2c49c:0x35002080, # sw nonzero result aborts
    0x2c904:0xb4000162, 0x2c90c:0x37080123, # bs bit 1 early return
    0x2c924:0x91010100, 0x2c928:0x97fffd90, # bs identity helper
    0x2c92c:0x340001c0, # bs zero result continues
    0x2c970:0x39403108, 0x2c974:0x34fffde8, # bs runtime +0xc
}
PREFIX_SITES = (0x2bf98, 0x2bfa4, 0x2bfac, 0x2bfb4, 0x2bfbc, 0x2bfc4)
SUFFIX_SITES = (0x2bfd0, 0x2bfd8, 0x2bfe0, 0x2bfe8,
                0x2bff0, 0x2bff8, 0x2c000, 0x2c008)


def word(elf, va):
    return struct.unpack_from("<I", elf, elf_file_offset(elf, va))[0]


def text_from_original_ldr(elf, chars, sites):
    # x9 = decrypted printable ASCII table + 0x0f at 0x2bf8c.
    output = []
    for pc in sites:
        w = word(elf, pc)
        if (w & 0xffc003ff) != 0x39400128:
            raise ValueError("changed LDRB W8,[X9,#imm] at " + hex(pc))
        off = 0x0f + ((w >> 10) & 0xfff)
        if off >= len(chars):
            raise ValueError("printable ASCII table index out of bounds")
        output.append(chars[off])
    return bytes(output).decode("ascii")


def bittest_target(w, pc, register, bit, target):
    if (w & 0x7f000000) != 0x37000000:
        raise ValueError("expected original TBNZ")
    disp = (w >> 5) & 0x3fff
    if disp & 0x2000:
        disp -= 0x4000
    bit_number = ((w >> 31) << 5) | ((w >> 19) & 31)
    if (w & 31, bit_number, pc + disp*4) != (register, bit, target):
        raise ValueError("original TBNZ register/bit/target changed")


def branch_imm_target(w, pc, opcode, target):
    # Zero-test CBZ/CBNZ: condition prefix with signed imm19.
    if (w & 0x7f000000) != opcode:
        raise ValueError("expected original CBZ/CBNZ")
    imm = (w >> 5) & 0x7ffff
    if imm & (1 << 18):
        imm -= 1 << 19
    if pc + imm*4 != target:
        raise ValueError("changed original conditional branch target")


def audit(elf):
    if hashlib.sha256(elf).hexdigest() != SHA:
        raise ValueError("original nested ELF SHA-256 mismatch")
    for pc, expected in WORDS.items():
        if word(elf, pc) != expected:
            raise ValueError("original ARM64 machine word changed at " + hex(pc))
    chars = decode_table(elf)
    prefix = text_from_original_ldr(elf, chars, PREFIX_SITES)
    suffix = text_from_original_ldr(elf, chars, SUFFIX_SITES)
    if (prefix, suffix) != ("/proc/", "/cmdline"):
        raise ValueError("original procfs identity path changed")
    if (bl_target(elf, 0x2c498) != 0x2bf68 or
            bl_target(elf, 0x2c928) != 0x2bf68):
        raise ValueError("sw/bs no longer share identity helper")
    bittest_target(word(elf, 0x2c46c), 0x2c46c, 3, 0, 0x2c8ac)
    bittest_target(word(elf, 0x2c90c), 0x2c90c, 3, 1, 0x2c930)
    branch_imm_target(word(elf, 0x2c49c), 0x2c49c, 0x35000000, 0x2c8ac)
    branch_imm_target(word(elf, 0x2c92c), 0x2c92c, 0x34000000, 0x2c964)
    branch_imm_target(word(elf, 0x2c480), 0x2c480, 0x34000000, 0x2c8ac)
    branch_imm_target(word(elf, 0x2c974), 0x2c974, 0x34000000, 0x2c930)
    return {
        "inner_elf_sha256": SHA,
        "identity_helper": {
            "entry": "0x2bf68",
            "uses": "getpid (AArch64 syscall 172)",
            "proc_path": prefix + "<current PID>" + suffix,
            "operations": [
                "openat via AArch64 syscall 56",
                "read via AArch64 syscall 63",
                "compare procfs cmdline against runtime expected name"
            ],
            "possible_return_codes": [0, 1, 2, 3],
            "code_semantics": "individual return-code meaning not fully established"
        },
        "sw_gate": {
            "entry": "0x2c440",
            "flag_bit0_set": "skip at 0x2c8ac",
            "helper_call": "0x2c498 -> 0x2bf68",
            "identity_nonzero": "skip at 0x2c8ac",
            "runtime_byte_offset": "0xc",
            "runtime_byte_zero": "skip at 0x2c8ac",
        },
        "bs_gate": {
            "entry": "0x2c8d8",
            "flag_bit1_set": "return NULL at 0x2c930",
            "helper_call": "0x2c928 -> 0x2bf68",
            "identity_zero": "continue at 0x2c964",
            "runtime_byte_offset": "0xc",
            "runtime_byte_zero": "return NULL at 0x2c930",
        },
        "default_java_flag": 255,
        "under_original_H_PC_FLAG_initial_value": "both sw and bs short-circuit before procfs identity helper",
        "limits": (
            "No proof of runtime PC_FLAG modification, a successful service "
            "bind, or remote Messenger reply. No DEC or crash attribution."
        ),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path, help="pinned original APK or diagnostic ZIP")
    args = p.parse_args()
    raw = args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        if "apks/01-base.apk" in z.namelist():
            raw = z.read("apks/01-base.apk")
    if hashlib.sha256(raw).hexdigest() != APK_SHA:
        raise ValueError("original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as apk:
        inner, _ = recover(apk.read("lib/arm64-v8a/libDexHelper.so"),
                           SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(inner), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
