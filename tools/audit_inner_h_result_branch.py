#!/usr/bin/env python3
"""Audit the native decisions after the SecNeo H pipe read, using original ELF.

Pinned CNMB 12.5.5 APK/diagnostic ZIP only. Recovers nested libDexHelper.so
in memory, asserts original ARM64 words and decodes actual conditional targets.
Does not execute instructions or assert device-time crash/DEC attribution.
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

# Static evidence from SHA-pinned inner ELF. Every address is ELF VA.
WORDS = {
    0x5ad30: 0xd63f0120,  # JNI ExceptionCheck vtable call
    0x5ad34: 0x72001c1f,  # tst w0,0xff
    0x5ad38: 0x54000720,  # b.eq 0x5ae1c (no JNI exception)
    0x5ae1c: 0xb4000a94,  # cbz x20,cleanup
    0x5ae30: 0xf942a508,  # JNI vtable GetStringUTFChars
    0x5ae34: 0xd63f0100,  # blr x8
    0x5ae38: 0x97fecf6e,  # BL atoi@plt
    0x5ae3c: 0x7100041f,  # cmp w0,#1
    0x5ae40: 0x5400096b,  # b.lt cleanup
    0x5ae44: 0xb0000648,  # adrp x8,0x123000
    0x5ae48: 0xf946e108,  # ldr x8,[x8,#0xdc0]
    0x5ae4c: 0xf9400108,  # ldr x8,[x8]
    0x5ae50: 0x3945f108,  # ldrb w8,[x8,#0x17c]
    0x5ae54: 0x37000628,  # tbnz w8,#0,0x5af18
    0x5ae60: 0x52803f0a,  # mov w10,#0x1f8 (branch register)
    0x5ae70: 0xd2800000,  # mov x0,#0
    0x5ae74: 0x9100001f,  # mov sp,x0
    0x5ae78: 0xaa0003fe,  # mov x30,x0
    0x5ae80: 0xaa0a03e9,  # mov x9,x10 (not branch)
    0x5ae84: 0xd61f0140,  # br x10
    0x5af18: 0x6f00e400,  # alternate branch entry
    0x5af6c: 0xf9400fe1,  # cleanup branch entry
    0x5b334: 0x90000648,  # adrp x8,0x123000
    0x5b338: 0xf946e108,  # ldr x8,[x8,#0xdc0]
    0x5b33c: 0xf9400108,  # ldr x8,[x8]
    0x5b340: 0x3945f108,  # ldrb w8,[x8,#0x17c]
    0x5b344: 0x370003e8,  # tbnz w8,#0,0x5b3c0
    0x5b350: 0x52803e0b,  # mov w11,#0x1f0
    0x5b354: 0xd2800000,  # mov x0,#0
    0x5b358: 0x9100001f,  # mov sp,x0
    0x5b35c: 0xaa0003fe,  # mov x30,x0
    0x5b368: 0xd61f0160,  # br x11
    0x5b3c0: 0x6f00e400,  # alternate second branch
    0x3af24: 0x395fc3e9,  # ldrb w9,[sp,#0x7f0]
    0x3af28: 0x34000309,  # cbz w9 ...
    0x3af44: 0xb000078c,  # adrp x12,0x12b000
    0x3af48: 0x3905f189,  # strb w9,[x12,#0x17c]
}


def sext(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def bcond_target(word, pc):
    if (word & 0xff000010) != 0x54000000:
        raise ValueError("expected ARM64 B.cond")
    return pc + (sext((word >> 5) & 0x7ffff, 19) << 2), word & 15


def tbnz_target(word, pc):
    # Top bit is the bit-index high bit, so ignore it when matching TBNZ.
    if (word & 0x7f000000) != 0x37000000:
        raise ValueError("expected ARM64 TBNZ")
    target = pc + (sext((word >> 5) & 0x3fff, 14) << 2)
    bit = ((word >> 31) << 5) | ((word >> 19) & 0x1f)
    return target, bit, word & 31


def word_at(elf, addr):
    return struct.unpack_from("<I", elf, elf_file_offset(elf, addr))[0]


def audit(elf):
    for addr, expected in WORDS.items():
        if word_at(elf, addr) != expected:
            raise ValueError(f"original instruction changed at {addr:#x}")
    targets = {
        "jni_no_exception": bcond_target(word_at(elf, 0x5ad38), 0x5ad38),
        "zero_or_negative": bcond_target(word_at(elf, 0x5ae40), 0x5ae40),
        "positive_check_guard": tbnz_target(word_at(elf, 0x5ae54), 0x5ae54),
        "other_guard": tbnz_target(word_at(elf, 0x5b344), 0x5b344),
    }
    if targets != {
        "jni_no_exception": (0x5ae1c, 0),
        "zero_or_negative": (0x5af6c, 11),
        "positive_check_guard": (0x5af18, 0, 8),
        "other_guard": (0x5b3c0, 0, 8),
    }:
        raise ValueError("original conditional target or condition changed")
    if bl_target(elf, 0x5ae38) != 0xebf0:
        raise ValueError("atoi PLT target changed")
    # MOVZ to 32-bit W10/W11 zero extends to x10/x11 before BR.
    return {
        "sample": "CNMB 12.5.5 pinned original APK / inner DexHelper ELF",
        "original_elf_sha256": SAMPLES["libDexHelper.so"]["inner_sha"],
        "jni_no_exception_branch": {
            "site": "0x5ad38", "condition": "eq",
            "target": "0x5ae1c", "precondition": "ExceptionCheck == 0",
        },
        "result_check": {
            "source": "0x5ae30 GetStringUTFChars -> 0x5ae38 atoi",
            "comparison": "0x5ae3c cmp w0,#1",
            "value_below_one": {
                "site": "0x5ae40", "condition": "lt",
                "target": "0x5af6c", "meaning": "cleanup/continuation",
            },
            "value_at_least_one": {
                "runtime_byte": "0x5ae44..0x5ae50 two pointer loads then byte at +0x17c",
                "bit_test": "0x5ae54 tbnz w8,#0",
                "bit_set_target": "0x5af18",
                "bit_clear_path": {
                    "zero_stack": "0x5ae70..0x5ae74",
                    "zero_link_register": "0x5ae78",
                    "branch_reg_imm": "x10=0x1f8",
                    "indirect_branch": "0x5ae84 br x10",
                    "classification": "trap-like low-address jump; no on-device execution proof",
                },
            },
        },
        "additional_guard": {
            "state_byte": "0x5b334..0x5b340 same indirect +0x17c",
            "bit_set_target": "0x5b3c0",
            "bit_clear_path": {
                "zero_stack_and_link_register": "0x5b354..0x5b35c",
                "branch_reg_imm": "x11=0x1f0",
                "indirect_branch": "0x5b368 br x11",
            },
        },
        "possible_static_writer": {
            "site": "0x3af48", "operation": "strb w9,[x12,#0x17c]",
            "direct_base": "0x12b000",
            "source": "0x3af24 ldrb w9,[sp,#0x7f0]",
            "scope": ("Direct destination 0x12b17c verified. Dynamic pointer chain "
                      "at 0x5ae44..0x5ae4c has NOT been proven to alias 0x12b000."),
        },
        "limits": (
            "Conditional branches and trap-like original instructions proven "
            "statically. Runtime state byte value, actual trap execution, "
            "the observed 0x978 crash, and DECMsgDialog causality remain unproven."
        ),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path, help="original APK or diagnostic ZIP")
    args = p.parse_args()
    original = args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(original)) as outer:
        if "apks/01-base.apk" in outer.namelist():
            original = outer.read("apks/01-base.apk")
    if hashlib.sha256(original).hexdigest() != APK_SHA:
        raise ValueError("original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(original)) as apk:
        elf, _ = recover(apk.read("lib/arm64-v8a/libDexHelper.so"),
                         SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(elf), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
