#!/usr/bin/env python3
"""Verify original SecNeo H parent-side JNI pipe reader in pinned CNMB 12.5.5.

Reads original APK or diagnostic ZIP. Recovers pinned nested ELF in memory,
checks original ARM64 code words, decoded JNI class/method names and
pipe-read-end propagation. Never writes unpacked proprietary binaries.
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

WORDS = {
    0x5a3d0: 0x97fed204,  # pipe@plt
    0x5a3e0: 0x29725bb3,  # ldp w19(read),w22(write),[x29,#-0x70]
    0x5a418: 0x97fed37a,  # first fork
    0x5a440: 0x2a1603e0,  # mov w0,w22 (close write end in parent)
    0x5a444: 0x97fed497,  # close@plt
    0x5a454: 0x97fed4f3,  # waitpid@plt
    0x5a468: 0xb94023f5,  # ldr w21,[sp,#0x20] (read end)
    0x5a8c8: 0xb94023e3,  # ldr w3,[sp,#0x20] (read FD into JNI arg)
    0x5a8dc: 0x97ff3e8e,  # JNI CallStaticObjectMethodV wrapper
    0x5a9d4: 0xf9408508,  # JNIEnv vtable offset 0x108 GetMethodID
    0x5a9f4: 0x97ff4ceb,  # JNI object constructor wrapper
    0x5ac00: 0x97ff4c68,  # JNI object constructor wrapper
    0x5ad04: 0xd63f0120,  # readUTF GetMethodID
    0x5ad18: 0x97fee42b,  # JNI CallObjectMethodV wrapper
    0x5ad30: 0xd63f0120,  # JNI exception check
    0x5ae30: 0xf942a508,  # JNIEnv vtable offset 0x548 GetStringUTFChars
    0x5ae34: 0xd63f0100,  # blr x8
    0x5ae38: 0x97fecf6e,  # atoi@plt
    0x5ae3c: 0x7100041f,  # cmp w0,#1
    0x5ae40: 0x5400096b,  # branch if <1
}

# AArch64 LDRB W9,[X19,#imm12] / STRB W9,[SP,#imm12]
LDRB_X19_W9 = 0x39400269
STRB_SP_W9 = 0x390003e9
IMM12_MASK = 0xffc003ff
EXPECTED_STACK = (
    # start, stop, destination stack displacement, literal
    (0x5a9fc, 0x5aacc, 0x98, "java/io/DataInputStream"),
    (0x5aad4, 0x5ab1c, 0x48, "<init>"),
    (0x5ab1c, 0x5abe0, 0x78, "(Ljava/io/InputStream;)V"),
    (0x5ac08, 0x5ac50, 0x38, "readUTF"),
    (0x5ac50, 0x5ad00, 0x60, "()Ljava/lang/String;"),
)


def code_word(elf, addr):
    return struct.unpack_from("<I", elf, elf_file_offset(elf, addr))[0]


def table_string(elf, ascii_table, va, length, first):
    """Read original indexed rodata and resolve byte indices to ASCII."""
    start = elf_file_offset(elf, va)
    indices = elf[start:start + length]
    if len(indices) != length:
        raise ValueError("truncated original indexed literal")
    lookup = [first, *indices[1:]]
    if any(index >= len(ascii_table) for index in lookup):
        raise ValueError("invalid original printable-table index")
    return bytes(ascii_table[index] for index in lookup).decode("ascii")


def stack_literal(elf, ascii_table, begin, end, destination, length):
    """Recover genuine LDRB->STRB pairs without embedding obfuscated strings."""
    saved = {}
    pending = None
    for addr in range(begin, end, 4):
        word = code_word(elf, addr)
        if word & IMM12_MASK == LDRB_X19_W9:
            pending = (addr, (word >> 10) & 0xfff)
        elif word & IMM12_MASK == STRB_SP_W9:
            offset = (word >> 10) & 0xfff
            if (pending is not None and addr - pending[0] <= 40
                    and destination <= offset < destination + length):
                index = pending[1] + 8  # verified x19 points at ASCII table+8
                if index >= len(ascii_table):
                    raise ValueError("JNI printable table index overflow")
                if offset in saved and saved[offset] != ascii_table[index]:
                    raise ValueError("inconsistent original JNI stack literal")
                saved[offset] = ascii_table[index]
            # A load is consumed by its immediate store. Do not let a later
            # orphan STRB silently reuse a prior character register source.
            pending = None
    if len(saved) != length:
        raise ValueError("JNI literal does not have enough verified byte stores")
    return bytes(saved[destination + i] for i in range(length)).decode("ascii")


def original_java_names(elf, ascii_table):
    # The first char is explicitly loaded from table+0x41 or table+0x08,
    # remaining bytes are rodata indices interpreted through the same table.
    expected_rodata = (
        (0xf1988, 31, 0x41, "android/os/ParcelFileDescriptor"),
        (0xf19a8, 36, 0x08, "(I)Landroid/os/ParcelFileDescriptor;"),
        (0xf19cd, 52, 0x41,
         "android/os/ParcelFileDescriptor$AutoCloseInputStream"),
    )
    decoded = []
    for va, size, first, expected in expected_rodata:
        actual = table_string(elf, ascii_table, va, size, first)
        if actual != expected:
            raise ValueError("original JNI rodata literal changed")
        decoded.append(actual)
    # adoptFd: 7 LDRB sites from x19=ascii+8.
    offsets = (0x39, 0x3c, 0x47, 0x48, 0x4c, 0x1e, 0x3c)
    sites = (0x5a844, 0x5a84c, 0x5a854, 0x5a85c,
             0x5a864, 0x5a86c, 0x5a874)
    for addr, index in zip(sites, offsets):
        # May use W8 instead of W9; base X19, byte immediate.
        word = code_word(elf, addr)
        if ((word & IMM12_MASK) != 0x39400268
                or (word >> 10) & 0xfff != index):
            raise ValueError("original adoptFd char load changed")
    method = bytes(ascii_table[x + 8] for x in offsets).decode()
    if method != "adoptFd":
        raise ValueError("original adoptFd literal changed")
    for begin, end, dest, expected in EXPECTED_STACK:
        actual = stack_literal(elf, ascii_table, begin, end, dest, len(expected))
        if actual != expected:
            raise ValueError("original JNI constructed method descriptor changed")
        decoded.append(actual)
    return [decoded[0], method, decoded[1], decoded[2], *decoded[3:]]


def audit(elf):
    ascii_table = decode_table(elf)
    for addr, expected in WORDS.items():
        if code_word(elf, addr) != expected:
            raise ValueError("original ARM64 instruction changed at " + hex(addr))
    if bl_target(elf, 0x5a3d0) != 0xebe0:
        raise ValueError("original pipe callsite changed")
    if bl_target(elf, 0x5a8dc) != 0x2a314:
        raise ValueError("original JNI static-call wrapper changed")
    if bl_target(elf, 0x5ad18) != 0x13dc4:
        raise ValueError("original JNI object-call wrapper changed")
    names = original_java_names(elf, ascii_table)
    return {
        "inner_elf_sha256": SAMPLES["libDexHelper.so"]["inner_sha"],
        "pipe": {
            "creation": "0x5a3d0 pipe@plt",
            "fd_pair": "0x5a3e0 w19=read, w22=write",
            "first_fork": "0x5a418",
            "parent_closes_write_fd": "0x5a440..0x5a444",
            "parent_waitpid": "0x5a454",
            "parent_read_fd_argument": "0x5a8c8 w3 <- [sp+0x20]",
        },
        "jni_reader": {
            "adopt_read_fd": names[0] + "." + names[1] + names[2],
            "input_stream_class": names[3],
            "data_input_stream_class": names[4],
            "data_input_stream_constructor": names[5] + names[6],
            "reader_method": names[7] + names[8],
            "return_jstring": "0x5ad18 JNI CallObjectMethodV",
            "extract_utf8": "0x5ae30 JNIEnv GetStringUTFChars",
            "parse_integer": "0x5ae38 atoi@plt",
            "comparison": "0x5ae3c cmp w0,#1",
        },
        "limits": (
            "Confirms original parent-side reader and integer threshold "
            "for the same pipe descriptor. Does not establish observed "
            "parent-child PIDs, delivery on a particular run or DEC causality."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="original pinned APK or diagnostic ZIP")
    args = parser.parse_args()
    raw = args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as outer:
        if "apks/01-base.apk" in outer.namelist():
            raw = outer.read("apks/01-base.apk")
    if hashlib.sha256(raw).hexdigest() != APK_SHA:
        raise ValueError("original APK SHA mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as apk:
        inner, _ = recover(apk.read("lib/arm64-v8a/libDexHelper.so"),
                           SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(inner), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
