#!/usr/bin/env python3
"""Recover *known* app_process execl argv strings from original inner ELF.

No binary output. Uses the SHA256-pinned original APK, verifies machine-code
calls and original bytes, and converts ELF virtual addresses via PT_LOAD.
The Java main class and pipe descriptor are runtime values: never invent them.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, recover, bl_target, app_process_path

# Original ARM64 instructions in the recovered DexHelper inner ELF.
INSTRUCTIONS = {
    0x149cc: 0x9000089a,  # adrp x26, data-page for encrypted ASCII table
    0x149e0: 0x9103d35a,  # add x26,x26,#0xf4
    0x14a08: 0x4a0b018b,  # eor w11,w12,w11 (decrypt in-place)
    0x14a0c: 0x38286b4b,  # strb w11,[x26,x8]
    0x14a14: 0xf1017d1f,  # cmp x8,#0x5f = 95 chars
    0x5a388: 0x9104e508,  # add x8,x8,#0x139 (table index origin)
    0x5a38c: 0x39405509,  # table[0x15]
    0x5a398: 0x39405109,  # table[0x14]
    0x5a3a0: 0x39400909,  # table[0x02]
    0x5a3a8: 0x39402909,  # table[0x0a]
    0x5a3b0: 0x39403d09,  # table[0x0f]
    0x5a3b8: 0x39400108,  # table[0x00]
    0x5a3bc: 0x39017bff,  # zero terminator at sp+0x5e
    0x5a3f4: 0x52800401,  # mov w1,#0x20 (pipe descriptor formatter)
    0x5a404: 0x97fee2bf,  # formatter for the pipe descriptor
    0x5a40c: 0x97fed471,  # strdup of formatted pipe descriptor
    0x5a410: 0xf9420eb5,  # ldr x21,[x21,#0x418] (runtime context)
    0x5a4f4: 0x910382b6,  # add x22,x21,#0xe0 (runtime Java entry candidate)
    0x5a570: 0x528d4ca8,  # mov w8,#0x6a65
    0x5a574: 0x72a00e08,  # movk w8,#0x70
    0x5a588: 0x528d2c48,  # mov w8,#0x6962 ('bi')
    0x5a590: 0x52800dc8,  # mov w8,#0x6e ('n')
    0x5a59c: 0x72a7aca8,  # movk w8,#0x3d65 ('e=')
    0x5a664: 0x528c8cc8,  # mov w8,#0x6466 ('fd')
    0x5a66c: 0x52800e68,  # mov w8,#0x73 ('s')
    0x5a684: 0x5285a5a9,  # mov w9,#0x2d2d ('--')
    0x5a68c: 0x72ad8cc9,  # movk w9,#0x6c66 ('fl')
    0x5a694: 0x528cec29,  # mov w9,#0x6761 ('ag')
    0x5a6dc: 0x913acc00,  # add x0,x0,#0xeb3 (CLASSPATH)
    0x5a6e8: 0x97fed32a,  # bl setenv@plt
    0x5a598: 0x528dac28,  # mov w8,#0x6d61 (appended 'ame=')
    0x5a5a4: 0xb9015be8,  # str w8,[sp,#0x158]
    0x5a658: 0x97ff2a63,  # bl sprintf-like checked formatter
    0x5a6d4: 0x97ff2a44,  # bl checked formatter for last '0'
    0x5a6ec: 0xf9400fe6,  # ldr x6,[sp,#0x18] (strdup pipe-fd text)
    0x5a6f0: 0x911603e0,  # x0 = app_process pathname
    0x5a6f4: 0x911603e1,  # x1 = argv0
    0x5a6f8: 0x910183e2,  # x2 = /system/bin
    0x5a6fc: 0x9116c3e3,  # x3 = --nice-name=zygote
    0x5a700: 0x9102c3e5,  # x5 = --write-fd
    0x5a704: 0x910263e7,  # x7 = --flags
    0x5a708: 0xaa1603e4,  # x4 = x22 (runtime main class candidate)
    0x5a70c: 0xa9007ff5,  # [sp] = x21 (string '0'), [sp+8] = NULL
    0x5a710: 0x97fed438,  # bl execl@plt
}
ASCII_DATA_VA = 0x1240f4
ASCII_KEY_VA = 0xf4de5
ZYGOTE_SOURCE_INDEXES = (0x15, 0x14, 0x02, 0x0a, 0x0f, 0x00)


def elf_file_offset(elf, address):
    """Translate address through on-disk ELF PT_LOAD; no VA=file assumptions."""
    if elf[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected ELF64")
    phoff = struct.unpack_from("<Q", elf, 32)[0]
    entsize, count = struct.unpack_from("<HH", elf, 54)
    if entsize != 56:
        raise ValueError("Unexpected ELF program header stride")
    hits = []
    for i in range(count):
        typ, flags, off, va, pa, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", elf, phoff + i*entsize)
        if typ == 1 and va <= address < va + filesz:
            filepos = off + address - va
            if filepos < len(elf):
                hits.append(filepos)
    if len(hits) != 1:
        raise ValueError(f"Unmapped or ambiguous file VA {address:#x}")
    return hits[0]


def decode_table(elf):
    """Recreate the original JNI_OnLoad 95-byte XOR transform."""
    where = elf_file_offset(elf, ASCII_DATA_VA)
    keypos = elf_file_offset(elf, ASCII_KEY_VA)
    key = elf[keypos:keypos+3]
    raw = elf[where:where+95]
    table = bytes(ch ^ key[i % 3] for i, ch in enumerate(raw))
    if table != bytes(range(32, 127)):
        raise ValueError("Original ASCII table not recovered")
    return table


def decode_argv(elf):
    for addr, word in INSTRUCTIONS.items():
        actual = struct.unpack_from("<I", elf, elf_file_offset(elf, addr))[0]
        if actual != word:
            raise ValueError(f"Original argv instruction changed at {addr:#x}")
    if bl_target(elf, 0x5a710) != 0xf7f0:
        raise ValueError("Original execl PLT branch changed")
    chars = decode_table(elf)
    table_base = 0x45  # 0x124139 - 0x1240f4, as in the instruction addresses
    nice_value = bytes(chars[table_base + i] for i in ZYGOTE_SOURCE_INDEXES)
    if nice_value != b"zygote":
        raise ValueError("Runtime ASCII table selected value diverged")
    def literal(at, expected):
        if elf[elf_file_offset(elf, at):elf_file_offset(elf, at)+len(expected)] != expected:
            raise ValueError("Original argv literal diverged at "+hex(at))
    for where, value in ((0xefdc0,b"/system/"),
                         (0xefdc8,b"--nice-n"),
                         (0xefdd0,b"--write-"),
                         (0xf0801,b"%s%s\x00"),
                         (0xffc4a,b"%d\x00"),
                         (0xf1eb3,b"CLASSPATH\x00")):
        literal(where,value)
    # Original MOV/STR append constants (little endian): "bin", "ame=",
    # "fd", "--fl" + "ag" + "s" (--flags), and integer format "0".
    cmd_dir = b"/system/" + b"bin"
    nice = b"--nice-n" + b"ame=" + nice_value
    write_flag = b"--write-" + b"fd"
    flags = b"--fl" + b"ag" + b"s"
    if (cmd_dir,nice,write_flag,flags) != (
            b"/system/bin",b"--nice-name=zygote",b"--write-fd",b"--flags"):
        raise ValueError("Process argument reconstruction changed")
    # x4 is sourced from x21+0xe0, runtime-owned state: its value is unknown.
    original_path = app_process_path(elf)
    return {
        "path": original_path,
        "execl_elf_va": "0x5a710",
        "arguments": [
            {"source": "x0", "value": "/system/bin/app_process", "role": "path"},
            {"source": "x1", "value": "/system/bin/app_process", "role": "argv0"},
            {"source": "x2", "value": cmd_dir.decode(), "role": "cmd_dir"},
            {"source": "x3", "value": nice.decode(), "role": "nice_name"},
            {"source": "x4", "value": None, "role": "runtime_java_entry_pointer",
             "derivation": "x21 + 0xe0"},
            {"source": "x5", "value": write_flag.decode(), "role": "write_fd_option"},
            {"source": "x6", "value": None, "role": "pipe_fd_decimal_string",
             "derivation": "format pipe write descriptor then strdup"},
            {"source": "x7", "value": flags.decode(), "role": "flags_option"},
            {"source": "stack[0]", "value": "0", "role": "flags_value"},
            {"source": "stack[8]", "value": None, "role": "variadic_terminator"}
        ],
        "runtime_ascii_table": "95 bytes from space through tilde",
        "note": ("Original byte-verified argument construction only. "
                 "The Java entry pointer and pipe FD vary at runtime. "
                 "JNI_OnLoad -> fork control-flow reachability not yet proven.")
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path,
                        help="Pinned original APK / diagnostic ZIP")
    args = parser.parse_args()
    outer = args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(outer)) as archive:
        if "apks/01-base.apk" in archive.namelist():
            outer = archive.read("apks/01-base.apk")
    if hashlib.sha256(outer).hexdigest() != APK_SHA:
        raise ValueError("Original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(outer)) as archive:
        inner, metadata = recover(
            archive.read("lib/arm64-v8a/libDexHelper.so"), SAMPLES["libDexHelper.so"])
    print(json.dumps({
        "inner_sha256": metadata["inner_sha256"],
        "analysis": decode_argv(inner)
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
