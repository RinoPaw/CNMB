#!/usr/bin/env python3
"""Verify original libDexHelper/libdexjni constructors from ELF dynamic RELA.

Read-only SHA-256-pinned 12.5.5 original APK or diagnostic ZIP. A constructor
pointer is evidence of linker configuration, not a runtime trace or proof of
which subsequent Java class was loaded.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

APK_SHA256 = "6282d2cf05f76f37a60fff322bcf0d6f1d876829e5c9c4eae5cdd93b7a972a83"
LIBS = {
    "libDexHelper.so": {
        "hash": "6b5abe051e75d630d5447785d1f1a9f480b2c636f2874a7494767cfcde2ac4db",
        "array": 0x14d08, "fini": 0x14d18, "constructor": 0x4780,
        "destructor": 0x2b10, "rela": 0x26e8,
    },
    "libdexjni.so": {
        "hash": "f567dde1e581483f7da6680d87183b522493b5109f19ea27bf388fd80aec9199",
        "array": 0x12d08, "fini": 0x12d18, "constructor": 0x2780,
        "destructor": 0xb10, "rela": 0x6e8,
    },
}
# Original AArch64 instruction words: constructor recovers ELF header address,
# locates 0x464c457f ('ELF' magic as little-endian 32-bit), then calls PLT.
DEXHELPER_WORDS = {
    0x4780: 0xd100c3ff,  # sub sp,sp,#0x30
    0x4804: 0x90000002,  # adrp x2,...
    0x4808: 0x5288afe0,  # mov w0,#0x457f
    0x4810: 0x72a8c980,  # movk w0,#0x464c,lsl#16
    0x4818: 0xb9400041,  # ldr w1,[x2]
    0x481c: 0x6b00003f,  # cmp w1,w0
    0x4850: 0x97fff878,  # bl relative PLT target
    0x485c: 0x97fff87d,  # bl relative PLT target
}


def inspect(data, name, config):
    if hashlib.sha256(data).hexdigest() != config["hash"]:
        raise ValueError("Original SO hash mismatch: " + name)
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Expected little-endian ELF64/AArch64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, count = struct.unpack_from("<HH", data, 54)
    if phentsize != 56 or phoff+phentsize*count > len(data):
        raise ValueError("Invalid ELF program headers")
    headers = [struct.unpack_from("<IIQQQQQQ", data, phoff+phentsize*i)
               for i in range(count)]

    def file_of(va):
        matching = [p for p in headers
                    if p[0] == 1 and p[3] <= va < p[3]+p[5]
                    and p[2]+va-p[3] < len(data)]
        if len(matching) != 1:
            raise ValueError(f"Unmapped/ambiguous ELF virtual address {va:#x}")
        return matching[0][2] + va - matching[0][3]

    dyns = [p for p in headers if p[0] == 2]
    if len(dyns) != 1:
        raise ValueError("Missing unique PT_DYNAMIC")
    dyn = dyns[0]
    tags = {}
    for pos in range(dyn[2], dyn[2]+dyn[5], 16):
        tag, val = struct.unpack_from("<QQ", data, pos)
        if tag == 0:
            break
        tags[tag] = val
    expected = (config["array"], 16, config["fini"], 16,
                config["rela"], 72, 24)
    if tuple(tags.get(tag) for tag in (25, 27, 26, 28, 7, 8, 9)) != expected:
        raise ValueError("Unexpected INIT_ARRAY/FINI_ARRAY/RELA dynamic tags")

    relas = [struct.unpack_from("<QQq", data, file_of(tags[7])+i)
             for i in range(0, tags[8], tags[9])]
    if (relas[0] != (config["array"], 1027, config["constructor"]) or
            relas[1] != (config["fini"], 1027, config["destructor"])):
        raise ValueError("Original R_AARCH64_RELATIVE relocations changed")
    if (struct.unpack_from("<QQ", data, file_of(config["array"])) != (0, 0)
            or struct.unpack_from("<QQ", data, file_of(config["fini"])) != (0, 0)):
        raise ValueError("Expected zero-valued pre-relocation array entries")
    executable = [p for p in headers
                  if p[0] == 1 and p[1] & 1 and
                  p[3] <= config["constructor"] < p[3]+p[5] and
                  p[3] <= config["destructor"] < p[3]+p[5]]
    if len(executable) != 1:
        raise ValueError("Constructor/destructor not in executable PT_LOAD")
    if name == "libDexHelper.so":
        for addr, expected_word in DEXHELPER_WORDS.items():
            if struct.unpack_from("<I", data, file_of(addr))[0] != expected_word:
                raise ValueError(f"Original constructor instruction changed @ {addr:#x}")
    return {
        "library": name,
        "load_constructor_elf_va": f"0x{config['constructor']:x}",
        "load_constructor_file_offset": f"0x{file_of(config['constructor']):x}",
        "fini_callback_elf_va": f"0x{config['destructor']:x}",
        "init_array_elf_va": f"0x{config['array']:x}",
        "init_array_slots": 2,
        "validated_relative_relocations": [
            {"target_elf_va": f"0x{a:x}", "type": n & 0xffffffff,
             "addend_elf_va": f"0x{v:x}"}
            for a, n, v in relas if n & 0xffffffff == 1027
        ],
        "checks": ("DexHelper constructor finds ELF header and calls two "
                   "PLT stubs" if name == "libDexHelper.so" else
                   "Executable ELF init/fini relocation pointers"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Original pinned APK or diagnostic ZIP")
    args = parser.parse_args()
    raw = args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if "apks/01-base.apk" in archive.namelist():
            raw = archive.read("apks/01-base.apk")
    if hashlib.sha256(raw).hexdigest() != APK_SHA256:
        raise ValueError("Original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        report = [inspect(archive.read("lib/arm64-v8a/"+name), name, config)
                  for name, config in LIBS.items()]
    print(json.dumps({"constructors": report,
                      "limitation": ("Static dynamic-linker metadata only; "
                                     "does not prove execution or DEC caller identity.")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
