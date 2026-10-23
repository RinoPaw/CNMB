#!/usr/bin/env python3
"""Original-only audit of libDexHelper/dexjni ELF hash fallback and reloc writes.

Static evidence. Identical minus-0x2000 native bootstrap validated through
SHA-256-pinned SOs. Original APK/diagnostic ZIP never exported.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_dexhelper_plt import APK_SHA, LIB_SHA, parse_elf, bl_target

# Exact ARM64 words from libDexHelper. libdexjni uses a -0x2000 VA shift.
HASH_WORDS = {
    0x2bf8: 0xd10043ff, # sub sp,sp,#0x10
    0x2c78: 0x39400002, # ldrb w2,[x0]
    0x2c84: 0x0b011041, # add w1,w2,w1,lsl#4
    0x2c88: 0x38401c02, # ldrb w2,[x0,#1]!
    0x2c8c: 0x12040c23, # and w3,w1,#0xf0000000
    0x2c90: 0x4a010061, # eor w1,w3,w1
    0x2c94: 0x4a436021, # eor w1,w1,w3,lsr#24
    0x2c9c: 0x2a0103e0, # mov w0,w1
    0x2ca4: 0xd65f03c0, # ret
}
FALLBACK_WORDS = {
    0x2e28: 0x97fffeda, # bl dlerror PLT (0x2990)
    0x2e34: 0x97fffef7, # bl strstr PLT (0x2a10)
    0x2e3c: 0xf94002fc, # ldr x28,[x23] [module symbol resolver context]
    0x2e44: 0xf9406396, # ldr x22,[x28,#0xc0] string table
    0x2e48: 0xf9406794, # ldr x20,[x28,#0xc8] symbol table
    0x2e50: 0xb940d382, # ldr w2,[x28,#0xd0] nbucket
    0x2e58: 0x1ac20801, # udiv w1,w0,w2
    0x2e5c: 0x1b028020, # msub w0,w1,w2,w0 => hash % nbucket
    0x2e60: 0xb8607863, # ldr w3,[x3,x0,lsl#2] bucket index
    0x2e88: 0xb8626a80, # ldr w0,[x20,x2] st_name
    0x2e90: 0x97ffff04, # bl strcmp PLT (0x2aa0)
    0x2e98: 0x39403340, # ldrb w0,[x26,#0xc] (ELF st_info)
    0x2eac: 0x79401f40, # ldrh w0,[x26,#0xe] (ELF st_shndx)
}
RELOC_WRITE_WORDS = {
    0x2fc8: 0xf8246873, # str x19,[x3,x4] (ABS/PREL)
    0x2ff0: 0xf8236853, # str x19,[x2,x3] (ABS)
    0x3018: 0xf8216840, # str x0,[x2,x1] (RELATIVE)
    0x3030: 0xf8216813, # str x19,[x0,x1] (GLOB_DAT/JUMP_SLOT)
}
RELOC_CONDITIONS = {
    0x2f00: 0x7104173f, # cmp w25,#0x105
    0x2f18: 0x71041b3f, # cmp w25,#0x106
    0x2fd0: 0x7104073f, # cmp w25,#0x101
    0x2ff8: 0x71100b3f, # cmp w25,#0x402
    0x3000: 0x71100f3f, # cmp w25,#0x403
    0x2f0c: 0x7110073f, # cmp w25,#0x401
}
ERROR_PREFIX = b"symbol found but not global:\x00"


def sysv_elf_hash(name):
    """ELF System V hash, independent pure-Python reference implementation."""
    if isinstance(name, str):
        name = name.encode("utf-8")
    h = 0
    for byte in name:
        h = ((h << 4) + byte) & 0xffffffff
        high = h & 0xf0000000
        if high:
            h ^= high >> 24
        h &= ~high
    return h


def audit_one(image, name):
    if hashlib.sha256(image).hexdigest() != LIB_SHA[name]:
        raise ValueError("Original SO SHA-256 mismatch: " + name)
    shift = -0x2000 if name == "libdexjni.so" else 0
    at, tags = parse_elf(image)
    for va, word in {**HASH_WORDS, **FALLBACK_WORDS,
                     **RELOC_CONDITIONS, **RELOC_WRITE_WORDS}.items():
        actual = struct.unpack_from("<I", image, at(va+shift))[0]
        if actual != word:
            raise ValueError(f"Original instruction changed: {name} {va+shift:#x}")
    if image[at(0x49d8+shift):at(0x49d8+shift)+len(ERROR_PREFIX)] != ERROR_PREFIX:
        raise ValueError("Original dlerror phrase changed")
    for site, destination in ((0x2e4c,0x2bf8), (0x30f0,0x2bf8),
                              (0x2e20,0x2a50), (0x2e28,0x2990),
                              (0x2e34,0x2a10), (0x2e90,0x2aa0)):
        if bl_target(image, at(site+shift)) != at(destination+shift):
            raise ValueError(f"BL target changed: {name} {site+shift:#x}")
    if tags.get(4) is None or tags.get(5) is None or tags.get(6) is None:
        raise ValueError("Missing ELF DT_HASH/STRTAB/SYMTAB")
    hash_pos = at(tags[4])
    buckets, chains = struct.unpack_from("<II", image, hash_pos)
    expected = (197,239) if name == "libDexHelper.so" else (17,29)
    if (buckets,chains) != expected:
        raise ValueError("Unexpected original hash table dimensions")
    bucket_pos=hash_pos+8
    chain_pos=bucket_pos+4*buckets
    bucket_values=struct.unpack_from(f"<{buckets}I",image,bucket_pos)
    chain_values=struct.unpack_from(f"<{chains}I",image,chain_pos)
    if any(bucket_values) or any(chain_values):
        raise ValueError("Original hash entries unexpectedly nonzero")
    return {
        "library":name,
        "elf_hash_function_va":hex(0x2bf8+shift),
        "hash_call_sites":[hex(x+shift) for x in (0x2e4c,0x30f0)],
        "error_text":ERROR_PREFIX[:-1].decode(),
        "fallback_uses_dlerror_strstr_sysv_hash_and_strcmp":True,
        "relocation_writes_verified":{hex(k+shift):hex(v) for k,v in RELOC_WRITE_WORDS.items()},
        "original_DT_HASH_va":hex(tags[4]),
        "original_DT_HASH_bucket_count":buckets,
        "original_DT_HASH_chain_count":chains,
        "nonzero_on_disk_buckets":sum(bool(v) for v in bucket_values),
        "nonzero_on_disk_chains":sum(bool(v) for v in chain_values),
        "boundary":("Hash entries belong to the original on-disk ELF. This does not "
                    "prove the process uses unchanged hash tables at runtime. "
                    "The fallback's module context is loaded dynamically; no "
                    "evidence connects it to DEC root checking or Java worker spawn.")
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path,help="Original pinned APK or diagnostic ZIP")
    args=parser.parse_args()
    raw=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        if "apks/01-base.apk" in z.namelist():
            raw=z.read("apks/01-base.apk")
    if hashlib.sha256(raw).hexdigest()!=APK_SHA:
        raise ValueError("Original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        result=[audit_one(z.read("lib/arm64-v8a/"+name),name) for name in LIB_SHA]
    print(json.dumps({
        "evidence":result,
        "algorithm_golden_vectors":{
            name:hex(sysv_elf_hash(name)) for name in
            ("printf","dlopen","JNI_OnLoad")
        }
    },indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
