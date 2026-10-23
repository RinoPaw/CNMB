#!/usr/bin/env python3
"""Verify original nested DexHelper fallback Java class for app_process.

Decodes the original 95-byte ASCII lookup table and ARM64 LDRB/STRB instructions
to recover the fallback Java class. Runtime configuration can override it.
No binary, secrets or runtime argv data is written to the repository.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, recover, bl_target
from audit_inner_app_process_argv import elf_file_offset, decode_table

CHAR_LOAD_SITES = (
    0x17328,0x17330,0x17338,0x17340,0x17348,0x17350,
    0x17358,0x17360,0x17368,0x17370,0x17378,0x17380,
    0x17388,0x17390,0x17398,0x173a0,0x173a8,0x173b0,
    0x173b8,0x173c0,0x173c8,0x173d0,0x173dc,
)
WORDS = {
    0x17078: 0x5280d000,  # mov w0,#0x680 (runtime heap object size)
    0x1708c: 0xf9020f60,  # str x0,[x27,#0x418] (allocated instance)
    0x17304: 0xf9420f76,  # ldr x22,[x27,#0x418]
    0x17314: 0xb000087c,  # adrp x28, 0x124000
    0x17318: 0x91040f9c,  # add x28,x28,#0x103, ASCII table
    0x173e4: 0x39041fff,  # strb wzr,[sp,#0x107] NUL
    0x173ec: 0xf9400129,  # ldr x9,[x9] runtime config ptr
    0x173f0: 0xb942012a,  # ldr w10,[x9,#0x200] override length
    0x173f8: 0xf9410534,  # ldr x20,[x9,#0x208] override pointer
    0x1740c: 0x9103c3f4,  # fallback x20=sp+0xf0
    0x17418: 0x91000689,  # add x9,x20,#1
    0x17438: 0x390382c8,  # strb w8,[x22,#0xe0]
    0x1743c: 0x910386c8,  # add x8,x22,#0xe1
    0x17484: 0x3903811f,  # terminate heap+0xe0+length
    0x5a040: 0x90000695,  # adrp x21,0x12a000
    0x5a410: 0xf9420eb5,  # ldr x21,[x21,#0x418]
    0x5a4f4: 0x910382b6,  # add x22,x21,#0xe0
    0x5a708: 0xaa1603e4,  # mov x4,x22
    0x5a710: 0x97fed438,  # bl execl@PLT
}
TABLE_BASE_INDEX=0x124103-0x1240f4
EXPECTED_DEFAULT="com/secneo/apkwrapper/H"


def decode_class_from_code(inner):
    table=decode_table(inner)
    output=bytearray()
    for index,site in enumerate(CHAR_LOAD_SITES):
        insn=struct.unpack_from("<I",inner,elf_file_offset(inner,site))[0]
        if (insn & 0xffc003e0)!=0x39400380:
            raise ValueError(f"Unexpected original LDRB at {site:#x}")
        rt=insn & 31
        char_index=TABLE_BASE_INDEX+((insn>>10)&0xfff)
        if char_index>=len(table):
            raise ValueError("Original ASCII table index outside range")
        output.append(table[char_index])
        store_site=site+(12 if site==0x173dc else 4)
        store=struct.unpack_from("<I",inner,elf_file_offset(inner,store_site))[0]
        if (store & 0xffc003e0)!=0x390003e0:
            raise ValueError(f"Unexpected original STRB at {store_site:#x}")
        if (store & 31)!=rt or ((store>>10)&0xfff)!=0xf0+index:
            raise ValueError("Class byte store position/register mismatch")
    result=output.decode("ascii")
    if result!=EXPECTED_DEFAULT:
        raise ValueError("Original fallback class content changed")
    return result


def audit(inner):
    for address,word in WORDS.items():
        actual=struct.unpack_from("<I",inner,elf_file_offset(inner,address))[0]
        if actual!=word:
            raise ValueError(f"Original entry flow instruction changed {address:#x}")
    if bl_target(inner,0x17080)!=0xf7b0:
        raise ValueError("Original instance allocation target changed")
    if bl_target(inner,0x5a710)!=0xf7f0:
        raise ValueError("Original execl target changed")
    entry=decode_class_from_code(inner)
    return {
        "fallback_java_main_internal_name":entry,
        "fallback_java_main_dot_name":entry.replace("/","."),
        "construction":{
            "load_instruction_count":len(CHAR_LOAD_SITES),
            "decoded_table":"ASCII printable 0x20..0x7e",
            "local_stack_buffer":"sp+0xf0..sp+0x107",
            "runtime_instance_alloc":"malloc(0x680) at 0x17080",
            "runtime_instance_slot_va":"0x12a418",
            "runtime_instance_class_offset":"0xe0",
            "copy_code":"0x17438..0x17484"
        },
        "runtime_override":{
            "length_from_runtime_config":"[cfg+0x200], 0x173f0",
            "string_ptr_from_runtime_config":"[cfg+0x208], 0x173f8",
            "uses_fallback_when":"override missing or empty",
            "actual_runtime_override_observed":False
        },
        "execl":{
            "same_instance_load":"0x5a410",
            "class_argument_address":"0x5a4f4",
            "argument_register":"x4, 0x5a708",
            "call":"execl at 0x5a710"
        },
        "limit":("Original default and heap-object address propagation verified; "
                 "the runtime override may change the executed main class. "
                 "No on-device argv capture or DEC-caller proof.")
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source",type=Path,help="SHA-pinned original APK or diagnostic ZIP")
    args=p.parse_args()
    data=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if "apks/01-base.apk" in z.namelist():
            data=z.read("apks/01-base.apk")
    if hashlib.sha256(data).hexdigest()!=APK_SHA:
        raise ValueError("Original APK digest mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        inner,meta=recover(z.read("lib/arm64-v8a/libDexHelper.so"),
                           SAMPLES["libDexHelper.so"])
    print(json.dumps({"inner_sha256":meta["inner_sha256"],
                      "audit":audit(inner)},ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
