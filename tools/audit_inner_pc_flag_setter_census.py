#!/usr/bin/env python3
"""SHA-pinned, read-only census of direct JNI SetStaticObjectField callsites.

For CNMB 12.5.5 original base APK or the original diagnostic ZIP, reconstruct
the nested libDexHelper.so and scan its entire ELF .text section for AArch64
LDR Xt,[Xn,#0x4d0] (JNINativeInterface SetStaticObjectField vtable entry).
Direct callsites are verified against the SecNeo sw/bs PC_FLAG literal and
integer bit-OR instructions. This deliberately DOES NOT exclude indirect
vtable loads, wrappers, reflection, dynamically loaded code, or runtime writes.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, recover
from audit_inner_app_process_argv import decode_table, elf_file_offset
from audit_inner_h_service_lifecycle import (
    PC_FLAG_SW_LOADS, PC_FLAG_BS_LOADS, native_pc_flag_field,
)

PINNED_SHA=SAMPLES["libDexHelper.so"]["inner_sha"]
EXPECTED_TEXT=(0xfa00,0xe0358)
SET_STATIC_FIELD_JNI_OFFSET=0x4d0
EXPECTED_SITES=((0x2c5d8,0xf9426908),(0x2cab8,0xf9426908))
ORR_WORDS=((0x2c4a4,0x320002a3),(0x2c97c,0x321f02c3))
INDIRECT_CALLS=((0x2c5e0,0xd63f0100),(0x2cac0,0xd63f0100))


def word(elf,va):
    return struct.unpack_from("<I",elf,elf_file_offset(elf,va))[0]


def elf_text_range(elf):
    """Derive executable section address and size from real ELF64 headers."""
    if not elf.startswith(b"\x7fELF") or elf[4]!=2 or elf[5]!=1:
        raise ValueError("invalid ELF64 little-endian header")
    shoff=struct.unpack_from("<Q",elf,40)[0]
    shentsize,shnum,shstrndx=struct.unpack_from("<HHH",elf,58)
    if (shentsize!=64 or not 0<shnum<256 or shstrndx>=shnum
            or shoff+shentsize*shnum>len(elf)):
        raise ValueError("invalid ELF section headers")
    sections=[struct.unpack_from("<IIQQQQIIQQ",elf,shoff+i*shentsize)
              for i in range(shnum)]
    strsection=sections[shstrndx]
    string_offset,string_size=strsection[4:6]
    if string_offset+string_size>len(elf):
        raise ValueError("section name table out of bounds")
    strings=elf[string_offset:string_offset+string_size]
    found=[]
    for sh in sections:
        name_start=sh[0]
        if name_start>=len(strings):
            raise ValueError("section name index out of bounds")
        end=strings.find(b"\x00",name_start)
        if end<0:
            raise ValueError("unterminated ELF section name")
        if strings[name_start:end]==b".text":
            name,typ,flags,addr,offset,size,*rest=sh
            if typ!=1 or not flags&4 or addr%4 or size%4 or offset+size>len(elf):
                raise ValueError("invalid executable .text section")
            found.append((addr,size,offset))
    if len(found)!=1 or found[0][:2]!=EXPECTED_TEXT:
        raise ValueError("pinned original executable .text section changed")
    return found[0]


def direct_jni_setter_vtable_loads(elf):
    va,length,off=elf_text_range(elf)
    locations=[]
    for offset in range(off,off+length,4):
        w=struct.unpack_from("<I",elf,offset)[0]
        # ARM64 LDR Xt,[Xn,#imm12*8], any register pair.
        if (w&0xffc00000)==0xf9400000 and ((w>>10)&0xfff)==(
                SET_STATIC_FIELD_JNI_OFFSET//8):
            locations.append((va+offset-off,w))
    return locations


def audit(elf):
    if hashlib.sha256(elf).hexdigest()!=PINNED_SHA:
        raise ValueError("original nested ELF SHA-256 mismatch")
    sites=direct_jni_setter_vtable_loads(elf)
    if sites!=list(EXPECTED_SITES):
        raise ValueError("original direct SetStaticObjectField census changed")
    for pc,expected in (*ORR_WORDS,*INDIRECT_CALLS):
        if word(elf,pc)!=expected:
            raise ValueError("original update flow instruction changed at "+hex(pc))
    chars=decode_table(elf)
    field_sw=native_pc_flag_field(elf,chars,PC_FLAG_SW_LOADS,0,23)
    field_bs=native_pc_flag_field(elf,chars,PC_FLAG_BS_LOADS,8,26)
    if field_sw!=field_bs:
        raise ValueError("original setters use different static fields")
    return {
        "inner_elf_sha256":PINNED_SHA,
        "section":".text",
        "text_va":hex(EXPECTED_TEXT[0]),
        "text_bytes":EXPECTED_TEXT[1],
        "direct_jni_SetStaticObjectField_loads":[hex(pc) for pc,_ in sites],
        "direct_callsite_count":len(sites),
        "shared_field":field_sw,
        "writers":[
            {"native":"sw(Context,int)","set_site":"0x2c5d8",
             "new_value":"incoming integer OR 0x01",
             "guard":"incoming bit0 clear and other sw conditions pass"},
            {"native":"bs(Context,int)","set_site":"0x2cab8",
             "new_value":"incoming integer OR 0x02",
             "guard":"incoming bit1 clear and other bs conditions pass"}],
        "under_original_PC_FLAG_255":"both writers bypassed by native bit guards",
        "limits":(
            "Exhaustive for direct AArch64 64-bit unsigned-offset JNI table "
            "loads in this original ELF .text only. Other instruction forms, "
            "computed offsets, wrappers, alternative native libraries, "
            "reflective writes, dynamic code and observed runtime values "
            "are not covered. No bit-clearing path established.")
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source",type=Path)
    args=p.parse_args()
    raw=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        if "apks/01-base.apk" in z.namelist():
            raw=z.read("apks/01-base.apk")
    if hashlib.sha256(raw).hexdigest()!=APK_SHA:
        raise ValueError("original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        elf,_=recover(z.read("lib/arm64-v8a/libDexHelper.so"),
                      SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(elf),ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
