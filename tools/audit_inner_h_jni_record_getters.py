#!/usr/bin/env python3
"""Original SecNeo H native read-only record getters and JNI registration.

SHA-pinned CNMB 12.5.5 original APK / private diagnostic ZIP. Recover inner
DexHelper ELF in memory; verify JNI registration and original H DEX signatures.
Do not export original binaries, user file contents, or pretend a DEC caller.
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
from audit_secneo_h_ipc import DEX_SHA, H, metadata, u32, uleb
from audit_inner_h_guard_config import adrp_page

ELF_SHA = SAMPLES["libDexHelper.so"]["inner_sha"]
EXPECTED = {
    "gha": "(Ljava/lang/String;)I",
    "ghc": "(Ljava/lang/String;)J",
}
WORDS = {
    0x17490:0xaa1403e1, # x1 = constructed runtime Java class name
    0x17494:0xf9401908, # FindClass, JNIEnv table +0x30
    0x17498:0xd63f0100,
    0x174a8:0xf9405508, # NewGlobalRef, table +0xa8
    0x174ac:0xd63f0100,
    0x174b0:0xf900b2c0, # publish class ref in runtime instance +0x160
    0x16010:0xf940b115, # same instance +0x160 -> x21
    0x160cc:0x911103ea, # first method descriptor buffer sp+0x440
    0x160f4:0xf90023e9, # first method name pointer [sp+0x40]
    0x1610c:0x910103e2, # JNINativeMethod array at sp+0x40
    0x16118:0x528000c3, # six methods in this registration
    0x16120:0xaa1503e1, # same class x21
    0x160f8:0x90000109, # address of first JNI callback page
    0x16104:0x911e9129, # add 0x7a4 -> 0x367a4
    0x161c0:0xa904a7ea, # first method signature and callback ptr
    0x161c4:0x90000109, # second JNI callback page
    0x161d0:0x911d43ea, # second method descriptor buffer sp+0x750
    0x161ec:0xf9002ff6, # second method name pointer [sp+0x58]
    0x161d4:0x91205129, # add 0x814 -> 0x36814
    0x1629c:0xa90627ea, # second method signature and callback ptr
    0x164f4:0xf9400288,
    0x164f8:0xf9435d08, # JNIEnv->RegisterNatives +0x6b8
    0x164fc:0xd63f0100,
    0x367c8:0xf942a508, # GetStringUTFChars, +0x548
    0x367e4:0x2a0003f6, # status read result w22 <- w0
    0x367f0:0xf942a908, # ReleaseStringUTFChars, +0x550
    0x367f8:0xd63f0100,
    0x367fc:0x12001ec0, # return status low 8 bits
    0x36834:0xf942a508, # GetStringUTFChars
    0x36848:0xb9000fff, # initialize output marker slot to 0
    0x36860:0xf942a908, # ReleaseStringUTFChars
    0x36864:0xd63f0100,
    0x36868:0xb9400fe0, # return low 32 bits of marker (zero-extended)
}
# LDRB W8,[X28,#imm] where X28 points 8 bytes into original printable ASCII table
METHOD_TEXT_SITES = (
    (0x160c4,0x160f0,3,"gha"),
    (0x16100,0x161b8,21,"(Ljava/lang/String;)I"),
    (0x161cc,0x161e4,3,"ghc"),
    (0x161f4,0x16294,21,"(Ljava/lang/String;)J"),
)


def word(elf, va):
    return struct.unpack_from("<I",elf,elf_file_offset(elf,va))[0]


def method_text(elf, table, start, end, expected_count):
    letters = []
    for pc in range(start,end+1,4):
        instruction = word(elf,pc)
        if instruction & 0xffc003ff != 0x39400388:
            continue
        index = 8 + ((instruction >> 10) & 0xfff)
        if index >= len(table):
            raise ValueError("original JNI literal index exceeds table")
        letters.append(table[index])
    if len(letters) != expected_count:
        raise ValueError("unexpected JNI literal load count")
    return bytes(letters).decode("ascii")


def dex_declarations(dex):
    if (hashlib.sha256(dex).hexdigest()!=DEX_SHA or len(dex)!=21820):
        raise ValueError("original classes.dex hash/length mismatch")
    strings,types,methods=metadata(dex)
    wanted={(H,name,proto) for name,proto in EXPECTED.items()}
    found={}
    count=u32(dex,0x60)
    base=u32(dex,0x64)
    for c in range(count):
        start=base+32*c
        if types[u32(dex,start)]!=H:
            continue
        pos=u32(dex,start+24)
        sizes=[]
        for _ in range(4):
            size,pos=uleb(dex,pos);sizes.append(size)
        for _ in range(sizes[0]+sizes[1]):
            _,pos=uleb(dex,pos);_,pos=uleb(dex,pos)
        for total in sizes[2:]:
            mid=0
            for _ in range(total):
                inc,pos=uleb(dex,pos)
                flags,pos=uleb(dex,pos)
                code_offset,pos=uleb(dex,pos)
                mid+=inc
                if mid>=len(methods):
                    raise ValueError("invalid DEX method index")
                meth=methods[mid]
                if meth in wanted:
                    if flags!=0x109 or code_offset!=0 or meth in found:
                        raise ValueError("invalid original H native declaration")
                    found[meth]={"method_idx":mid,"access_flags":"0x109",
                                 "code_off":code_offset}
    if set(found)!=wanted:
        raise ValueError("original H native declarations absent")
    # A no-direct-call observation is strictly scoped to the small original
    # classes.dex. Other runtime DEX, reflection and native invocation excluded.
    calls=0
    for c in range(count):
        pos=u32(dex,base+32*c+24)
        sizes=[]
        for _ in range(4):
            size,pos=uleb(dex,pos);sizes.append(size)
        for _ in range(sizes[0]+sizes[1]):
            _,pos=uleb(dex,pos);_,pos=uleb(dex,pos)
        for total in sizes[2:]:
            mid=0
            for _ in range(total):
                inc,pos=uleb(dex,pos);mid+=inc
                _,pos=uleb(dex,pos)
                code_off,pos=uleb(dex,pos)
                if not code_off:
                    continue
                size=u32(dex,code_off+12)
                if code_off+16+size*2>len(dex):
                    raise ValueError("DEX code bounds")
                code=dex[code_off+16:code_off+16+size*2]
                for offset in range(0,len(code)-5,2):
                    if code[offset] in (*range(0x6e,0x73),*range(0x74,0x79)):
                        target=struct.unpack_from("<H",code,offset+2)[0]
                        if target in (found[key]["method_idx"] for key in found):
                            calls+=1
    return found,calls


def audit(elf,dex):
    if hashlib.sha256(elf).hexdigest()!=ELF_SHA:
        raise ValueError("original inner ELF SHA-256 mismatch")
    for at,expected in WORDS.items():
        if word(elf,at)!=expected:
            raise ValueError("original JNI machine word changed at "+hex(at))
    for site,target in ((0x367dc,0x2682c),(0x3684c,0x2682c)):
        if bl_target(elf,site)!=target:
            raise ValueError("original native record reader call changed")
    for page_site,add_site,target in (
        (0x160f8,0x16104,0x367a4),
        (0x161c4,0x161d4,0x36814),
    ):
        base=adrp_page(word(elf,page_site),page_site)
        immediate=(word(elf,add_site)>>10)&0xfff
        if base+immediate!=target:
            raise ValueError("original JNI registration callback mismatch")
    ascii_table=decode_table(elf)
    texts=[method_text(elf,ascii_table,start,end,n)
           for start,end,n,expected in METHOD_TEXT_SITES]
    if texts!=[entry[3] for entry in METHOD_TEXT_SITES]:
        raise ValueError("original registered method name or signature changed")
    declared,base_calls=dex_declarations(dex)
    return {
        "apk_sha256":APK_SHA,
        "classes_dex_sha256":DEX_SHA,
        "inner_elf_sha256":ELF_SHA,
        "registration":{
            "default_java_class":"com.secneo.apkwrapper.H",
            "class_from":"0x17490 FindClass runtime-selected name; 0x174b0 stores global ref at instance+0x160",
            "class_ref_used":"0x16010 reads instance+0x160 into x21",
            "register_natives":"0x164f8/0x164fc JNIEnv RegisterNatives",
            "registration_count":6,
            "runtime_class_name_override_possible":True,
        },
        "record_getters":{
            "gha":{"descriptor":texts[1],"native_function":"0x367a4",
                   "read_record_call":"0x367dc -> 0x2682c",
                   "returns":"record status low byte (w0 & 0xff)",
                   "dex_method_idx":declared[(H,"gha",EXPECTED["gha"])]["method_idx"]},
            "ghc":{"descriptor":texts[3],"native_function":"0x36814",
                   "read_record_call":"0x3684c -> 0x2682c",
                   "returns":"zero-extended 32-bit hex record marker via output pointer",
                   "dex_method_idx":declared[(H,"ghc",EXPECTED["ghc"])]["method_idx"]},
        },
        "original_base_dex_direct_invoke_candidates":base_calls,
        "scope":"Native registration and Java-accessible record getters verified statically. No proof of their actual invocations from dynamically loaded DEX or any DEC consumer."
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source",type=Path)
    args=p.parse_args()
    data=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if "apks/01-base.apk" in z.namelist():
            data=z.read("apks/01-base.apk")
    if hashlib.sha256(data).hexdigest()!=APK_SHA:
        raise ValueError("original APK hash mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        dex=z.read("classes.dex")
        elf,_=recover(z.read("lib/arm64-v8a/libDexHelper.so"),
                      SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(elf,dex),ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
