#!/usr/bin/env python3
"""Verify six original SecNeo H JNI registrations and sensitive native roles.

Pinned original CNMB 12.5.5 base APK / private diagnostic ZIP. Exact original
DEX and recovered inner ELF SHA-256, machine instruction words and method
descriptors required. No device access or binary extraction to repository.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, recover, bl_target
from audit_inner_app_process_argv import decode_table
from audit_inner_h_guard_config import adrp_page
from audit_inner_h_jni_record_getters import method_text, word
from audit_secneo_h_ipc import DEX_SHA, H, metadata, u32, uleb

# (Name, signature, original JNI target, registered name source, signature source)
METHODS = (
    ("gha", "(Ljava/lang/String;)I", 0x367a4,
     (0x160c4, 0x160f0), (0x16100, 0x161b8)),
    ("ghc", "(Ljava/lang/String;)J", 0x36814,
     (0x161cc, 0x161e4), (0x161f4, 0x16294)),
    ("gah", "()[Ljava/lang/Object;", 0x3687c,
     (0x162a8, 0x162c8), (0x162d0, 0x16380)),
    ("sha", "(Ljava/lang/String;I)V", 0x36f14,
     (0x16384, 0x163ac), (0x163b0, 0x16464)),
    ("he", "(I)V", 0x36f4c,
     (0x1646c, 0x16484), (0x16488, 0x164b0)),
    ("gv", "()I", 0x3714c,
     (0x164b4, 0x164c4), (0x164c8, 0x164e4)),
)
# (ADRP PC, ADD PC, callback VA). Both instructions checked as original words.
POINTER_PAIRS = (
    (0x160f8, 0x16104, 0x367a4),
    (0x161c4, 0x161d4, 0x36814),
    (0x162a0, 0x162b0, 0x3687c),
    (0x1637c, 0x16388, 0x36f14),
    (0x1638c, 0x16390, 0x36f4c),
    (0x164e8, 0x164ec, 0x3714c),
)
PINNED = {
    0x16118:0x528000c3,  # count 6
    0x164f8:0xf9435d08,  # RegisterNatives vtable offset
    0x164fc:0xd63f0100,  # RegisterNatives call
    0x162a0:0x90000109, 0x162b0:0x9121f129,
    0x1637c:0x90000109, 0x16388:0x913c5129,
    0x1638c:0x9000010a, 0x16390:0x913d314a,
    0x164e8:0xb0000108, 0x164ec:0x91053108,
    0x3687c:0xa9ba6ffc,  # gah: file-reading JNI handler
    0x3697c:0x97ff63b9,  # fopen
    0x36a74:0x97ff61d7,  # fgets
    0x36f14:0xf81e0ff3,  # sha
    0x36f30:0xf942a508,  # GetStringUTFChars
    0x36f48:0x17ffbf1e,  # tail b 0x26bc0 (record update)
    0x36f4c:0xd10303ff,  # he
    0x36f64:0x7107e05f,  # compare arg with 0x1f8
    0x36f70:0x7138785f,  # compare arg with 0xe1e
    0x36f84:0x3945f508,  # runtime byte +0x17d
    0x36f88:0x37300828,  # bit 6 guard
    0x3700c:0x3945f108,  # runtime byte +0x17c
    0x37010:0x37000668,  # bit 0 guard
    0x37078:0x97ff5fc6,  # getpid
    0x37080:0x97ffbc2b,  # local helper
    0x37084:0x52800060,  # _exit argument 3
    0x37088:0x97ff5fae,  # _exit
    0x3714c:0x528067c0,  # gv returns 830
    0x37150:0xd65f03c0,  # ret
}


def native_declarations(dex):
    if hashlib.sha256(dex).hexdigest() != DEX_SHA or len(dex) != 21820:
        raise ValueError("original classes.dex SHA-256 mismatch")
    _, types, ids = metadata(dex)
    definitions = {}
    class_count = u32(dex, 0x60)
    defs_base = u32(dex, 0x64)
    for i in range(class_count):
        item = defs_base + i*32
        if types[u32(dex, item)] != H:
            continue
        pos = u32(dex, item+24)
        counts = []
        for _ in range(4):
            n,pos = uleb(dex,pos)
            counts.append(n)
        for _ in range(counts[0]+counts[1]):
            _,pos=uleb(dex,pos)
            _,pos=uleb(dex,pos)
        for amount in counts[2:]:
            mid=0
            for _ in range(amount):
                inc,pos=uleb(dex,pos)
                flags,pos=uleb(dex,pos)
                off,pos=uleb(dex,pos)
                mid+=inc
                definitions[mid]=(flags,off)
    expected_ids=(138,139,135,146,141,140)
    results=[]
    for (name,desc,target,*_), mid in zip(METHODS,expected_ids):
        if ids[mid]!=(H,name,desc):
            raise ValueError("original H native method reference changed")
        flags,code_off=definitions[mid]
        if flags!=(0x10a if name=="he" else 0x109) or code_off!=0:
            raise ValueError("original H native method flags/code changed")
        results.append({"name":name,"signature":desc,"dex_method_idx":mid,
                        "flags":hex(flags),"native_entry":hex(target)})
    return results


def unconditional_branch_target(w,pc):
    if w & 0x7c000000 != 0x14000000:
        raise ValueError("expected original unconditional B")
    disp=w & 0x3ffffff
    if disp & (1<<25):
        disp-=1<<26
    return pc+4*disp


def audit(elf,dex):
    if hashlib.sha256(elf).hexdigest()!=SAMPLES["libDexHelper.so"]["inner_sha"]:
        raise ValueError("original inner ELF SHA-256 mismatch")
    for pc,w in PINNED.items():
        if word(elf,pc)!=w:
            raise ValueError("original JNI instruction mismatch at "+hex(pc))
    for site,dest in ((0x3697c,0xf860),(0x36a74,0xf1d0),
                      (0x37078,0xef90),(0x37080,0x2612c),
                      (0x37088,0xef40)):
        if bl_target(elf,site)!=dest:
            raise ValueError("original call target changed at "+hex(site))
    if unconditional_branch_target(word(elf,0x36f48),0x36f48)!=0x26bc0:
        raise ValueError("original sha tail call changed")
    for page_site,add_site,addr in POINTER_PAIRS:
        page=adrp_page(word(elf,page_site),page_site)
        offset=(word(elf,add_site)>>10)&0xfff
        if page+offset!=addr:
            raise ValueError("original JNI callback address changed")
    chars=decode_table(elf)
    for name,signature,_,name_range,sig_range in METHODS:
        if (method_text(elf,chars,*name_range,len(name)) != name or
                method_text(elf,chars,*sig_range,len(signature)) != signature):
            raise ValueError("original registration name/signature changed")
    decl=native_declarations(dex)
    return {
        "apk_sha256":APK_SHA,
        "classes_dex_sha256":DEX_SHA,
        "inner_elf_sha256":SAMPLES["libDexHelper.so"]["inner_sha"],
        "registration":"0x164f8 RegisterNatives, six methods on H runtime class",
        "methods":decl,
        "native_roles":{
            "gha":"0x367dc calls envc.push reader 0x2682c; returns status",
            "ghc":"0x3684c calls envc.push reader 0x2682c; returns record marker",
            "gah":"0x3697c fopen + 0x36a74 fgets; returns Java Object[]",
            "sha":"0x36f48 tail-branches to record update 0x26bc0",
            "he":"0x36f64/0x36f70 compare argument with 0x1f8/0xe1e; "
                 "0x3700c and 0x36f84 test runtime config bytes, "
                 "with 0x37078..0x37088 process exit pathway",
            "gv":"0x3714c returns 830 (0x33e)",
        },
        "limits":"Native entry binding and static branches verified; no actual "
                 "call count or DEC causality established."
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
    with zipfile.ZipFile(io.BytesIO(raw)) as apk:
        dex=apk.read("classes.dex")
        elf,_=recover(apk.read("lib/arm64-v8a/libDexHelper.so"),
                      SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(elf,dex),ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
