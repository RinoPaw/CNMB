#!/usr/bin/env python3
"""Pinned original SecNeo positive TracerPid follow-up file I/O audit.

Checks instruction and PLT call-sites in original inner DexHelper ELF. Reads
original APK/diagnostic ZIP only, never writes the target filesystem.
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

# Original AArch64 instruction words, confirmed against full nested ELF SHA.
WORDS = {
  0x5af20:0x52800020, 0x5af34:0x97ff2c8e,
  0x5af38:0x340001a0, 0x5af44:0x97ff2e3a,
  0x5af4c:0x54000101, 0x5af60:0x910343e0,
  0x5af64:0x52800021, 0x5af68:0x97ff2f16,
  0x26bec:0x71003c3f, 0x26c04:0x1a89b033,
  0x26d30:0x97ffa0e4, 0x26d44:0x97ffa2c7,
  0x26d5c:0x97ffa2c1, 0x26d68:0x97ffa132,
  0x26d70:0x97ffa1ac, 0x26d94:0x97ffa197,
  0x26e04:0x97ffa0f3, 0x26e44:0x97ffa0e3,
  0x26ebc:0x94000147, 0x26eec:0x9400018d,
  0x26f14:0x97ffa24f, 0x26f2c:0x97ffa271,
  0x26f5c:0x6b08015f, 0x26f80:0x9100054a,
  0x2707c:0x94000399, 0x270d0:0x97ffa208,
  0x270ec:0x94000319, 0x27114:0x14000007,
  0x27130:0x97ffa0b0, 0x27144:0x97ffa1cf,
  0x2714c:0x97ffa011, 0x27154:0x97ff9fff,
  0x26930:0x97ffa3cc, 0x269b0:0x97ffa208,
}
PLT_CALLS = {
  0x26d30:("access",0xf0c0),
  0x26d44:("fopen",0xf860),
  0x26d5c:("fopen",0xf860),
  0x26d68:("fileno",0xf230),
  0x26d70:("flock",0xf420),
  0x26d94:("fseek",0xf3f0),
  0x26e04:("fgets",0xf1d0),
  0x26e44:("fgets",0xf1d0),
  0x26f14:("memset",0xf850),
  0x26f2c:("free",0xf8f0),
  0x270d0:("free",0xf8f0),
  0x27130:("fseek",0xf3f0),
  0x27144:("fwrite",0xf880),
  0x2714c:("fflush",0xf190),
  0x27154:("fclose",0xf150),
  0x26930:("fopen",0xf860),
  0x269b0:("fgets",0xf1d0),
}
INTERNAL_CALLS = {
  0x5af34:0x2616c, 0x5af44:0x2682c, 0x5af68:0x26bc0,
  0x26ebc:0x273d8, 0x26eec:0x27524, 0x2707c:0x27ee0,
  0x270ec:0x27d50
}


def at(elf,va):
    return struct.unpack_from("<I",elf,elf_file_offset(elf,va))[0]


def audit(elf):
    if hashlib.sha256(elf).hexdigest()!=SAMPLES["libDexHelper.so"]["inner_sha"]:
        raise ValueError("inner ELF hash differs from original")
    for va,word in WORDS.items():
        if at(elf,va)!=word:
            raise ValueError(f"original instruction modified at {va:#x}")
    for va,(name,target) in PLT_CALLS.items():
        if bl_target(elf,va)!=target:
            raise ValueError(f"original PLT {name} branch changed at {va:#x}")
    for va,target in INTERNAL_CALLS.items():
        if bl_target(elf,va)!=target:
            raise ValueError(f"internal branch changed at {va:#x}")
    return {
      "inner_elf_sha256":SAMPLES["libDexHelper.so"]["inner_sha"],
      "positive_result_follow_up":{
          "enter":"0x5af18",
          "record_key_builder":"0x2616c (selector 1 -> root)",
          "file_read_or_match_check":"0x2682c",
          "file_update_helper":"0x26bc0",
          "helper_arg_0":"root record key built on stack by 0x2616c; file envc.push assembled separately inside helper",
          "helper_arg_1":"1 (w1 at 0x5af64)",
          "helper_arg_2":"computed value from 0x5af50..0x5af5c"
      },
      "file_update_helper":{
          "entry":"0x26bc0",
          "requires_file_open_and_lock":True,
          "matching_logic":"line reading, transformed candidate data, comparison, conditional update",
          "verified_calls":[{"site":hex(pc),"function":name}
                            for pc,(name,_) in sorted(PLT_CALLS.items())
                            if 0x26bc0<=pc<0x271b4],
          "conditional_write":{
              "fseek":"0x27130","fwrite":"0x27144",
              "fflush":"0x2714c","fclose":"0x27154",
              "branch":"0x270f0/0x27104 determines whether write block is reached",
          },
          "encoding_or_transform_helpers":["0x273d8","0x27524","0x27ee0","0x27d50"]
      },
      "limits":"Verified original conditional envc.push file update path for key root. Runtime directory prefix, actual bytes written, device execution and DEC relationship remain unproven."
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path)
    args=parser.parse_args()
    data=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as outer:
        if "apks/01-base.apk" in outer.namelist():
            data=outer.read("apks/01-base.apk")
    if hashlib.sha256(data).hexdigest()!=APK_SHA:
        raise ValueError("original APK hash mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as apk:
        elf,_=recover(apk.read("lib/arm64-v8a/libDexHelper.so"),
                      SAMPLES["libDexHelper.so"])
    print(json.dumps(audit(elf),ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
