#!/usr/bin/env python3
"""Trace the pinned inner DexHelper MessagePack config boolean at +0x4a.

Read-only and standard-library only. Reconstructs the original inner ELF using
audit_nested_elf and validates the exact JNI parser call sequence, message
encoding, and the bit-0x04 dispatcher dependency. Prints no embedded strings
or proprietary payload bytes. Does not prove the runtime config was unchanged.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, bl_target, recover
from audit_inner_app_process_argv import elf_file_offset

CONFIG_STREAM_VA = 0x12415b
XOR_BYTE = 0xac
# ABI and parser instruction observations in original inner ELF.
WORDS = {
    0x14afc: 0x900000a2,  # adrp x2, 0x28000
    0x14b08: 0x91056c21,  # add x1,x1,#0x15b => blob VA 0x12415b
    0x14b0c: 0x911c3042,  # add x2,x2,#0x70c => decoder 0x2870c
    0x14b10: 0x910103e0,  # add x0,sp,#0x40
    0x14b14: 0xaa1f03e3,  # x3=0, decoder context
    0x14c24: 0x91012ac1,  # add x1,x22,#0x4a destination
    0x85ce4: 0x39000268,  # strb w8,[x19] after decoding typed boolean
    0x28758: 0x4f05e580,  # vector XOR 0xac for 32-byte batches
    0x2878c: 0x5280158a,  # scalar XOR mask 0xac
    0x28798: 0x4a0a016b,  # eor w11,w11,w10
    0x1e014: 0x39412909,  # ldrb w9,[x8,#0x4a] separate later config read
    0x1e084: 0x1a8b0149,  # csel w9,w10,w11,eq
    0x1e458: 0x39002013,  # strb w19,[x0,#8] dispatcher flag
    0x4b484: 0x927e0288,  # and x8,x20,#4
    0x4b48c: 0xf8687a68,  # ldr x8,[table,x8,lsl#3]
}
# Each input item is consumed by one decoder call. For a bin value,
# separate length and data readers are accounted for by the binary tag.
FIELD_CALLS = (
    (0x14b34,0x85c9c,"bool"),  # x22+0x0c
    (0x14b40,0x85c9c,"bool"),  # x22+0x14
    (0x14b4c,0x856ac,"int"),   # x22+0x18
    (0x14b58,0x85c9c,"bool"),  # x22+0x1c
    (0x14b64,0x856ac,"int"),   # stack
    (0x14b70,0x856ac,"int"),   # stack
    (0x14b8c,0x85c9c,"bool"),  # x22+0x24
    (0x14b98,0x85c9c,"bool"),  # x22+0x25
    (0x14ba4,0x85c9c,"bool"),  # x22+0x26
    (0x14bb0,0x85c9c,"bool"),  # x22+0x27
    (0x14bbc,0x85c9c,"bool"),  # x22+0x28
    (0x14bc8,0x85ec4,"binary"),# x22+0x2c length
    (0x14bf4,0x85c9c,"bool"),  # x22+0x38
    (0x14c00,0x85ec4,"binary"),# x22+0x3c length
    (0x14c2c,0x85c9c,"bool"),  # x22+0x4a
)
EXTRA_BLOCK_READS = ((0x14be8,0x85f54), (0x14c20,0x85f54))
EXPECTED_SCALARS = (
    ("bool",True),("bool",False),("int",16392),
    ("bool",False),("int",0),("int",0),("bool",False),
    ("bool",True),("bool",False),("bool",False),("bool",True),
    ("binary",1),("bool",True),("binary",44),("bool",True),
)


def parse_prefix(encoded, count=len(FIELD_CALLS), mask=XOR_BYTE):
    """Small, deliberately restricted MessagePack scalar reader.

    Returns only types, primitive numeric/bool values, and opaque bin lengths.
    It cannot return any embedded private or proprietary string.
    """
    data = bytes(v ^ mask for v in encoded)
    at = 0
    fields = []
    for _ in range(count):
        start = at
        if at >= len(data):
            raise ValueError("Truncated MessagePack field prefix")
        opcode=data[at]
        at+=1
        if opcode in (0xc2,0xc3):
            kind,val="bool",opcode==0xc3
        elif opcode == 0xcd:
            if at+2>len(data):
                raise ValueError("Truncated uint16 field")
            kind,val="int",int.from_bytes(data[at:at+2],"big")
            at+=2
        elif opcode <= 0x7f:
            kind,val="int",opcode
        elif opcode == 0xcc:
            if at>=len(data):
                raise ValueError("Truncated uint8 field")
            kind,val="int",data[at]
            at+=1
        elif opcode == 0xc4:
            if at>=len(data):
                raise ValueError("Truncated binary length")
            width=data[at]
            at+=1
            if at+width>len(data):
                raise ValueError("Truncated binary payload")
            kind,val="binary",width
            at+=width
        else:
            raise ValueError(f"Unexpected MessagePack field opcode {opcode:#x}")
        fields.append((start,at,kind,val))
    return fields


def audit(inner):
    for addr, word in WORDS.items():
        off=elf_file_offset(inner,addr)
        if struct.unpack_from("<I",inner,off)[0]!=word:
            raise ValueError(f"Original instruction mismatch at {addr:#x}")
    for site,target,_ in FIELD_CALLS:
        if bl_target(inner,site)!=target:
            raise ValueError(f"Original config scalar decoder branch changed at {site:#x}")
    if bl_target(inner,0x14b28)!=0x8569c:
        raise ValueError("Expected original config decoder initialization")
    for site,target in EXTRA_BLOCK_READS:
        if bl_target(inner,site)!=target:
            raise ValueError("Expected original MessagePack binary payload read")
    src=elf_file_offset(inner,CONFIG_STREAM_VA)
    if src!=0x12015b:
        raise ValueError("Original data VA to file mapping changed")
    fields=parse_prefix(inner[src:src+128])
    actual=tuple((type_,value) for _,_,type_,value in fields)
    if actual!=EXPECTED_SCALARS:
        raise ValueError("Original embedded config field sequence changed")
    start,end,kind,val=fields[-1]
    if (start,end,kind,val)!=(63,64,"bool",True):
        raise ValueError("Config +0x4a boolean value/position changed")
    # On the normal initializer path the nonzero value would set bit 0x04.
    selected=0x20 if val else 0
    return {
        "embedded_config_stream_va":hex(CONFIG_STREAM_VA),
        "embedded_config_file_offset":hex(src),
        "decoder": {"algorithm":"XOR 0xAC (original 0x2870c)",
                    "encoding":"MessagePack scalar/binary prefix"},
        "verified_fields_before_target":14,
        "target_field":{"struct_offset":"0x4a",
                        "jni_parse_callsite":"0x14c2c",
                        "encoded_stream_byte_offset":start,
                        "decoded_msgpack_type":"boolean",
                        "on_disk_value":val},
        "conditional_dispatch":{"normal_initializer_condition":
                                "runtime_config[0x4a] != 0",
                                "callback_flag":"0x04",
                                "callback_slot_if_on_disk_value_used":
                                hex(selected)},
        "evidence_limit":(
            "The embedded original field is true. The later initializer reads "
            "through a separate runtime config pointer; its identity, possible "
            "mutations and actual value at thread dispatch have not yet been "
            "proven. No DEC rule or device-specific PID is attributed.")
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source",type=Path,help="Original hash-pinned APK or diagnostics ZIP")
    args=ap.parse_args()
    data=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if "apks/01-base.apk" in z.namelist():
            data=z.read("apks/01-base.apk")
    if hashlib.sha256(data).hexdigest()!=APK_SHA:
        raise ValueError("Original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        inner,meta=recover(z.read("lib/arm64-v8a/libDexHelper.so"),
                           SAMPLES["libDexHelper.so"])
    print(json.dumps({"inner_sha256":meta["inner_sha256"],
                      "audit":audit(inner)},indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
