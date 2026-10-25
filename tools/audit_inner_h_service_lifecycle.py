#!/usr/bin/env python3
"""Pinned original SecNeo H SW/BS service lifecycle and Manifest evidence.

Read-only: accept the original China Mobile 12.5.5 APK or private diagnostic ZIP.
Verify original DEX invoke operands, native ARM64 words, JNI service API calls,
and registered Manifest service names. No APK extraction or device modification.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, recover, bl_target
from audit_inner_app_process_argv import decode_table, elf_file_offset
from audit_inner_h_guard_config import adrp_page
from audit_secneo_h_ipc import DEX_SHA, H, metadata, u16, u32
from audit_h_messenger_he_callchain import pin_source, code_items

INNER_SHA = SAMPLES["libDexHelper.so"]["inner_sha"]
# The four additional H JNI natives, separate from the previously
# verified six-method table at 0x164f8.
JNI_CALLBACKS = (
    ("sw", "(Landroid/content/Context;I)V", 0x2c440,
     0x152c4, 0x152c8, 150),
    ("bs", "(Landroid/content/Context;I)Ljava/lang/Object;", 0x2c8d8,
     0x152e0, 0x152e4, 127),
    ("is", "(I)Z", 0x2d158,
     0x1545c, 0x15464, 142),
    ("us", "(Landroid/content/Context;)V", 0x2d178,
     0x1547c, 0x15480, 151),
)
NATIVE_WORDS = {
    0x154a4:0x52800083, # RegisterNatives method count 4
    0x154b4:0xaa1503e1, # same runtime Java class
    0x155e4:0xf9435d08, # JNIEnv +0x6b8 RegisterNatives
    0x155e8:0xd63f0100,
    0x2c464:0xb4002242, # sw: cbz Context
    0x2c46c:0x37002203, # sw: tbnz w3 bit0 -> return
    0x2c468:0x2a0303f5, # sw preserve incoming flags
    0x2c4a4:0x320002a3, # sw formatter arg: incoming flags | 1
    0x2c4b8:0x97ffe2cb, # sw snprintf("%d")
    0x2c4bc:0x900007d7, 0x2c4c0:0x9103d2f7, # x23=printable table
    0x2c5a8:0xf9424108, # sw GetStaticFieldID +0x480
    0x2c5c0:0xf9429d08, # sw NewStringUTF +0x538
    0x2c5d8:0xf9426908, # sw SetStaticObjectField +0x4d0
    0x2c904:0xb4000162, # bs: cbz Context
    0x2c97c:0x321f02c3, # bs formatter arg: incoming flags | 2
    0x2c998:0x97ffe193, # bs snprintf("%d")
    0x2c99c:0x900007da, # bs printable table page
    0x2ca88:0xf9424108, # bs GetStaticFieldID +0x480
    0x2caa0:0xf9429d08, # bs NewStringUTF +0x538
    0x2cab8:0xf9426908, # bs SetStaticObjectField +0x4d0
    0x2c90c:0x37080123, # bs: tbnz w3 bit1 -> return
    0x2c9a0:0x9103f35a, # JNI string table+8
    0x2cc34:0x9103e529, # JNI string table+5
    0x2cc68:0x91010103, # runtime prefix argument object+0x40
    0x2cce0:0x97ffe0c1, # formatted %s/IsoService
    0x2cd14:0xd63f0100, # FindClass target from runtime format
    0x2cd84:0x94000407, # JNI NewObjectV for Intent
    0x2cf10:0xf9408508, # JNIEnv GetMethodID +0x108 bindService
    0x2d004:0x91045508, # JNI string table+0x21
    0x2d0b0:0xf9424108, # JNIEnv GetStaticFieldID +0x480
    0x2d0c8:0xf9425908, # JNIEnv GetStaticIntField +0x4b0
    0x2d0ec:0x97fff4d8, # CallBooleanMethodV wrapper
    0x2a4b8:0xf9409908, # JNIEnv +0x130 CallBooleanMethodV
    0x2d378:0xf9408508, # JNIEnv GetMethodID +0x108 unbindService
    0x2d45c:0xf9424508, # JNIEnv GetStaticObjectField +0x488
    0x2d474:0x97fff3cf, # CallVoidMethodV wrapper
    0x2a41c:0xf940f908, # JNIEnv +0x1f0 CallVoidMethodV
}
# Each group is a linear sequence of original LDRB unsigned offset sites;
# immediate offsets are read from original original AArch64 words.
STRINGS = (
    ("%s/IsoService", (0x2cc5c,0x2cc70,0x2cc84,0x2cc8c,0x2cc94,
                      0x2cc9c,0x2cca4,0x2ccac,0x2ccb4,0x2ccbc,
                      0x2ccc4,0x2cccc,0x2ccd4), 5, 9),
    ("bindService", tuple(range(0x2ce78,0x2cec9,8)), 8, 26),
    ("unbindService",(0x2d2cc,0x2d2dc,0x2d2e4,0x2d2ec,0x2d2f4,
                      0x2d2fc,0x2d304,0x2d30c,0x2d314,0x2d31c,
                      0x2d324,0x2d32c,0x2d334), 8, 22),
    ("BIND_AUTO_CREATE",(0x2d008,0x2d01c,0x2d02c,0x2d034,0x2d03c,
                          0x2d044,0x2d04c,0x2d054,0x2d05c,0x2d064,
                          0x2d06c,0x2d074,0x2d07c,0x2d084,0x2d08c,
                          0x2d094),0x21,8),
)
# Original LDRB W8,[X23/X26,#imm] sites. The different base offsets
# still construct identical field name + JNI descriptor in both functions.
PC_FLAG_SW_LOADS = (0x2c4c4,0x2c4d8,0x2c4e4,0x2c4ec,0x2c4f4,0x2c4fc,
                    0x2c504,0x2c510,0x2c518,0x2c520,0x2c528,0x2c530,
                    0x2c538,0x2c540,0x2c548,0x2c550,0x2c558,0x2c560,
                    0x2c568,0x2c570,0x2c578,0x2c580,0x2c588,0x2c590,
                    0x2c598)
PC_FLAG_BS_LOADS = (0x2c9a4,0x2c9b8,0x2c9c4,0x2c9cc,0x2c9d4,0x2c9dc,
                    0x2c9e4,0x2c9f0,0x2c9f8,0x2ca00,0x2ca08,0x2ca10,
                    0x2ca18,0x2ca20,0x2ca28,0x2ca30,0x2ca38,0x2ca40,
                    0x2ca48,0x2ca50,0x2ca58,0x2ca60,0x2ca68,0x2ca70,
                    0x2ca78)


DEX_WORDS = {
    0x3e18:0x1071, 0x3e1a:0x0083, # AW.onCreate -> H.callSW
    0x3e26:0x1071, 0x3e28:0x0082, # AW.onCreate -> H.callBS
    0x42ec:0x001a, 0x42ee:0x000e, # const-string "255"
    0x42f0:0x0069, 0x42f2:0x000b, # sput-object H.PC_FLAG
    0x4bda:0x0062, 0x4bdc:0x000b, # sget H.PC_FLAG
    0x4bde:0x1071, 0x4be0:0x00bf, # Integer.parseInt
    0x4be6:0x2071, 0x4be8:0x007f, # H.bs
    0x4c36:0x0062, 0x4c38:0x000b, # sget H.PC_FLAG
    0x4c3a:0x1071, 0x4c3c:0x00bf, # Integer.parseInt
    0x4c42:0x2071, 0x4c44:0x0096, # H.sw
    0x424e:0x1071, 0x4250:0x0097, # H.us after reply received
}


def elf_word(data, va):
    return struct.unpack_from("<I",data,elf_file_offset(data,va))[0]


def decoded_indexed_string(elf, ascii_table, sites, base, register):
    chars=[]
    for i,pc in enumerate(sites):
        instruction=elf_word(elf,pc)
        if ((instruction & 0xffc003e0) != (0x39400000 | (register << 5))
                or (instruction & 31) != (9 if i==len(sites)-1 and base==5 else
                                         10 if base==5 else 9 if base==0x21 else 8)):
            raise ValueError("changed original LDRB operands at "+hex(pc))
        index=base+((instruction>>10)&0xfff)
        if not 0<=index<len(ascii_table):
            raise ValueError("original printable table index out of bounds")
        chars.append(ascii_table[index])
    return bytes(chars).decode("ascii")


def native_pc_flag_field(elf, printable, sites, base_index, base_reg):
    """Decode original LDRB instructions specifying the JNI static field."""
    result=[]
    if len(sites)!=25:
        raise ValueError("unexpected original JNI field literal length")
    for site in sites:
        insn=elf_word(elf,site)
        if insn & 0xffc003ff != (0x39400000 | (base_reg<<5) | 8):
            raise ValueError("changed JNI PC_FLAG field LDRB at "+hex(site))
        index=base_index+((insn>>10)&0xfff)
        if not 0<=index<len(printable):
            raise ValueError("original JNI field index outside printable table")
        result.append(printable[index])
    literal=bytes(result).decode("ascii")
    if literal!="PC_FLAGLjava/lang/String;":
        raise ValueError("original PC_FLAG JNI field name/descriptor changed")
    return {"name":literal[:7], "descriptor":literal[7:]}


def native_registration_name(elf, printable, sites):
    # Four original JNINativeMethod names are constructed through LDRB
    # from the original readable ASCII table+8, two characters each.
    characters=[]
    for pc in sites:
        insn=elf_word(elf,pc)
        if ((insn & 0xffc003ff) != 0x39400388):
            raise ValueError("original JNI method-name LDRB changed at "+hex(pc))
        index=8+((insn>>10)&0xfff)
        if index>=len(printable):
            raise ValueError("original JNI method-name index outside table")
        characters.append(printable[index])
    return bytes(characters).decode("ascii")


def bittest(insn,pc):
    if insn & 0x7f000000 != 0x37000000:
        raise ValueError("expected TBNZ")
    index=((insn>>31)<<5)|((insn>>19)&31)
    disp=(insn>>5)&0x3fff
    if disp&0x2000:
        disp-=0x4000
    return ((insn&31), index, pc+disp*4)


def manifest_service_names(xml):
    """Read only android:name attributes of service START_ELEMENT in AXML."""
    if (len(xml)<8 or struct.unpack_from("<H",xml)[0]!=0x0003 or
            struct.unpack_from("<I",xml,4)[0]!=len(xml)):
        raise ValueError("original Android binary XML header invalid")
    strings=[]
    result=[]
    pos=8
    def u16(off):
        if off<0 or off+2>len(xml):raise ValueError("truncated Manifest string")
        return struct.unpack_from("<H",xml,off)[0]
    def u32(off):
        if off<0 or off+4>len(xml):raise ValueError("truncated Manifest chunk")
        return struct.unpack_from("<I",xml,off)[0]
    def encoded_len(at,unit):
        val=u16(at) if unit==2 else xml[at]
        at+=unit
        if val & (0x8000 if unit==2 else 0x80):
            val=((val & (0x7fff if unit==2 else 0x7f))
                 << (16 if unit==2 else 8)) | (u16(at) if unit==2 else xml[at])
            at+=unit
        return val,at
    while pos<len(xml):
        if pos+8>len(xml):raise ValueError("truncated Manifest chunk header")
        typ,header,size=struct.unpack_from("<HHI",xml,pos)
        if header<8 or size<header or pos+size>len(xml):
            raise ValueError("invalid Manifest chunk layout")
        if typ==0x0001:
            n=u32(pos+8)
            flags=u32(pos+16)
            start=u32(pos+20)
            if n>65536 or pos+header+4*n>pos+size:
                raise ValueError("invalid Manifest string pool")
            strings=[]
            for i in range(n):
                start_idx=u32(pos+header+4*i)
                off=pos+start+start_idx
                if off>=pos+size:raise ValueError("string offset outside pool")
                _,off=encoded_len(off,1 if flags&0x100 else 2)
                if flags&0x100:
                    count,off=encoded_len(off,1)
                    if off+count>pos+size:raise ValueError("truncated string")
                    value=xml[off:off+count].decode("utf-8")
                else:
                    count,off=_,off
                    if off+count*2>pos+size:raise ValueError("truncated UTF16")
                    value=xml[off:off+count*2].decode("utf-16le")
                strings.append(value)
        elif typ==0x0102:
            if pos+36>pos+size:raise ValueError("truncated START_ELEMENT")
            name=u32(pos+20)
            attr_start=u16(pos+24)
            width=u16(pos+26)
            count=u16(pos+28)
            if name>=len(strings) or width<20 or pos+16+attr_start+width*count>pos+size:
                raise ValueError("invalid Manifest element attributes")
            if strings[name]=="service":
                names=[]
                for i in range(count):
                    off=pos+16+attr_start+i*width
                    sid=u32(off+4)
                    raw=u32(off+8)
                    vtype=xml[off+15]
                    value=u32(off+16)
                    if sid>=len(strings):raise ValueError("invalid attribute name")
                    if strings[sid]=="name":
                        idx=raw if raw!=0xffffffff else value if vtype==3 else -1
                        if idx<0 or idx>=len(strings):
                            raise ValueError("unresolved service name")
                        names.append(strings[idx])
                if len(names)!=1:raise ValueError("service without unique name")
                result.append(names[0])
        pos+=size
    if not strings or not result:raise ValueError("Manifest service census empty")
    return result


def direct_pc_flag_sites(dex, methods, types):
    """Scoped 16-bit aligned field instruction census within real code_items.

    A scan of syntactically plausible opcode words is deliberately not a
    complete Dalvik disassembler. For each of these pinned source locations
    we independently check the exact instruction with DEX_WORDS.
    """
    results=[]
    for caller,mid,off in code_items(dex,methods,types):
        units=u32(dex,off+12)
        if not 0<units<100000 or off+16+units*2>len(dex):
            raise ValueError("invalid original PC_FLAG code item")
        for pos in range(off+16,off+16+units*2-3,2):
            opcode=u16(dex,pos)&0xff
            if opcode not in (0x62,0x69):
                continue
            if u16(dex,pos+2)==11:
                results.append((pos,opcode))
    results.sort()
    if results!=[(0x42f0,0x69),(0x4bda,0x62),(0x4c36,0x62)]:
        raise ValueError("original direct PC_FLAG field use census changed")
    return {
        "scope":"original base classes.dex 65 code_items; aligned 16-bit field opcode candidates only",
        "direct_writes":["0x42f0 H.<clinit>"],
        "direct_reads":["0x4bda H.callBS","0x4c36 H.callSW"],
        "reflective_native_or_loaded_dex_writes_excluded":True,
    }


def audit(elf,dex,manifest):
    if hashlib.sha256(elf).hexdigest()!=INNER_SHA:
        raise ValueError("original inner ELF SHA-256 mismatch")
    if hashlib.sha256(dex).hexdigest()!=DEX_SHA:
        raise ValueError("original H classes.dex SHA-256 mismatch")
    for pc,w in NATIVE_WORDS.items():
        if elf_word(elf,pc)!=w:raise ValueError("changed original native word "+hex(pc))
    for pc,w in DEX_WORDS.items():
        if u16(dex,pc)!=w:raise ValueError("changed original Java bytecode "+hex(pc))
    strings,types,methods=metadata(dex)
    field_sites=direct_pc_flag_sites(dex,methods,types)
    if (strings[14]!="255" or methods[127] !=
            (H,"bs","(Landroid/content/Context;I)Ljava/lang/Object;")):
        raise ValueError("original PC_FLAG or bs declaration changed")
    for name,signature,address,page_site,add_site,idx in JNI_CALLBACKS:
        if methods[idx]!=(H,name,signature):
            raise ValueError("original registered H method changed")
        page=adrp_page(elf_word(elf,page_site),page_site)
        offset=(elf_word(elf,add_site)>>10)&0xfff
        if page+offset!=address:
            raise ValueError("original JNI callback pointer changed")
    ascii_table=decode_table(elf)
    static_field_sw=native_pc_flag_field(
        elf,ascii_table,PC_FLAG_SW_LOADS,0,23)
    static_field_bs=native_pc_flag_field(
        elf,ascii_table,PC_FLAG_BS_LOADS,8,26)
    if static_field_sw!=static_field_bs:
        raise ValueError("sw/bs JNI field names differ")
    if elf[elf_file_offset(elf,0xffc4a):elf_file_offset(elf,0xffc4a)+3] != b"%d\x00":
        raise ValueError("original PC_FLAG integer formatter changed")
    if (bl_target(elf,0x2c4b8)!=0x24fe4
            or bl_target(elf,0x2c998)!=0x24fe4):
        raise ValueError("PC_FLAG snprintf call changed")
    for expected,sites,base,reg in STRINGS:
        actual=decoded_indexed_string(elf,ascii_table,sites,base,reg)
        if actual!=expected:raise ValueError("original decoded JNI literal changed")
    for expected,sites in (("sw",(0x152d8,0x152ec)),
                           ("bs",(0x153fc,0x1540c)),
                           ("is",(0x15474,0x15488)),
                           ("us",(0x154d8,0x154e4))):
        if native_registration_name(elf,ascii_table,sites)!=expected:
            raise ValueError("original JNI registered method name changed")
    if (bittest(elf_word(elf,0x2c46c),0x2c46c)!=(3,0,0x2c8ac)
            or bittest(elf_word(elf,0x2c90c),0x2c90c)!=(3,1,0x2c930)):
        raise ValueError("original native PC_FLAG guard changed")
    for pc,target in ((0x2cce0,0x24fe4),(0x2cd84,0x2dda0),
                      (0x2d0ec,0x2a44c),(0x2d474,0x2a3b0)):
        if bl_target(elf,pc)!=target:
            raise ValueError("original native JNI call target changed")
    # Cross-check Java Message sender/receiver to avoid claiming a Service
    # instance just from an unexecuted construction instruction.
    messenger=pin_source(dex)
    services=manifest_service_names(manifest)
    if len(services)!=78:
        raise ValueError("original base Manifest service declaration count changed")
    iso=[name for name in services if name.endswith("IsoService")]
    if iso:
        raise ValueError("original base Manifest now declares IsoService")
    return {
        "original_inner_elf_sha256":INNER_SHA,
        "original_classes_dex_sha256":DEX_SHA,
        "default_flag":"255 (0xff) from H.<clinit> at 0x42ec",
        "native_pc_flag_updates":{
            "field":static_field_sw,
            "sw":{
                "formatter":"0x2c4a4 (incoming flags | 1) -> snprintf('%d')",
                "field_lookup":"0x2c5a8 JNIEnv.GetStaticFieldID",
                "new_string":"0x2c5c0 JNIEnv.NewStringUTF",
                "write":"0x2c5d8 JNIEnv.SetStaticObjectField",
                "precondition":"original flag bit0 clear, runtime byte +0xc nonzero, process identity check returns zero"
            },
            "bs":{
                "formatter":"0x2c97c (incoming flags | 2) -> snprintf('%d')",
                "field_lookup":"0x2ca88 JNIEnv.GetStaticFieldID",
                "new_string":"0x2caa0 JNIEnv.NewStringUTF",
                "write":"0x2cab8 JNIEnv.SetStaticObjectField",
                "precondition":"original flag bit1 clear, process identity check returns zero, runtime byte +0xc nonzero"
            },
            "under_initial_flag_255":"both corresponding bit guards return before either write",
            "other_writers_unexcluded":True,
        },
        "PC_FLAG_base_dex_direct_field_sites":field_sites,
        "java_callers":{
            "H.callSW":"Integer.parseInt(H.PC_FLAG) -> H.sw(Context,int)",
            "H.callBS":"Integer.parseInt(H.PC_FLAG) -> H.bs(Context,int)",
            "H_a.handleMessage":"H.us(Context) when sApp!=null before H.he(arg2)",
            "H_static_initializer":"creates H.sConnection SecNeo b",
        },
        "native_register_natives":{
            "count":4,
            "methods":[{"method":n+sig,"entry":hex(addr)}
                       for n,sig,addr,*_ in JNI_CALLBACKS],
            "register_natives":"0x155e4/0x155e8",
        },
        "default_bits":{
            "sw":{
                "guard":"0x2c46c TBNZ w3 bit0",
                "default_bit":1,"early_return":"0x2c8ac",
            },
            "bs":{
                "guard":"0x2c90c TBNZ w3 bit1",
                "default_bit":1,"early_return":"0x2c930",
            },
        },
        "original_bind_path":{
            "target_java_class_format":"%s/IsoService",
            "class_prefix_source":"runtime context object +0x40",
            "intent_construction":"JNI NewObjectV at 0x2cd84",
            "method":"Context.bindService",
            "flag":"Context.BIND_AUTO_CREATE",
            "method_wrapper":"0x2d0ec -> CallBooleanMethodV",
            "reachable_under_PC_FLAG_255":False,
            "service_declared_in_base_manifest":False,
        },
        "original_unbind_path":{
            "method":"Context.unbindService",
            "service_connection":"H.sConnection",
            "method_wrapper":"0x2d474 -> CallVoidMethodV",
            "java_call_site":"H$a.handleMessage at 0x424e",
        },
        "manifest_service_declaration_count":len(services),
        "messenger_receiver":"Message.what == 1000, H.he(Message.arg2)",
        "limitations":(
            "Original default flag gates both sw and bs. Runtime flag may "
            "change; bound Service location/availability, reply arg2 and "
            "on-device execution are unproven. No direct DEC attribution.")
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path)
    args=parser.parse_args()
    raw=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as outer:
        if "apks/01-base.apk" in outer.namelist():
            raw=outer.read("apks/01-base.apk")
    if hashlib.sha256(raw).hexdigest()!=APK_SHA:
        raise ValueError("original APK hash mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as apk:
        elf,_=recover(apk.read("lib/arm64-v8a/libDexHelper.so"),
                      SAMPLES["libDexHelper.so"])
        print(json.dumps(audit(elf,apk.read("classes.dex"),
                               apk.read("AndroidManifest.xml")),
                         ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
