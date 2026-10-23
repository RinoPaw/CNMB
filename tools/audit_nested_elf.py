#!/usr/bin/env python3
"""Audit encrypted *inner* ELF files in pinned China Mobile 12.5.5.

Original APK or diagnostics ZIP only. Decodes in memory; never writes binary
payloads, original RC4 keys, or device private data to the public repository.
No runtime execution or DEC-caller attribution is claimed.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

APK_SHA = "6282d2cf05f76f37a60fff322bcf0d6f1d876829e5c9c4eae5cdd93b7a972a83"
SAMPLES = {
    "libDexHelper.so": {
        "outer_sha": "6b5abe051e75d630d5447785d1f1a9f480b2c636f2874a7494767cfcde2ac4db",
        "params": 0x5008, "start": 0x8000,
        "inner_sha": "b0d42eb0d86a7fdd3c4e5669c46376d0d4c041da5adb3f5d0e3ccbe9f369ef54",
        "jni_va": 0x148cc, "jni_size": 10096, "phnum": 8, "shnum": 26,
    },
    "libdexjni.so": {
        "outer_sha": "f567dde1e581483f7da6680d87183b522493b5109f19ea27bf388fd80aec9199",
        "params": 0x3008, "start": 0x4000,
        "inner_sha": "cb2a9ebd1a40fd7d0e42557c029ea1fa0405c487dd11b5bf1b10a5aea372b950",
        "jni_va": 0x2eac, "jni_size": 148, "phnum": 6, "shnum": 20,
    },
}
CALLS = {
    "fork": (0xf200, (0x1b440, 0x1e610, 0x1e738, 0x5a418, 0x5a4c4,
                       0x602ac, 0x60c04)),
    "execl": (0xf7f0, (0x5a710,)),
}


# Exact original ARM64 instructions in the unnamed inner ELF code region.
SPAWN_FLOW_WORDS = {
    0x5a3d0: 0x97fed204, # bl pipe@plt
    0x5a418: 0x97fed37a, # bl fork@plt
    0x5a428: 0x34000480, # cbz w0 -> child
    0x5a454: 0x97fed4f3, # bl waitpid@plt
    0x5a4c4: 0x97fed34f, # bl fork@plt
    0x5a4e4: 0x35007b20, # cbnz w0 -> parent
    0x5a6f0: 0x911603e0, # add x0,sp,#0x580 (path)
    0x5a6f4: 0x911603e1, # add x1,sp,#0x580 (argv0)
    0x5a710: 0x97fed438, # bl execl@plt
}



def rc4_start(ciphertext, key):
    """Return precisely the RC4-decoded first 64 bytes, no retained key."""
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % 16]) & 255
        box[i], box[j] = box[j], box[i]
    i = j = 0
    output = bytearray()
    for value in ciphertext[:64]:
        i = (i + 1) & 255
        j = (j + box[i]) & 255
        box[i], box[j] = box[j], box[i]
        output.append(value ^ box[(box[i] + box[j]) & 255])
    return output


def recover(original, conf):
    if hashlib.sha256(original).hexdigest() != conf["outer_sha"]:
        raise ValueError("Unexpected original outer SO hash")
    p = struct.unpack_from("<7I", original, conf["params"])
    start, end = p[0], p[-1]
    if start != conf["start"] or end <= start + 64 or end + 20 > len(original):
        raise ValueError("Original inner ELF bounds changed")
    if original[end + 17:end + 20] != b"\x00\x00\x00":
        raise ValueError("Unexpected original transform metadata")
    key = original[end:end + 16]
    mask = original[end + 16]
    output = bytearray(v ^ mask for v in original[start:end])
    output[:64] = rc4_start(original[start:start + 64], key)
    inner = bytes(output)
    if hashlib.sha256(inner).hexdigest() != conf["inner_sha"]:
        raise ValueError("Full inner ELF SHA-256 mismatch")
    return inner, {
        "inner_file_bytes": len(inner),
        "inner_sha256": conf["inner_sha"],
        "outer_inner_start": hex(start),
        "outer_inner_end": hex(end),
        "first_header_64_bytes": "RC4 stream",
        "remaining_bytes": "single-byte XOR from original trailer",
    }


def inner_symbols(elf, hdr):
    shoff, stride, count = hdr[6], hdr[11], hdr[12]
    sections = [struct.unpack_from("<IIQQQQIIQQ", elf, shoff + stride*i)
                for i in range(count)]
    result = {}
    for sect in sections:
        if sect[1] not in (2, 11):
            continue
        strings = sections[sect[6]]
        if strings[1] != 3 or strings[4]+strings[5] > len(elf):
            raise ValueError("Invalid string table link")
        values = elf[strings[4]:strings[4]+strings[5]]
        width = sect[9]
        if width != 24 or sect[4] + sect[5] > len(elf):
            raise ValueError("Invalid dynamic or static symbol table")
        for offset in range(sect[4], sect[4]+sect[5], width):
            sid, info, other, sec, value, size = struct.unpack_from(
                "<IBBHQQ", elf, offset)
            if sid >= len(values):
                raise ValueError("Invalid symbol name index")
            end = values.find(b"\x00", sid)
            if end < 0:
                raise ValueError("Unterminated symbol")
            label = values[sid:end].decode("utf-8", "replace")
            if label:
                result[label] = {"value": value, "size": size, "section": sec}
    return result


def bl_target(elf, address):
    w = struct.unpack_from("<I", elf, address)[0]
    if w >> 26 != 0b100101:
        raise ValueError("Expected original BL at " + hex(address))
    disp = w & 0x3ffffff
    if disp & (1<<25):
        disp -= 1<<26
    return address + 4*disp


def app_process_path(elf):
    # Exact transformation of 0x5a538..0x5a654 instructions (inner ELF):
    # byte 0 '/', add 16 literal vector bytes, subtract six more offsets.
    data = bytearray(elf[0xf1e8f:0xf1e8f+24])
    increment = elf[0xf0030:0xf0030+16]
    data[0] = ord("/")
    for i in range(16):
        data[i+1] = (data[i+1] + increment[i]) & 255
    for i, step in enumerate((3,1,2,3,1,2)):
        data[i+17] = (data[i+17] - step) & 255
    if bytes(data) != b"/system/bin/app_process\x00":
        raise ValueError("Process executable string changed")
    return data[:-1].decode()


def inspect(elf, conf, library):
    if elf[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Invalid recovered ELF header")
    hdr = struct.unpack_from("<16sHHIQQQIHHHHHH", elf)
    if (hdr[1],hdr[2],hdr[8],hdr[9],hdr[10],hdr[11],hdr[12]) != (
            3, 183, 64, 56, conf["phnum"], 64, conf["shnum"]):
        raise ValueError("Invalid recovered inner ELF structure")
    if hdr[5]+56*hdr[10]>len(elf) or hdr[6]+64*hdr[12]>len(elf):
        raise ValueError("Recovered ELF tables outside file")
    for i in range(hdr[10]):
        ph = struct.unpack_from("<IIQQQQQQ", elf, hdr[5]+56*i)
        if ph[2]+ph[5] > len(elf):
            raise ValueError("Inner program segment outside file")
    symbols=inner_symbols(elf,hdr)
    jni=symbols.get("JNI_OnLoad")
    if not jni or (jni["value"],jni["size"]) != (
            conf["jni_va"],conf["jni_size"]) or not jni["section"]:
        raise ValueError("Recovered JNI_OnLoad export does not match original evidence")
    result={
        "inner_arch": "ELF64 / AArch64",
        "program_header_count": hdr[10],
        "section_header_count": hdr[12],
        "JNI_OnLoad": {"address":hex(conf["jni_va"]), "size":conf["jni_size"],
                       "declared_end":hex(conf["jni_va"]+conf["jni_size"])},
    }
    if library=="libDexHelper.so":
        calls={}
        for name,(dest,sites) in CALLS.items():
            imp=symbols.get(name)
            if imp is None or imp["section"]!=0:
                raise ValueError("Expected original import not found: "+name)
            for site in sites:
                if bl_target(elf,site)!=dest:
                    raise ValueError("Original "+name+" callsite changed")
            calls[name]=[hex(site) for site in sites]
        if any(conf["jni_va"] <= site < conf["jni_va"]+conf["jni_size"]
               for _,sites in CALLS.values() for site in sites):
            raise ValueError("Callsites unexpectedly inside JNI_OnLoad bounds")
        for at, expected in SPAWN_FLOW_WORDS.items():
            if struct.unpack_from("<I", elf, at)[0] != expected:
                raise ValueError("Changed inner process control flow at "+hex(at))
        for site, dest in ((0x5a3d0,0xebe0),(0x5a454,0xf820)):
            if bl_target(elf,site)!=dest:
                raise ValueError("pipe or waitpid PLT address changed")
        result.update({
            "fork_and_execl_direct_calls":calls,
            "double_fork_pattern_sites":["0x5a418","0x5a4c4"],
            "execl_path": app_process_path(elf),
            "execl_callsite":"0x5a710",
            "fork_execl_inside_declared_JNI_OnLoad":False,
        })
    result["scope"]=("Original static ELF recovery; a direct JNI_OnLoad caller "
                     "or association with DeviceEnvironmentCheck or observed "
                     "Android process PIDs is not established.")
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source",type=Path,help="Pinned original APK or diagnostics ZIP")
    args=p.parse_args()
    data=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if "apks/01-base.apk" in z.namelist():
            data=z.read("apks/01-base.apk")
    if hashlib.sha256(data).hexdigest()!=APK_SHA:
        raise ValueError("Original APK SHA-256 mismatch")
    report=[]
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for lib, conf in SAMPLES.items():
            inner,meta=recover(z.read("lib/arm64-v8a/"+lib),conf)
            report.append({"library":lib,**meta,**inspect(inner,conf,lib)})
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
