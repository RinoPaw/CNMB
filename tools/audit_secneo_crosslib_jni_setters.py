#!/usr/bin/env python3
"""Cross-library original CNMB 12.5.5 JNI static field writer census.

Recover SecNeo inner ELF payloads in memory from SHA-256 pinned original APK
(or diagnostic ZIP), scan executable PT_LOAD regions including stripped ELF
without .text sections. Raw loads and JNI-shaped candidates are not proof of
writes to any particular field. No device access, patches, binary exports.
"""
import argparse
from collections import Counter
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path
from audit_nested_elf import APK_SHA, SAMPLES, recover

PINNED = {
    "libDexHelper.so": SAMPLES["libDexHelper.so"]["inner_sha"],
    "libdexjni.so": SAMPLES["libdexjni.so"]["inner_sha"],
    "libdexvmp.so": "1003c91df71d44bb8d4e44dd0b89e4d708bf4422d27646863155b58e2ef65cfb",
}
SITES = {
    "libDexHelper.so": ((0x2c5c8, 0x2c5d8, 0x2c5e0),
                        (0x2caa8, 0x2cab8, 0x2cac0)),
    "libdexjni.so": ((0x86388, 0x8638c, 0x863a0),
                     (0x863b4, 0x863bc, 0x863c8)),
    "libdexvmp.so": ((0x6a14c, 0x6a154, 0x6a160),
                     (0x6a240, 0x6a244, 0x6a258)),
}
EXPECTED = {
    "arm64_files": 191,
    "elf_files": 176,
    "non_elf_files": 15,
    "executable_bytes": 92840901,
    "raw_ldr_candidates": 219,
    "jni_shape_candidates": 9,
}


def executable_segments(elf):
    """PT_LOAD SHF_EXEC files, no dependence on missing section headers."""
    if not (elf.startswith(b"\x7fELF\x02\x01") and len(elf) >= 64):
        return None
    phoff = struct.unpack_from("<Q", elf, 32)[0]
    entsize, count = struct.unpack_from("<HH", elf, 54)
    if entsize != 56 or not 0 < count < 200 or phoff + entsize*count > len(elf):
        raise ValueError("invalid original ELF program headers")
    result = []
    for i in range(count):
        typ, flags, off, va, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", elf, phoff + i*entsize)
        if typ == 1 and flags & 1:
            if off + size > len(elf):
                raise ValueError("executable PT_LOAD exceeds original ELF")
            result.append((va, off, size))
    if not result:
        raise ValueError("ELF without executable PT_LOAD")
    return result


def word(elf, va):
    hits = []
    for base, off, size in executable_segments(elf):
        if base <= va < base + size - 3:
            hits.append(struct.unpack_from("<I", elf, off + va - base)[0])
    if len(hits) != 1:
        raise ValueError("unmapped/ambiguous executable machine word")
    return hits[0]


def candidate_sites(elf):
    segments = executable_segments(elf)
    if segments is None:
        return [], 0
    candidates = []
    executable_bytes = 0
    for va, off, size in segments:
        executable_bytes += size
        first = off + (-va) % 4
        last = off + size
        words = [struct.unpack_from("<I", elf, f)[0]
                 for f in range(first, last-3, 4)]
        for idx, insn in enumerate(words):
            # LDR Xt,[Xn,#imm12*8], #0x4d0 is JNI SetStaticObjectField
            # only when Xn actually points to JNIEnv's function table.
            if (insn & 0xffc00000) != 0xf9400000 or (
                    (insn >> 10) & 0xfff) != 154:
                continue
            dst, src = insn & 31, (insn >> 5) & 31
            previous = words[max(0, idx-5):idx]
            following = words[idx+1:idx+10]
            # Narrow signature: source register loaded from [another register]
            # recently, and destination subsequently BLR-called. Heuristic!
            shape = (any((p & 0xfffffc1f) == (0xf9400000 | src)
                         for p in previous)
                     and (0xd63f0000 | (dst << 5)) in following)
            candidates.append((va + first-off + 4*idx, insn, shape))
    return candidates, executable_bytes


def direct_bl_callers(elf, target):
    """Only direct AArch64 BL, not B/BLR/BR or data-pointer callbacks."""
    matches = []
    for va, off, size in executable_segments(elf):
        start = off + (-va) % 4
        for position in range(start, off+size-3, 4):
            insn = struct.unpack_from("<I", elf, position)[0]
            if insn >> 26 != 0b100101:
                continue
            disp = insn & 0x3ffffff
            if disp & (1 << 25):
                disp -= 1 << 26
            site = va + position-off
            if site+disp*4 == target:
                matches.append(site)
    return sorted(matches)


def audit_apk(apk):
    if hashlib.sha256(apk).hexdigest() != APK_SHA:
        raise ValueError("original base APK SHA-256 mismatch")
    counts = Counter()
    executable_bytes = 0
    candidates = 0
    jni_shapes = 0
    focused = {}
    with zipfile.ZipFile(io.BytesIO(apk)) as archive:
        files = [x for x in archive.infolist()
                 if x.filename.startswith("lib/arm64-v8a/")
                 and x.filename.endswith(".so")]
        for entry in files:
            name = entry.filename.rsplit("/", 1)[1]
            elf = archive.read(entry)
            if name in SAMPLES:
                elf, _ = recover(elf, SAMPLES[name])
            if name in PINNED:
                if hashlib.sha256(elf).hexdigest() != PINNED[name]:
                    raise ValueError("original SecNeo library hash changed: " + name)
                focused[name] = elf
            sites, size = candidate_sites(elf)
            if size == 0:
                counts["non_elf_files"] += 1
                continue
            counts["elf_files"] += 1
            executable_bytes += size
            candidates += len(sites)
            jni_shapes += sum(is_jni for _, _, is_jni in sites)
    observed = {
        "arm64_files": len(files),
        "elf_files": counts["elf_files"],
        "non_elf_files": counts["non_elf_files"],
        "executable_bytes": executable_bytes,
        "raw_ldr_candidates": candidates,
        "jni_shape_candidates": jni_shapes,
    }
    if observed != EXPECTED:
        raise ValueError("pinned full-APK executable PT_LOAD census changed")
    for name, site_groups in SITES.items():
        for env_ldr, static_ldr, jni_blr in site_groups:
            if (word(focused[name], env_ldr) != 0xf9400268
                    or word(focused[name], static_ldr) != 0xf9426908
                    or word(focused[name], jni_blr) != 0xd63f0100):
                raise ValueError("native JNI static setter triple changed: "
                                 + name + " " + hex(static_ldr))
    for name, findclass, getfield in (
        ("libdexjni.so", 0x862d4, 0x862e8),
        ("libdexvmp.so", 0x6a1e8, 0x6a1fc),
    ):
        if (word(focused[name], findclass) != 0xf9401908
                or word(focused[name], getfield) != 0xf9424108):
            raise ValueError("generic native FindClass/GetStaticFieldID changed")
    # One concrete direct caller loads its inputs through VM runtime slots.
    # This proves the input is not a fixed literal at this callsite; it does
    # not prove any PC_FLAG target or runtime execution.
    dexjni = focused["libdexjni.so"]
    for pc, insn in ((0x667f8,0xf8687922),  # x2 <- indexed VM table
                     (0x66800,0xaa1403e0),  # x0 <- saved JNIEnv
                     (0x66808,0xf94487e1),  # x1 <- VM stack slot
                     (0x6680c,0x94007e99)): # BL to 0x86270
        if word(dexjni, pc) != insn:
            raise ValueError("original dexjni runtime dispatcher input changed")
    dexjni_callers = direct_bl_callers(dexjni,0x86270)
    dexvmp_callers = direct_bl_callers(focused["libdexvmp.so"],0x6a0a0)
    if dexjni_callers != [0x6680c] or dexvmp_callers:
        raise ValueError("original generic dispatcher direct BL callers changed")
    # This is a GOT load for printf@plt, not JNI. Including PLT in an
    # executable-segment scan creates raw #0x4d0 false positives.
    if word(focused["libDexHelper.so"], 0xec94) != 0xf9426a11:
        raise ValueError("pinned original printf PLT GOT load changed")
    return {
        "apk_sha256": APK_SHA,
        "raw_executable_segment_census": observed,
        "verified_secneo_static_field_calls": {
            name: [hex(site[1]) for site in groups]
            for name, groups in SITES.items()
        },
        "generic_dispatchers": {
            "libdexjni.so": {
                "FindClass": "0x862d4", "GetStaticFieldID": "0x862e8",
                "SetStaticObjectField": ["0x8638c", "0x863bc"],
                "field_selected_at_runtime": True,
            },
            "libdexvmp.so": {
                "FindClass": "0x6a1e8", "GetStaticFieldID": "0x6a1fc",
                "SetStaticObjectField": ["0x6a154", "0x6a244"],
                "field_selected_at_runtime": True,
            },
        },
        "direct_dispatcher_callers": {
            "libdexjni.so": {
                "entry": "0x86270", "direct_BL": ["0x6680c"],
                "JNI_env_source": "0x66800 x0 <- x20",
                "field_descriptor_source": "0x66808 x1 <- [sp+0x908]",
                "new_field_value_source": "0x667f8 x2 <- [x9,x8,lsl#3]",
            },
            "libdexvmp.so": {
                "entry": "0x6a0a0", "direct_BL": [],
                "limit": "No direct BL found; indirect calls/branch dispatch are not excluded.",
            },
        },
        "negative_evidence_boundary": (
            "Original full APK contains generic static-field JNI dispatchers, "
            "but no proof they target H.PC_FLAG or clear flag bits. "
            "Raw #0x4d0 loads include non-JNI struct offsets and PLT GOT; "
            "indirect JNI offsets, reflection, packed binary files and "
            "runtime-generated code are not excluded."),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path)
    args = p.parse_args()
    raw = args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as outer:
        if "apks/01-base.apk" in outer.namelist():
            raw = outer.read("apks/01-base.apk")
    print(json.dumps(audit_apk(raw), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
