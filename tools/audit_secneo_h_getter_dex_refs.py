#!/usr/bin/env python3
"""Audit SecNeo H.gha/ghc symbolic caller surface in 14 pinned DEX fragments.

The 14 fragments are metadata/carved code inside original libdatajar.so.
Require SHA-pinned original CNMB 12.5.5 base APK (or original diagnostic ZIP).
Count complete recovered string/type/method tables; absence of a DEX owner
descriptor rules out direct symbolic invoke of that exact owner *within these
fragments*. It cannot rule out runtime-generated DEX, other encrypted data,
reflection, dynamically assembled names, or JNI/native callers.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA
from carve_all_dex import (STRING_TABLES, EXPECTED_CLASSES, carve, dex_string)
from inspect_dec_tables import SO_HASH

OWNER = "Lcom/secneo/apkwrapper/H;"
METHOD_NAMES = frozenset({"gha", "ghc"})
TARGET_STRINGS = frozenset({OWNER, *METHOD_NAMES})
DEC_OWNERS = frozenset({
    "Lcom/a/b/c/DECApp;",
    "Lcom/a/b/c/DeviceEnvironmentCheck;",
})
EXPECTED_TOTAL_CLASSES = 101716
EXPECTED_FRAGMENTS = 14


def summarize_fragment(data, f, visible):
    """Inspect a validated carved metadata table; no instruction guesses."""
    pointers, types = f["pointers"], f["types"]
    string_refs = {}
    for sid, pointer in enumerate(pointers):
        decoded = dex_string(data, pointer)
        if decoded in TARGET_STRINGS:
            string_refs[decoded] = sid

    found_types = {}
    for tid, sid in enumerate(types):
        decoded = dex_string(data, pointers[sid])
        if decoded == OWNER or decoded in DEC_OWNERS:
            found_types[decoded] = {
                "type_id": tid,
                "class_defined": tid in f["defined"],
            }

    exact_method_refs = []
    partial_name_refs = 0
    for mid in range(f["methods"]):
        cls, proto, name_sid = struct.unpack_from(
            "<HHI", data, f["method_offset"] + 8*mid)
        if name_sid not in (string_refs.get("gha"), string_refs.get("ghc")):
            continue
        partial_name_refs += 1
        owner_name = dex_string(data, pointers[types[cls]])
        if owner_name == OWNER:
            exact_method_refs.append({
                "method_idx": mid,
                "method_name": dex_string(data, pointers[name_sid]),
                "proto_idx": proto,
            })

    return {
        "fragment": hex(visible),
        "class_definitions": f["classes"],
        "type_ids": len(types),
        "method_ids": f["methods"],
        "strings": len(pointers),
        "H_owner_descriptor": OWNER in found_types,
        "exact_getter_names_in_string_table": sorted(
            METHOD_NAMES.intersection(string_refs)),
        "H_getter_method_ids": exact_method_refs,
        "any_owner_getter_name_refs": partial_name_refs,
        "DEC_types": {
            name: values for name, values in found_types.items()
            if name in DEC_OWNERS
        },
    }


def census(so):
    if hashlib.sha256(so).hexdigest() != SO_HASH:
        raise ValueError("original libdatajar.so SHA-256 mismatch")
    if len(STRING_TABLES) != EXPECTED_FRAGMENTS:
        raise ValueError("fragment inventory unexpectedly changed")
    results = [
        summarize_fragment(so, carve(so, visible, count), visible)
        for visible, count in zip(STRING_TABLES, EXPECTED_CLASSES)
    ]
    total_classes = sum(r["class_definitions"] for r in results)
    if total_classes != EXPECTED_TOTAL_CLASSES:
        raise ValueError("original 14-fragment class census changed")
    refs = sum(len(r["H_getter_method_ids"]) for r in results)
    present = sum(bool(r["H_owner_descriptor"]) for r in results)
    getter_strings = sum(len(r["exact_getter_names_in_string_table"])
                         for r in results)
    if (refs, present, getter_strings) != (0, 0, 0):
        raise ValueError("pinned original getter-reference evidence changed")
    return {
        "original_libdatajar_sha256": SO_HASH,
        "fragments": len(results),
        "validated_class_definitions": total_classes,
        "scanned_string_entries": sum(r["strings"] for r in results),
        "scanned_type_ids": sum(r["type_ids"] for r in results),
        "scanned_method_ids": sum(r["method_ids"] for r in results),
        "H_owner_type_occurrences": present,
        "H_getter_exact_method_references": refs,
        "gha_ghc_exact_string_occurrences": getter_strings,
        "per_fragment": results,
        "conclusion": (
            "No direct symbolic invoke of Lcom/secneo/apkwrapper/H;->gha/ghc "
            "can be encoded using these 14 recovered method/type tables. "
            "This conclusion is only for the validated metadata fragments."
        ),
        "limits": (
            "Unrecovered or runtime-loaded/generated code, runtime reflection, "
            "native callers and later configurations remain outside scope. "
            "Does not locate or exclude a DEC caller elsewhere."
        ),
    }


def load_so(source):
    archive = source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(archive)) as outer:
        if "apks/01-base.apk" in outer.namelist():
            archive = outer.read("apks/01-base.apk")
    if hashlib.sha256(archive).hexdigest() != APK_SHA:
        raise ValueError("original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as apk:
        return apk.read("lib/arm64-v8a/libdatajar.so")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path, help="original APK or diagnostic ZIP")
    args = p.parse_args()
    print(json.dumps(census(load_so(args.source)),
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
