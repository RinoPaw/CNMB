#!/usr/bin/env python3
"""Verify original inner ELF callback-table -> pthread_create -> fork/exec.

Read-only; original APK SHA256 and inner ELF SHA256 checked by the decoder.
No decoded commercial ELF is written or uploaded. This proves a static
registration/call path, not JNI_OnLoad runtime reachability or DEC linkage.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA, SAMPLES, recover, bl_target
from audit_inner_app_process_argv import decode_argv

# Address values for pinned *inner* ELF, never for the outer wrapper.
REGISTRATION = {
    0x1e3d4: 0xb0000876,  # adrp x22, 0x12b000
    0x1e3d8: 0x911002d6,  # add x22,x22,#0x400
    0x1e3f0: 0x90000188,  # adrp x8,0x4e000
    0x1e3f4: 0x91072108,  # add x8,x8,#0x1c8 -> 0x4e1c8
    0x1e3f8: 0xf90012c8,  # str x8,[x22,#0x20] (global callback table)
}
# JNI-invoked initializer creates the dispatcher thread and forwards a
# configuration struct whose byte +8 selects the callback-table slot.
INITIALIZER_THREAD = {
    0x1e458: 0x39002013,  # strb w19,[x0,#8] (per-worker flag byte)
    0x1e4e0: 0xb0000162,  # adrp x2, page 0x4b000
    0x1e4e4: 0x910ef042,  # add x2,x2,#0x3bc -> 0x4b3bc
    0x1e4ec: 0xaa1f03e1,  # default pthread attrs
    0x1e4f0: 0xaa1403e3,  # x3=x20 (worker context)
    0x1e4f4: 0x97ffc1c3,  # bl pthread_create@plt
    0x1e518: 0xaa1503e2,  # retry x2=x21 (same dispatcher)
    0x1e51c: 0xaa1403e3,  # retry same context
    0x1e520: 0x97ffc1b8,  # retry pthread_create@plt
}
# Dispatcher thread at 0x4b3bc tests flag bit 0x04, then loads slot +0x20.
CALLBACK_DISPATCH = {
    0x4b3e8: 0x97ff0de2,  # initial sleep(1)
    0x4b3f0: 0x39402274,  # ldrb w20,[x19,#8] configuration byte
    0x4b480: 0x90000713,  # adrp x19, 0x12b000
    0x4b484: 0x927e0288,  # and x8,x20,#0x4
    0x4b488: 0x91100273,  # add x19,x19,#0x400 global callback table
    0x4b48c: 0xf8687a68,  # ldr x8,[x19,x8,lsl#3]; if bit4 -> +0x20
    0x4b490: 0x910043e0,  # x0=sp+0x10 (callback data)
    0x4b494: 0xd63f0100,  # blr x8
}
THREAD_CREATION = {
    0x4fff0: 0xd0000042,  # adrp x2,0x59000
    0x4fff4: 0x911c0042,  # add x2,x2,#0x700 -> worker at 0x59700
    0x4fff8: 0x911d03e0,  # add x0,sp,#0x740 (pthread_t)
    0x4fffc: 0xaa1f03e1,  # mov x1,xzr (default thread attrs)
    0x50000: 0xaa1f03e3,  # mov x3,xzr (thread argument)
    0x50004: 0x97fefaff,  # bl pthread_create@plt 0xec00
    0x5000c: 0xb0000053,  # retry: adrp x19,0x59000
    0x50014: 0x911c0273,  # retry: add x19,x19,#0x700
    0x50028: 0xaa1303e2,  # retry: mov x2,x19
    0x50030: 0x97fefaf4,  # retry: bl pthread_create@plt
}
WORKER_START = {
    0x59700: 0xa9ba6ffc,  # distinct ARM64 thread entry function prologue
    0x59728: 0x52800040,  # mov w0,#2
    0x59738: 0x97fed50e,  # bl sleep@plt (initial 2-second sleep)
}
FDE_EXPECTED = {
    0x788: (0x148cc, 0x1703c),   # JNI_OnLoad
    0x1cc8: (0x4e1c8, 0x50354),  # pthread_create callsites
    0x1fb0: (0x59700, 0x5b45c),  # fork/execl worker
    0x32c8: (0x1df7c, 0x249d0),  # JNI-invoked callback-table initializer
    0x1c18: (0x4b3bc, 0x4b768),  # first dispatcher pthread entry
}
JNI_CALL_REGISTRATION = {
    0x16990: 0x94001d7b,  # JNI_OnLoad BL 0x1df7c
}
EH_FRAME_FILE_OFFSET = 0x1063a0
TEXT_RANGE = (0xfa00, 0xefd58)


def verify_fdes(elf):
    """Decode pcrel/sdata4 FDE first-location directly from original .eh_frame."""
    found = {}
    for relative_offset, expected in FDE_EXPECTED.items():
        rec = EH_FRAME_FILE_OFFSET + relative_offset
        length, cie_delta, displacement, size = struct.unpack_from(
            "<IIiI", elf, rec)
        start = rec + 8 + displacement
        end = start + size
        if length != (0x34 if relative_offset == 0x32c8 else 0x2c) or not cie_delta or (start, end) != expected:
            raise ValueError("Original FDE changed at "+hex(relative_offset))
        found[hex(relative_offset)] = [hex(start), hex(end)]
    return found


def direct_bl_callers(elf, target):
    hits = []
    for position in range(*TEXT_RANGE, 4):
        op = struct.unpack_from("<I", elf, position)[0]
        if op >> 26 != 0b100101:
            continue
        disp = op & 0x3ffffff
        if disp & 0x2000000:
            disp -= 0x4000000
        if position + 4*disp == target:
            hits.append(position)
    return hits


def verify(elf):
    for address, word in {**JNI_CALL_REGISTRATION, **REGISTRATION,
                          **INITIALIZER_THREAD, **CALLBACK_DISPATCH,
                          **THREAD_CREATION, **WORKER_START}.items():
        if struct.unpack_from("<I", elf, address)[0] != word:
            raise ValueError("Changed native callback/thread instruction: "+hex(address))
    for position, target in (
        (0x1e4f4, 0xec00), (0x1e520, 0xec00),
        (0x4b3e8, 0xeb70),
        (0x50004, 0xec00), (0x50030, 0xec00),
        (0x59738, 0xeb70)):
        if bl_target(elf, position) != target:
            raise ValueError("Original pthread_create or sleep PLT target changed")
    if bl_target(elf, 0x16990) != 0x1df7c:
        raise ValueError("JNI_OnLoad callback table initializer call changed")
    owner_fdes = verify_fdes(elf)
    # The worker address is passed to pthread_create through x2.
    # No static immediate BL to that address exists in the original .text.
    if direct_bl_callers(elf, 0x59700):
        raise ValueError("Unexpected direct BL to worker; review caller classification")
    argv = decode_argv(elf)
    if not (0x59700 <= 0x5a418 < 0x5a710 < 0x5b45c):
        raise ValueError("Spawn instruction escapes its documented unwind range")
    return {
        "jni_bootstrap": {
            "JNI_OnLoad_symbol_range": ["0x148cc","0x1703c"],
            "direct_call_site": "0x16990",
            "callback_registration_initializer": "0x1df7c",
            "initializer_unwind_range": ["0x1df7c","0x249d0"]
        },
        "dispatcher_thread": {
            "created_by_initializer": "0x1df7c",
            "entry_function": "0x4b3bc",
            "pthread_create_calls": ["0x1e4f4", "0x1e520"],
            "unwind_range": ["0x4b3bc", "0x4b768"],
            "config_byte_offset": 8,
            "callback_bit_mask": "0x04",
            "selected_table_slot_if_set": "0x20",
            "indirect_call": "0x4b494",
            "reasoning": ("The initializer stores flag byte at context+8. "
                          "Dispatcher loads it, computes x20 & 4, then "
                          "loads table[(x20 & 4)] in 8-byte entries; "
                          "setting bit 0x04 selects slot +0x20."),
            "limitation": "Actual flag-byte value has not been observed."
        },
        "global_registration": {
            "code_address": "0x1e3f0",
            "callback_function": "0x4e1c8",
            "global_table_address": "0x12b400",
            "callback_slot_offset": "0x20",
            "limitation": "Static pointer storage; not proof of runtime invocation"
        },
        "pthread_create": {
            "enclosing_unwind_function": ["0x4e1c8", "0x50354"],
            "call_sites": ["0x50004", "0x50030"],
            "plt_address": "0xec00",
            "thread_start_function": "0x59700",
            "thread_arg": None,
            "note": "Two callsites include a retry branch; x3 is null at both"
        },
        "thread_worker": {
            "unwind_range": ["0x59700", "0x5b45c"],
            "starts_with_sleep_seconds": 2,
            "fork_calls": ["0x5a418", "0x5a4c4"],
            "execl_call": "0x5a710",
            "process_path": argv["path"],
            "nice_name": next(
                arg["value"] for arg in argv["arguments"] if arg["role"] == "nice_name")
        },
        "unwind_fdes": owner_fdes,
        "direct_immediate_bl_to_worker_count": 0,
        "limits": ("JNI_OnLoad calls the callback-table initializer, but runtime "
                   "dispatcher calls the callback when config bit 0x04 is set; "
                   "the runtime config byte and actual branch outcome "
                   "remain unobserved. "
                   "The original executable machine code establishes callback "
                   "registration, thread start, and subsequent fork-execl, "
                   "but runtime causality and DEC involvement require more evidence.")
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path,
                   help="Original SHA-pinned APK or diagnostic ZIP")
    args = p.parse_args()
    archive_data = args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(archive_data)) as container:
        if "apks/01-base.apk" in container.namelist():
            archive_data = container.read("apks/01-base.apk")
    if hashlib.sha256(archive_data).hexdigest() != APK_SHA:
        raise ValueError("Original APK hash mismatch")
    with zipfile.ZipFile(io.BytesIO(archive_data)) as container:
        inner, meta = recover(
            container.read("lib/arm64-v8a/libDexHelper.so"),
            SAMPLES["libDexHelper.so"])
    print(json.dumps({
        "pinned_inner_sha256": meta["inner_sha256"],
        "analysis": verify(inner)
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
