#!/usr/bin/env python3
"""Prove ELF->PLT->dlopen/dlsym->maps scanner for original CNMB 12.5.5.

Read-only: SHA-pinned commercial APK is read locally, never exported.
Provides original AArch64 call-site evidence, not dynamic execution proof.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

APK_SHA = '6282d2cf05f76f37a60fff322bcf0d6f1d876829e5c9c4eae5cdd93b7a972a83'
LIB_SHA = {
    'libDexHelper.so': '6b5abe051e75d630d5447785d1f1a9f480b2c636f2874a7494767cfcde2ac4db',
    'libdexjni.so': 'f567dde1e581483f7da6680d87183b522493b5109f19ea27bf388fd80aec9199',
}
# All instruction and literal addresses here refer to libDexHelper.so;
# libdexjni.so uses an exact -0x2000 offset for this shared bootstrap region.
CALLS = {
    0x4850: ('dlopen', 0x2a30),
    0x485c: ('dlsym', 0x2a50),
    0x3574: ('fopen', 0x2a60),
    0x35d0: ('fgets', 0x29a0),
    0x3628: ('fclose', 0x2a80),
    0x370c: ('mmap', 0x29e0),
    0x3884: ('mmap', 0x29e0),
    0x4088: ('mprotect', 0x2af0),
    0x40c4: ('mprotect', 0x2af0),
}
LITERALS = {
    0x4a60: b'libc.so\x00',
    0x4a68: b'sscanf\x00',
    0x4a08: b'/proc/self/maps\x00',
    0x4a18: b'r\x00',
    0x4a20: b'%lx-%lx %s %s %s %s %s\x00',
}
# Exact original instructions establish how data and function pointers travel.
CRITICAL_WORDS = {
    0x483c: 0xb0000083,   # adrp x3, page containing global storage
    0x4844: 0x52800041,   # mov w1, #2 (RTLD_NOW)
    0x4848: 0x91298000,   # add x0,x0,#0xa60 ("libc.so")
    0x4858: 0x9129a021,   # add x1,x1,#0xa68 ("sscanf")
    0x4878: 0xf9001c40,   # str x0,[x2,#0x38] stores dlsym ptr
    0x4940: 0x97fffaae,   # bl 0x33f8 (same-library helper)
    0x3564: 0x91286021,   # add x1,x1,#0xa18 ("r")
    0x3568: 0x91282000,   # add x0,x0,#0xa08 ("/proc/self/maps")
    0x35c4: 0xaa1303e0,   # mov x0,x19 (line buffer)
    0x35e0: 0xaa1603e1,   # mov x1,x22 (scanf format)
    0x35dc: 0xf9401f28,   # ldr x8,[x25,#0x38] (resolved sscanf ptr)
    0x3600: 0xd63f0100,   # blr x8 (indirect sscanf)
}


def parse_elf(image):
    if image[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', image, 18)[0] != 183:
        raise ValueError('Original ELF64/AArch64 header expected')
    p_off = struct.unpack_from('<Q', image, 32)[0]
    p_size, p_count = struct.unpack_from('<HH', image, 54)
    if p_size != 56 or p_off + p_size*p_count > len(image):
        raise ValueError('Invalid program header region')
    headers = [struct.unpack_from('<IIQQQQQQ', image, p_off+i*p_size)
               for i in range(p_count)]

    def at(va):
        matches = [h[2]+va-h[3] for h in headers
                   if h[0] == 1 and h[3] <= va < h[3]+h[5]
                   and h[2]+va-h[3] < len(image)]
        if len(matches) != 1:
            raise ValueError('Unmapped or ambiguous VA: '+hex(va))
        return matches[0]

    dynamic = [h for h in headers if h[0] == 2]
    if len(dynamic) != 1:
        raise ValueError('Expected unique PT_DYNAMIC')
    h = dynamic[0]
    tags = {}
    for o in range(h[2], h[2]+h[5], 16):
        tag, value = struct.unpack_from('<QQ', image, o)
        if tag == 0:
            break
        tags[tag] = value
    if tags.get(2) != 576 or tags.get(20) != 7 or tags.get(9) != 24:
        raise ValueError('Unexpected PLT RELA configuration')
    return at, tags


def imports(image, at, tags):
    items = []
    for n in range(tags[2] // 24):
        r_offset, r_info, addend = struct.unpack_from('<QQq', image, at(tags[23])+24*n)
        sym = r_info >> 32
        if r_info & 0xffffffff != 1026:
            raise ValueError('Unexpected PLT relocation type')
        name_index = struct.unpack_from('<I', image, at(tags[6])+sym*24)[0]
        name_off = at(tags[5])+name_index
        end = image.find(b'\x00', name_off)
        if end < 0 or end-name_off > 256:
            raise ValueError('Invalid imported symbol name')
        name = image[name_off:end].decode('ascii')
        items.append({'name': name, 'got_elf_va': r_offset, 'symbol_index': sym})
    if len(items) != 24:
        raise ValueError('Unexpected PLT import count')
    return items


def dynamic_symbol_census(image, at, tags, name):
    if 4 not in tags:
        raise ValueError('Missing DT_HASH')
    bucket_count, symbol_count = struct.unpack_from('<II', image, at(tags[4]))
    expected = ((197, 239) if name == 'libDexHelper.so' else (17, 29))
    if (bucket_count, symbol_count) != expected:
        raise ValueError('Unexpected dynamic symbol table size')
    empty = 0
    symbols = set()
    exported = set()
    for n in range(symbol_count):
        name_idx, info, vis, section, va, size = struct.unpack_from(
            '<IBBHQQ', image, at(tags[6]) + 24*n)
        ptr = at(tags[5]) + name_idx
        end = image.find(b'\x00', ptr)
        if end < 0 or end-ptr > 256:
            raise ValueError('Invalid dynamic symbol string')
        label = image[ptr:end].decode('ascii')
        if not label:
            empty += 1
        else:
            symbols.add(label)
            if section:
                exported.add(label)
    if 'JNI_OnLoad' in symbols:
        raise ValueError('Unexpected static JNI_OnLoad dynamic symbol')
    return {
        'hash_buckets': bucket_count,
        'hash_symbol_chain_entries': symbol_count,
        'empty_name_slots': empty,
        'static_jni_onload_symbol_found': False,
        'limitation': ('A JNI_OnLoad literal string exists, but no dynamic symbol '
                       'by this name; runtime-created symbols are not ruled out.')
    }


def bl_target(image, file_position):
    op = struct.unpack_from('<I', image, file_position)[0]
    if op >> 26 != 0b100101:
        raise ValueError('Expected AArch64 BL @ '+hex(file_position))
    delta = op & 0x3ffffff
    if delta & (1 << 25):
        delta -= 1 << 26
    return file_position + 4*delta


def audit(image, name):
    if hashlib.sha256(image).hexdigest() != LIB_SHA[name]:
        raise ValueError('SO digest mismatch: '+name)
    shift = -0x2000 if name == 'libdexjni.so' else 0
    at, tags = parse_elf(image)
    resolved = imports(image, at, tags)
    symbol_census = dynamic_symbol_census(image, at, tags, name)
    expected_got = 0x14f30 + shift
    for i, entry in enumerate(resolved):
        if entry['got_elf_va'] != expected_got + 8*i:
            raise ValueError('PLT slot/GOT offset mismatch')
    for position, literal in LITERALS.items():
        if image[position+shift:position+shift+len(literal)] != literal:
            raise ValueError('Original string changed at '+hex(position+shift))
    for position, word in CRITICAL_WORDS.items():
        if struct.unpack_from('<I', image, position+shift)[0] != word:
            raise ValueError('Original instruction changed at '+hex(position+shift))
    call_report = []
    for site, (symbol, target) in CALLS.items():
        real_site, real_target = site+shift, target+shift
        if bl_target(image, real_site) != real_target:
            raise ValueError('Unexpected BL call destination')
        if not (0x2990+shift <= real_target < 0x2b10+shift):
            raise ValueError('Not a target PLT slot')
        n = (real_target-(0x2990+shift))//16
        if resolved[n]['name'] != symbol:
            raise ValueError('PLT symbol mismatch for '+symbol)
        call_report.append({'callsite_elf_va':hex(real_site),
                            'plt_elf_va':hex(real_target),
                            'imported_function':symbol})
    local_site, local_target = 0x4940+shift, 0x33f8+shift
    if bl_target(image, local_site) != local_target:
        raise ValueError('Constructor did not branch to native helper')
    return {
        'library':name, 'constructor_calls_from':hex(0x4780+shift),
        'dlopen_library':'libc.so', 'dlsym_function':'sscanf',
        'local_helper':hex(local_target),
        'local_helper_maps_file':'/proc/self/maps',
        'local_helper_scanf_format':'%lx-%lx %s %s %s %s %s',
        'local_helper_uses_resolved_sscanf_via_blr':True,
        'resolved_plt_calls':call_report,
        'native_imports':len(resolved),
        'dynamic_symbol_census':symbol_census,
        'scope':('Raw ELF imports, callsites and strings only; does not establish '
                 'runtime execution or DEC-specific root check.')
    }


def read_apk(source):
    raw = source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if 'apks/01-base.apk' in archive.namelist():
            raw = archive.read('apks/01-base.apk')
    if hashlib.sha256(raw).hexdigest() != APK_SHA:
        raise ValueError('Original APK hash mismatch')
    return raw


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path)
    a=p.parse_args()
    with zipfile.ZipFile(io.BytesIO(read_apk(a.source))) as z:
        result=[audit(z.read('lib/arm64-v8a/'+name),name) for name in LIB_SHA]
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
