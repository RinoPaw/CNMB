#!/usr/bin/env python3
"""Read-only census of repeated executable loader stubs in pinned CNMB 12.5.5.

The signature is a 2,565-byte identical ARM64 executable core; it appears in
10/191 original APK arm64 shared libraries. It contains syscalls for file IO,
memory mapping, and process exit, but contains no clone/execve wrapper.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

APK_SHA256 = '6282d2cf05f76f37a60fff322bcf0d6f1d876829e5c9c4eae5cdd93b7a972a83'
TAIL_SIZE = 0xa50
CORE_START = 0x20
CORE_END = 0xa25
STUB_MARKER = b'__b_a_n_g_c_l_e__check1234567_'
MAPS = b'/proc/self/maps\x00'
EXPECTED_NAMES = {
    'libAlipayBitmapNative.so', 'libdatabase_sqlcrypto.so',
    'libdatajar.so', 'libdexvmp.so', 'libentryexpro.so',
    'libijkrecorder.so', 'libijksdl.so', 'libmmkv.so',
    'libv8worker-native.so', 'libyewu.so',
}
# Offsets relative to each 0xa50-byte executable segment.
SYSCALLS = {
    0x100: ('write', 64), 0x10c: ('munmap', 215),
    0x120: ('mmap', 222), 0x12c: ('mprotect', 226),
    0x138: ('write', 64), 0x144: ('read', 63),
    0x150: ('openat', 56), 0x15c: ('close', 57),
    0x168: ('exit_group', 94),
}


def read_apk(source):
    raw = source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if 'apks/01-base.apk' in archive.namelist():
            raw = archive.read('apks/01-base.apk')
    if hashlib.sha256(raw).hexdigest() != APK_SHA256:
        raise ValueError('APK SHA-256 mismatch: refusing version-specific conclusions')
    return raw


def executable_segment(image, offset):
    if image[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', image, 18)[0] != 183:
        raise ValueError('ELF64/AArch64 mismatch')
    phoff = struct.unpack_from('<Q', image, 32)[0]
    phent, phnum = struct.unpack_from('<HH', image, 54)
    if phent != 56 or phoff + phnum * phent > len(image):
        raise ValueError('Invalid program headers')
    for i in range(phnum):
        ptype, flags, off, va, pa, size, memsize, align = struct.unpack_from(
            '<IIQQQQQQ', image, phoff+i*phent)
        if ptype == 1 and flags & 1 and off == offset and size == TAIL_SIZE:
            return va
    raise ValueError(f'No matching executable PT_LOAD at {offset:#x}')


def wrappers(tail):
    if len(tail) != TAIL_SIZE:
        raise ValueError('Wrong loader stub length')
    result = []
    for pos, (name, num) in SYSCALLS.items():
        before, call, after = struct.unpack_from('<III', tail, pos-4)
        if not (before & 0xff80001f == 0xd2800008 and
                (before >> 5) & 0xffff == num and
                call == 0xd4000001 and after == 0xd65f03c0):
            raise ValueError(f'Syscall wrapper mismatch at {pos:#x}')
        result.append({'offset_in_stub': f'0x{pos:x}',
                       'syscall': name, 'number': num})
    actual = [p for p in range(0, len(tail)-3, 4)
              if struct.unpack_from('<I', tail, p)[0] & 0xffe0001f == 0xd4000001]
    if actual != list(SYSCALLS):
        raise ValueError(f'Unexpected SVC opcodes: {actual}')
    return result


def analyze(apk):
    with zipfile.ZipFile(io.BytesIO(apk)) as z:
        libs = [n for n in z.namelist()
                if n.startswith('lib/arm64-v8a/') and n.endswith('.so')]
        reference = z.read('lib/arm64-v8a/libdexvmp.so')[0x7f078:0x7fac8]
        assert len(reference) == TAIL_SIZE
        core = reference[CORE_START:CORE_END]
        assert len(core) == 2565
        assert reference.count(STUB_MARKER) == 1
        assert reference.count(MAPS) == 1
        assert reference.find(MAPS) == 0x9f4
        syscall_info = wrappers(reference)
        found = []
        for member in libs:
            image = z.read(member)
            where = image.find(core)
            if where < 0:
                continue
            if image.find(core, where+1) != -1:
                raise ValueError('Duplicate protected core in ' + member)
            start = where - CORE_START
            tail = image[start:start+TAIL_SIZE]
            if len(tail) != TAIL_SIZE or tail[CORE_START:CORE_END] != core:
                raise ValueError('Invalid embedded stub at ' + member)
            va = executable_segment(image, start)
            if wrappers(tail) != syscall_info:
                raise ValueError('Divergent wrappers ' + member)
            found.append({'library': member.rsplit('/', 1)[-1],
                          'file_offset': f'0x{start:x}',
                          'virtual_address': f'0x{va:x}',
                          'total_stub_bytes': TAIL_SIZE,
                          'shared_core_bytes': len(core),
                          'different_bytes_vs_dexvmp': sum(
                              a != b for a, b in zip(tail, reference))})
    if {f['library'] for f in found} != EXPECTED_NAMES or len(libs) != 191:
        raise ValueError('Original 191-library census diverges')
    found.sort(key=lambda item: item['library'])
    return {
        'arm64_libraries_scanned': len(libs),
        'libraries_with_identical_core': len(found),
        'stub_marker': STUB_MARKER.decode(),
        'literal_maps_path': MAPS.rstrip(b'\0').decode(),
        'core_relative_range': '[0x20, 0xa25)',
        'syscall_wrappers_per_stub': syscall_info,
        'matched_libraries': found,
        'limit': ('Static file and instruction evidence only. No proven link to '
                  'DEC startCheck, no proof of actual execution or vendor attribution. '
                  'No clone, fork or execve wrapper among these nine SVC sites.')
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path,
                        help='SHA256-pinned base.apk or original diagnostic ZIP')
    args = parser.parse_args()
    print(json.dumps(analyze(read_apk(args.source)), indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
