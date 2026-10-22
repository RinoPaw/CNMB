#!/usr/bin/env python3
"""Read-only CNMB 12.5.5 native-loader and tombstone evidence audit.

Inputs: original base.apk or diagnostic ZIP, optional offline tombstone text.
Prints only file hashes, literal positions, ELF load summaries, and sanitized
mapping basenames. It does not modify APKs, hook processes, or access a phone.
"""
import argparse
import hashlib
import io
import json
import re
import struct
import zipfile
from pathlib import Path

APK_SHA256 = '6282d2cf05f76f37a60fff322bcf0d6f1d876829e5c9c4eae5cdd93b7a972a83'
LIBS = (
    'libDexHelper.so',
    'libdexjni.so',
    'libdexvmp.so',
    'libdatajar.so',
    'libZWRiskComm-v7_6_4r_61803305.so',
)
LITERALS = {
    'libDexHelper.so': ('JNI_OnLoad','/proc/self/maps','liblinkerstub.so'),
    'libdexjni.so': ('JNI_OnLoad','/proc/self/maps','liblinkerstub.so'),
    'libdexvmp.so': ('JNI_OnLoad','/proc/self/maps'),
    'libZWRiskComm-v7_6_4r_61803305.so': (
        'frida-agent','frida-dump','frida_agent_main',
        'possible frida: loading', 'kernel ptrace hooked',
        '/system/bin/su','/proc/self/maps',
    ),
}
# Tombstone entries can contain apostrophes inside 64-bit addresses.
MAP = re.compile(
    r"^\s*([0-9a-fA-F]{8})'([0-9a-fA-F]{8})-"
    r"([0-9a-fA-F]{8})'([0-9a-fA-F]{8})\s+"
    r"([rwx-]{3})\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
    r"(?:\s+(.*))?$"
)


def read_apk(path):
    raw = path.read_bytes()
    if not zipfile.is_zipfile(io.BytesIO(raw)):
        raise ValueError('Source must be APK or diagnostic ZIP')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = set(archive.namelist())
        if 'apks/01-base.apk' in names:
            raw = archive.read('apks/01-base.apk')
        elif 'classes.dex' not in names:
            raise ValueError('No base.apk or APK classes.dex found')
    sha = hashlib.sha256(raw).hexdigest()
    if sha != APK_SHA256:
        raise ValueError('APK SHA-256 mismatch: refusing version-specific conclusions')
    return raw


def load_segments(data):
    if data[:5] != b'\x7fELF\x02' or data[5] != 1:
        raise ValueError('Unsupported ELF format (requires ELF64 little-endian)')
    phoff = struct.unpack_from('<Q',data,32)[0]
    phentsize,phnum = struct.unpack_from('<HH',data,54)
    if phentsize != 56 or phoff+phnum*phentsize > len(data):
        raise ValueError('Invalid program headers')
    out=[]
    for i in range(phnum):
        typ, flags,off,va,pa,filesz,memsz,align=(
            struct.unpack_from('<IIQQQQQQ',data,phoff+i*phentsize))
        if typ==1:
            if off+filesz>len(data):
                raise ValueError('Invalid PT_LOAD file extent')
            out.append({'offset':f'0x{off:x}','file_bytes':filesz,
                        'memory_bytes':memsz,
                        'permissions':''.join(c if flags&bit else '-'
                                            for c,bit in (('r',4),('w',2),('x',1)))})
    return out


def summarize_apk(apk):
    summary={'apk_sha256':APK_SHA256,'libraries':{}}
    with zipfile.ZipFile(io.BytesIO(apk)) as archive:
        for basename in LIBS:
            path='lib/arm64-v8a/'+basename
            raw=archive.read(path)
            data=raw
            nested=None
            if zipfile.is_zipfile(io.BytesIO(raw)):
                with zipfile.ZipFile(io.BytesIO(raw)) as inner:
                    entries=inner.namelist()
                    if entries != [path]:
                        raise ValueError(f'Unexpected nested SO archive for {basename}: {entries}')
                    data=inner.read(path)
                    nested={'inner_path':path, 'wrapper_bytes':len(raw),
                            'wrapper_sha256':hashlib.sha256(raw).hexdigest()}
            summary['libraries'][basename]={
                'size':len(data), 'sha256':hashlib.sha256(data).hexdigest(),
                'nested_zip_wrapper':nested,
                'elf_load_segments':load_segments(data),
                'literal_offsets':{
                    phrase: [f'0x{m.start():x}' for m in re.finditer(
                        re.escape(phrase.encode('ascii')),data)][:20]
                    for phrase in LITERALS.get(basename,())
                },
            }
    return summary


def summarize_tombstone(path):
    txt=path.read_text(encoding='utf-8',errors='replace')
    header=txt.split('memory map (',1)[0]
    matches=re.findall(r'\b(x19|pc|lr|sp)\s+([0-9a-f]{16})\b',
                       header.split('backtrace:',1)[0])
    registers={key:int(value,16) for key,value in matches}
    mappings=[]
    for line in txt.splitlines():
        m=MAP.match(line)
        if not m:continue
        start=int(m[1]+m[2],16)
        end=int(m[3]+m[4],16)+1
        assert end>start
        pathpart=m[8] or ''
        basename=pathpart.rsplit('/',1)[-1] if '/' in pathpart else pathpart
        mappings.append({'start':start,'end':end,'permissions':m[5],
                         'name':basename})
    if not mappings:
        raise ValueError('No parseable 64-bit tombstone memory mappings')
    target=registers.get('x19')
    region=next((m for m in mappings
                 if target is not None and m['start']<=target<m['end']),None)
    name=re.search(r'^Cmdline:\s*([^\n]+)',header,re.M)
    signal=re.search(r'^signal\s+([0-9]+)\s+\(([^)]*)\).*?fault addr\s+(0x[0-9a-f]+)',
                     header,re.M)
    app_libraries=sorted({m['name'] for m in mappings if
        m['name'].endswith('.so') and
        ('DexHelper' in m['name'] or 'dexjni' in m['name'] or
         'dexvmp' in m['name'] or 'datajar' in m['name'] or
         'ZWRisk' in m['name'])})
    out={'process':name.group(1) if name else None,
         'signal':{'number':int(signal.group(1)),'name':signal.group(2),
                   'fault_address':signal.group(3)} if signal else None,
         'registers':{k:f'0x{v:x}' for k,v in registers.items()},
         'memory_map_entries':len(mappings),
         'relevant_mapped_libraries':app_libraries}
    if region is not None:
        out['x19_region']={'start':f'0x{region["start"]:x}',
                           'end_exclusive':f'0x{region["end"]:x}',
                           'bytes':region['end']-region['start'],
                           'permissions':region['permissions'],
                           'name':region['name'] or '[anonymous]'}
    else:
        out['x19_region']=None
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path,help='Base APK or its diagnostic ZIP')
    p.add_argument('--tombstone',type=Path,help='Tombstone from the same version')
    args=p.parse_args()
    result=summarize_apk(read_apk(args.source))
    if args.tombstone:
        result['tombstone']=summarize_tombstone(args.tombstone)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
