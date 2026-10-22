#!/usr/bin/env python3
"""Read-only, standard-library-only APK static evidence collector.

Input: original APK, or the diagnostic ZIP containing apks/01-base.apk.
Output: hashes, SecNeo launch stub, AXML activity declaration, literal locations.
This does not decrypt protected Dex or alter the original package.
"""
import argparse
import hashlib
import io
import re
import struct
import zipfile
from pathlib import Path


def u16(data, off):
    return struct.unpack_from('<H', data, off)[0]


def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def leb(data, off):
    val = shift = 0
    while True:
        b = data[off]
        off += 1
        val |= (b & 0x7f) << shift
        if b < 0x80:
            return val, off
        shift += 7


def dex_audit(data):
    if not data.startswith(b'dex\n'):
        raise ValueError('Input classes.dex does not have standard Dex magic')
    count, off = u32(data, 0x38), u32(data, 0x3c)
    strings = []
    for i in range(count):
        p = u32(data, off + 4*i)
        _, p = leb(data, p)
        end = data.index(0, p)
        strings.append(data[p:end].decode('utf-8', 'replace'))
    types = [strings[u32(data, u32(data, 0x44)+4*i)] for i in range(u32(data, 0x40))]
    methods = []
    for i in range(u32(data, 0x58)):
        p = u32(data, 0x5c)+8*i
        cl, proto, name = struct.unpack_from('<HHI', data, p)
        methods.append((types[cl], strings[name], proto))
    classes = []
    for i in range(u32(data, 0x60)):
        p = u32(data, 0x64)+32*i
        classes.append((types[u32(data, p)], u32(data, p+24)))
    findings = []
    for classname, cdo in classes:
        if not cdo: continue
        num_sf, cdo = leb(data, cdo)
        num_if, cdo = leb(data, cdo)
        num_direct, cdo = leb(data, cdo)
        num_virtual, cdo = leb(data, cdo)
        for _ in range(num_sf+num_if):
            _, cdo = leb(data, cdo)
            _, cdo = leb(data, cdo)
        method_i = 0
        for k in range(num_direct+num_virtual):
            if k == num_direct: method_i = 0
            delta, cdo = leb(data, cdo)
            _, cdo = leb(data, cdo)
            code, cdo = leb(data, cdo)
            method_i += delta
            if not code: continue
            insn_count = u32(data, code+12)
            instrs = data[code+16:code+16+2*insn_count]
            refs = []
            for token in ('/proc/self/status', 'TracerPid:', 'read tracer', 'DexHelper',
                          'com.mc10086.cmcc.base.CmccApplication'):
                if token not in strings: continue
                index = strings.index(token)
                needle = struct.pack('<H',index)
                # DEX const-string 21c opcode (0x1a), two code units.
                for j in range(0,len(instrs)-3,2):
                    if instrs[j] == 0x1a and instrs[j+2:j+4] == needle:
                        refs.append((token,code+16+j))
            if refs:
                findings.append((classname, methods[method_i][1], code, refs))
    return classes, findings


def axml_strings(data, p=8):
    t, hdr, length = struct.unpack_from('<HHI', data, p)
    if t != 1: raise ValueError('Expected Android XML string pool')
    count, _, flags, strings_offset, _ = struct.unpack_from('<IIIII', data, p+8)
    def string_at(q):
        if flags & 0x100:
            def varlen(q):
                a=data[q]; q+=1
                if a & 0x80: a=((a&127)<<8)|data[q];q+=1
                return a,q
            _, q=varlen(q)
            n, q=varlen(q)
            return data[q:q+n].decode('utf-8','replace')
        n=u16(data,q);q+=2
        if n & 0x8000:
            n=((n&0x7fff)<<16)|u16(data,q);q+=2
        return data[q:q+2*n].decode('utf-16le','replace')
    strings=[string_at(p+strings_offset+u32(data,p+hdr+4*i)) for i in range(count)]
    return strings,length


def manifest_audit(data):
    strings, pool_size = axml_strings(data)
    p=8+pool_size
    found=[]
    while p<len(data):
        typ,hdr,size=struct.unpack_from('<HHI',data,p)
        if size==0:break
        if typ==0x102:
            ns,nm,start,asz,num,_,_,_=struct.unpack_from('<IIHHHHHH',data,p+16)
            name=strings[nm]
            attrs={}
            for i in range(num):
                q=p+16+start+i*asz
                _,key,raw=struct.unpack_from('<III',data,q)
                dtype=data[q+15];rawdat=u32(data,q+16)
                if raw!=0xffffffff: v=strings[raw]
                elif dtype==3: v=strings[rawdat]
                elif dtype==0x12: v='true' if rawdat else 'false'
                else:v=f'0x{rawdat:x}'
                attrs[strings[key]]=v
            if name=='application' or (name=='activity' and ('DEC' in attrs.get('name','') or 'StartPageActivity' in attrs.get('name',''))):
                found.append((name,attrs))
        p+=size
    return found


def scan_entry(archive, info, terms):
    finds=set();last=b''
    with archive.open(info) as stream:
        while True:
            block=stream.read(1024*1024)
            if not block:break
            hay=last+block
            for term in terms:
                if term not in finds and (term.encode() in hay or term.encode('utf-16le') in hay):
                    finds.add(term)
            last=hay[-128:]
    return finds


def main():
    pa=argparse.ArgumentParser(description=__doc__)
    pa.add_argument('input',type=Path,help='Original base APK or diagnostic ZIP')
    args=pa.parse_args()
    source=args.input.read_bytes()
    if zipfile.is_zipfile(io.BytesIO(source)):
        outer=zipfile.ZipFile(io.BytesIO(source))
        if 'apks/01-base.apk' in outer.namelist():source=outer.read('apks/01-base.apk')
    print('APK SHA256:',hashlib.sha256(source).hexdigest())
    apk=zipfile.ZipFile(io.BytesIO(source))
    print('Entries:',len(apk.infolist()))
    for name in ('classes.dex','lib/arm64-v8a/libDexHelper.so','lib/arm64-v8a/libdexjni.so','lib/arm64-v8a/libdatajar.so','lib/arm64-v8a/libdexvmp.so'):
        print('Entry:',name,'size:',apk.getinfo(name).file_size)
    classes, finds=dex_audit(apk.read('classes.dex'))
    print('Dex classes:',len(classes),','.join(name for name,off in classes))
    for cls, method, code, refs in finds:
        print(f'Dex {cls}->{method} code_off=0x{code:x}: '+', '.join(f'{token}@0x{at:x}' for token,at in refs))
    for tag, attrs in manifest_audit(apk.read('AndroidManifest.xml')):
        print('Manifest:',tag,attrs)
    terms=['DECMsgDialog','DeviceEnvironmentCheck','envc.push',
           'Lcom/a/b/c/DECApp;','Lcom/mc10086/lib/tools/root/RootBeer;']
    for info in apk.infolist():
        if not info.file_size:continue
        seen=scan_entry(apk,info,terms)
        if seen:print('APK literal:',info.filename,', '.join(sorted(seen)))
    jar=apk.read('lib/arm64-v8a/libdatajar.so')
    for term in ('Lcom/a/b/c/DECApp;','Lcom/a/b/c/DeviceEnvironmentCheck;',
                 'getCheckResult','Lcom/mc10086/lib/tools/root/RootBeer;'):
        pat=term.encode();loc=[];offset=0
        while True:
            p=jar.find(pat,offset)
            if p<0:break
            loc.append(f'0x{p:x}');offset=p+len(pat)
        print('libdatajar literal',repr(term),':',','.join(loc))
    print('libdatajar standard Dex magic:',bool(re.search(rb'dex\n0[0-9]{2}\x00',jar)))


if __name__=='__main__':main()