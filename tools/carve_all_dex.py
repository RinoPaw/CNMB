#!/usr/bin/env python3
"""Carve and validate 14 Dex metadata fragments from pinned CNMB 12.5.5 SO.

Read-only, standard library only. Counts valid tables and class definitions,
resolves DEC ownership and the unrelated getCheckResult method. The embedded
Dex payloads are incomplete; this does not decrypt their protected content.
"""
import argparse
import bisect
import struct
from pathlib import Path
from inspect_dec_tables import load, uleb

STRING_TABLES=(
    0x2500c,0x1cd900c,0x25a000c,0x2f2e00c,0x383200c,
    0x42bb00c,0x493900c,0x523500c,0x5bf200c,0x69c600c,
    0x729300c,0x7b8d00c,0x84fe00c,0x93eb00c,
)
EXPECTED_CLASSES=(16526,3799,7148,7771,7201,5062,8138,8085,8092,
                  8767,7793,8081,4349,904)
CHECKER=b'Lcom/a/b/c/DeviceEnvironmentCheck;'


def u32(data, offset):
    return struct.unpack_from('<I',data,offset)[0]


def dex_string(data, offset):
    _,pos=uleb(data,offset)
    return data[pos:data.index(b'\0',pos)].decode('utf-8','replace')


def consecutive_string_data(data,start,next_start):
    if not(0<start<next_start<len(data) and
           next_start-start<=0x200000 and data[next_start-1]==0):
        return False
    try:
        length,value=uleb(data,start)
        return length<0x200000 and value<next_start and (
            data.find(b'\0',value,next_start)==next_start-1)
    except (IndexError,ValueError):
        return False


def carve(data, visible, expected_classes):
    base=visible-0x20000
    hidden=(visible-base-0x70)//4
    assert hidden==32740
    pairs=0
    while consecutive_string_data(
            data,base+u32(data,visible+4*pairs),
            base+u32(data,visible+4*(pairs+1))):
        pairs+=1
    visible_count=pairs+1
    type_offset=visible+4*visible_count
    string_count=hidden+visible_count

    types=[]
    last=-1
    while True:
        sid=u32(data,type_offset+4*len(types))
        if not last<sid<string_count:break
        types.append(sid)
        last=sid

    proto_offset=type_offset+4*len(types)
    protos=0
    while True:
        shorty,ret,params=struct.unpack_from('<III',data,proto_offset+12*protos)
        if not(shorty<string_count and ret<len(types) and
               (params==0 or (params%4==0 and base+params<len(data)))):
            break
        protos+=1

    field_offset=proto_offset+12*protos
    fields=0
    last=-1
    while True:
        cls,t,name=struct.unpack_from('<HHI',data,field_offset+8*fields)
        if not(cls<len(types) and t<len(types) and
               name<string_count and cls>=last):break
        fields+=1
        last=cls

    method_offset=field_offset+8*fields
    methods=0
    last=-1
    while True:
        cls,proto,name=struct.unpack_from('<HHI',data,method_offset+8*methods)
        if not(cls<len(types) and proto<protos and
               name<string_count and cls>=last):break
        methods+=1
        last=cls

    class_offset=method_offset+8*methods
    defined=set()
    while True:
        cls,flags,parent,interfaces,source,annotations,cdata,statics=(
            struct.unpack_from('<8I',data,class_offset+32*len(defined)))
        if not(cls<len(types) and
               (parent<len(types) or parent==0xffffffff) and
               (source<string_count or source==0xffffffff) and
               cls not in defined):
            break
        defined.add(cls)
    assert len(defined)==expected_classes,(hex(visible),len(defined))

    # The 128 KiB early string_ids are obscured, but string_data is contiguous.
    pointers=[0]*hidden
    pos=base+u32(data,visible)
    for sid in range(hidden-1,-1,-1):
        assert data[pos-1]==0
        pos=data.rfind(b'\0',0,pos-1)+1
        assert pos>0
        pointers[sid]=pos
    pointers.extend(base+u32(data,visible+4*i) for i in range(visible_count))
    assert len(pointers)==string_count
    assert all(a<b for a,b in zip(pointers,pointers[1:]))

    dec=[]
    for tid,sid in enumerate(types):
        name=dex_string(data,pointers[sid])
        if name.startswith('Lcom/a/b/c/'):
            dec.append((tid,name,tid in defined))
    return {
        'base':base,'strings':string_count,'types':types,
        'protos':protos,'fields':fields,'methods':methods,
        'classes':len(defined),'pointers':pointers,
        'method_offset':method_offset,'defined':defined,'dec':dec,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path)
    args=p.parse_args()
    data=load(args.source)  # fixed sample APK/SO SHA-256 validation
    assert data.count(CHECKER)==1
    dec=[]
    for table,expected in zip(STRING_TABLES,EXPECTED_CLASSES):
        f=carve(data,table,expected)
        print(f"{table:#x}: base={f['base']:#x} strings={f['strings']:,} "
              f"types={len(f['types']):,} methods={f['methods']:,} "
              f"classes={f['classes']:,}")
        dec.extend((table,*item) for item in f['dec'])
        for tid,name,defined in f['dec']:
            print(' ', 'DEFINED' if defined else 'REFERENCE ONLY',
                  f'type#{tid}',name)

        if table==0x7b8d00c:
            pointers=f['pointers']
            target=0x7ec143d
            sid=bisect.bisect_left(pointers,target)
            assert pointers[sid]==target
            assert dex_string(data,target)=='getCheckResult'
            owners=[]
            for mid in range(f['methods']):
                cls,proto,name=struct.unpack_from(
                    '<HHI',data,f['method_offset']+8*mid)
                if name==sid:
                    descriptor=dex_string(data,pointers[f['types'][cls]])
                    owners.append((mid,cls,cls in f['defined'],descriptor))
            expected_owner=(10684,2113,True,
                             'Lcom/alipay/mobile/quinox/resources/BundleResources;')
            assert owners==[expected_owner],owners
            print(f'  getCheckResult string_id={sid}; owner={owners}')

    checker_owners=[(table,tid,defined) for table,tid,name,defined in dec
                    if name==CHECKER.decode()]
    assert checker_owners==[(0x2500c,17421,False)],checker_owners
    assert len(dec)==6,dec
    print('14 verified Dex metadata fragments; 101,716 class definitions.')
    print('DeviceEnvironmentCheck: reference only; no class body in these fragments.')
    print('getCheckResult: Alipay BundleResources method, unrelated to DEC.')
    print('LIMIT: encrypted and dynamically loaded code remains outside this census.')


if __name__=='__main__':
    main()
