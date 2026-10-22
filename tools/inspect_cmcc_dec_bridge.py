#!/usr/bin/env python3
"""Verify CmccApplication.onCreate -> DECApp.intiDECabcOnCreate in CNMB 12.5.5.

Only fixed, SHA256-pinned original libdatajar.so bytes. This parses a separate
recoverable Dex fragment and restores the early masked string index offsets.
"""
import argparse
import struct
from pathlib import Path
from inspect_dec_tables import load, uleb

BASE=0x2f0e00c
STRINGS=0x2f2e00c
TYPES=0x2f5c99c
PROTOS=0x2f677d4
FIELDS=0x2f8c038
METHODS=0x2ffcfb0
CLASSES=0x307b908
FIRST_ID=(STRINGS-(BASE+0x70))//4
STRING_COUNT=FIRST_ID+(TYPES-STRINGS)//4
TYPE_COUNT=(PROTOS-TYPES)//4
METHOD_COUNT=(CLASSES-METHODS)//8


def u32(data,off):
    return struct.unpack_from('<I',data,off)[0]


def recover_strings(data):
    first=BASE+u32(data,STRINGS)
    assert first==0x3202ede
    ptr=first
    hidden=[0]*FIRST_ID
    for sid in range(FIRST_ID-1,-1,-1):
        assert data[ptr-1]==0
        ptr=data.rfind(b'\0',0,ptr-1)+1
        assert ptr>0
        hidden[sid]=ptr
    assert ptr==0x30b8469
    assert hidden[13917]==0x3134767
    hidden.extend(BASE+u32(data,STRINGS+4*i) for i in range((TYPES-STRINGS)//4))
    assert len(hidden)==STRING_COUNT==80456
    assert all(a<b for a,b in zip(hidden,hidden[1:]))
    return hidden


def text(data,pointers,sid):
    _,start=uleb(data,pointers[sid])
    return data[start:data.index(b'\0',start)].decode('utf-8','replace')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path)
    a=p.parse_args()
    data=load(a.source)
    pointers=recover_strings(data)
    ty=[u32(data,TYPES+4*i) for i in range(TYPE_COUNT)]
    assert TYPE_COUNT==11150 and METHOD_COUNT==64811
    assert text(data,pointers,13917)=='Lcom/a/b/c/DECApp;'
    assert (ty[781],ty[6791])==(13917,20058)
    assert text(data,pointers,20058)=='Lcom/mc10086/cmcc/base/CmccApplication;'
    defs={}
    for i in range(TYPE_COUNT):
        pos=CLASSES+32*i
        record=struct.unpack_from('<8I',data,pos)
        cl,fl,supercls,it,src,ann,cdata,static=record
        if not(cl<TYPE_COUNT and (supercls<TYPE_COUNT or supercls==0xffffffff)
               and (src<STRING_COUNT or src==0xffffffff)):
            break
        assert cl not in defs
        defs[cl]=(pos,record)
    assert len(defs)==7771
    assert 6791 in defs and 781 not in defs
    pos,rec=defs[6791]
    assert pos==0x30a1908
    super_name=text(data,pointers,ty[rec[2]])
    assert super_name=='Landroid/app/Application;'

    def methodref(i):
        cl,proto,nm=struct.unpack_from('<HHI',data,METHODS+8*i)
        return cl,proto,text(data,pointers,nm)
    assert methodref(3299)==(781,5864,'intiDECabcOnCreate')
    assert methodref(44315)[0]==6791 and methodref(44315)[2]=='DEC_origin_onCreate'
    assert methodref(44339)[0]==6791 and methodref(44339)[2]=='onCreate'
    # Exact prototype: void (Application), including the parameter type_list.
    shorty,retval,params=struct.unpack_from('<III',data,PROTOS+12*5864)
    assert text(data,pointers,ty[retval])=='V'
    param=BASE+params
    assert u32(data,param)==1
    typ=struct.unpack_from('<H',data,param+4)[0]
    assert text(data,pointers,ty[typ])=='Landroid/app/Application;'

    # The CmccApplication class_data_item contains both original and woven entry.
    at=BASE+rec[6]
    counts=[]
    for _ in range(4):
        n,at=uleb(data,at)
        counts.append(n)
    assert counts==[8,5,16,15],counts
    for _ in range(counts[0]+counts[1]):
        _,at=uleb(data,at)
        _,at=uleb(data,at)
    code={}
    for size in counts[2:]:
        idx=0
        for _ in range(size):
            delta,at=uleb(data,at)
            _,at=uleb(data,at)
            off,at=uleb(data,at)
            idx+=delta
            if off:code[idx]=BASE+off
    assert code[44315]==0x364ab78
    assert code[44339]==0x364ae1c
    head=struct.unpack_from('<HHHHII',data,code[44339])
    assert head[:4]==(2,1,1,0) and head[5]==7
    instructions=data[code[44339]+16:code[44339]+30]
    assert instructions==bytes.fromhex('6e 10 1b ad 01 00 71 10 e3 0c 01 00 0e 00')
    print('Recovered 32,740 masked string indices in second Dex fragment')
    print('CmccApplication type=6791 classdef=0x30a1908 extends Application')
    print('DECApp type=781, method_id=3299, proto void(Application)')
    print('CmccApplication.onCreate @0x364ae1c:')
    print('  invoke-virtual {v1}, DEC_origin_onCreate()  @0x364ae2c')
    print('  invoke-static  {v1}, DECApp.intiDECabcOnCreate(Application) @0x364ae32')
    print('  return-void')
    print('CONFIRMED: real application startup is wired to DEC initialization')
    print('LIMIT: DeviceEnvironmentCheck.startCheck implementation remains missing')


if __name__=='__main__':
    main()
