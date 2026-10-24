#!/usr/bin/env python3
"""Audit the original SecNeo Messenger message -> H.he(int) Java/native path.

Pinned original 12.5.5 base classes.dex inside APK/diagnostic ZIP. Verify
DEX declarations, original encoded-method code_items, instruction operands,
Message fields and methods. This is static evidence: no runtime messages,
remote service implementation, or DEC behavior is inferred.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from audit_nested_elf import APK_SHA
from audit_secneo_h_ipc import DEX_SHA, metadata, u32, u16, uleb

H="Lcom/secneo/apkwrapper/H;"
HANDLER="Lcom/secneo/apkwrapper/H$a;"
SERVICE="Lcom/secneo/apkwrapper/b;"
SENDER=(SERVICE,"onServiceConnected",
        "(Landroid/content/ComponentName;Landroid/os/IBinder;)V")
RECEIVER=(HANDLER,"handleMessage","(Landroid/os/Message;)V")
DELEGATE=(H,"c","(I)V")
INITIALIZER=(H,"<clinit>","()V")
NATIVE=(H,"he","(I)V")
CODE_OFFSETS={SENDER:0x518c, RECEIVER:0x41fc, DELEGATE:0x4af0,
              INITIALIZER:0x427c}
METHOD_REFS={
  52:("Landroid/os/Message;","obtain",
      "(Landroid/os/Handler;I)Landroid/os/Message;"),
  55:("Landroid/os/Messenger;","send","(Landroid/os/Message;)V"),
  58:("Landroid/os/Process;","myPid","()I"),
  112:(H,"a","()Landroid/os/Messenger;"),
  117:(H,"b","()Landroid/os/Messenger;"),
  128:DELEGATE,
  141:NATIVE,
  154:(SERVICE,"<init>","()V"),
}
FIELD_REFS={
  3:("Landroid/os/Message;","arg1","I"),
  4:("Landroid/os/Message;","arg2","I"),
  5:("Landroid/os/Message;","replyTo","Landroid/os/Messenger;"),
  6:("Landroid/os/Message;","what","I"),
}
WORDS={
  0x42fe:0x0022, 0x4300:0x0032, # H.<clinit> creates b ServiceConnection
  0x4302:0x1070, 0x4304:0x009a, # invoke-direct b.<init>
  0x4226:0x7052, 0x4228:0x0006, # receiver reads Message.what
  0x422a:0x0113, 0x422c:0x03e8, # compare against 1000
  0x422e:0x1032, 0x4230:0x0006, # if-eq -> handle branch
  0x4254:0x7752, 0x4256:0x0004, # receiver Message.arg2
  0x4258:0x1071, 0x425a:0x0080, # -> H.c(int)
  0x4b1a:0x1071, 0x4b1c:0x008d, # -> H.he(int)
  0x51fa:0x0813, 0x51fc:0x03e8, # sender what=1000
  0x51fe:0x2071, 0x5200:0x0034, # Message.obtain
  0x5206:0x0071, 0x5208:0x003a, # Process.myPid
  0x520e:0x7859, 0x5210:0x0003, # Message.arg1
  0x5212:0x0071, 0x5214:0x0070, # H.a() reply Messenger
  0x521a:0x785b, 0x521c:0x0005, # Message.replyTo
  0x521e:0x0071, 0x5220:0x0075, # H.b() remote Messenger
  0x5226:0x206e, 0x5228:0x0037, # Messenger.send
}


def code_items(dex,methods,types):
    count=u32(dex,0x60)
    base=u32(dex,0x64)
    encoded=[]
    for c in range(count):
        item=base+32*c
        class_id=u32(dex,item)
        if class_id>=len(types):
            raise ValueError("DEX class id out of bounds")
        pos=u32(dex,item+24)
        if not pos:
            continue
        counts=[]
        for _ in range(4):
            n,pos=uleb(dex,pos)
            counts.append(n)
        if sum(counts)>100000:
            raise ValueError("DEX class data count unreasonable")
        for _ in range(counts[0]+counts[1]):
            _,pos=uleb(dex,pos)
            _,pos=uleb(dex,pos)
        for amount in counts[2:]:
            mid=0
            for _ in range(amount):
                diff,pos=uleb(dex,pos)
                flags,pos=uleb(dex,pos)
                offset,pos=uleb(dex,pos)
                mid+=diff
                if mid>=len(methods):
                    raise ValueError("DEX encoded method id out of bounds")
                if offset:
                    encoded.append((methods[mid],mid,offset))
    return encoded


def pin_source(dex):
    if hashlib.sha256(dex).hexdigest()!=DEX_SHA or len(dex)!=21820:
        raise ValueError("original classes.dex SHA-256 mismatch")
    strings,types,methods=metadata(dex)
    for index,expected in METHOD_REFS.items():
        if methods[index]!=expected:
            raise ValueError("original method reference changed at "+str(index))
    fields_count=u32(dex,0x50)
    field_base=u32(dex,0x54)
    for index,expected in FIELD_REFS.items():
        if index>=fields_count:
            raise ValueError("original Message field absent")
        cl,typ,name=struct.unpack_from("<HHI",dex,field_base+index*8)
        observed=(types[cl],strings[name],types[typ])
        if observed!=expected:
            raise ValueError("original Message field changed at "+str(index))
    codes=code_items(dex,methods,types)
    indexed={key:(mid,off) for key,mid,off in codes}
    if len(codes)!=65:
        raise ValueError("original base DEX code_item census changed")
    for key,expected in CODE_OFFSETS.items():
        if key not in indexed or indexed[key][1]!=expected:
            raise ValueError("original code_item offset changed: "+str(key))
    for offset,w in WORDS.items():
        if u16(dex,offset)!=w:
            raise ValueError("original Dalvik instruction changed at "+hex(offset))
    # Validated call targets are real invoke-static, not arbitrary method-name
    # strings: the operand is 16-bit method_idx immediately after opcode.
    def invoke_at(offset,method_index):
        if (u16(dex,offset)&0xff)!=0x71 or u16(dex,offset+2)!=method_index:
            raise ValueError("expected invoke-static method operand")
    invoke_at(0x4258,128)
    invoke_at(0x4b1a,141)
    for offset,method_index in ((0x51fe,52),(0x5206,58),
                                (0x5212,112),(0x521e,117)):
        invoke_at(offset,method_index)
    # An aligned invoke-candidate census is scoped only to complete
    # code_items in the pinned original small DEX, never protected DEX.
    target_ids={135,138,139,140,141,146}
    targets=[]
    for caller,caller_id,codeoff in codes:
        n=u32(dex,codeoff+12)
        if not 0<n<100000 or codeoff+16+2*n>len(dex):
            raise ValueError("invalid original code_item size")
        body=dex[codeoff+16:codeoff+16+2*n]
        for i in range(0,len(body)-5,2):
            if body[i] in (*range(0x6e,0x73),*range(0x74,0x79)):
                callee=struct.unpack_from("<H",body,i+2)[0]
                if callee in target_ids:
                    targets.append({
                        "caller":caller[0]+"->"+caller[1]+caller[2],
                        "callee":methods[callee][1],
                        "instruction_va":hex(codeoff+16+i),
                    })
    if targets!=[{
        "caller":H+"->c(I)V",
        "callee":"he",
        "instruction_va":"0x4b1a",
    }]:
        raise ValueError("base DEX six-native direct-call candidates changed")
    return {
        "classes_dex_sha256":DEX_SHA,
        "validated_code_items":len(codes),
        "service_connection_created":(
            "H.<clinit> at 0x42fe/0x4302 constructs SecNeo b ServiceConnection; "
            "remote Service identity/bind implementation not established"),
        "sender":{
            "method":SERVICE+"->onServiceConnected",
            "code_item":hex(CODE_OFFSETS[SENDER]),
            "obtains":"Message.obtain(Handler,1000) at 0x51fe",
            "sets_arg1":"Process.myPid() -> Message.arg1 at 0x520e",
            "sets_replyTo":"H.a() Messenger -> Message.replyTo at 0x521a",
            "sends":"H.b() Messenger.send(message) at 0x5226",
        },
        "receiver":{
            "method":HANDLER+"->handleMessage",
            "code_item":hex(CODE_OFFSETS[RECEIVER]),
            "filter":"Message.what == 1000 (0x4226..0x4230)",
            "forwards":"Message.arg2 -> H.c(int) (0x4254..0x425a)",
        },
        "java_to_native":"H.c(int) 0x4b1a -> H.he(int), JNI function 0x36f4c",
        "direct_calls_to_six_native_methods_in_base_dex":targets,
        "limitations":"Remote Messenger service and actual reply payload unobserved. "
                      "No static proof of DEC use, device-time messages or "
                      "the selected he() native branch.",
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source",type=Path)
    args=p.parse_args()
    raw=args.source.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if "apks/01-base.apk" in archive.namelist():
            raw=archive.read("apks/01-base.apk")
    if hashlib.sha256(raw).hexdigest()!=APK_SHA:
        raise ValueError("original APK SHA mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        dex=archive.read("classes.dex")
    print(json.dumps(pin_source(dex),ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
