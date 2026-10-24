"""Synthetic-only tests for SecNeo H service bind/unbind static audit."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_inner_h_service_lifecycle",
    TOOLS/"audit_inner_h_service_lifecycle.py")
audit=importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class SecneoServiceLifecycleTests(unittest.TestCase):
    def test_original_four_native_callbacks_are_distinct(self):
        self.assertEqual(
            [(n,target) for n,desc,target,*rest in audit.JNI_CALLBACKS],
            [("sw",0x2c440),("bs",0x2c8d8),
             ("is",0x2d158),("us",0x2d178)])
        self.assertEqual(audit.NATIVE_WORDS[0x154a4],0x52800083)

    def test_native_flag_guards_and_early_return_offsets(self):
        self.assertEqual(audit.bittest(0x37002203,0x2c46c),
                         (3,0,0x2c8ac))
        self.assertEqual(audit.bittest(0x37080123,0x2c90c),
                         (3,1,0x2c930))
        with self.assertRaisesRegex(ValueError,"TBNZ"):
            audit.bittest(0x36002203,0x2c46c)
        default=255
        self.assertTrue(default&(1<<0))
        self.assertTrue(default&(1<<1))

    def test_all_jni_format_strings_recover_from_synthetic_instruction_words(self):
        printable=bytes(range(32,127))
        instructions={}
        for expected,sites,base,reg in audit.STRINGS:
            for i,(pc,char) in enumerate(zip(sites,expected)):
                target=9 if base==0x21 else 10 if base==5 and i<len(sites)-1 \
                    else 9 if base==5 else 8
                immediate=ord(char)-32-base
                self.assertTrue(immediate>=0)
                instructions[pc]=0x39400000|(immediate<<10)|(reg<<5)|target
        with patch.object(audit,"elf_word",
                          side_effect=lambda elf,pc:instructions[pc]):
            actual=[audit.decoded_indexed_string(
                b"synthetic",printable,sites,base,reg)
                    for expected,sites,base,reg in audit.STRINGS]
        self.assertEqual(actual,["%s/IsoService","bindService",
                                 "unbindService","BIND_AUTO_CREATE"])

    def test_four_native_method_names_from_synthetic_original_style_ldr(self):
        names=(("sw",(0x152d8,0x152ec)),
               ("bs",(0x153fc,0x1540c)),
               ("is",(0x15474,0x15488)),
               ("us",(0x154d8,0x154e4)))
        instructions={}
        for name,sites in names:
            for pc,char in zip(sites,name):
                instructions[pc]=0x39400388|((ord(char)-32-8)<<10)
        with patch.object(audit,"elf_word",
                          side_effect=lambda elf,pc:instructions[pc]):
            self.assertEqual(
                [audit.native_registration_name(
                    b"synthetic",bytes(range(32,127)),sites)
                 for name,sites in names],
                [name for name,sites in names])
        instructions[0x154d8]=0x39400389
        with patch.object(audit,"elf_word",
                          side_effect=lambda elf,pc:instructions[pc]):
            with self.assertRaisesRegex(ValueError,"method-name LDRB"):
                audit.native_registration_name(
                    b"",bytes(range(32,127)),(0x154d8,0x154e4))

    def test_corrupted_original_ldr_operand_is_rejected(self):
        with patch.object(audit,"elf_word",return_value=0x39400008):
            with self.assertRaisesRegex(ValueError,"LDRB operands"):
                expected,sites,base,reg=audit.STRINGS[0]
                audit.decoded_indexed_string(
                    b"",bytes(range(32,127)),sites,base,reg)

    def test_axml_manifest_counts_only_service_names(self):
        # Independently manufactured binary AXML; no original Manifest bytes.
        strings=["manifest","service","name","com.test.NormalService"]
        pooldata=bytearray()
        offsets=[]
        for s in strings:
            raw=s.encode()
            offsets.append(len(pooldata))
            pooldata.extend(bytes((len(s),len(raw)))+raw+b"\0")
        pool_head=28+len(offsets)*4
        pool=bytearray(struct.pack("<HHI",1,28,pool_head+len(pooldata)))
        pool.extend(struct.pack("<IIIII",len(strings),0,0x100,pool_head,0))
        for off in offsets:
            pool.extend(struct.pack("<I",off))
        pool.extend(pooldata)
        # START_ELEMENT with one android:name style string attribute.
        elem=bytearray(56)
        struct.pack_into("<HHI",elem,0,0x102,16,len(elem))
        struct.pack_into("<II",elem,16,0xffffffff,1)
        struct.pack_into("<HHH",elem,24,20,20,1)
        struct.pack_into("<III",elem,36,0xffffffff,2,3)
        elem[51]=3
        struct.pack_into("<I",elem,52,3)
        body=pool+elem
        data=struct.pack("<HHI",3,8,8+len(body))+body
        self.assertEqual(audit.manifest_service_names(data),
                         ["com.test.NormalService"])

    def test_scoped_pc_flag_direct_field_sites(self):
        # Three independent synthetic code_items, no original DEX bytes.
        data=bytearray(0x5300)
        items=[(("LH;","<clinit>","()V"),108,0x427c,65),
               (("LH;","callBS","()V"),130,0x4bb0,23),
               (("LH;","callSW","()V"),131,0x4c0c,23)]
        for caller,mid,off,units in items:
            struct.pack_into("<I",data,off+12,units)
        for pc,opcode in ((0x42f0,0x69),(0x4bda,0x62),(0x4c36,0x62)):
            struct.pack_into("<HH",data,pc,opcode,11)
        fake_items=[(caller,mid,off) for caller,mid,off,units in items]
        with patch.object(audit,"code_items",return_value=fake_items):
            result=audit.direct_pc_flag_sites(bytes(data),[],[])
            self.assertEqual(len(result["direct_writes"]),1)
            self.assertEqual(len(result["direct_reads"]),2)
            struct.pack_into("<H",data,0x42f2,12)
            with self.assertRaisesRegex(ValueError,"PC_FLAG field use census"):
                audit.direct_pc_flag_sites(bytes(data),[],[])

    def test_manifest_unresolvable_name_and_invalid_blob_fail_closed(self):
        with self.assertRaisesRegex(ValueError,"header"):
            audit.manifest_service_names(b"")
        with self.assertRaisesRegex(ValueError,"inner ELF SHA"):
            audit.audit(b"synthetic",b"synthetic",b"synthetic")


if __name__=="__main__":
    unittest.main()
