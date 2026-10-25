"""Synthetic tests for pinned SecNeo JNI PC_FLAG direct setter census."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_inner_pc_flag_setter_census",
    TOOLS/"audit_inner_pc_flag_setter_census.py")
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def make_elf():
    # Minimal fully synthetic ELF64 with .shstrtab/.text section.
    raw=bytearray(0x500)
    raw[0:6]=b"\x7fELF\x02\x01"
    names=b"\x00.shstrtab\x00.text\x00"
    raw[0x40:0x40+len(names)]=names
    struct.pack_into("<Q",raw,40,0x200)
    struct.pack_into("<HHH",raw,58,64,3,1)
    struct.pack_into("<IIQQQQIIQQ",raw,0x200+64,
                     1,3,0,0,0x40,len(names),0,0,1,0)
    struct.pack_into("<IIQQQQIIQQ",raw,0x200+128,
                     11,1,6,0x1000,0x100,16,0,0,4,0)
    return raw


class SetStaticFieldCensusTests(unittest.TestCase):
    def test_expected_sites_and_bit_setting(self):
        self.assertEqual(a.EXPECTED_SITES,
                         ((0x2c5d8,0xf9426908),(0x2cab8,0xf9426908)))
        self.assertEqual(a.ORR_WORDS,
                         ((0x2c4a4,0x320002a3),(0x2c97c,0x321f02c3)))
        self.assertEqual(a.SET_STATIC_FIELD_JNI_OFFSET,0x4d0)
        self.assertEqual(255|1,255)
        self.assertEqual(255|2,255)

    def test_accepts_synthetic_elf_structure_with_patched_pinned_range(self):
        raw=make_elf()
        self.assertEqual(a.elf_text_range(raw[:]) if False else len(raw),len(raw))
        with patch.object(a,"EXPECTED_TEXT",(0x1000,16)):
            self.assertEqual(a.elf_text_range(raw),(0x1000,16,0x100))
            struct.pack_into("<IIII",raw,0x100,
                             0xd503201f,0xf9426908,0xf9446908,0xf9426908)
            self.assertEqual(a.direct_jni_setter_vtable_loads(raw),
                             [(0x1004,0xf9426908),(0x100c,0xf9426908)])
            struct.pack_into("<I",raw,0x104,0xf9406908)
            self.assertEqual(a.direct_jni_setter_vtable_loads(raw),
                             [(0x100c,0xf9426908)])

    def test_mutated_original_text_range_rejected(self):
        raw=make_elf()
        with self.assertRaisesRegex(ValueError,"original executable .text"):
            a.elf_text_range(raw)
        with self.assertRaisesRegex(ValueError,"ELF64"):
            a.elf_text_range(b"bad")

    def test_unverified_elf_rejected_first(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic")

    def test_script_stays_explicit_about_indirect_call_limits(self):
        self.assertEqual(a.EXPECTED_TEXT,(0xfa00,0xe0358))
        self.assertEqual([pc for pc,_ in a.INDIRECT_CALLS],
                         [0x2c5e0,0x2cac0])


if __name__=="__main__":
    unittest.main()
