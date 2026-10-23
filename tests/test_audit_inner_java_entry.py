"""Original-free tests for class-fallback ARM64 char builder and argv pointer."""
import importlib.util
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_inner_java_entry",TOOLS/"audit_inner_java_entry.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    b=bytearray(0x5a720)
    for pos,word in m.WORDS.items():
        struct.pack_into("<I",b,pos,word)
    for i,(addr,ch) in enumerate(zip(m.CHAR_LOAD_SITES,m.EXPECTED_DEFAULT)):
        # Synthetic LDRB w9,[x28,#imm12]; final byte uses w10.
        rt=10 if addr==0x173dc else 9
        idx=ord(ch)-32-m.TABLE_BASE_INDEX
        insn=0x39400000 | (idx<<10) | (28<<5) | rt
        struct.pack_into("<I",b,addr,insn)
        output_address=addr+(12 if addr==0x173dc else 4)
        st=0x39000000 | ((0xf0+i)<<10) | (31<<5) | rt
        struct.pack_into("<I",b,output_address,st)
    return b


class DefaultJavaEntryTests(unittest.TestCase):
    def test_exact_fallback_class_from_original_instruction_form(self):
        b=fixture()
        with patch.object(m,"elf_file_offset",side_effect=lambda _,pos:pos),\
             patch.object(m,"decode_table",return_value=bytes(range(32,127))):
            self.assertEqual(m.decode_class_from_code(b),
                             "com/secneo/apkwrapper/H")

    def test_java_class_field_used_for_execl_register(self):
        b=fixture()
        with patch.object(m,"elf_file_offset",side_effect=lambda _,pos:pos),\
             patch.object(m,"decode_table",return_value=bytes(range(32,127))),\
             patch.object(m,"bl_target",
                          side_effect=lambda _,pos:{0x17080:0xf7b0,
                                                    0x5a710:0xf7f0}[pos]):
            result=m.audit(b)
            self.assertEqual(result["execl"]["argument_register"],"x4, 0x5a708")
            self.assertEqual(result["construction"]["runtime_instance_slot_va"],"0x12a418")
            self.assertEqual(result["fallback_java_main_dot_name"],
                             "com.secneo.apkwrapper.H")
            self.assertFalse(result["runtime_override"]["actual_runtime_override_observed"])

    def test_changed_character_load_or_destination_rejected(self):
        b=fixture()
        b[m.CHAR_LOAD_SITES[0]] ^= 1
        with patch.object(m,"elf_file_offset",side_effect=lambda _,pos:pos),\
             patch.object(m,"decode_table",return_value=bytes(range(32,127))):
            with self.assertRaisesRegex(ValueError,"Unexpected original LDRB|position/register"):
                m.decode_class_from_code(b)
        b=fixture()
        b[m.CHAR_LOAD_SITES[3]+4] ^= 0x04
        with patch.object(m,"elf_file_offset",side_effect=lambda _,pos:pos),\
             patch.object(m,"decode_table",return_value=bytes(range(32,127))):
            with self.assertRaises(ValueError):
                m.decode_class_from_code(b)


if __name__=="__main__":
    unittest.main()
