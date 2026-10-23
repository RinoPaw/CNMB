"""Synthetic-only tests for System V hash and original ELF bucket assertions."""
import importlib.util
import sys
import unittest
import struct
from pathlib import Path
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_dexhelper_symbol_fallback",TOOLS/"audit_dexhelper_symbol_fallback.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SymbolFallbackTests(unittest.TestCase):
    def test_system_v_elf_hash_golden_vectors(self):
        self.assertEqual(m.sysv_elf_hash("printf"),0x77905a6)
        self.assertEqual(m.sysv_elf_hash("dlopen"),0x6b366be)
        self.assertEqual(m.sysv_elf_hash("JNI_OnLoad"),0x467e784)
        self.assertEqual(m.sysv_elf_hash(b""),0)

    def test_hash_masks_to_28_bits(self):
        for name in ("com.example.long_a_a_a_a_a_a", "some_module_symbol"):
            self.assertLess(m.sysv_elf_hash(name),1<<28)
        self.assertEqual(m.sysv_elf_hash("A"), ord("A"))

    def test_symbol_table_zero_region_is_detectable(self):
        buckets,chains=197,239
        data=bytearray(8+4*(buckets+chains))
        struct.pack_into("<II",data,0,buckets,chains)
        n_b,n_c=struct.unpack_from("<II",data,0)
        bvals=struct.unpack_from(f"<{n_b}I",data,8)
        cvals=struct.unpack_from(f"<{n_c}I",data,8+4*n_b)
        self.assertFalse(any(bvals))
        self.assertFalse(any(cvals))
        data[8+4*5]=1
        self.assertTrue(any(struct.unpack_from(f"<{n_b}I",data,8)))


if __name__=="__main__":
    unittest.main()
