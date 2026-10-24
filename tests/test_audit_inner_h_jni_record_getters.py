"""Synthetic-only regression for original H Java/native envc.push getter bindings."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_inner_h_jni_record_getters",TOOLS/"audit_inner_h_jni_record_getters.py")
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class NativeRecordGetterTests(unittest.TestCase):
    def test_method_names_and_descriptors_from_original_form_immediates(self):
        chars=bytes(range(32,127))
        code={}
        for begin,end,n,expected in a.METHOD_TEXT_SITES:
            assert len(expected)==n
            sites=list(range(begin,end+1,4))
            # Synthetic: use the first n available LDRB sites, then confirm
            # that the parser requires exactly n loads and decoded content.
            for site,ch in zip(sites,expected):
                idx=ord(ch)-32-8
                assert 0<=idx<95
                code[site]=0x39400388|(idx<<10)
        with patch.object(a,"word",side_effect=lambda elf,pc:code.get(pc,0)):
            actual=[a.method_text(b"",chars,start,end,n)
                    for start,end,n,_ in a.METHOD_TEXT_SITES]
        self.assertEqual(actual,["gha","(Ljava/lang/String;)I",
                                 "ghc","(Ljava/lang/String;)J"])

    def test_decode_rejects_name_length_mismatch(self):
        with patch.object(a,"word",return_value=0):
            with self.assertRaisesRegex(ValueError,"literal load count"):
                a.method_text(b"",bytes(range(32,127)),0x160c4,0x160f0,3)

    def test_bad_original_blob_rejected(self):
        with self.assertRaisesRegex(ValueError,"inner ELF SHA"):
            a.audit(b"not original",b"not original")

    def test_declarations_fail_on_invalid_original_dex(self):
        with self.assertRaisesRegex(ValueError,"classes.dex"):
            a.dex_declarations(b"not original")

    def test_static_branches_and_method_table_slots_pinned(self):
        self.assertEqual(a.WORDS[0x16118],0x528000c3)
        self.assertEqual(a.WORDS[0x164f8],0xf9435d08)
        self.assertEqual(a.WORDS[0x174b0],0xf900b2c0)
        self.assertEqual(a.WORDS[0x367fc],0x12001ec0)
        self.assertEqual(a.WORDS[0x36868],0xb9400fe0)

    def test_native_branch_mutation_rejected_before_interpreting(self):
        with patch.object(a.hashlib,"sha256") as digest, \
             patch.object(a,"word",return_value=0):
            digest.return_value.hexdigest.return_value=a.ELF_SHA
            with self.assertRaisesRegex(ValueError,"JNI machine word changed"):
                a.audit(b"synthetic ELF",b"synthetic DEX")


if __name__=="__main__":
    unittest.main()
