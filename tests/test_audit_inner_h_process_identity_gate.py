"""Synthetic regression for SecNeo sw/bs identity gate audit."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_inner_h_process_identity_gate",
    TOOLS/"audit_inner_h_process_identity_gate.py")
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class IdentityGateTests(unittest.TestCase):
    def test_original_procfs_strings_decode_from_synthetic_ldr(self):
        all_sites=a.PREFIX_SITES+a.SUFFIX_SITES
        text=b"/proc//cmdline"
        self.assertEqual(len(text),len(all_sites))
        words={site:0x39400128|((char-32-0x0f)<<10)
               for site,char in zip(all_sites,text)}
        with patch.object(a,"word",side_effect=lambda elf,pc:words[pc]):
            self.assertEqual(a.text_from_original_ldr(
                b"",bytes(range(32,127)),a.PREFIX_SITES),"/proc/")
            self.assertEqual(a.text_from_original_ldr(
                b"",bytes(range(32,127)),a.SUFFIX_SITES),"/cmdline")
            words[a.PREFIX_SITES[0]]^=1
            with self.assertRaisesRegex(ValueError,"LDRB"):
                a.text_from_original_ldr(
                    b"",bytes(range(32,127)),a.PREFIX_SITES)

    def test_original_sw_bs_bit_tests(self):
        a.bittest_target(0x37002203,0x2c46c,3,0,0x2c8ac)
        a.bittest_target(0x37080123,0x2c90c,3,1,0x2c930)
        with self.assertRaisesRegex(ValueError,"register/bit/target"):
            a.bittest_target(0x37080123,0x2c90c,3,0,0x2c930)

    def test_original_zero_and_nonzero_helper_result_branches(self):
        a.branch_imm_target(0x35002080,0x2c49c,0x35000000,0x2c8ac)
        a.branch_imm_target(0x340001c0,0x2c92c,0x34000000,0x2c964)
        a.branch_imm_target(0x34002168,0x2c480,0x34000000,0x2c8ac)
        a.branch_imm_target(0x34fffde8,0x2c974,0x34000000,0x2c930)
        with self.assertRaisesRegex(ValueError,"target"):
            a.branch_imm_target(0x340001c0,0x2c92c,0x34000000,0x2c930)

    def test_real_original_call_pairs_and_result_code_pins(self):
        self.assertEqual(a.WORDS[0x2c01c],0xd2801588) # getpid
        self.assertEqual(a.WORDS[0x2c194],0xd2800708) # openat
        self.assertEqual(a.WORDS[0x2c1dc],0xd28007e8) # read
        self.assertEqual(a.WORDS[0x2c2b8],0x52800020)
        self.assertEqual(a.WORDS[0x2c42c],0x52800040)
        self.assertEqual(a.WORDS[0x2c400],0x52800060)

    def test_identity_object_init_pointer_and_bit_layout_pinned(self):
        # Original x8 object 0x12a684 is published through RELATIVE GOT
        # 0x123bd8 -> 0x128008; the low byte of the decoded config is true.
        self.assertEqual(a.WORDS[0x15208], 0x39522b0a)
        self.assertEqual(a.WORDS[0x15214], 0x3400028a)
        self.assertEqual(a.WORDS[0x15250], 0xb800632d)
        self.assertEqual(a.WORDS[0x152a4], 0xf9000128)
        state=0x12a684
        store_at=0x12a689+6
        self.assertEqual(store_at,state+11)
        self.assertEqual((0x01000101 >> 8) & 0xff,1)
        self.assertEqual(store_at+1,0x12a690)

    def test_original_elf_hash_required_before_any_interpretation(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic-no-original")


if __name__=="__main__":
    unittest.main()
