"""Synthetic-only regression for full SecNeo H native JNI registration."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_inner_h_jni_full_registration",
    TOOLS/"audit_inner_h_jni_full_registration.py")
subject=importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class HNativeRegistrationTests(unittest.TestCase):
    def test_names_signatures_and_original_register_addresses(self):
        expected=[
            ("gha","(Ljava/lang/String;)I",0x367a4),
            ("ghc","(Ljava/lang/String;)J",0x36814),
            ("gah","()[Ljava/lang/Object;",0x3687c),
            ("sha","(Ljava/lang/String;I)V",0x36f14),
            ("he","(I)V",0x36f4c),
            ("gv","()I",0x3714c),
        ]
        self.assertEqual([x[:3] for x in subject.METHODS],expected)
        self.assertEqual([x[2] for x in subject.POINTER_PAIRS],
                         [x[2] for x in expected])
        self.assertEqual(subject.PINNED[0x16118],0x528000c3)

    def test_tail_branch_to_record_writer(self):
        self.assertEqual(subject.unconditional_branch_target(
            0x17ffbf1e,0x36f48),0x26bc0)
        with self.assertRaises(ValueError):
            subject.unconditional_branch_target(0xd65f03c0,0x36f48)

    def test_original_native_guard_and_exit_are_pinned(self):
        self.assertEqual(subject.PINNED[0x36f64],0x7107e05f)
        self.assertEqual(subject.PINNED[0x36f70],0x7138785f)
        self.assertEqual(subject.PINNED[0x37088],0x97ff5fae)
        self.assertEqual(subject.PINNED[0x3714c],0x528067c0)

    def test_unrelated_dex_rejected_before_native_registration(self):
        with self.assertRaisesRegex(ValueError,"classes.dex"):
            subject.native_declarations(b"synthetic")

    def test_recovered_elf_must_match_original_hash(self):
        with self.assertRaisesRegex(ValueError,"inner ELF SHA"):
            subject.audit(b"synthetic",b"synthetic")

    def test_synthetic_mutation_of_native_word_is_detected(self):
        mock_hash=patch.object(subject.hashlib,"sha256")
        with mock_hash as digest, patch.object(subject,"word",return_value=0):
            digest.return_value.hexdigest.return_value=subject.SAMPLES[
                "libDexHelper.so"]["inner_sha"]
            with self.assertRaisesRegex(ValueError,"JNI instruction mismatch"):
                subject.audit(b"synthetic",b"synthetic")


if __name__=="__main__":
    unittest.main()
