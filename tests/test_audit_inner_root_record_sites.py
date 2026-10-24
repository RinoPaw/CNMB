"""Synthetic regressions for independently pinned root-record source callsites."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_inner_root_record_sites",TOOLS/"audit_inner_root_record_sites.py")
subject=importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class RecordSourceTests(unittest.TestCase):
    def test_five_static_read_before_write_patterns(self):
        words={}
        targets={}
        for _,mov,name,read,write,marker,extras in subject.SITES:
            words[mov]=0x52800020
            words.update(extras)
            words[read+4]=0x72001c1f
            words[read+8]=0x540000c1
            targets.update({name:0x2616c,read:0x2682c,write:0x26bc0})
        with patch.object(subject,"word",side_effect=lambda elf,pc:words[pc]), \
             patch.object(subject,"bl_target",
                          side_effect=lambda elf,pc:targets[pc]):
            cases=subject.inspect_sites(b"synthetic")
        self.assertEqual(len(cases),5)
        self.assertEqual({r["record_marker"] for r in cases},{
            "0xb6a281f3","0xb6a281f2","0xb6a281f8",
            "0xb6a281f7","0xb6a281f5"})
        self.assertTrue(all(r["status_nonzero_skips_update"] for r in cases))

    def test_bad_movement_word_rejected(self):
        with patch.object(subject,"word",return_value=0):
            with self.assertRaisesRegex(ValueError,"instruction mismatch"):
                subject.inspect_sites(b"synthetic")

    def test_different_reader_branch_rejected(self):
        words={}
        targets={}
        for _,mov,name,read,write,marker,extras in subject.SITES:
            words[mov]=0x52800020; words.update(extras)
            words[read+4]=0x72001c1f
            words[read+8]=0x540000c0  # equal branch, not nonzero
            targets.update({name:0x2616c,read:0x2682c,write:0x26bc0})
        with patch.object(subject,"word",side_effect=lambda elf,pc:words[pc]), \
             patch.object(subject,"bl_target",
                          side_effect=lambda elf,pc:targets[pc]):
            with self.assertRaisesRegex(ValueError,"Expected B.NE|expected B.NE"):
                subject.inspect_sites(b"synthetic")

    def test_invalid_original_blob_rejected(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            subject.audit(b"not original")


if __name__=="__main__":
    unittest.main()
