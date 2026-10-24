"""Synthetic-only tests for pinned native conditional file I/O inspection."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_inner_h_followup_file_io",TOOLS/"audit_inner_h_followup_file_io.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FollowupTests(unittest.TestCase):
    def test_expected_output_with_synthetic_dispatch(self):
        with patch.object(module.hashlib,"sha256") as digest, \
             patch.object(module,"at",side_effect=lambda b,va:module.WORDS[va]), \
             patch.object(module,"bl_target",side_effect=lambda b,va:
                 module.PLT_CALLS[va][1] if va in module.PLT_CALLS
                 else module.INTERNAL_CALLS[va]):
            digest.return_value.hexdigest.return_value=module.SAMPLES[
                "libDexHelper.so"]["inner_sha"]
            result=module.audit(b"synthetic")
        self.assertEqual(result["file_update_helper"]["entry"],"0x26bc0")
        self.assertEqual(result["file_update_helper"]
                         ["conditional_write"]["fwrite"],"0x27144")
        functions={x["function"] for x in result["file_update_helper"]["verified_calls"]}
        self.assertTrue({"fopen","flock","fgets","fwrite","fflush"}.issubset(functions))

    def test_mismatched_source_bytes_fail(self):
        with self.assertRaisesRegex(ValueError,"hash differs"):
            module.audit(b"invalid")
        with patch.object(module.hashlib,"sha256") as digest, \
             patch.object(module,"at",return_value=0):
            digest.return_value.hexdigest.return_value=module.SAMPLES[
                "libDexHelper.so"]["inner_sha"]
            with self.assertRaisesRegex(ValueError,"instruction modified"):
                module.audit(b"synthetic")

    def test_bl_sites_cannot_be_relabelled(self):
        with patch.object(module.hashlib,"sha256") as digest, \
             patch.object(module,"at",side_effect=lambda b,va:module.WORDS[va]), \
             patch.object(module,"bl_target",return_value=0):
            digest.return_value.hexdigest.return_value=module.SAMPLES[
                "libDexHelper.so"]["inner_sha"]
            with self.assertRaisesRegex(ValueError,"PLT"):
                module.audit(b"synthetic")

    def test_callsite_distinction(self):
        self.assertEqual(module.WORDS[0x27144],0x97ffa1cf)
        self.assertIn(0x270d0,module.PLT_CALLS)
        self.assertNotIn(0x270cc,module.PLT_CALLS)
        self.assertEqual(module.INTERNAL_CALLS[0x5af68],0x26bc0)


if __name__=="__main__":
    unittest.main()
