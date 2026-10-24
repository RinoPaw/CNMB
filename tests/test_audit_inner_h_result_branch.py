"""Synthetic ARM64 branch decoding tests; no proprietary ELF fixtures."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "audit_inner_h_result_branch", TOOLS / "audit_inner_h_result_branch.py")
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class SecneoHResultBranchTests(unittest.TestCase):
    def test_real_original_branch_words_decode_expected_targets(self):
        self.assertEqual(subject.bcond_target(0x54000720, 0x5ad38),
                         (0x5ae1c, 0))
        self.assertEqual(subject.bcond_target(0x5400096b, 0x5ae40),
                         (0x5af6c, 11))
        self.assertEqual(subject.tbnz_target(0x37000628, 0x5ae54),
                         (0x5af18, 0, 8))
        self.assertEqual(subject.tbnz_target(0x370003e8, 0x5b344),
                         (0x5b3c0, 0, 8))

    def test_sign_extended_backward_conditional_branch(self):
        # B.EQ -4: immediate is 19-bit twos-complement -1.
        instruction = 0x54000000 | (0x7ffff << 5)
        self.assertEqual(subject.bcond_target(instruction, 0x1000),
                         (0xffc, 0))
        with self.assertRaises(ValueError):
            subject.bcond_target(0xd503201f, 0x1000)

    def test_backward_bit_test_and_invalid_opcode(self):
        # TBNZ W8 bit 0, -4 bytes.
        word = 0x37000008 | (0x3fff << 5)
        self.assertEqual(subject.tbnz_target(word, 0x1000),
                         (0xffc, 0, 8))
        with self.assertRaises(ValueError):
            subject.tbnz_target(0x36000008, 0x1000)

    def test_machine_word_checked_before_interpretation(self):
        def fake_word(elf, addr):
            return subject.WORDS[addr]
        with patch.object(subject, "word_at", side_effect=fake_word), \
             patch.object(subject, "bl_target", return_value=0xebf0):
            summary = subject.audit(b"synthetic-not-original")
            self.assertEqual(
                summary["result_check"]["value_at_least_one"]
                ["bit_clear_path"]["branch_reg_imm"], "x10=0x1f8")
            self.assertEqual(
                summary["additional_guard"]["bit_clear_path"]
                ["branch_reg_imm"], "x11=0x1f0")
        def corrupt_word(elf, addr):
            return subject.WORDS[addr] ^ (1 if addr == 0x5ae3c else 0)
        with patch.object(subject, "word_at", side_effect=corrupt_word):
            with self.assertRaisesRegex(ValueError, "original instruction changed"):
                subject.audit(b"synthetic-not-original")

    def test_wrong_atoi_plt_target_rejected(self):
        with patch.object(subject, "word_at",
                          side_effect=lambda elf, addr: subject.WORDS[addr]), \
             patch.object(subject, "bl_target", return_value=0x1000):
            with self.assertRaisesRegex(ValueError, "atoi PLT target"):
                subject.audit(b"synthetic-not-original")

    def test_all_expectations_are_covered_and_not_duplicate(self):
        self.assertGreaterEqual(len(subject.WORDS), 35)
        self.assertEqual(subject.WORDS[0x5ae3c], 0x7100041f)
        self.assertEqual(subject.WORDS[0x5ae74], 0x9100001f)
        self.assertEqual(subject.WORDS[0x5ae84], 0xd61f0140)
        self.assertEqual(subject.WORDS[0x5b368], 0xd61f0160)
        self.assertEqual(subject.WORDS[0x3af48], 0x3905f189)


if __name__ == "__main__":
    unittest.main()
