"""Synthetic only: original H envc.push record audit (no private APK bytes)."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "audit_inner_h_envc_push", TOOLS / "audit_inner_h_envc_push.py")
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class HEnvcPushTests(unittest.TestCase):
    def test_decodes_indexed_literal_only_from_valid_original_style_ldrb(self):
        char_table = bytes(range(32,127))
        sites = (0x1000,0x1004,0x1008,0x100c)
        base = 0x41
        chars = "root"
        fake_words = {
            pc: 0x39400009 | (8 << 5) | ((ord(char)-32-base) << 10)
            for pc,char in zip(sites,chars)
        }
        with patch.object(subject, "insn", side_effect=lambda elf, pc: fake_words[pc]):
            self.assertEqual(subject.decode_loads(
                b"", char_table, sites, base, 8, chars), chars)
            with self.assertRaisesRegex(ValueError, "indexed LDRB"):
                subject.decode_loads(b"", char_table, sites, base, 22, chars)
        fake_words[0x1004] ^= 0x400
        with patch.object(subject, "insn", side_effect=lambda elf, pc: fake_words[pc]):
            with self.assertRaisesRegex(ValueError, "decoded indexed string"):
                subject.decode_loads(b"", char_table, sites, base, 8, chars)

    def test_read_record_prefix_and_hex_parser_sites(self):
        chars = bytes(range(32,127))
        prefix = "%s="
        sites = subject.READER_FORMAT_SITES
        fake_words = {
            pc: 0x39400008 | (8 << 5) | ((ord(char)-32-5) << 10)
            for pc,char in zip(sites,prefix)
        }
        with patch.object(subject,"insn",
                          side_effect=lambda elf,pc:fake_words[pc]):
            self.assertEqual(subject.decode_loads(
                b"",chars,sites,5,8,prefix),prefix)
        self.assertEqual(subject.PINNED[0x26b4c],0x52800202)
        self.assertEqual(subject.PINNED[0x26b50],0x5100c116)
        self.assertEqual(subject.PINNED[0x26b54],0x97ffa0af)
        self.assertEqual(subject.PINNED[0x26b90],0x2a1603e0)

    def test_selector_one_skips_usb_assignment(self):
        elf = bytearray(64)
        elf[12] = 1
        with patch.object(subject, "elf_file_offset", return_value=12):
            self.assertEqual(subject.branch_target_for_lookup_one(elf),0x265f8)
            elf[12] = 0
            with self.assertRaisesRegex(ValueError, "jump table"):
                subject.branch_target_for_lookup_one(elf)

    def test_c_literal_exact_and_nul_terminated(self):
        elf=bytearray(b"%s%s\x00some-other-binary")
        with patch.object(subject, "elf_file_offset", return_value=0):
            self.assertEqual(subject.nul_literal(elf,0,"%s%s"),"%s%s")
            with self.assertRaisesRegex(ValueError,"format/mode"):
                subject.nul_literal(elf,0,"%s%x")

    def test_original_opcode_sites_and_marker_are_pinned(self):
        self.assertGreater(len(subject.PINNED),35)
        self.assertEqual(subject.PINNED[0x5af20],0x52800020)
        self.assertEqual(subject.PINNED[0x5af68],0x97ff2f16)
        self.assertEqual(subject.PINNED[0x26d6c],0x52800041)
        self.assertEqual(subject.PINNED[0x27144],0x97ffa1cf)
        self.assertEqual(len(subject.ROOT_SITES),4)
        self.assertEqual(len(subject.WRITER_FILE_SITES),9)

    def test_census_scans_exact_text_section_and_all_three_helpers(self):
        import struct
        text_start, text_size = 0xfa00, 0xe0358
        elf = bytearray(text_start + text_size)
        # Synthetic ELF section metadata only; no proprietary source bytes.
        struct.pack_into("<Q", elf, 40, 0x200)
        struct.pack_into("<HHH", elf, 58, 64, 3, 1)
        names = b"\0.shstrtab\0.text\0"
        elf[0x400:0x400+len(names)] = names
        struct.pack_into("<IIQQQQIIQQ", elf, 0x200+64,
                         1, 3, 0, 0, 0x400, len(names), 0, 0, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", elf, 0x200+128,
                         11, 1, 0x6, text_start, text_start,
                         text_size, 0, 0, 4, 0)
        expected = {
            0x2616c: (83, (0x5af34, 0x5b3dc)),
            0x2682c: (84, (0x5af44, 0x5b3f0)),
            0x26bc0: (48, (0x5af68, 0x5b40c)),
        }
        nxt = 0x90000
        for target,(total,pinned) in expected.items():
            sites = list(pinned)
            while len(sites) < total:
                sites.append(nxt)
                nxt += 4
            for pc in sites:
                imm26 = ((target-pc)//4) & 0x3ffffff
                struct.pack_into("<I", elf, pc, 0x94000000 | imm26)
        result = subject.native_callsite_census(elf)
        self.assertEqual(result,
                         {"0x2616c": 83, "0x2682c": 84, "0x26bc0": 48})
        struct.pack_into("<I", elf, nxt-4, 0)
        with self.assertRaisesRegex(ValueError,"callsite census"):
            subject.native_callsite_census(elf)

    def test_audit_fails_closed_on_nonoriginal_elf(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            subject.audit(b"synthetic wrong ELF")

    def test_audit_detects_mutated_opcode_and_path_relocation(self):
        good_sha=type("Hash",(),{"hexdigest":lambda self:subject.ELF_SHA})()
        with patch.object(subject.hashlib,"sha256",return_value=good_sha), \
             patch.object(subject,"insn",return_value=0):
            with self.assertRaisesRegex(ValueError,"original ARM64 instruction"):
                subject.audit(b"synthetic ELF")
        with patch.object(subject.hashlib,"sha256",return_value=good_sha), \
             patch.object(subject,"insn",side_effect=lambda elf,pc:subject.PINNED[pc]), \
             patch.object(subject,"bl_target",return_value=0):
            with self.assertRaisesRegex(ValueError, "call target changed"):
                subject.audit(b"synthetic ELF")


if __name__ == "__main__":
    unittest.main()
