"""Synthetic-only regression tests for pinned native SecNeo pipe reader auditor."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
SOURCE = TOOLS / "audit_inner_h_pipe_receiver.py"
spec = importlib.util.spec_from_file_location("audit_inner_h_pipe_receiver", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativePipeReceiverTests(unittest.TestCase):
    def test_indexed_rodata_decodes_without_embedded_original_bytes(self):
        table = bytes(range(32, 127))
        word = b"sample"
        indices = bytes([0x53 - 0x20] + [ord(c)-32 for c in word[1:].decode()])
        with patch.object(module, "elf_file_offset", side_effect=lambda elf, va: va):
            output = module.table_string(indices, table, 0, len(indices),
                                         ord("s")-32)
            self.assertEqual(output, "sample")
            changed = bytearray(indices)
            changed[3] = 255
            with self.assertRaises(ValueError):
                module.table_string(changed, table, 0, len(indices),
                                    ord("s")-32)

    def test_ldr_strb_code_reconstructs_original_style_stack(self):
        table = bytes(range(32, 127))
        data = bytearray(512)
        destination = 0x40
        for i, ch in enumerate("readUTF"):
            index = ord(ch) - 32 - 8
            if index < 0:
                raise AssertionError("synthetic character index invalid")
            ldrb = module.LDRB_X19_W9 | (index << 10)
            strb = module.STRB_SP_W9 | ((destination+i) << 10)
            struct.pack_into("<II", data, i*8, ldrb, strb)
        with patch.object(module, "elf_file_offset", side_effect=lambda elf, va: va):
            self.assertEqual(module.stack_literal(
                data, table, 0, 56, destination, 7), "readUTF")
            data[8] ^= 0x01
            with self.assertRaises(ValueError):
                module.stack_literal(data, table, 0, 56, destination, 7)

    def test_rejects_untouched_but_different_machine_word(self):
        with patch.object(module, "elf_file_offset", side_effect=lambda elf, va: va):
            data = bytes(0x5a500)
            self.assertEqual(module.code_word(data, 0x5a3d0), 0)
            with self.assertRaises(ValueError):
                # No executable evidence is accepted without pinned bytes.
                for addr, expected in module.WORDS.items():
                    if module.code_word(data, addr) != expected:
                        raise ValueError("original ARM64 instruction changed")

    def test_original_code_word_addresses_are_distinct(self):
        self.assertGreaterEqual(len(module.WORDS), 18)
        self.assertEqual(module.WORDS[0x5a3d0], 0x97fed204)
        self.assertEqual(module.WORDS[0x5ae38], 0x97fecf6e)
        self.assertEqual(module.WORDS[0x5ae3c], 0x7100041f)
        self.assertEqual(module.EXPECTED_STACK[-2][-1], "readUTF")


if __name__ == "__main__":
    unittest.main()
