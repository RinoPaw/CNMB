"""No original binary data: ARM64 byte-loader regression for H envc.push audit."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "audit_inner_h_envc_file", TOOLS / "audit_inner_h_envc_file.py")
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


def fake_ldr(immediate, base, dest):
    return 0x39400000 | (immediate << 10) | (base << 5) | dest


class EnvcStaticTests(unittest.TestCase):
    def test_selector_one_decodes_usb(self):
        instructions = {
            pc: fake_ldr(imm, 8, 9)
            for pc, imm in zip(subject.USB_LOADS, (0x14, 0x12, 0x01))
        }
        with patch.object(subject, "word", side_effect=lambda elf, pc: instructions[pc]):
            self.assertEqual(
                subject.decode_loads(b"", bytes(range(32,127)),
                                     subject.USB_LOADS, 0x41, 8, (9,9,9)), "usb")

    def test_both_differently_indexed_literals_decode_same_file(self):
        read_indexes = (0x37,0x40,0x48,0x35,0,0x42,0x47,0x45,0x3a)
        write_indexes = (64,73,81,62,9,75,80,78,67)
        instructions = {}
        for pc, imm, reg in zip(subject.READ_FILE_LOADS, read_indexes,
                                (9,9,9,9,9,9,9,9,8)):
            instructions[pc] = fake_ldr(imm, 8, reg)
        for pc, imm in zip(subject.WRITE_FILE_LOADS, write_indexes):
            instructions[pc] = fake_ldr(imm, 22, 8)
        with patch.object(subject, "word", side_effect=lambda elf, pc: instructions[pc]):
            read_name = subject.decode_loads(b"", bytes(range(32,127)),
                        subject.READ_FILE_LOADS, 0xe, 8, (9,9,9,9,9,9,9,9,8))
            write_name = subject.decode_loads(b"", bytes(range(32,127)),
                        subject.WRITE_FILE_LOADS, 5, 22, (8,)*9)
        self.assertEqual(read_name, "envc.push")
        self.assertEqual(write_name, read_name)

    def test_reader_and_writer_format_operands(self):
        source = {
            **{pc: fake_ldr(imm, 8, reg)
               for pc, imm, reg in zip(subject.READ_LINE_LOADS,
                                       (0,0x4e,0x18), (9,9,8))},
            **{pc: fake_ldr(imm, 22, 8)
               for pc, imm in zip(subject.WRITE_LINE_LOADS,
                                  (0,0x4e,0x18,0,0x53,0,0x53))}
        }
        with patch.object(subject,"word",side_effect=lambda elf,pc:source[pc]):
            self.assertEqual(subject.decode_loads(
                b"",bytes(range(32,127)),subject.READ_LINE_LOADS,
                5,8,(9,9,8)),"%s=")
            self.assertEqual(subject.decode_loads(
                b"",bytes(range(32,127)),subject.WRITE_LINE_LOADS,
                5,22,(8,)*7),"%s=%x%x")

    def test_instruction_mutation_rejected(self):
        with patch.object(subject, "word", return_value=0x39400009):
            with self.assertRaisesRegex(ValueError, "operand changed"):
                subject.decode_loads(b"",bytes(range(32,127)),
                                     subject.USB_LOADS,0x41,8,(9,9,9))

    def test_pinned_hash_rejects_arbitrary_blob(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            subject.audit(b"untrusted")

    def test_specific_evidence_sites_are_pinned(self):
        self.assertEqual(subject.WORDS[0x5af20],0x52800020)
        self.assertEqual(subject.BL[0x5af34],0x2616c)
        self.assertEqual(subject.BL[0x26d24],0x12f00)
        self.assertEqual(subject.BL[0x27144],0xf880)
        self.assertNotEqual(subject.READ_FILE_LOADS,subject.WRITE_FILE_LOADS)


if __name__=="__main__":
    unittest.main()
