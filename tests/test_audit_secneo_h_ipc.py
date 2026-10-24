"""Synthetic, no proprietary DEX, regression checks for SecNeo H IPC auditor."""
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "audit_secneo_h_ipc.py"
spec = importlib.util.spec_from_file_location("audit_secneo_h_ipc", SOURCE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditSecneoHPipeTests(unittest.TestCase):
    def test_u16_u32_bounds(self):
        raw = b"\x34\x12\x78\x56\xab\xcd"
        self.assertEqual(audit.u16(raw, 0), 0x1234)
        self.assertEqual(audit.u32(raw, 2), 0xcdab5678)
        with self.assertRaises(ValueError):
            audit.u16(raw, 5)
        with self.assertRaises(ValueError):
            audit.u32(raw, -1)

    def test_uleb_and_malformed_dex(self):
        self.assertEqual(audit.uleb(b"\x80\x01", 0), (128, 2))
        self.assertEqual(audit.uleb(b"\x7f", 0), (127, 1))
        with self.assertRaises(ValueError):
            audit.uleb(b"\x80", 0)
        with self.assertRaises(ValueError):
            audit.uleb(b"\xff\xff\xff\xff\xff\x00", 0)
        with self.assertRaises(ValueError):
            audit.audit(b"dex\n035\x00" + bytes(128))

    def test_validates_method_reference_and_opcode(self):
        methods = [("Ltest/Sample;", "emit", "(I)V")]
        body = bytearray(10)
        struct.pack_into("<HHH", body, 2, 0x1071, 0, 0x0000)
        audit.invokes(body, methods, {2: methods[0]}, "synthetic")
        with self.assertRaises(ValueError):
            audit.invokes(body, methods, {2:("Ltest/Sample;", "read", "(I)V")}, "synthetic")
        body[2] = 0x00
        with self.assertRaises(ValueError):
            audit.invokes(body, methods, {2: methods[0]}, "synthetic")

    def test_validates_string_id_from_code(self):
        body = struct.pack("<HHH", 0, 0x001a, 1)
        audit.const_string(body, ["a", "TracerPid:"], 2, "TracerPid:")
        with self.assertRaises(ValueError):
            audit.const_string(body, ["a", "PPid:"], 2, "TracerPid:")

    def test_single_instruction_mutation_fails(self):
        body = bytearray(struct.pack("<HHH", 0x6021, 0x4212, 0x2032))
        audit.words(body, {0:0x6021, 2:0x4212, 4:0x2032}, "synthetic")
        body[2] ^= 0x01
        with self.assertRaises(ValueError):
            audit.words(body, {2:0x4212}, "synthetic")

    def test_code_item_requires_original_definition(self):
        raw = bytearray(180)
        # Synthetic code_item with 7 regs, 1 input and two 16-bit instructions.
        struct.pack_into("<HHHHII", raw, 32, 7, 1, 2, 0, 0, 2)
        key = (audit.H, "main", "([Ljava/lang/String;)V")
        code = audit.code(raw, {key:32}, "main", key[2], 32, 2)
        self.assertEqual(code, bytes(4))
        with self.assertRaises(ValueError):
            audit.code(raw, {}, "main", key[2], 32, 2)
        struct.pack_into("<I", raw, 44, 65535)
        with self.assertRaises(ValueError):
            audit.code(raw, {key:32}, "main", key[2], 32, 2)

    def test_original_dex_sha_is_pinned(self):
        # A sample may only be analyzed when its original DEX hash matches.
        with mock.patch.object(audit.hashlib, "sha256", wraps=audit.hashlib.sha256):
            with self.assertRaisesRegex(ValueError, "SHA mismatch"):
                audit.audit(bytes(21820))


if __name__ == "__main__":
    unittest.main()
