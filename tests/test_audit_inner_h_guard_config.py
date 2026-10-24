"""Synthetic-only verification of original SecNeo H guard pointer/config audit."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0,str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "audit_inner_h_guard_config", TOOLS/"audit_inner_h_guard_config.py")
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class GuardConfigTests(unittest.TestCase):
    def test_adrp_targets_from_original_insns(self):
        self.assertEqual(subject.adrp_page(0xd00008b6,0x14a54),0x12a000)
        self.assertEqual(subject.adrp_page(0xd000086b,0x151d0),0x123000)
        self.assertEqual(subject.adrp_page(0xb000078c,0x3af44),0x12b000)
        with self.assertRaises(ValueError):
            subject.adrp_page(0xd503201f,0x14a54)

    def test_synthetic_relocation_is_checked_and_fails_closed(self):
        data=bytearray(360)
        struct.pack_into("<Q",data,40,64)
        struct.pack_into("<HH",data,58,64,1)
        struct.pack_into("<IIQQQQIIQQ",data,64,
                         0,4,0,0,160,24,0,0,8,24)
        struct.pack_into("<QQq",data,160,0x123dc0,1027,0x128000)
        self.assertEqual(subject.relocation_target(data,0x123dc0),0x128000)
        struct.pack_into("<Q",data,168,1026)
        with self.assertRaises(ValueError):
            subject.relocation_target(data,0x123dc0)
        struct.pack_into("<Q",data,168,1027)
        with self.assertRaises(ValueError):
            subject.relocation_target(data,0x123dc8)

    def test_bool_integer_and_raw_messagepack_headers(self):
        self.assertEqual(subject.msgpack_value(bytes.fromhex("c3"),0,"bool"),(True,1))
        self.assertEqual(subject.msgpack_value(bytes.fromhex("c2"),0,"bool"),(False,1))
        self.assertEqual(subject.msgpack_value(bytes.fromhex("0d"),0,"integer"),(13,1))
        self.assertEqual(subject.msgpack_value(bytes.fromhex("cd4008"),0,"integer"),(16392,3))
        self.assertEqual(subject.msgpack_value(bytes.fromhex("ccff"),0,"integer"),(255,2))
        self.assertEqual(subject.msgpack_value(bytes.fromhex("c42c"),0,"binary_length"),(44,2))
        self.assertEqual(subject.msgpack_value(bytes.fromhex("ff"),0,"integer"),(-1,1))
        for raw,kind in ((b"\x00","bool"),(b"\xc4","integer"),(b"\xc2","binary_length")):
            with self.assertRaises(ValueError):
                subject.msgpack_value(raw,0,kind)
        with self.assertRaises(ValueError):
            subject.msgpack_value(b"\xcd\x01",0,"integer")

    def test_helper_call_sequence_rejects_mutation(self):
        # No original bytes: only a handful of synthetic callsites.
        with patch.object(subject,"word",return_value=0x14000000):
            with self.assertRaises(ValueError):
                subject.decoder_calls(b"synthetic")

    def test_field_and_different_write_address(self):
        self.assertEqual(subject.STATE+0x17c,0x12a5bc)
        self.assertNotEqual(subject.STATE+0x17c,0x12b17c)
        self.assertEqual(subject.WORDS[0x151e8],0xf9000176)
        self.assertEqual(subject.WORDS[0x5ae54],0x37000628)
        self.assertEqual(subject.WORDS[0x5af68],0x97ff2f16)


if __name__=="__main__":
    unittest.main()
