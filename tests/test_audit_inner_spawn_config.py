"""Synthetic-only evidence tests for original inner MessagePack spawn config."""
import importlib.util
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_inner_spawn_config",TOOLS/"audit_inner_spawn_config.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def prefix():
    buf=bytearray()
    for typ,value in m.EXPECTED_SCALARS:
        if typ=="bool":
            buf.append(0xc3 if value else 0xc2)
        elif typ=="int":
            if value<128:
                buf.append(value)
            elif value<65536:
                buf+=bytes([0xcd])+value.to_bytes(2,"big")
            else:
                raise ValueError("synthetic int too large")
        elif typ=="binary":
            buf+=bytes([0xc4,value])+bytes(value)
    assert len(buf)==64
    return bytes(x ^ m.XOR_BYTE for x in buf)


class SpawnConfigTests(unittest.TestCase):
    def test_messagepack_prefix_target_true_at_plus_63(self):
        parsed=m.parse_prefix(prefix())
        self.assertEqual(len(parsed),15)
        self.assertEqual(parsed[0],(0,1,"bool",True))
        self.assertEqual(parsed[2],(2,5,"int",16392))
        self.assertEqual(parsed[11][2:],("binary",1))
        self.assertEqual(parsed[13][2:],("binary",44))
        self.assertEqual(parsed[14],(63,64,"bool",True))
        self.assertEqual(bytes(x ^ m.XOR_BYTE for x in prefix())[63],0xc3)

    def test_original_prefix_rejects_silent_scalar_mutation(self):
        blob=bytearray(prefix())
        blob[63]^=1
        self.assertEqual(m.parse_prefix(blob)[-1][-1],False)
        blob=bytearray(prefix())
        blob[63]=0
        with self.assertRaisesRegex(ValueError,"Unexpected MessagePack"):
            m.parse_prefix(blob)

    def test_truncated_binary_payload_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"Truncated binary payload"):
            m.parse_prefix(bytes([0xc4 ^ m.XOR_BYTE,
                                  9 ^ m.XOR_BYTE,0,0]),1)
        with self.assertRaisesRegex(ValueError,"Truncated MessagePack"):
            m.parse_prefix(b"",1)

    def test_original_flow_uses_data_va_and_branch_targets(self):
        mem=bytearray(0x12015b+128)
        for addr,word in m.WORDS.items():
            struct.pack_into("<I",mem,addr,word)
        mem[0x12015b:0x12015b+64]=prefix()
        calls={site:target for site,target,_ in m.FIELD_CALLS}
        calls[0x14b28]=0x8569c
        calls.update(m.EXTRA_BLOCK_READS)
        def fake_target(_,site):
            return calls.get(site)
        with patch.object(m,"elf_file_offset",
                          side_effect=lambda _,va:va-0x4000 if va>=0x124000 else va),\
             patch.object(m,"bl_target",side_effect=fake_target):
            data=m.audit(mem)
            self.assertTrue(data["target_field"]["on_disk_value"])
            self.assertEqual(data["target_field"]["encoded_stream_byte_offset"],63)
            self.assertEqual(data["conditional_dispatch"]["callback_slot_if_on_disk_value_used"],"0x20")
            mem[0x12015b+63]^=1
            with self.assertRaisesRegex(ValueError,"field sequence changed"):
                m.audit(mem)


if __name__=="__main__":
    unittest.main()
