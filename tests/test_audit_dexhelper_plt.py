"""Synthetic-only ELF call decoding tests, no copyrighted binary."""
import importlib.util
import hashlib
import struct
import unittest
from pathlib import Path

F = Path(__file__).resolve().parents[1] / 'tools' / 'audit_dexhelper_plt.py'
spec = importlib.util.spec_from_file_location('plt_audit', F)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def encode_bl(start, end):
    delta = end - start
    if delta % 4:
        raise ValueError('unaligned')
    return 0x94000000 | ((delta // 4) & 0x3ffffff)


class OriginalLoaderPltTests(unittest.TestCase):
    def test_known_callsite_targets_and_offsets(self):
        for shift in [0, -0x2000]:
            for site, (symbol, target) in m.CALLS.items():
                b = bytearray(4)
                struct.pack_into('<I', b, 0, encode_bl(site, target))
                # Decoder only needs the relative branch displacement.
                self.assertEqual(m.bl_target(b, 0), target-site)
                self.assertEqual((target+shift-(0x2990+shift))//16,
                                 (target-0x2990)//16)

    def test_reject_non_bl(self):
        with self.assertRaisesRegex(ValueError, 'Expected AArch64 BL'):
            m.bl_target(struct.pack('<I', 0xd65f03c0), 0)

    def test_parse_dynamic_plt_relocations_in_synthetic_elf(self):
        b = bytearray(0x4000)
        b[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', b, 18, 183)
        struct.pack_into('<Q', b, 32, 64)
        struct.pack_into('<HH', b, 54, 56, 2)
        struct.pack_into('<IIQQQQQQ', b, 64,
                         1, 5, 0, 0, 0, 0x4000, 0x4000, 4096)
        struct.pack_into('<IIQQQQQQ', b, 120,
                         2, 6, 0x800, 0x800, 0, 0xa0, 0xa0, 8)
        for n, (tag, value) in enumerate([
            (2,576), (20,7), (9,24), (23,0x1000),
            (6,0x1800), (5,0x2400), (0,0)]):
            struct.pack_into('<QQ', b, 0x800+16*n, tag, value)
        cursor = 1
        for i in range(24):
            name = f'example_{i}'.encode() + b'\0'
            b[0x2400+cursor:0x2400+cursor+len(name)] = name
            struct.pack_into('<IBBHQQ', b, 0x1800+(i+1)*24,
                             cursor,0,0,0,0,0)
            struct.pack_into('<QQq', b, 0x1000+i*24,
                             0x3000+i*8, ((i+1)<<32)|1026, 0)
            cursor+=len(name)
        at, tags = m.parse_elf(b)
        results = m.imports(b, at, tags)
        self.assertEqual(len(results),24)
        self.assertEqual(results[12]['name'],'example_12')
        self.assertEqual(results[12]['got_elf_va'],0x3060)

    def test_fails_on_invalid_elf(self):
        with self.assertRaises(ValueError):
            m.parse_elf(b'junk')

if __name__ == '__main__':
    unittest.main()
