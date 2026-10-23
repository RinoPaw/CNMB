"""Synthetic-only verification for original inner ELF app_process argv analysis."""
import importlib.util
import struct
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "audit_inner_app_process_argv", TOOLS / "audit_inner_app_process_argv.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fake_elf():
    # Mirrors PT_LOAD VA-to-file offset shift without embedding proprietary bytes.
    b = bytearray(0x124000)
    b[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", b, 32, 0x40)
    struct.pack_into("<HH", b, 54, 56, 2)
    struct.pack_into("<IIQQQQQQ", b, 0x40, 1, 5, 0, 0, 0,
                     0x1192e0, 0x1192e0, 0x4000)
    struct.pack_into("<IIQQQQQQ", b, 0x78, 1, 6, 0x11b910, 0x11f910, 0x11f910,
                     0x7c18, 0x28450, 0x4000)
    key = b"\xab\xcd\xef"
    b[0xf4de5:0xf4de8] = key
    b[0x1200f4:0x1200f4+95] = bytes(
        value ^ key[i % 3] for i, value in enumerate(range(32, 127)))
    for address, word in m.INSTRUCTIONS.items():
        struct.pack_into("<I", b, address, word)
    for address, value in (
        (0xefdc0, b"/system/"), (0xefdc8, b"--nice-n"),
        (0xefdd0, b"--write-"), (0xf0801, b"%s%s\x00"),
        (0xffc4a, b"%d\x00"), (0xf1eb3, b"CLASSPATH\x00")
    ):
        b[address:address+len(value)] = value
    target = b"/system/bin/app_process\x00"
    inc = bytes([254,253,255,254,253,255,254,253,
                 255,254,253,255,254,253,255,254])
    b[0xf0030:0xf0030+16] = inc
    obfuscated = bytearray(target)
    for i in range(16):
        obfuscated[i+1] = (obfuscated[i+1]-inc[i]) & 255
    for i, amount in enumerate((3,1,2,3,1,2)):
        obfuscated[i+17] = (obfuscated[i+17]+amount) & 255
    b[0xf1e8f:0xf1e8f+24] = obfuscated
    return b


class InnerArgvTests(unittest.TestCase):
    def test_data_va_requires_load_offset_translation(self):
        b = fake_elf()
        self.assertEqual(m.elf_file_offset(b, 0x1240f4), 0x1200f4)
        self.assertEqual(m.elf_file_offset(b, 0xf4de5), 0xf4de5)
        self.assertEqual(m.decode_table(b), bytes(range(32,127)))
        self.assertNotEqual(b[0x1240f4:0x1240f4+95],bytes(range(32,127)))

    def test_full_expected_execl_argv(self):
        result = m.decode_argv(fake_elf())
        roles = {a["role"]:a["value"] for a in result["arguments"]}
        self.assertEqual(result["path"],"/system/bin/app_process")
        self.assertEqual(roles["cmd_dir"],"/system/bin")
        self.assertEqual(roles["nice_name"],"--nice-name=zygote")
        self.assertEqual(roles["write_fd_option"],"--write-fd")
        self.assertEqual(roles["flags_option"],"--flags")
        self.assertEqual(roles["flags_value"],"0")
        self.assertIsNone(roles["runtime_java_entry_pointer"])
        self.assertIsNone(roles["pipe_fd_decimal_string"])
        self.assertIsNone(roles["variadic_terminator"])

    def test_modified_utf_table_or_branch_fails(self):
        b = fake_elf()
        b[0x1200f4+35] ^= 1
        with self.assertRaisesRegex(ValueError,"ASCII table"):
            m.decode_argv(b)
        b = fake_elf()
        b[0x5a708] ^= 1
        with self.assertRaisesRegex(ValueError,"argv instruction changed"):
            m.decode_argv(b)

    def test_unmapped_virtual_address_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"Unmapped"):
            m.elf_file_offset(fake_elf(), 0x1300000)


if __name__ == "__main__":
    unittest.main()
