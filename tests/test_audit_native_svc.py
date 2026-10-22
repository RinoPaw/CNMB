"""Sample-free tests for encoded ARM64 SVC recognition."""
import importlib.util
import sys
import struct
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    'audit_native_svc', TOOLS / 'audit_native_svc.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class NativeSyscallAuditTests(unittest.TestCase):
    def test_executable_load_only(self):
        image = bytearray(0x100)
        image[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', image, 18, 183)
        struct.pack_into('<Q', image, 32, 64)
        struct.pack_into('<HH', image, 54, 56, 1)
        struct.pack_into('<IIQQQQQQ', image, 64,
                         1, 5, 0x80, 0x80, 0, 16, 16, 4)
        struct.pack_into('<I', image, 0x80, 0x52800008)  # mov w8,#0
        struct.pack_into('<I', image, 0x84, 0xd4000001)  # svc #0
        struct.pack_into('<I', image, 0x88, 0xd4000021)  # svc #1
        struct.pack_into('<I', image, 0xc0, 0xd4000001)  # outside load
        self.assertEqual(m.svc_file_offsets(image), [0x84, 0x88])

    def test_mov_220_immediate_used_as_stack_byte(self):
        # mov w8,#0xdc; strb w8,[sp,#0xf]; ldr x8,[x19,#0x18]
        data = struct.pack('<III', 0x52801b88, 0x39003fe8, 0xf9400e68)
        self.assertTrue(m.is_obfuscated_byte_store_not_clone(data, 0))
        # A genuine MOV x8,#220 followed by an SVC is a different pattern.
        trap = struct.pack('<II', 0xd2801b88, 0xd4000001)
        self.assertFalse(m.is_obfuscated_byte_store_not_clone(trap, 0))

    def test_non_arm64_fails_closed(self):
        with self.assertRaises(ValueError):
            m.svc_file_offsets(b'NOT ELF')
        image = bytearray(0x100)
        image[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', image, 18, 62)
        with self.assertRaisesRegex(ValueError, 'wrong ELF machine'):
            m.svc_file_offsets(image)


if __name__ == '__main__':
    unittest.main()
