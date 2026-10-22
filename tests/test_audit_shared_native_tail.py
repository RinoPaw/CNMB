"""Sample-free tests for original APK shared ARM64 loader-tail verification."""
import importlib.util
import struct
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
spec = importlib.util.spec_from_file_location(
    'audit_shared_native_tail', TOOLS / 'audit_shared_native_tail.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def synthetic_stub():
    data = bytearray(m.TAIL_SIZE)
    for offset, (_, number) in m.SYSCALLS.items():
        struct.pack_into('<III', data, offset-4,
                         0xd2800008 | (number << 5),
                         0xd4000001, 0xd65f03c0)
    return data


class SharedNativeTailTests(unittest.TestCase):
    def test_all_nine_arm64_syscall_wrappers(self):
        decoded = m.wrappers(synthetic_stub())
        self.assertEqual([x['number'] for x in decoded],
                         [64, 215, 222, 226, 64, 63, 56, 57, 94])
        self.assertNotIn(220, [x['number'] for x in decoded])

    def test_modified_wrapper_rejected(self):
        stub = synthetic_stub()
        stub[0x150] ^= 1
        with self.assertRaisesRegex(ValueError, 'mismatch|Unexpected'):
            m.wrappers(stub)

    def test_exec_segment_must_be_load_of_exact_size(self):
        data = bytearray(0xc00)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 18, 183)
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<IIQQQQQQ', data, 64,
                         1, 5, 0x100, 0x2300, 0, 0xa50, 0xa50, 0x1000)
        self.assertEqual(m.executable_segment(data, 0x100), 0x2300)
        with self.assertRaisesRegex(ValueError, 'No matching executable'):
            m.executable_segment(data, 0x104)


if __name__ == '__main__':
    unittest.main()
