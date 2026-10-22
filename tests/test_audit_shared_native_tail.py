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
    def test_one_variable_byte_does_not_hide_shared_2564_byte_core(self):
        reference = synthetic_stub()
        sample = bytearray(reference)
        sample[0xa24] = (sample[0xa24] + 1) & 0xff
        self.assertEqual(m.CORE_END - m.CORE_START, 2564)
        core = reference[m.CORE_START:m.CORE_END]
        self.assertEqual(sample.find(core), m.CORE_START)
        self.assertNotEqual(
            sample[m.CORE_START:0xa25], reference[m.CORE_START:0xa25])

    def test_shared_protection_metadata_is_outside_exact_core(self):
        reference = synthetic_stub()
        sample = bytearray(reference)
        for offset in (0x08, 0x11, 0xa24, 0xa2d, 0xa4c):
            sample[offset] ^= 0x5a
        self.assertEqual(
            sample[m.CORE_START:m.CORE_END],
            reference[m.CORE_START:m.CORE_END])

    def test_all_nine_arm64_syscall_wrappers(self):
        decoded = m.wrappers(synthetic_stub())
        self.assertEqual([x['number'] for x in decoded],
                         [64, 215, 222, 226, 64, 63, 56, 57, 94])
        self.assertNotIn(220, [x['number'] for x in decoded])

    def test_loader_maps_mprotect_and_icache_bytes(self):
        stub = synthetic_stub()
        stub[0x550:0x550+len(m.STUB_MARKER)] = m.STUB_MARKER
        stub[0x9f4:0x9f4+len(m.MAPS)] = m.MAPS
        for offset, insn in m.LOADER_INSTRUCTIONS.items():
            struct.pack_into('<I', stub, offset, insn)
        verified = m.loader_operations(stub)
        self.assertTrue(verified['reads_own_process_maps'])
        self.assertTrue(verified['sets_mprotect_7_at_callsite'])
        self.assertTrue(verified['performs_instruction_cache_maintenance'])
        stub[0x5e4] ^= 1
        with self.assertRaisesRegex(ValueError, 'Loader operation mismatch'):
            m.loader_operations(stub)

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
