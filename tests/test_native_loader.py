#!/usr/bin/env python3
"""No proprietary APK or private device logs needed."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'inspect_native_loader.py'
spec = importlib.util.spec_from_file_location('native_loader', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class NativeLoaderAuditTests(unittest.TestCase):
    def test_tombstone_parse_sanitizes_path(self):
        synthetic = """Cmdline: com.greenpoint.android.mc10086.activity
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x978
    x19 00000075aa6cd870
    lr  0000000000000000  sp  0000000000000000  pc  0000000000000978
backtrace:
    00000075'aa6b8000-00000075'aa7d1fff rwx         0    11a000
    00000075'afe0b000-00000075'afe0ffff r-x         0      5000  /data/app/secret/lib/arm64/libDexHelper.so
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'tombstone.txt'
            path.write_text(synthetic)
            result = m.summarize_tombstone(path)
        self.assertEqual(result['signal']['fault_address'], '0x978')
        self.assertEqual(result['memory_map_entries'], 2)
        self.assertEqual(result['relevant_mapped_libraries'], ['libDexHelper.so'])
        self.assertEqual(result['x19_region']['bytes'], 0x11a000)
        self.assertEqual(result['x19_region']['permissions'], 'rwx')
        self.assertNotIn('secret', str(result))

    def test_invalid_elf_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported ELF'):
            m.load_segments(b'PK\x03\x04')

    def test_sha_pinning_rejects_arbitrary_zip(self):
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'not-our.apk'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('classes.dex', b'not the same sample')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                m.read_apk(path)


if __name__ == '__main__':
    unittest.main()
