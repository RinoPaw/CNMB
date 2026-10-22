import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    'maps', Path(__file__).resolve().parents[1] /
    'experiments' / 'capture_loaded_modules.py'
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class LoadedModulesTests(unittest.TestCase):
    def test_exact_process_matching(self):
        ps = ('PID NAME\n123 com.greenpoint.android.mc10086.activity\n'
              '124 com.greenpoint.android.mc10086.activity:remote\n')
        self.assertEqual(m.process_ids(ps, m.PACKAGE), [123])

    def test_maps_redaction(self):
        raw = """75aa6b8000-75aa7d2000 rwxp 00000000 00:00 0
75afe0b000-75afe10000 r-xp 00000000 00:00 100 /data/app/secret/lib/arm64/libDexHelper.so
75aff0b000-75aff0f000 r-xp 00000000 00:00 100 /data/app/secret/base.apk
75aff10000-75aff18000 r-xp 00000000 00:00 100 /memfd:jit-cache
"""
        value = m.summarize_maps(raw)
        self.assertEqual(value['native_and_dex_files'],
                         ['base.apk', 'libDexHelper.so'])
        self.assertEqual(value['anonymous_rwx_regions'], 1)
        self.assertEqual(value['anonymous_rwx_bytes'], 0x11a000)
        self.assertNotIn('secret', str(value))
