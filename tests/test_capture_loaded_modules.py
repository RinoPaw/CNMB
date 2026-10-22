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

    def test_ppid_parser_requires_exact_process_name(self):
        ps = ("PID PPID NAME\n"
              "9069 672 com.greenpoint.android.mc10086.activity\n"
              "9187 9069 com.greenpoint.android.mc10086.activity\n"
              "9222 9069 com.greenpoint.android.mc10086.activity:remote\n"
              "9478 1 com.unrelated.app\n")
        self.assertEqual(m.process_parentage(ps, m.PACKAGE),
                         {9069: 672, 9187: 9069})

    def test_ppid_in_compact_report(self):
        summary = m.concise_report({
            'package': m.PACKAGE, 'duration_seconds': 18,
            'events': [{'elapsed_seconds': 1.1, 'pid': 9187, 'ppid': 9069,
                        'native_and_dex_files': ['libDexHelper.so'],
                        'anonymous_rwx_regions': 1,
                        'anonymous_rwx_bytes': 1155072,
                        'memfd_or_ashmem_entries': 5}],
            'errors': [], 'note': 'synthetic'})
        self.assertEqual(summary['events'][0]['ppid'], 9069)

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

    def test_compact_report_shows_only_research_libraries(self):
        sample = {
            'package': m.PACKAGE, 'duration_seconds': 18,
            'events': [{'elapsed_seconds': 0.35, 'pid': 123,
                        'native_and_dex_files': ['libart.so','libDexHelper.so','libdatajar.so'],
                        'anonymous_rwx_regions': 2,
                        'anonymous_rwx_bytes': 1171456,
                        'memfd_or_ashmem_entries': 7},
                       {'elapsed_seconds': 12.36, 'pid': 123,
                        'native_and_dex_files': [],
                        'anonymous_executable_regions': 0,
                        'anonymous_rwx_regions': 0,
                        'anonymous_rwx_bytes': 0,
                        'memfd_or_ashmem_entries': 0},
                       {'elapsed_seconds': 13, 'pid': 123, 'state': 'not_in_ps'}],
            'errors': [], 'note': 'test'
        }
        summary=m.concise_report(sample)
        self.assertEqual(summary['events'][0]['mapped_research_libraries'],
                         ['libDexHelper.so', 'libdatajar.so'])
        self.assertEqual(summary['events'][1]['state'],
                         'invalid_empty_maps_legacy_capture')
        self.assertEqual(summary['events'][2]['state'], 'not_in_ps')
        self.assertNotIn('libart.so', str(summary))

    def test_empty_maps_does_not_generate_fake_unload(self):
        from unittest.mock import patch
        class Clock:
            t = 0.0
            def now(self):
                return self.t
            def sleep(self, delta):
                self.t += delta
        clock = Clock()
        calls = {'maps': 0}
        def adb(*args, **kwargs):
            if args[-2:] == ('-o', 'PID,NAME') and 'ps' in args:
                return ('123 '+m.PACKAGE) if clock.t < 2 else 'PID NAME'
            if 'maps' in args[-1]:
                calls['maps'] += 1
                if calls['maps'] == 1:
                    return ('75aa6b8000-75aa7d2000 rwxp 0 00:00 0\n'
                            '75afe0b000-75afe10000 r-xp 0 00:00 0 /data/app/secret/libDexHelper.so\n')
                return ''  # Android may return an empty map during process exit
            raise AssertionError(args)
        with patch.object(m, 'run_adb', side_effect=adb), \
             patch.object(m.time, 'monotonic', side_effect=clock.now), \
             patch.object(m.time, 'sleep', side_effect=clock.sleep):
            result = m.observe(m.PACKAGE, duration=3, interval=1)
        self.assertEqual(len(result['events']), 2, result['events'])
        self.assertEqual(result['events'][0]['anonymous_rwx_bytes'], 0x11a000)
        self.assertEqual(result['events'][1]['state'], 'not_in_ps')
        self.assertEqual(result['errors'][0]['kind'], 'maps-empty')
        self.assertNotIn('native_and_dex_files', result['events'][1])
