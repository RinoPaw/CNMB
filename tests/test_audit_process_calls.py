"""Synthetic-only tests for Dalvik process-call candidate scanner."""
import importlib.util
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    'audit_process_calls', TOOLS / 'audit_process_calls.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class DexProcessCallTests(unittest.TestCase):
    def test_class_data_index_deltas_reset(self):
        # static_fields=0, instance_fields=0, direct=2, virtual=1
        data = bytes([0,0,2,1, 1,1,0x10, 2,1,0x20, 4,1,0x30])
        self.assertEqual(list(m.encoded_methods(data, 0, 0)),
                         [(1,16), (3,32), (4,48)])

    def test_invoke_virtual_and_static_candidates(self):
        data = bytes.fromhex(
            '6e 10 32 12 01 00'  # invoke-virtual, method 0x1232
            '71 00 16 40 00 00'  # invoke-static, method 0x4016
            '1a 00 32 12'        # const-string, should be excluded
        )
        got = list(m.call_candidates(
            data, {0x1232:'Runtime.exec',0x4016:'Process.killProcess'}))
        self.assertEqual(got, [(0,'Runtime.exec'),(6,'Process.killProcess')])

    def test_range_invoke_and_odd_byte_do_not_match(self):
        code = bytes.fromhex('77 00 02 00 00 00 00 71 01 34 12 00 00')
        self.assertEqual(list(m.call_candidates(code, {2:'ProcessBuilder.start'})),
                         [(0,'ProcessBuilder.start')])


if __name__ == '__main__':
    unittest.main()
