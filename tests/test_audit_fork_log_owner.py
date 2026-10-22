"""Sample-free tests for the pinned Dex class_data method index decoder."""
import importlib.util
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "audit_fork_log_owner", TOOLS / "audit_fork_log_owner.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class DexMethodDecoderTests(unittest.TestCase):
    def test_method_delta_resets_between_direct_and_virtual(self):
        # static_fields=0, instance_fields=0, direct=2, virtual=1
        # direct IDs 1,3; virtual ID 4; offsets relative to provided base.
        encoded = bytes([0, 0, 2, 1,
                         1, 1, 0x10, 2, 1, 0x20,
                         4, 1, 0x30])
        result = list(m.decoded_methods(encoded, 0, 0))
        self.assertEqual(result, [(1, 0x10), (3, 0x20), (4, 0x30)])

    def test_code_offset_zero_is_abstract_or_native(self):
        encoded = bytes([0, 0, 1, 0, 9, 1, 0])
        self.assertEqual(list(m.decoded_methods(encoded, 0, 0)),
                         [(9, None)])


if __name__ == "__main__":
    unittest.main()
