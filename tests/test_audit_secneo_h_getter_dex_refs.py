"""Synthetic-only checks for SecNeo H getter callsite census."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "audit_secneo_h_getter_dex_refs",
    TOOLS / "audit_secneo_h_getter_dex_refs.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def sample(with_h=True, with_methods=True):
    # Small valid string_data entries; the *sample* is not an original DEX.
    strings = [
        module.OWNER if with_h else "Lsynthetic/Example;",
        "Lcom/a/b/c/DECApp;",
        "Lcom/a/b/c/DeviceEnvironmentCheck;",
        "gha", "ghc", "unrelated",
    ]
    data = bytearray(2048)
    pointers = []
    pos = 128
    for value in strings:
        raw = value.encode("ascii")
        data[pos] = len(raw)
        data[pos+1:pos+1+len(raw)] = raw
        data[pos+1+len(raw)] = 0
        pointers.append(pos)
        pos += len(raw)+2
    if with_methods:
        struct.pack_into("<HHI", data, 512, 0, 0, 3)
        struct.pack_into("<HHI", data, 520, 0, 1, 4)
        struct.pack_into("<HHI", data, 528, 1, 0, 5)
    frag = {
        "pointers": pointers,
        "types": [0, 1, 2],
        "methods": 3 if with_methods else 0,
        "method_offset": 512,
        "classes": 2,
        "defined": {1},
    }
    return bytes(data), frag


class SecneoHGetterRefCensusTests(unittest.TestCase):
    def test_h_owner_plus_methods_returns_exact_references(self):
        data, frag = sample()
        result = module.summarize_fragment(data, frag, 0x2500c)
        self.assertTrue(result["H_owner_descriptor"])
        self.assertEqual(result["exact_getter_names_in_string_table"],
                         ["gha", "ghc"])
        self.assertEqual(
            [(x["method_idx"], x["method_name"])
             for x in result["H_getter_method_ids"]],
            [(0, "gha"), (1, "ghc")])
        self.assertTrue(
            result["DEC_types"]["Lcom/a/b/c/DECApp;"]["class_defined"])
        self.assertFalse(
            result["DEC_types"]["Lcom/a/b/c/DeviceEnvironmentCheck;"]
            ["class_defined"])

    def test_name_matches_but_owner_missing_is_not_h_call(self):
        data, frag = sample(with_h=False)
        result = module.summarize_fragment(data, frag, 0x2500c)
        self.assertFalse(result["H_owner_descriptor"])
        self.assertEqual(result["any_owner_getter_name_refs"], 2)
        self.assertEqual(result["H_getter_method_ids"], [])

    def test_type_present_without_method_reference(self):
        data, frag = sample(with_h=True, with_methods=False)
        result = module.summarize_fragment(data, frag, 0x2500c)
        self.assertTrue(result["H_owner_descriptor"])
        self.assertEqual(result["H_getter_method_ids"], [])

    def test_not_a_sha_pinned_source_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            module.census(b"not original")

    def test_original_inventory_is_fixed(self):
        self.assertEqual(module.EXPECTED_FRAGMENTS, 14)
        self.assertEqual(module.EXPECTED_TOTAL_CLASSES, 101716)
        self.assertEqual(sum(module.EXPECTED_CLASSES), 101716)


if __name__ == "__main__":
    unittest.main()
