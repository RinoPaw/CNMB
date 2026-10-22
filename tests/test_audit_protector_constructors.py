"""Sample-free synthetic ELF tests for constructor/relocalization audits."""
import hashlib
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "tools"
spec = importlib.util.spec_from_file_location(
    "audit_protector_constructors", ROOT / "audit_protector_constructors.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    b = bytearray(0x1000)
    b[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", b, 18, 183)
    struct.pack_into("<Q", b, 32, 64)
    struct.pack_into("<HH", b, 54, 56, 2)
    struct.pack_into("<IIQQQQQQ", b, 64, 1, 5, 0, 0, 0, len(b), len(b), 4096)
    struct.pack_into("<IIQQQQQQ", b, 120, 2, 6, 0x800, 0x800, 0x800,
                     0x80, 0x80, 8)
    for i, (tag, val) in enumerate(((25, 0x700), (27, 16), (26, 0x710),
                                    (28, 16), (7, 0x500), (8, 72),
                                    (9, 24), (0, 0))):
        struct.pack_into("<QQ", b, 0x800 + 16*i, tag, val)
    for i, triple in enumerate(((0x700, 1027, 0x300),
                                (0x710, 1027, 0x310),
                                (0x7f8, 1025, 0))):
        struct.pack_into("<QQq", b, 0x500 + 24*i, *triple)
    return b


def config(data):
    return {"hash": hashlib.sha256(data).hexdigest(), "array": 0x700,
            "fini": 0x710, "constructor": 0x300,
            "destructor": 0x310, "rela": 0x500}


class ConstructorTests(unittest.TestCase):
    def test_identical_bootstrap_suffix_and_prior_mismatch(self):
        helper = bytearray(0x4ca0)
        jni = bytearray(0x2ca0)
        ha, hz = m.SHARED_BOOTSTRAP["DexHelper_range"]
        ja, jz = m.SHARED_BOOTSTRAP["dexjni_range"]
        helper[ha-1] = 1
        for marker, offset in ((b"JNI_OnLoad", 0x49f8),
                               (b"/proc/self/maps", 0x4a08)):
            helper[offset:offset+len(marker)] = marker
            shifted = offset-0x2000
            jni[shifted:shifted+len(marker)] = marker
        from unittest.mock import patch
        digest = hashlib.sha256(helper[ha:hz]).hexdigest()
        with patch.dict(m.SHARED_BOOTSTRAP, {"sha256": digest}):
            result = m.compare_bootstrap(helper, jni)
            self.assertEqual(result["identical_executable_segment_suffix_bytes"], 9030)
            jni[ja+100] ^= 1
            with self.assertRaisesRegex(ValueError, "suffix mismatch"):
                m.compare_bootstrap(helper, jni)

    def test_init_and_fini_relative_relocations(self):
        b = fixture()
        report = m.inspect(b, "libdexjni.so", config(b))
        self.assertEqual(report["load_constructor_file_offset"], "0x300")
        self.assertEqual(report["fini_callback_elf_va"], "0x310")
        self.assertEqual(len(report["validated_relative_relocations"]), 2)
        self.assertEqual(report["init_array_slots"], 2)

    def test_malformed_relative_relocation_fails_closed(self):
        b = fixture()
        struct.pack_into("<q", b, 0x500+16, 0x600)
        with self.assertRaisesRegex(ValueError, "relocations changed"):
            m.inspect(b, "libdexjni.so", config(b))

    def test_changed_original_hash_rejected(self):
        b = fixture()
        cfg = config(b)
        b[0x400] ^= 1
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            m.inspect(b, "libdexjni.so", cfg)


if __name__ == "__main__":
    unittest.main()
