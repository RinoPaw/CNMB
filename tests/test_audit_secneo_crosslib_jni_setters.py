"""Synthetic-only checks for original cross-library SecNeo JNI setter census."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "audit_secneo_crosslib_jni_setters",
    TOOLS / "audit_secneo_crosslib_jni_setters.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def synthetic_stripped_elf():
    # ELF64 LE AArch64, PT_LOAD executable, deliberately NO section table.
    elf = bytearray(0x180)
    elf[:16] = b"\x7fELF\x02\x01\x01" + b"\x00"*9
    struct.pack_into("<HHIQQQIHHHHHH", elf, 16,
                     3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", elf, 64,
                     1, 5, 0x100, 0x1000, 0x1000, 0x50, 0x50, 4)
    struct.pack_into("<IIIIII", elf, 0x100,
                     0xf9400268, 0xf9426908, 0xd63f0100,
                     0xd503201f, 0xf9426a11, 0xd503201f)
    return elf


class CrossLibSettersTests(unittest.TestCase):
    def test_stripped_elf_program_headers_work_without_sections(self):
        elf = synthetic_stripped_elf()
        self.assertEqual(a.executable_segments(elf), [(0x1000, 0x100, 0x50)])
        self.assertEqual(a.word(elf, 0x1004), 0xf9426908)
        with self.assertRaisesRegex(ValueError, "unmapped"):
            a.word(elf, 0x3000)

    def test_jni_like_vs_plt_got_and_arbitrary_load(self):
        sites, size = a.candidate_sites(synthetic_stripped_elf())
        self.assertEqual(size, 0x50)
        self.assertEqual(sites, [
            (0x1004, 0xf9426908, True),
            (0x1010, 0xf9426a11, False),
        ])

    def test_non_elf_and_corrupt_executable_segment_rejected(self):
        self.assertEqual(a.candidate_sites(b"not an ELF"), ([], 0))
        elf = synthetic_stripped_elf()
        struct.pack_into("<Q", elf, 64 + 32, 0x800)
        with self.assertRaisesRegex(ValueError, "executable PT_LOAD"):
            a.candidate_sites(elf)
        elf = synthetic_stripped_elf()
        struct.pack_into("<H", elf, 54, 20)
        with self.assertRaisesRegex(ValueError, "program headers"):
            a.candidate_sites(elf)

    def test_original_secneo_sites_and_full_apk_census_are_pinned(self):
        self.assertEqual(a.EXPECTED["arm64_files"], 191)
        self.assertEqual(a.EXPECTED["elf_files"], 176)
        self.assertEqual(a.EXPECTED["non_elf_files"], 15)
        self.assertEqual(a.EXPECTED["raw_ldr_candidates"], 219)
        self.assertEqual(a.EXPECTED["jni_shape_candidates"], 9)
        self.assertEqual(a.SITES["libdexjni.so"][0],
                         (0x86388, 0x8638c, 0x863a0))
        self.assertEqual(a.SITES["libdexvmp.so"][1],
                         (0x6a240, 0x6a244, 0x6a258))
        self.assertEqual(a.SITES["libDexHelper.so"][0],
                         (0x2c5c8, 0x2c5d8, 0x2c5e0))

    def test_direct_bl_caller_census_excludes_indirect_call(self):
        elf = synthetic_stripped_elf()
        # 0x1020 -> BL 0x1030, branch imm = +4 instructions.
        struct.pack_into("<I", elf, 0x120, 0x94000004)
        struct.pack_into("<I", elf, 0x124, 0xd63f0100) # BLR x8
        self.assertEqual(a.direct_bl_callers(elf, 0x1030), [0x1020])
        self.assertEqual(a.direct_bl_callers(elf, 0x1040), [])
        # An invalid opcode at the same position must cease to be a BL caller.
        struct.pack_into("<I", elf, 0x120, 0x14000004) # B (not BL)
        self.assertEqual(a.direct_bl_callers(elf, 0x1030), [])

    def test_runtime_dispatcher_input_sites_are_original_pins(self):
        self.assertEqual(a.SITES["libdexjni.so"][1][1], 0x863bc)
        self.assertEqual(a.SITES["libdexvmp.so"][0][1], 0x6a154)

    def test_original_apk_sha_is_required(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            a.audit_apk(b"synthetic cannot substitute original")


if __name__ == "__main__":
    unittest.main()
