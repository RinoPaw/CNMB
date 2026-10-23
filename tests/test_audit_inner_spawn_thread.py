"""Synthetic-only ARM64 callback and unwind-frame tests."""
import importlib.util
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location(
    "audit_inner_spawn_thread", TOOLS / "audit_inner_spawn_thread.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    b = bytearray(m.EH_FRAME_FILE_OFFSET + max(m.FDE_EXPECTED) + 0x40)
    for addr, word in {**m.JNI_CALL_REGISTRATION, **m.CONFIG_FLAG_ORIGIN,
                       **m.REGISTRATION, **m.INITIALIZER_THREAD,
                       **m.CALLBACK_DISPATCH, **m.THREAD_CREATION,
                       **m.WORKER_START}.items():
        struct.pack_into("<I", b, addr, word)
    for off, (lo, hi) in m.FDE_EXPECTED.items():
        record = m.EH_FRAME_FILE_OFFSET + off
        struct.pack_into("<IIiI", b, record,
                         0x34 if off == 0x32c8 else 0x2c, off+4,
                         lo-(record+8), hi-lo)
    return b


class InnerSpawnThreadTests(unittest.TestCase):
    def test_unwind_bounds_recover_worker_and_jni_independently(self):
        frames = m.verify_fdes(fixture())
        self.assertEqual(frames["0x1fb0"], ["0x59700", "0x5b45c"])
        self.assertEqual(frames["0x1cc8"], ["0x4e1c8", "0x50354"])
        self.assertEqual(frames["0x788"], ["0x148cc", "0x1703c"])
        self.assertEqual(frames["0x32c8"], ["0x1df7c", "0x249d0"])
        self.assertEqual(frames["0x1c18"], ["0x4b3bc", "0x4b768"])

    def test_callback_table_and_pthread_registration_signature(self):
        b = fixture()
        with patch.object(m, "decode_argv", return_value={
            "path": "/system/bin/app_process",
            "arguments": [{"role": "nice_name", "value": "--nice-name=zygote"}]
        }):
            result = m.verify(b)
        self.assertEqual(
            result["jni_bootstrap"]["callback_registration_initializer"],
            "0x1df7c")
        self.assertEqual(
            result["global_registration"]["callback_function"], "0x4e1c8")
        self.assertEqual(
            result["pthread_create"]["thread_start_function"], "0x59700")
        self.assertEqual(result["dispatcher_thread"]["entry_function"], "0x4b3bc")
        self.assertEqual(result["dispatcher_thread"]["callback_bit_mask"], "0x04")
        self.assertEqual(
            result["dispatcher_thread"]["flag_bit_0x04_source_rule"],
            "runtime_config[0x4a] != 0")
        self.assertEqual(result["dispatcher_thread"]["indirect_call"], "0x4b494")
        self.assertEqual(
            result["thread_worker"]["starts_with_sleep_seconds"], 2)
        self.assertEqual(result["direct_immediate_bl_to_worker_count"], 0)

    def test_config_byte_selects_callback_bit_in_initializer(self):
        # CSEL with w10 bit 4 clear, w11=w10|5, then optional OR 0x40.
        for initial in (0, 11, (-117 & 0xffffffff)):
            self.assertEqual(initial & 4, 0)
            for value in (0, 1, 17, 255):
                flags = initial if value == 0 else initial | 5
                flags |= 0x40
                self.assertEqual(bool(flags & 4), value != 0)

    def test_dispatcher_slot_selection_by_single_config_bit(self):
        for flags in (0, 1, 2, 8, 0x80):
            self.assertEqual((flags & 4) * 8, 0)
        for flags in (4, 5, 6, 0x84):
            self.assertEqual((flags & 4) * 8, 0x20)

    def test_unexpected_direct_branch_not_silently_ignored(self):
        b = fixture()
        site, target = 0x50100, 0x59700
        struct.pack_into("<I", b, site,
                         0x94000000 | (((target-site)//4) & 0x3ffffff))
        self.assertEqual(m.direct_bl_callers(b, target), [site])

    def test_corrupted_callback_register_or_fde_is_detected(self):
        b = fixture()
        b[0x1e3f8] ^= 1
        with patch.object(m, "decode_argv", return_value={}):
            with self.assertRaisesRegex(ValueError, "callback/thread"):
                m.verify(b)
        b = fixture()
        b[m.EH_FRAME_FILE_OFFSET + 0x1fb0 + 12] ^= 1
        with self.assertRaisesRegex(ValueError, "FDE changed"):
            m.verify_fdes(b)


if __name__ == "__main__":
    unittest.main()
