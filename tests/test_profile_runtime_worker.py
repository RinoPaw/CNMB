"""Purely synthetic validation of privacy-safe app_process log profiling."""
import importlib.util
import sys
import unittest
from pathlib import Path

EXPERIMENTS = Path(__file__).resolve().parents[1] / "experiments"
sys.path.insert(0, str(EXPERIMENTS))
spec = importlib.util.spec_from_file_location(
    "profile_runtime_worker", EXPERIMENTS / "profile_runtime_worker.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class WorkerProfileTests(unittest.TestCase):
    def test_pid_strict_and_only_whitelisted_fields(self):
        src = [
            "10-22 20:23:01.100  9187  9187 E app_process: createInstance(64bit) : createExtendedFactory\n",
            "10-22 20:23:01.111  9187  9187 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 10250 <<<<<<\n",
            "10-22 20:23:01.115  9187  9187 I auditd: avc: denied something app=com.greenpoint.android.mc10086.activity path=/data/private/SECRET\n",
            "10-22 20:23:02.171  9187  9187 D nativeloader: Load libicu_jni.so using APEX ns from /apex/secret/path: ok\n",
            "10-22 20:23:02.240  9187  9187 I Passwords: SECRET_TOTP_TOKEN=ABCD\n",
            "10-22 20:23:02.300  9087  9087 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 10250 <<<<<<\n",
        ]
        out = m.profile(src, 9187)
        self.assertEqual(out["lines"], 5)
        self.assertEqual(out["events"][0]["kind"], "app_process_extensions_init")
        self.assertTrue(any(e.get("library") == "libicu_jni.so" for e in out["events"]))
        self.assertFalse(out["has_explicit_main_entry_log"])
        self.assertNotIn("SECRET", str(out))
        self.assertNotIn("9087", str(out))

    def test_explicit_entry_class_only_when_logged(self):
        src = ["10-22 20:23:02.100  9187  9187 D AndroidRuntime: Calling main entry com.example.SampleMain with key=HIDDEN\n"]
        out = m.profile(src, 9187)
        self.assertTrue(out["has_explicit_main_entry_log"])
        self.assertEqual(out["events"][0]["class_name"], "com.example.SampleMain")
        self.assertNotIn("HIDDEN", str(out))


if __name__ == "__main__":
    unittest.main()
