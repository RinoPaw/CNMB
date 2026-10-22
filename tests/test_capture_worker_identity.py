"""Synthetic-only checks for safe Android worker process ancestry collection."""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

EXPERIMENTS = Path(__file__).resolve().parents[1] / "experiments"
sys.path.insert(0, str(EXPERIMENTS))
spec = importlib.util.spec_from_file_location(
    "capture_worker_identity", EXPERIMENTS / "capture_worker_identity.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class WorkerIdentityTests(unittest.TestCase):
    def test_sanitizes_full_argv(self):
        raw = (
            "/system/bin/app_process64\x00/system/bin\x00"
            "--nice-name=SECRET_TOKEN\x00-Xmx128m\x00"
            "com.secneo.apkwrapper.AW\x00"
            "--session=SECRET_ACCOUNT\x00")
        result = module.sanitize_cmdline(raw)
        self.assertEqual(result["argv0_kind"], "app_process")
        self.assertEqual(result["allowlisted_java_entry_candidate"],
                         "com.secneo.apkwrapper.AW")
        self.assertNotIn("SECRET_TOKEN", str(result))
        self.assertNotIn("SECRET_ACCOUNT", str(result))
        self.assertNotIn("/system/bin", str(result))

    def test_unknown_argv_must_not_leak(self):
        raw = (
            "com.greenpoint.android.mc10086.activity\x00"
            "com.attacker.UserToken\x00TOKEN=E3C31\x00"
            "--key=com.secneo.private.SECRET\x00"
        )
        result = module.sanitize_cmdline(raw)
        self.assertEqual(result["argv0_kind"], "renamed_to_target_package")
        self.assertIsNone(result["allowlisted_java_entry_candidate"])
        self.assertNotIn("TOKEN", str(result))
        self.assertEqual(module.sanitize_cmdline(""), {
            "cmdline_state": "empty_or_exited"})

    def test_snapshot_parentage_and_process_disappearance(self):
        class Clock:
            t = 0.0
            def now(self):
                return self.t
            def sleep(self, s):
                self.t += s
        clock = Clock()
        def fake_adb(*args, **kwargs):
            if args[-2:] == ("-o", "PID,PPID,NAME"):
                if clock.t < 1:
                    return ("PID PPID NAME\n"
                            "9187 9069 " + module.PACKAGE + "\n")
                return "PID PPID NAME\n"
            if args[-1] == "cat /proc/9187/cmdline":
                return "/system/bin/app_process64\x00com.a.b.c.DECApp\x00SECRET=HIDDEN\x00"
            raise AssertionError(args)
        with patch.object(module, "run_adb", side_effect=fake_adb), \
             patch.object(module.time, "monotonic", side_effect=clock.now), \
             patch.object(module.time, "sleep", side_effect=clock.sleep):
            result = module.observe(module.PACKAGE, 2, 0.5, False)
        self.assertEqual(result["events"][0]["pid"], 9187)
        self.assertEqual(result["events"][0]["ppid"], 9069)
        self.assertEqual(result["events"][0]["allowlisted_java_entry_candidate"],
                         "com.a.b.c.DECApp")
        self.assertEqual(result["events"][-1]["state"], "not_in_ps")
        self.assertNotIn("SECRET", str(result))


if __name__ == "__main__":
    unittest.main()
