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

    def test_timestamp_order_even_when_log_file_is_out_of_order(self):
        src = [
            "10-22 21:20:15.578  11209  11209 E app_process: Could not create image space\n",
            "10-22 21:20:15.575  11209  11209 I auditd: avc: denied app="
            + m.PACKAGE + "\n",
        ]
        result = m.profile(src, 11209)
        self.assertEqual([event["clock"] for event in result["events"]],
                         ["10-22 21:20:15.575", "10-22 21:20:15.578"])
        self.assertEqual(result["first_message_clock"], "10-22 21:20:15.575")
        self.assertEqual(result["last_message_clock"], "10-22 21:20:15.578")

    def test_explicit_entry_class_only_when_logged(self):
        src = ["10-22 20:23:02.100  9187  9187 D AndroidRuntime: Calling main entry com.example.SampleMain with key=HIDDEN\n"]
        out = m.profile(src, 9187)
        self.assertTrue(out["has_explicit_main_entry_log"])
        self.assertEqual(out["events"][0]["class_name"], "com.example.SampleMain")
        self.assertNotIn("HIDDEN", str(out))


    def test_slash_separated_main_entry_from_android_runtime(self):
        src = [
            "10-22 15:26:00.969  8714  8714 D AndroidRuntime: Calling main entry com/secneo/apkwrapper/H with secret=HIDDEN\\n",
            "10-22 15:26:00.970  8300  8300 D AndroidRuntime: Calling main entry com/android/commands/monkey/Monkey\\n",
            "10-22 15:26:01.000  8714  8714 I OtherTag: token=PRIVATE\\n",
        ]
        out = m.profile(src, 8714)
        self.assertTrue(out["has_explicit_main_entry_log"])
        self.assertEqual(
            [e.get("class_name") for e in out["events"]
             if e["kind"] == "explicit_main_entry_log"],
            ["com.secneo.apkwrapper.H"])
        self.assertNotIn("HIDDEN", str(out))
        self.assertNotIn("PRIVATE", str(out))
        self.assertNotIn("Monkey", str(out))

    def test_main_entry_does_not_treat_path_as_java_class(self):
        src = [
            "10-22 15:26:00.969  8714  8714 D AndroidRuntime: Calling main entry /data/private/file\\n",
        ]
        out = m.profile(src, 8714)
        self.assertFalse(out["has_explicit_main_entry_log"])


if __name__ == "__main__":
    unittest.main()
