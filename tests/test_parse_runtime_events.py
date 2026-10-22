"""Synthetic-only validation of privacy-minimized logcat event parsing."""
import importlib.util
import unittest
from pathlib import Path

file = Path(__file__).resolve().parents[1] / "experiments" / "parse_runtime_events.py"
spec = importlib.util.spec_from_file_location("runtime_events", file)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
PKG = module.PACKAGE


class RuntimeEventTests(unittest.TestCase):
    def test_dec_native_crash_and_pid_lifecycle(self):
        lines = [
            f"10-22 15:36:40.000  1874  2000 I am_proc_start: [0,9586,10250,{PKG},top-activity]\n",
            f"10-22 15:36:42.000  1874  2000 I ActivityTaskManager: START u0 {{cmp={PKG}/com.a.b.c.DECMsgDialog}}\n",
            "10-22 15:36:43.002  9586  9605 F libc    : Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x97c in tid 9605 (c10086.activity), pid 9586 (c10086.activity)\n",
            f"10-22 15:36:44.249  1874  8033 I am_crash: [1874,0,{PKG},10250,Native crash,Segmentation fault,unknown,0]\n",
            f"10-22 15:36:44.411  1874  4743 I am_proc_died: [0,9586,{PKG},955,19]\n",
        ]
        got = module.parse(lines)
        self.assertEqual(
            [e["kind"] for e in got],
            ["am_proc_start", "dec_launch", "fatal_signal",
             "native_crash_report", "am_proc_died"])
        self.assertEqual(got[2]["pid"], 9586)
        self.assertEqual(got[2]["fault_addr"], "0x97c")
        self.assertNotIn("Segmentation fault", str(got))
        self.assertNotIn("10250", str(got))
        self.assertNotIn("top-activity", str(got))

    def test_excludes_other_app_crashes_and_sensitive_intent(self):
        lines = [
            "10-22 15:45:00.000  3333  4444 F libc: Fatal signal 11 (SIGSEGV), fault addr 0x4, pid 3333 (com.termux)\n",
            f"10-22 15:45:03.000  1874  4444 I ActivityTaskManager: START u0 {{cmp={PKG}/com.a.b.c.DECMsgDialog token=SECRET_ACCOUNT}}\n",
            f"10-22 15:45:03.200  1874  4444 I ActivityTaskManager: Displayed {PKG}/com.a.b.c.DECMsgDialog: +197ms\n",
        ]
        got = module.parse(lines)
        self.assertEqual([e["kind"] for e in got], ["dec_launch", "dec_displayed"])
        self.assertNotIn("SECRET_ACCOUNT", str(got))
        self.assertNotIn("3333", str(got))

    def test_no_false_pid_assigned_to_am_crash(self):
        data = [f"10-22 15:50:00.000  1874  3333 I am_crash: [1874,0,{PKG},10250,Native crash,Segmentation fault,unknown,0]\n"]
        got = module.parse(data)
        self.assertEqual(got, [
            {"clock": "10-22 15:50:00.000", "kind": "native_crash_report"}])
        self.assertNotIn("pid", got[0])

    def test_runtime_init_requires_matching_app_audit(self):
        lines = [
            "10-22 20:23:01.111  9187  9187 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 10250 <<<<<<\n",
            "10-22 20:23:01.115  9187  9187 I auditd: type=1400 audit(...) avc: denied app=" + PKG + "\n",
            "10-22 20:23:02.000  9999  9999 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 9999 <<<<<<\n",
            "10-22 20:23:02.005  9999  9999 I auditd: type=1400 avc: denied app=com.other.application\n",
            "10-22 20:23:02.100  8971  8971 I adbd: shell,v2,raw:su -c cat /proc/9187/maps\n",
        ]
        got = module.parse(lines)
        self.assertEqual(got, [
            {"clock": "10-22 20:23:01.111",
             "kind": "app_process_runtime_init", "pid": 9187, "uid": 10250}])
        self.assertNotIn("com.other.application", str(got))

    def test_runtime_init_without_audit_is_unattributed(self):
        lines = [
            "10-22 20:23:01.111  9187  9187 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 10250 <<<<<<\n",
        ]
        self.assertEqual(module.parse(lines), [])

    def test_deduplicate_exact_lines(self):
        line = f"10-22 15:42:22.000  1874  2222 I am_proc_died: [0,9069,{PKG},955,19]\n"
        self.assertEqual(len(module.parse([line, line])), 1)


if __name__ == "__main__":
    unittest.main()
