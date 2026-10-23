"""Synthetic, privacy-focused tests for one-session H/DEC correlation."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "experiments" / "correlate_reboot_h_entry.py"
spec = importlib.util.spec_from_file_location("correlate_reboot_h_entry", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
PKG = module.PACKAGE


def line(clock, pid, tag, body):
    return f"10-22 {clock} {pid:>5} {pid:>5} I {tag}: {body}\n"


def valid():
    return [
        line("15:25:54.027", 1780, "ActivityManager",
             f"Start proc 8387:{PKG}/u0a250 for pre-top-activity"),
        line("15:25:53.693", 8300, "AndroidRuntime",
             "Calling main entry com.android.commands.monkey.Monkey"),
        line("15:25:59.234", 8714, "AndroidRuntime",
             ">>>>>> START com.android.internal.os.RuntimeInit uid 10250 <<<<<<"),
        line("15:25:59.238", 8714, "zygote",
             f"avc: denied name=PRIVATE app={PKG}"),
        line("15:26:00.969", 8714, "AndroidRuntime",
             "Calling main entry com/secneo/apkwrapper/H key=SECRET"),
        line("15:26:02.981", 8714, "AndroidRuntime", "Shutting down VM"),
        line("15:26:03.908", 1780, "ActivityTaskManager",
             f"START u0 {{cmp={PKG}/com.a.b.c.DECMsgDialog "
             "(has extras) mCallingUid=10250} from uid 10250"),
        line("15:26:03.920", 1780, "OplusZoomWindowManagerService",
             f"unSupportZoom: false ,callingPid: 8387 ,sourceStack: Task{{A=10250:{PKG}}}"),
    ]


class CorrelateRebootHEntryTests(unittest.TestCase):
    def test_realistic_time_and_strict_pid_identity(self):
        records = valid()
        result = module.correlate(records + [records[3], records[4]])
        self.assertEqual(result["status"], "correlated")
        session = result["session"]
        self.assertEqual(session["main_pid"], 8387)
        self.assertEqual(session["worker_pid"], 8714)
        self.assertEqual(session["main_uid"], 10250)
        self.assertTrue(session["vendor_window_log_names_main_pid"])
        self.assertEqual(session["intervals_seconds"], {
            "main_start_to_runtime_init": 5.207,
            "main_start_to_h_entry": 6.942,
            "h_entry_to_dec_launch": 2.939,
            "main_start_to_dec_launch": 9.881,
            "worker_shutdown_to_dec_launch": 0.927,
        })
        self.assertNotIn("SECRET", str(result))
        self.assertNotIn("PRIVATE", str(result))
        self.assertNotIn("Monkey", str(result))

    def test_rejects_missing_same_pid_app_context(self):
        records = [row for row in valid() if "avc: denied" not in row]
        self.assertEqual(module.correlate(records)["status"], "insufficient")

    def test_rejects_wrong_runtime_uid(self):
        records = [row.replace("uid 10250", "uid 10251")
                   if "RuntimeInit uid" in row else row for row in valid()]
        self.assertEqual(module.correlate(records)["status"], "insufficient")

    def test_rejects_main_process_as_worker(self):
        records = [row.replace(" 8714 ", " 8387 ")
                   for row in valid()]
        self.assertEqual(module.correlate(records)["status"], "insufficient")

    def test_without_vendor_log_remains_a_correlated_chronology(self):
        records = [row for row in valid()
                   if "OplusZoomWindowManagerService" not in row]
        result = module.correlate(records)
        self.assertEqual(result["status"], "correlated")
        self.assertFalse(result["session"]["vendor_window_log_names_main_pid"])

    def test_rejects_worker_runtime_and_audit_from_prior_session(self):
        records = valid()
        records[2] = records[2].replace("15:25:59.234", "15:20:59.234")
        records[3] = records[3].replace("15:25:59.238", "15:20:59.238")
        self.assertEqual(module.correlate(records)["status"], "insufficient")

    def test_ignores_shutdown_after_dec(self):
        records = valid()
        records[5] = records[5].replace("15:26:02.981", "15:26:04.981")
        result = module.correlate(records)
        self.assertEqual(result["status"], "correlated")
        self.assertIsNone(
            result["session"]["intervals_seconds"]["worker_shutdown_to_dec_launch"])

    def test_no_association_across_log_days(self):
        records = valid()
        records[-2] = records[-2].replace("10-22", "10-23")
        self.assertEqual(module.correlate(records)["status"], "insufficient")

    def test_two_distinct_sessions_fail_closed(self):
        first = valid()
        second = [row.replace("8387", "9387").replace("8714", "9714")
                  .replace("15:25:", "15:35:").replace("15:26:", "15:36:")
                  for row in first]
        result = module.correlate(first + second)
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["matching_sessions"], 2)

    def test_requires_explicit_main_start(self):
        self.assertEqual(module.correlate(valid()[1:])["status"], "insufficient")


if __name__ == "__main__":
    unittest.main()
