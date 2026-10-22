"""Tests use synthetic JSON and logcat only, never user diagnostic files."""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "experiments"
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location(
    "correlate_worker_session", ROOT / "correlate_worker_session.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
PKG = "com.greenpoint.android.mc10086.activity"


def capture():
    return {
        "package": PKG,
        "host_utc_anchor": "2026-10-22T13:19:32+00:00",
        "events": [
            {"t": .33, "pid": 11103, "ppid": 862,
             "argv0_kind": "renamed_to_target_package",
             "allowlisted_java_entry_candidate": None},
            {"t": .41, "pid": 11120, "ppid": 11103},
            {"t": 1.04, "pid": 11124, "ppid": 11103},
            {"t": 2.01, "pid": 11120, "state": "not_in_ps"},
            {"t": 4.07, "pid": 11209, "ppid": 1},
            {"t": 4.33, "pid": 11209, "state": "not_in_ps"},
            {"t": 12.17, "pid": 11103, "state": "not_in_ps"},
            {"t": 12.17, "pid": 11124, "state": "not_in_ps"},
        ]
    }


def lines():
    return [
        f"10-22 20:23:05.609  1874  2000 I ActivityTaskManager: START u0 {{cmp={PKG}/com.a.b.c.DECMsgDialog}}\n",
        f"10-22 21:19:32.100  1874  2000 I am_proc_start: [0,11103,10250,{PKG},top]\n",
        "10-22 21:19:36.140  11209  11209 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 10250 <<<<<<\n",
        f"10-22 21:19:36.141  11209  11209 I auditd: avc: denied app={PKG} path=/data/SECRET\n",
        "10-22 21:19:36.200  11120  11120 I app_process: createInstance(64bit): createExtendedFactory\n",
        f"10-22 21:19:41.000  1874  2000 I ActivityTaskManager: START u0 {{cmp={PKG}/com.a.b.c.DECMsgDialog token=HIDDEN}}\n",
        f"10-22 21:19:45.000  1874  2000 I am_proc_died: [0,11103,{PKG},955,19]\n",
    ]


class WorkerCorrelationTests(unittest.TestCase):
    def test_known_direct_children_and_init_reparented_worker(self):
        result = m.correlate_with_events(capture(),
                                          m.parse(lines(), PKG),
                                          lines())
        identity = result["identity"]
        self.assertEqual(identity["main_pid_candidate"], 11103)
        self.assertEqual(identity["direct_children_of_main_at_snapshot"],
                         [11120, 11124])
        self.assertEqual(identity["ppid_1_at_first_snapshot"], [11209])
        self.assertEqual(result["device_log_anchor"], "10-22 21:19:32.100")
        self.assertEqual([e["kind"] for e in result["logcat_events"]],
                         ["am_proc_start", "app_process_runtime_init",
                          "dec_launch", "am_proc_died"])
        self.assertEqual(result["process_log_profiles"][-1]["pid"], 11209)
        self.assertEqual(result["process_log_profiles"][-1]["lines"], 2)
        self.assertNotIn("SECRET", str(result))
        self.assertNotIn("HIDDEN", str(result))
        self.assertNotIn("20:23", str(result))

    def test_no_main_proc_start_refuses_to_join_history(self):
        old = [line for line in lines() if "am_proc_start" not in line]
        result = m.correlate_with_events(capture(), m.parse(old, PKG), old)
        self.assertIsNone(result["device_log_anchor"])
        self.assertEqual(result["logcat_events"], [])
        self.assertEqual(result["process_log_profiles"], [])

    def test_reparenting_does_not_infer_original_parent(self):
        identity = m.summarize_identity(capture())
        child = next(p for p in identity["processes"] if p["pid"] == 11209)
        self.assertEqual(child["ppid_at_first_snapshot"], 1)
        self.assertNotIn("original_ppid", child)
        self.assertEqual(child["first_not_in_ps_relative_seconds"], 4.33)


if __name__ == "__main__":
    unittest.main()
