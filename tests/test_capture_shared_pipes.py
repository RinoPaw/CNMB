"""Synthetic-only checks for shared pipe FD observer, with no ADB access."""
import importlib.util
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "experiments"
sys.path.insert(0, str(BASE))
spec = importlib.util.spec_from_file_location(
    "capture_shared_pipes", BASE / "capture_shared_pipes.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SharedPipesTests(unittest.TestCase):
    def test_identifies_cross_pid_read_write_ends_without_leaking_inode(self):
        raw = (
            "8387 14 987654 0100000\n"
            "8714 6 987654 01\n"
            "8387 33 123 00\n"
            "8387 34 123 01\n"
            "9999 77 987654 01\n"
            "8714 9 12345678 02\n"
        )
        links = module.shared_links(raw, {8387: 861, 8714: 1}, {})
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["pipe"], "pipe_1")
        self.assertEqual(links[0]["members"], [
            {"pid": 8387, "fd": 14, "access_mode": "read", "ppid_at_sample": 861},
            {"pid": 8714, "fd": 6, "access_mode": "write", "ppid_at_sample": 1},
        ])
        self.assertTrue(links[0]["opposite_access_modes_observed"])
        self.assertNotIn("987654", str(links))
        self.assertNotIn("12345678", str(links))

    def test_identical_inode_in_one_pid_is_not_shared(self):
        raw = "8387 4 12345 00\n8387 5 12345 01\n"
        self.assertEqual(module.parse_fd_rows(raw, {8387}), {})

    def test_invalid_rows_filtered_and_missing_flag_is_unknown(self):
        raw = (
            "8387 4 12345 -\n"
            "8714 5 12345 00000001\n"
            "9999 8 12345 00\n"
            "8387 6 socket:[555] 00\n"
            "8387 7 /private/secret 01\n"
            "8714 6 0 01\n"
            "untrusted user supplied data\n"
        )
        links = module.shared_links(raw, {8387: 1, 8714: 1}, {})
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["members"][0]["access_mode"], "unknown")
        self.assertFalse(links[0]["opposite_access_modes_observed"])
        self.assertNotIn("secret", str(links))

    def test_pipe_tag_stable_per_session_and_order(self):
        tags = {}
        first = module.shared_links(
            "8387 5 100 00\n8714 7 100 01\n", {8387: 861, 8714: 1}, tags)
        second = module.shared_links(
            "8387 5 100 00\n8714 7 100 01\n8387 8 200 00\n8714 9 200 01\n",
            {8387: 861, 8714: 1}, tags)
        self.assertEqual(first[0]["pipe"], "pipe_1")
        self.assertEqual([link["pipe"] for link in second],
                         ["pipe_1", "pipe_2"])

    def test_pipe_fd_commands_only_allow_numeric_pids(self):
        original = module.run_adb
        calls = []
        try:
            def stub(*args, **kwargs):
                calls.append((args, kwargs))
                return "8387 3 123 01\n"
            module.run_adb = stub
            self.assertEqual(module.read_pipe_fds([8714, 8387]),
                             "8387 3 123 01\n")
            command = calls[0][0][3]
            self.assertIn("for pid in 8387 8714;", command)
            self.assertIn("pipe:", command)
            self.assertNotIn("/data/user", command)
            with self.assertRaises(ValueError):
                module.read_pipe_fds([-1])
            self.assertEqual(len(calls), 1)
        finally:
            module.run_adb = original

    def test_numeric_uid_peers_are_selected_without_exposing_names(self):
        ps = ("PID PPID UID NAME\n"
              "8387 862 10250 com.greenpoint.android.mc10086.activity\n"
              "8714 1 10250 zygote\n"
              "8800 8387 10250 app_process\n"
              "995 2 1000 system_server\n"
              "9210 1 10000 com.other.app\n")
        parents, identities, uid = module.select_app_uid_processes(ps, module.PACKAGE)
        self.assertEqual(uid, 10250)
        self.assertEqual(parents, {8387: 862, 8714: 1, 8800: 8387})
        self.assertEqual(identities, {
            8387: "target_package",
            8714: "same_uid_other_name",
            8800: "same_uid_other_name"})
        self.assertNotIn("zygote", str(identities))
        self.assertNotIn("com.other", str(identities))
        links = module.shared_links("8387 4 999 00\n8714 5 999 01\n",
                                    parents, {}, identities)
        self.assertEqual(links[0]["members"][1]["name_class"],
                         "same_uid_other_name")

    def test_uid_can_survive_transient_name_changes_but_must_be_confirmed(self):
        ps = ("PID PPID UID NAME\n"
              "8714 1 10250 zygote\n"
              "995 2 1000 system_server\n")
        parents, identities, uid = module.select_app_uid_processes(
            ps, module.PACKAGE)
        self.assertIsNone(uid)
        self.assertEqual(parents, {})
        parents, identities, uid = module.select_app_uid_processes(
            ps, module.PACKAGE, 10250)
        self.assertEqual(parents, {8714: 1})
        self.assertEqual(identities[8714], "same_uid_other_name")
        with self.assertRaises(ValueError):
            module.select_app_uid_processes(
                "8387 862 10251 " + module.PACKAGE, module.PACKAGE, 10250)

    def test_invalid_or_nonnumeric_uid_ps_is_reported(self):
        with self.assertRaises(ValueError):
            module.select_app_uid_processes(
                "PID PPID USER NAME\n8387 862 u0_a250 " + module.PACKAGE,
                module.PACKAGE)
        parents, _, uid = module.select_app_uid_processes(
            "995 2 1000 system_server", module.PACKAGE)
        self.assertEqual(parents, {})
        self.assertIsNone(uid)

    def test_shell_scanner_emits_one_newline_per_fd(self):
        # The Python template itself is raw to avoid Windows SyntaxWarning,
        # while printf still needs exactly ONE literal backslash before n.
        command = module.READ_PIPES % {"pids": "8387 8714"}
        self.assertIn("printf '%s %s %s %s\\n'", command)
        self.assertNotIn("printf '%s %s %s %s\\\\n'", command)
        self.assertIn("inode=${inode%]}", command)
        self.assertNotIn("%%s", command)

    def test_probe_counter_parser_detects_missing_output(self):
        sample = (
            "8387 4 900 00\n"
            "STAT 8387 1 1 1 120 118 116 3\n"
            "STAT 8714 1 1 1 18 18 18 1\n"
            "STAT 9999 1 1 1 900 900 900 900\n"
        )
        counts = module.parse_probe_stats(sample, {8387, 8714})
        self.assertEqual(counts, {
            "probe_pid_count": 2,
            "probes_complete": True,
            "fd_dir_exists_count": 2,
            "fd_dir_readable_count": 2,
            "fd_dir_searchable_count": 2,
            "fd_glob_match_count": 138,
            "fd_symlink_count": 136,
            "fd_readlink_success_count": 134,
            "pipe_target_count": 4,
        })
        incomplete = module.parse_probe_stats(
            "STAT 8387 1 0 0 0 0 0 0\n", {8387, 8714})
        self.assertFalse(incomplete["probes_complete"])
        self.assertEqual(incomplete["fd_readlink_success_count"], 0)
        self.assertEqual(module.parse_probe_stats("", {8387})["probe_pid_count"], 0)

    def test_probe_counter_rejects_inconsistent_claims(self):
        self.assertFalse(module.parse_probe_stats(
            "STAT 8387 1 1 1 1 2 0 0\n", {8387})["probes_complete"])
        self.assertFalse(module.parse_probe_stats(
            "STAT 8387 1 1 1 4 1 2 3\n", {8387})["probes_complete"])

    def test_silent_directory_denial_is_not_usable_fd_coverage(self):
        ps = module.parse_probe_stats(
            "STAT 8387 1 0 0 0 0 0 0\n"
            "STAT 8714 0 0 0 0 0 0 0\n", {8387, 8714})
        self.assertTrue(ps["probes_complete"])
        self.assertEqual(ps["fd_dir_readable_count"], 0)
        self.assertEqual(ps["fd_glob_match_count"], 0)
        self.assertEqual(ps["fd_readlink_success_count"], 0)

    def test_fd_scanner_reports_real_pipe_and_probe_on_linux(self):
        import os
        import subprocess
        import sys
        if not sys.platform.startswith("linux"):
            self.skipTest("Linux procfs self-check")
        # Test within our own process, which owns both ends of an os.pipe.
        read_fd, write_fd = os.pipe()
        try:
            pid = os.getpid()
            script = module.READ_PIPES % {"pids": str(pid)}
            execution = subprocess.run(
                ["sh", "-c", script], capture_output=True, text=True,
                check=True, timeout=5,
            )
            stat = module.parse_probe_stats(execution.stdout, {pid})
            self.assertTrue(stat["probes_complete"])
            self.assertGreaterEqual(stat["fd_symlink_count"], 2)
            self.assertGreaterEqual(stat["fd_readlink_success_count"], 2)
            self.assertGreaterEqual(stat["pipe_target_count"], 2)
            rows = module.parse_fd_rows(execution.stdout, {pid})
            # Rows from a single PID cannot be cross-process links.
            self.assertEqual(rows, {})
            self.assertIn(f"{pid} {read_fd} ", execution.stdout)
            self.assertIn(f"{pid} {write_fd} ", execution.stdout)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_access_diagnosis_distinguishes_root_self_from_denied_target(self):
        old_run = module.run_adb
        calls = []
        def stub(*args, **kwargs):
            calls.append(args)
            if args == ("shell", "su", "-c", "id -u"):
                return "0\n"
            if args == ("shell", "ps", "-A", "-o", "PID,PPID,UID,NAME"):
                return (
                    "PID PPID UID NAME\n"
                    "8387 862 10250 " + module.PACKAGE + "\n"
                    "8714 1 10250 zygote\n")
            if args[:3] == ("shell", "su", "-c"):
                self.assertIn("for pid in SELF 8387;", args[3])
                return (
                    "STAT SELF 1 1 1 8 8 8 2\n"
                    "STAT 8387 1 0 0 0 0 0 0\n")
            raise AssertionError(args)
        try:
            module.run_adb = stub
            result = module.diagnose_fd_access(module.PACKAGE)
        finally:
            module.run_adb = old_run
        self.assertEqual(result["status"], "target_fd_denied_or_hidden")
        self.assertTrue(result["root_uid_confirmed"])
        self.assertEqual(result["root_shell"]["fd_readlinks_succeeded"], 8)
        self.assertEqual(result["target_process"]["fd_readlinks_succeeded"], 0)
        self.assertNotIn("zygote", str(result))
        self.assertNotIn("8387", str(result))
        self.assertFalse(any("force-stop" in call or "monkey" in call
                             for call in calls))

    def test_access_diagnosis_target_available(self):
        original = module.run_adb
        def stub(*args, **kwargs):
            if args[-1] == "id -u":
                return "0\n"
            if args[:2] == ("shell", "ps"):
                return "8387 862 10250 " + module.PACKAGE + "\n"
            return ("STAT SELF 1 1 1 8 8 8 1\n"
                    "STAT 8387 1 1 1 120 120 120 6\n")
        try:
            module.run_adb = stub
            result = module.diagnose_fd_access(module.PACKAGE)
        finally:
            module.run_adb = original
        self.assertEqual(result["status"], "target_fd_readlink_accessible")

    def test_access_diagnosis_handles_missing_package_without_relaunch(self):
        original = module.run_adb
        def stub(*args, **kwargs):
            if args[-1] == "id -u":
                return "0\n"
            if args[:2] == ("shell", "ps"):
                return "992 1 1000 system_server\n"
            self.assertIn("for pid in SELF;", args[-1])
            return "STAT SELF 1 1 1 6 6 6 2\n"
        try:
            module.run_adb = stub
            result = module.diagnose_fd_access(module.PACKAGE)
        finally:
            module.run_adb = original
        self.assertEqual(result["status"], "target_not_running")
        self.assertFalse(result["target_package_pid_seen"])

    def test_real_self_fd_probe_on_linux(self):
        import subprocess
        if not sys.platform.startswith("linux"):
            self.skipTest("requires Linux /proc")
        script = module.READ_PIPES % {"pids": "SELF"}
        result = subprocess.run(
            ["sh", "-c", script], capture_output=True, text=True,
            check=True, timeout=5)
        probe = module.parse_probe_stats(result.stdout, {"SELF"})
        self.assertTrue(probe["probes_complete"])
        self.assertEqual(probe["probe_pid_count"], 1)
        self.assertGreaterEqual(probe["fd_dir_readable_count"], 1)
        self.assertGreaterEqual(probe["fd_readlink_success_count"], 1)

    def test_explicit_launch_then_diagnose(self):
        old_run = module.run_adb
        calls = []
        def stub(*args, **kwargs):
            calls.append(args)
            if args == ("shell", "su", "-c", "id -u"):
                return "0\n"
            if args[:3] == ("shell", "am", "force-stop"):
                return ""
            if args[:3] == ("shell", "monkey", "-p"):
                return ""
            if args[:2] == ("shell", "ps"):
                return "8387 862 10250 " + module.PACKAGE + "\n"
            if args[:3] == ("shell", "su", "-c"):
                self.assertIn("for pid in SELF 8387;", args[3])
                return ("STAT SELF 1 1 1 10 10 10 2\n"
                        "STAT 8387 1 0 0 0 0 0 0\n")
            raise AssertionError(args)
        try:
            module.run_adb = stub
            result = module.diagnose_fd_access(module.PACKAGE, launch=True)
        finally:
            module.run_adb = old_run
        self.assertEqual(result["status"], "target_fd_denied_or_hidden")
        self.assertTrue(any(x[:3] == ("shell", "am", "force-stop") for x in calls))
        self.assertTrue(any(x[:3] == ("shell", "monkey", "-p") for x in calls))

    def test_proc_flags_parsing(self):
        self.assertEqual(module.access_mode("00"), "read")
        self.assertEqual(module.access_mode("01"), "write")
        self.assertEqual(module.access_mode("02"), "read_write")
        self.assertEqual(module.access_mode("02000002"), "read_write")
        self.assertEqual(module.access_mode("-"), "unknown")
        self.assertEqual(module.access_mode("03"), "unknown")


if __name__ == "__main__":
    unittest.main()
