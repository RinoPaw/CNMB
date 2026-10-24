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

    def test_proc_flags_parsing(self):
        self.assertEqual(module.access_mode("00"), "read")
        self.assertEqual(module.access_mode("01"), "write")
        self.assertEqual(module.access_mode("02"), "read_write")
        self.assertEqual(module.access_mode("02000002"), "read_write")
        self.assertEqual(module.access_mode("-"), "unknown")
        self.assertEqual(module.access_mode("03"), "unknown")


if __name__ == "__main__":
    unittest.main()
