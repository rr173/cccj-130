"""入口行为测试：`python -m ipfix_offline.nat_correlate` 与现有 cli 的 nat 子命令。

`-I` 不会把当前目录放进 sys.path，因此测试里显式加回仓库根目录。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.test_nat_semantics import EXP, OBS, SESS, Scene

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BOOT = ("import sys; sys.path.insert(0, " + repr(ROOT) + "); "
        "import ipfix_offline.nat_correlate as m; "
        "sys.exit(m.main(sys.argv[1:]))")
BOOT_CLI = ("import sys; sys.path.insert(0, " + repr(ROOT) + "); "
            "import ipfix_offline.cli as m; "
            "sys.exit(m.main(sys.argv[1:]))")


def clean(proc):
    proc.stderr = "\n".join(
        line for line in proc.stderr.splitlines()
        if not line.startswith("<frozen ") and "RuntimeWarning" not in line)
    return proc


class EntrypointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nat_entry_")
        self.dir = self.tmp.name
        self.scene = Scene({
            "realms": ["H", "W"], "links": [["H", "W"]], "origins": ["H"],
            "observations": [{"exporter": EXP, "transport_session": SESS,
                              "observation_domain_id": OBS, "realm": "W"}]})
        self.scene.dir = self.dir
        self.scene.db = os.path.join(self.dir, "store.db")
        self.scene.config_path = os.path.join(self.dir, "topology.json")
        with open(self.scene.config_path, "w") as fh:
            json.dump(self.scene.config, fh)
        self.five = [6, "198.51.100.1", 80, "203.0.113.1", 5000]
        self.flow_id = self.scene.ingest_flow(self.five, 0, 10)
        self.log = self.scene.write_logs("logs.jsonl", [])
        self.req = os.path.join(self.dir, "req.jsonl")
        with open(self.req, "w") as fh:
            fh.write(json.dumps({"request_id": "r", "flow_id": self.flow_id})
                     + "\n")

    def tearDown(self):
        self.scene.cleanup()
        self.tmp.cleanup()

    def _common(self):
        return ["--db", self.scene.db, "--config", self.scene.config_path,
                "--log", self.log, "--requests", self.req,
                "--out", os.path.join(self.dir, "out.json"),
                "--work-dir", self.dir]

    def test_module_main(self):
        proc = clean(subprocess.run(
            [sys.executable, "-I", "-c", BOOT, *self._common()],
            capture_output=True, text=True))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["summary"]["request_count"], 1)

    def test_cli_nat_subcommand(self):
        args = ["--db", self.scene.db, "nat",
                "--config", self.scene.config_path,
                "--log", self.log, "--requests", self.req,
                "--out", os.path.join(self.dir, "out2.json"),
                "--work-dir", self.dir]
        proc = clean(subprocess.run(
            [sys.executable, "-I", "-c", BOOT_CLI, *args],
            capture_output=True, text=True))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["complete"])


if __name__ == "__main__":
    unittest.main()
