"""离线 NAT 关联的命令行测试。

检查：报告文件落盘、完成标志、invalid_flow 返回非零但合法请求答案仍齐全、
结构错误返回 2 且不写报告、临时索引只清理本次创建的文件。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.test_nat_semantics import EXP, OBS, SESS, Scene
from ipfix_offline.nat_correlate import build_parser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


BOOT = ("import sys; sys.path.insert(0, " + repr(ROOT) + "); "
        "from ipfix_offline.nat_correlate import main; "
        "sys.exit(main(sys.argv[1:]))")


def run_cli(args, cwd=None):
    # -I 会忽略 PYTHONPATH 与 cwd，因此显式把仓库根目录放进 sys.path
    proc = subprocess.run(
        [sys.executable, "-I", "-c", BOOT, *args],
        cwd=cwd or ROOT, capture_output=True, text=True)
    # 过滤掉解释器本身的 warning 行，stdout/stderr 只留工具输出
    proc.stderr = "\n".join(
        line for line in proc.stderr.splitlines()
        if not line.startswith("<frozen ")
        and "RuntimeWarning" not in line)
    return proc


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nat_cli_")
        self.dir = self.tmp.name
        self.work = os.path.join(self.dir, "work")
        os.makedirs(self.work)
        self.scene = Scene({
            "realms": ["H", "M", "W"],
            "links": [["H", "M"], ["M", "W"]],
            "origins": ["H"],
            "observations": [{"exporter": EXP, "transport_session": SESS,
                              "observation_domain_id": OBS, "realm": "W"}]})
        # 场景目录就在临时目录里；命令行使用绝对路径
        self.scene.dir = self.dir
        self.scene.db = os.path.join(self.dir, "store.db")
        self.scene.config_path = os.path.join(self.dir, "topology.json")
        with open(self.scene.config_path, "w", encoding="utf-8") as fh:
            json.dump(self.scene.config, fh)
        self.A = [6, "10.0.0.1", 1000, "198.51.100.1", 80]
        self.X = [6, "10.0.9.1", 2000, "198.51.100.1", 80]
        self.Z = [6, "198.51.100.1", 80, "203.0.113.1", 5000]
        self.flow_id = self.scene.ingest_flow(self.Z, 0, 10)
        self.logs = [self.scene.write_logs("l.jsonl", [
            {"mapping_id": "A-M", "from_realm": "H", "to_realm": "M",
             "before": self.A, "after": self.X, "start_ms": 0, "end_ms": 10},
            {"mapping_id": "X-W", "from_realm": "M", "to_realm": "W",
             "before": self.X, "after": self.Z, "start_ms": 0, "end_ms": 10},
        ])]

    def tearDown(self):
        self.scene.cleanup()
        self.tmp.cleanup()

    def _args(self, requests, out):
        args = ["--db", self.scene.db, "--config", self.scene.config_path]
        for log in self.logs:
            args += ["--log", log]
        return args + ["--requests", requests, "--out", out,
                       "--work-dir", self.work]

    def test_success_writes_report_and_returns_zero(self):
        req = os.path.join(self.dir, "req.jsonl")
        with open(req, "w") as fh:
            fh.write(json.dumps({"request_id": "r", "flow_id": self.flow_id})
                     + "\n")
        out = os.path.join(self.dir, "report.json")
        proc = run_cli(self._args(req, out))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(out) as fh:
            report = json.load(fh)
        self.assertTrue(report["complete"])
        self.assertEqual(report["summary"]["status"], "complete")
        self.assertEqual(report["summary"]["invalid_flow_count"], 0)
        self.assertEqual(report["requests"][0]["fragments"][0]["status"],
                         "unique")
        # 命令行 stdout 也给完成标志与汇总
        stdout = json.loads(proc.stdout)
        self.assertTrue(stdout["complete"])
        # 临时索引已清理，工作目录没有残留
        self.assertEqual(os.listdir(self.work), [])

    def test_invalid_flow_returns_nonzero_but_answers_complete(self):
        req = os.path.join(self.dir, "req.jsonl")
        with open(req, "w") as fh:
            fh.write(json.dumps({"request_id": "ok", "flow_id": self.flow_id})
                     + "\n")
            fh.write(json.dumps({"request_id": "missing", "flow_id": 9999})
                     + "\n")
        out = os.path.join(self.dir, "report.json")
        proc = run_cli(self._args(req, out))
        self.assertEqual(proc.returncode, 1)
        with open(out) as fh:
            report = json.load(fh)
        self.assertTrue(report["complete"])
        by_id = {r["request_id"]: r for r in report["requests"]}
        self.assertEqual(by_id["ok"]["fragments"][0]["status"], "unique")
        self.assertEqual(by_id["missing"]["outcome"], "invalid_flow")
        self.assertEqual(by_id["missing"]["reason"], "flow_not_found")
        self.assertEqual(report["summary"]["invalid_flow_count"], 1)

    def test_structure_error_returns_two_and_writes_no_report(self):
        bad_log = os.path.join(self.dir, "bad.jsonl")
        with open(bad_log, "w") as fh:
            fh.write('{"mapping_id": "x"}\n')
        req = os.path.join(self.dir, "req.jsonl")
        with open(req, "w") as fh:
            fh.write(json.dumps({"request_id": "r", "flow_id": self.flow_id})
                     + "\n")
        out = os.path.join(self.dir, "report.json")
        args = ["--db", self.scene.db, "--config", self.scene.config_path,
                "--log", bad_log, "--requests", req, "--out", out,
                "--work-dir", self.work]
        proc = run_cli(args)
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(os.path.exists(out))
        error = json.loads(proc.stderr)["error"]
        self.assertEqual(error["kind"], "log_error")
        self.assertEqual(error["code"], "log_missing_field")

    def test_keep_index_preserves_index(self):
        req = os.path.join(self.dir, "req.jsonl")
        with open(req, "w") as fh:
            fh.write(json.dumps({"request_id": "r", "flow_id": self.flow_id})
                     + "\n")
        out = os.path.join(self.dir, "report.json")
        proc = run_cli(self._args(req, out) + ["--keep-index"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(out) as fh:
            report = json.load(fh)
        index_path = report["index"]["path"]
        self.assertTrue(index_path and os.path.isfile(index_path))
        self.assertTrue(index_path.startswith(self.work))

    def test_parser_surface(self):
        parser = build_parser()
        args = parser.parse_args(["--db", "d", "--config", "c", "--log", "l",
                                  "--requests", "r", "--out", "o",
                                  "--work-dir", "w"])
        self.assertEqual(args.log, ["l"])
        self.assertFalse(args.keep_index)


if __name__ == "__main__":
    unittest.main()
