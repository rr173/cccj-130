"""输入侧结构错误的拒绝测试：配置、转换日志、请求文件。

这些错误与业务结论（unmapped/incomplete/ambiguous 等）严格分开：结构错误
必须在输出任何请求答案之前失败，且不能留下部分结果。
"""

import json
import os
import tempfile
import unittest

from tests.test_nat_semantics import (
    EXP,
    OBS,
    SESS,
    Scene,
    edge,
)

from ipfix_offline import wire
from ipfix_offline.nat_correlate import (
    ConfigError,
    NatCorrelator,
    NatLogError,
    RequestFileError,
    load_config,
    load_requests,
)

BASE_CONFIG = {
    "realms": ["H", "M", "W"],
    "links": [["H", "M"], ["M", "W"]],
    "origins": ["H"],
    "observations": [{"exporter": EXP, "transport_session": SESS,
                      "observation_domain_id": OBS, "realm": "W"}],
}

A = [6, "10.0.0.1", 1000, "198.51.100.1", 80]
X = [6, "10.0.9.1", 2000, "198.51.100.1", 80]
Z = [6, "198.51.100.1", 80, "203.0.113.1", 5000]


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nat_inputs_")
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text, binary=False):
        path = os.path.join(self.dir, name)
        mode = "wb" if binary else "w"
        kwargs = {} if binary else {"encoding": "utf-8"}
        with open(path, mode, **kwargs) as fh:
            fh.write(text)
        return path

    def write_config(self, payload):
        return self.write("cfg.json", json.dumps(payload))


class ConfigValidationTests(_Base):
    def _expect(self, payload, code):
        path = self.write_config(payload)
        with self.assertRaises(ConfigError) as ctx:
            load_config(path)
        self.assertEqual(ctx.exception.code, code)

    def test_duplicate_realm(self):
        cfg = dict(BASE_CONFIG, realms=["H", "M", "W", "M"])
        self._expect(cfg, "duplicate_realm")

    def test_empty_realm_name(self):
        cfg = dict(BASE_CONFIG, realms=["H", "M", "W", ""])
        self._expect(cfg, "bad_realm_name")

    def test_self_link(self):
        cfg = dict(BASE_CONFIG, links=[["H", "M"], ["M", "M"]])
        self._expect(cfg, "self_link")

    def test_duplicate_link(self):
        cfg = dict(BASE_CONFIG, links=[["H", "M"], ["H", "M"], ["M", "W"]])
        self._expect(cfg, "duplicate_link")

    def test_cycle(self):
        cfg = dict(BASE_CONFIG, links=[["H", "M"], ["M", "W"], ["W", "H"]],
                   origins=["H"])
        self._expect(cfg, "link_cycle")

    def test_origin_with_incoming_edge(self):
        cfg = dict(BASE_CONFIG, origins=["H", "M"])
        self._expect(cfg, "origin_has_incoming_edge")

    def test_origins_must_be_exact_in_degree_zero(self):
        cfg = {"realms": ["H", "M", "W", "N"],
               "links": [["H", "M"], ["M", "W"]],
               "origins": ["H"],
               "observations": BASE_CONFIG["observations"]}
        # N 没有入边却不是原始域（日志暂缺的中间域不能当原始域，反之也不行）
        self._expect(cfg, "origins_not_exact")

    def test_unknown_realm_in_link(self):
        cfg = dict(BASE_CONFIG, links=[["H", "Q"], ["M", "W"]])
        self._expect(cfg, "unknown_realm")

    def test_duplicate_observation_binding(self):
        obs = BASE_CONFIG["observations"] + [{
            "exporter": EXP, "transport_session": SESS,
            "observation_domain_id": OBS, "realm": "H"}]
        cfg = dict(BASE_CONFIG, observations=obs)
        self._expect(cfg, "duplicate_observation")

    def test_observation_requires_exact_triple(self):
        # 只有 exporter 正确，domain 不同：不能通配
        cfg = dict(BASE_CONFIG, observations=[{
            "exporter": EXP, "transport_session": SESS,
            "observation_domain_id": OBS + 1, "realm": "W"}])
        path = self.write_config(cfg)
        parsed, digest = load_config(path)
        self.assertEqual(parsed.observations,
                         {((EXP, SESS, OBS + 1)): "W"})
        self.assertEqual(len(digest), 64)

    def test_bad_observation_domain_type(self):
        cfg = dict(BASE_CONFIG, observations=[{
            "exporter": EXP, "transport_session": SESS,
            "observation_domain_id": True, "realm": "W"}])
        self._expect(cfg, "bad_observation_domain_id")


class LogValidationTests(_Base):
    def setUp(self):
        super().setUp()
        self.scene = Scene(BASE_CONFIG)
        self.cfg_path = self.scene.config_path
        self.db = self.scene.db
        self.flow_id = self.scene.ingest_flow(Z, 0, 10)

    def tearDown(self):
        self.scene.cleanup()
        super().tearDown()

    def _run(self, rows, *, raw_text=None):
        if raw_text is None:
            raw_text = "\n".join(json.dumps(r) for r in rows) + "\n"
        log = self.write("logs.jsonl", raw_text)
        req = self.write("req.jsonl", json.dumps(
            {"request_id": "r", "flow_id": self.flow_id}) + "\n")
        with NatCorrelator(self.db, self.cfg_path, [log], self.dir,
                           measure_memory=False) as nc:
            return nc.correlate_requests(load_requests(req))

    def _expect(self, rows, code, *, raw_text=None):
        with self.assertRaises(NatLogError) as ctx:
            self._run(rows, raw_text=raw_text)
        self.assertEqual(ctx.exception.code, code)
        self.assertIsNotNone(ctx.exception.line)

    def test_bad_json_on_last_line_fails_whole_job(self):
        good = edge("A-M", "H", "M", A, X, 0, 10)
        text = json.dumps(good) + "\n" + '{"mapping_id": "broken"\n'
        self._expect([], "bad_json", raw_text=text)

    def test_bad_ipv4(self):
        row = edge("A-M", "H", "M", A, X, 0, 10)
        row["before"] = [6, "10.0.0.256", 1000, "198.51.100.1", 80]
        self._expect([row], "bad_ipv4")

    def test_non_canonical_ipv4(self):
        row = edge("A-M", "H", "M", A, X, 0, 10)
        row["after"] = [6, "010.0.9.1", 2000, "198.51.100.1", 80]
        self._expect([row], "bad_ipv4")

    def test_bad_protocol(self):
        row = edge("A-M", "H", "M", A, X, 0, 10)
        row["before"] = [1, "10.0.0.1", 1000, "198.51.100.1", 80]
        self._expect([row], "bad_protocol")

    def test_protocol_must_not_change(self):
        row = edge("A-M", "H", "M", A, X, 0, 10)
        row["after"] = [17, "10.0.9.1", 2000, "198.51.100.1", 80]
        self._expect([row], "protocol_changed")

    def test_boolean_port_rejected(self):
        row = edge("A-M", "H", "M", A, X, 0, 10)
        row["before"] = [6, "10.0.0.1", True, "198.51.100.1", 80]
        self._expect([row], "bad_port")

    def test_float_time_rejected(self):
        row = edge("A-M", "H", "M", A, X, 0, 10)
        row["start_ms"] = 1.0
        self._expect([row], "bad_time")

    def test_time_beyond_uint64(self):
        row = edge("A-M", "H", "M", A, X, 0, 10)
        row["end_ms"] = 1 << 64
        self._expect([row], "bad_time")

    def test_empty_interval(self):
        row = edge("A-M", "H", "M", A, X, 5, 5)
        self._expect([row], "bad_interval")

    def test_realm_pair_must_be_a_link(self):
        row = edge("A-M", "H", "W", A, X, 0, 10)
        self._expect([row], "not_a_link")

    def test_unknown_realm(self):
        row = edge("A-M", "H", "Q", A, X, 0, 10)
        self._expect([row], "unknown_realm")

    def test_missing_field(self):
        row = edge("A-M", "H", "M", A, X, 0, 10)
        del row["after"]
        self._expect([row], "log_missing_field")

    def test_empty_mapping_id(self):
        row = edge("", "H", "M", A, X, 0, 10)
        self._expect([row], "bad_mapping_id")

    def test_duplicate_mapping_id_across_files(self):
        good = edge("A-M", "H", "M", A, X, 0, 10)
        log1 = self.write("l1.jsonl", json.dumps(good) + "\n")
        other = dict(good, start_ms=1, end_ms=10)
        log2 = self.write("l2.jsonl", json.dumps(other) + "\n")
        req = self.write("req.jsonl", json.dumps(
            {"request_id": "r", "flow_id": self.flow_id}) + "\n")
        with self.assertRaises(NatLogError) as ctx:
            with NatCorrelator(self.db, self.cfg_path, [log1, log2],
                               self.dir, measure_memory=False) as nc:
                nc.correlate_requests(load_requests(req))
        self.assertEqual(ctx.exception.code, "duplicate_mapping_id")

    def test_empty_line_rejected(self):
        good = edge("A-M", "H", "M", A, X, 0, 10)
        text = json.dumps(good) + "\n\n"
        self._expect([], "empty_line", raw_text=text)

    def test_bad_utf8(self):
        good = edge("A-M", "H", "M", A, X, 0, 10)
        blob = json.dumps(good).encode() + b"\n" + b'{"x":"\xff"}\n'
        log = self.write("logs.jsonl", blob, binary=True)
        req = self.write("req.jsonl", json.dumps(
            {"request_id": "r", "flow_id": self.flow_id}) + "\n")
        with self.assertRaises(NatLogError) as ctx:
            with NatCorrelator(self.db, self.cfg_path, [log], self.dir,
                               measure_memory=False) as nc:
                nc.correlate_requests(load_requests(req))
        self.assertEqual(ctx.exception.code, "bad_utf8")

    def test_structure_error_writes_no_partial_answer(self):
        log = self.write("logs.jsonl", json.dumps(
            edge("A-M", "H", "M", A, X, 0, 10)) + "\n{bad\n")
        req = self.write("req.jsonl", json.dumps(
            {"request_id": "r", "flow_id": self.flow_id}) + "\n")
        out = os.path.join(self.dir, "out.json")
        from ipfix_offline.nat_correlate import run_job
        with self.assertRaises(NatLogError):
            run_job(self.db, self.cfg_path, [log], req, out, self.dir)
        self.assertFalse(os.path.exists(out))


class RequestValidationTests(_Base):
    def setUp(self):
        super().setUp()
        self.scene = Scene(BASE_CONFIG)
        self.log = self.scene.write_logs("logs.jsonl", [])

    def tearDown(self):
        self.scene.cleanup()
        super().tearDown()

    def test_duplicate_request_id(self):
        path = self.write("req.jsonl", '{"request_id":"a","flow_id":1}\n'
                          '{"request_id":"a","flow_id":2}\n')
        with self.assertRaises(RequestFileError) as ctx:
            load_requests(path)
        self.assertEqual(ctx.exception.code, "duplicate_request_id")

    def test_flow_id_must_be_positive_int(self):
        for value in (0, -1, True, 1.5, "1"):
            path = self.write("req.jsonl",
                              json.dumps({"request_id": "a", "flow_id": value})
                              + "\n")
            with self.assertRaises(RequestFileError) as ctx:
                load_requests(path)
            self.assertEqual(ctx.exception.code, "bad_flow_id")

    def test_empty_request_id(self):
        path = self.write("req.jsonl", '{"request_id":"","flow_id":1}\n')
        with self.assertRaises(RequestFileError) as ctx:
            load_requests(path)
        self.assertEqual(ctx.exception.code, "bad_request_id")


if __name__ == "__main__":
    unittest.main()
