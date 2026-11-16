"""共享路径很多、节点很少的转换链，以及真实规模下的访问范围与资源。

一、24 层“分叉再汇合”：每层从一个状态分出 2 个分支，再全部汇合到下一层的
    同一状态。完整来源链有 2^24 ≈ 1.68e7 条，但反向证据图只有几十个节点、
    几十条边。作业必须在线性规模内给出“唯一来源 + 全部依据”。

二、20 万条大多不相关的日志 + 1000 个请求：记录索引实际返回行数、查询次数、
    图节点/边数、耗时和峰值 Python 内存；断言访问范围不随日志总量线性增长。
"""

import json
import os
import socket
import tempfile
import resource
import time
import unittest

from ipfix_offline import wire
from ipfix_offline.ingestor import CaptureEntry, Ingestor
from ipfix_offline.nat_correlate import run_job

OBS = 909
EXP = "exporter-scale"
SESS = "session-scale"

LAYOUT = [
    wire.field_spec(4, 1),
    wire.field_spec(8, 4),
    wire.field_spec(7, 2),
    wire.field_spec(12, 4),
    wire.field_spec(11, 2),
    wire.field_spec(152, 8),
    wire.field_spec(153, 8),
]


def flow_body(five, start, end):
    proto, sip, sport, dip, dport = five
    return (bytes([proto]) + socket.inet_aton(sip) + sport.to_bytes(2, "big")
            + socket.inet_aton(dip) + dport.to_bytes(2, "big")
            + start.to_bytes(8, "big") + end.to_bytes(8, "big"))


def make_db(path, flows):
    """把若干 (five, start, end) 经现有 import 真正入库，返回 flow_id 列表。"""
    tmpdir = os.path.dirname(path)
    with Ingestor(path, max_waiting_bytes=10_000_000,
                  max_waiting_messages_k=10) as ing:
        pos = 0
        tpl = wire.message(1, 0, OBS, [wire.template_set(
            [wire.template_record(300, LAYOUT)])])
        tpl_path = os.path.join(tmpdir, "tpl.bin")
        with open(tpl_path, "wb") as fh:
            fh.write(tpl)
        ing.import_manifest([CaptureEntry(pos, EXP, SESS, tpl_path)])
        pos += 1
        for five, start, end in flows:
            data = wire.message(1, pos, OBS, [
                wire.data_set(300, [flow_body(five, start, end)])])
            p = os.path.join(tmpdir, f"f{pos}.bin")
            with open(p, "wb") as fh:
                fh.write(data)
            ing.import_manifest([CaptureEntry(pos, EXP, SESS, p)])
            pos += 1
        return [f["flow_id"] for f in ing.flows()]


def build_ladder(width, depth, *, extra_realms=(), extra_links=()):
    """构造 depth 层分叉汇合。

    第 i 层：P_i（汇合点，realm R_i）分叉到 width 个分支状态 B_{i,k}
    （realm S_i），每个分支再汇合到 P_{i+1}（realm R_{i+1}）。R_0 是原始域 H，
    R_depth 是观察域 W。完整链数量 = width**depth。
    返回 (realms, links, logs, A, Z)。
    """
    realms = ["H"]
    links = []
    logs = []
    A = [6, "10.90.255.1", 9000, "192.0.2.200", 80]
    Z = [6, "203.0.113.200", 4000, "192.0.2.200", 80]
    prev_realm = "H"
    prev_state = A
    for layer in range(depth):
        sid = f"S{layer}"
        rid = "W" if layer + 1 == depth else f"R{layer + 1}"
        realms.extend([sid] if sid not in realms else [])
        if rid not in realms:
            realms.append(rid)
        links.append([prev_realm, sid])
        links.append([sid, rid])
        next_state = Z if layer + 1 == depth else [
            6, f"10.90.{layer}.250", 7000 + layer, "192.0.2.200", 80]
        for k in range(width):
            branch = [6, f"10.91.{layer}.{k + 1}",
                      1000 + layer * 8 + k, "192.0.2.200", 80]
            logs.append({
                "mapping_id": f"L{layer}f{k}",
                "from_realm": prev_realm, "to_realm": sid,
                "before": prev_state, "after": branch,
                "start_ms": 0, "end_ms": 1000,
            })
            logs.append({
                "mapping_id": f"L{layer}j{k}",
                "from_realm": sid, "to_realm": rid,
                "before": branch, "after": next_state,
                "start_ms": 0, "end_ms": 1000,
            })
        prev_realm = rid
        prev_state = next_state
    realms.extend(r for r in extra_realms if r not in realms)
    links.extend([list(x) for x in extra_links])
    return realms, links, logs, A, Z


class ScaleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nat_scale_")
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _write_json(self, name, payload):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        return path

    def _write_jsonl(self, name, rows):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        return path

    def _config(self, realms, links, origins):
        return self._write_json("topology.json", {
            "realms": realms,
            "links": links,
            "origins": origins,
            "observations": [{"exporter": EXP, "transport_session": SESS,
                              "observation_domain_id": OBS, "realm": "W"}],
        })

    # ------------------------------------------------------------------
    def test_2_pow_24_paths_represented_compactly(self):
        depth, width = 24, 2
        realms, links, logs, A, Z = build_ladder(width, depth)
        cfg_path = self._config(realms, links, ["H"])
        log_path = self._write_jsonl("logs.jsonl", logs)
        db = os.path.join(self.dir, "store.db")
        flow_ids = make_db(db, [(Z, 0, 1000)])
        req_path = self._write_jsonl("req.jsonl", [
            {"request_id": "r", "flow_id": flow_ids[0]}])

        started = time.monotonic()
        report = run_job(db, cfg_path, [log_path], req_path,
                         os.path.join(self.dir, "out.json"), self.dir)
        elapsed = time.monotonic() - started
        fragment = report["requests"][0]["fragments"][0]
        self.assertEqual(fragment["status"], "unique")
        self.assertEqual([(o["realm"], tuple(o["five_tuple"]))
                          for o in fragment["origins"]], [("H", tuple(A))])
        n_nodes = len(fragment["graph"]["nodes"])
        n_edges = len(fragment["graph"]["edges"])
        self.assertEqual(n_edges, len(logs))
        self.assertEqual(len({e["mapping_id"]
                              for e in fragment["graph"]["edges"]}), n_edges)
        # 完整链数量与图规模的关系
        self.assertEqual(width ** depth, 16_777_216)
        self.assertLess(n_nodes, 100)
        self.assertLess(n_edges, 200)
        print(f"\n[ladder] depth={depth} width={width} "
              f"full_chains={width ** depth} nodes={n_nodes} edges={n_edges} "
              f"elapsed_ms={elapsed * 1000:.1f}")

    # ------------------------------------------------------------------
    def test_large_log_and_request_volume(self):
        depth, width = 6, 3
        realms, links, chain, A, Z = build_ladder(
            width, depth,
            extra_realms=("N", "P"),
            extra_links=(("N", "W"), ("N", "P")))
        cfg_path = self._config(realms, links, ["H", "N"])
        n_noise = 200_000
        log_path = os.path.join(self.dir, "logs.jsonl")
        with open(log_path, "w", encoding="utf-8") as fh:
            for row in chain:
                fh.write(json.dumps(row) + "\n")
            for i in range(n_noise):
                # 无关日志：不同外侧地址/端口/时间
                after = [6, f"10.101.{(i // 250) % 250}.{i % 250 + 1}",
                         1024 + i % 60000, "198.18.0.1", 443]
                before = [6, f"10.100.{(i // 250) % 250}.{i % 250 + 1}",
                          1024 + i % 60000, "198.18.0.1", 443]
                fh.write(json.dumps({
                    "mapping_id": f"noise-{i}",
                    "from_realm": "N",
                    "to_realm": "P" if i % 2 else "W",
                    "before": before, "after": after,
                    "start_ms": 1_000_000 + i,
                    "end_ms": 1_000_001 + i,
                }) + "\n")

        db = os.path.join(self.dir, "store.db")
        flow_ids = make_db(db, [(Z, 0, 1000)] * 40)
        req_path = self._write_jsonl("req.jsonl", [
            {"request_id": f"r{i}", "flow_id": flow_ids[i % len(flow_ids)]}
            for i in range(1000)])

        started = time.monotonic()
        report = run_job(db, cfg_path, [log_path], req_path,
                         os.path.join(self.dir, "out.json"), self.dir)
        elapsed = time.monotonic() - started
        summary = report["summary"]
        self.assertEqual(summary["request_count"], 1000)
        self.assertEqual(summary["associated_count"], 1000)
        self.assertEqual(summary["invalid_flow_count"], 0)
        self.assertEqual(report["inputs"]["log_entries"], n_noise + len(chain))
        # 索引访问范围：返回行数与查询次数都远小于“每条请求扫一遍全表”
        rows = report["index"]["log_rows_returned"]
        lookups = report["index"]["lookups"]
        self.assertLess(rows, 200_000)
        self.assertLess(lookups, 1000 * 200)
        nodes_per = summary["graph_nodes_total"] / 1000
        edges_per = summary["graph_edges_total"] / 1000
        self.assertLess(nodes_per, 80)
        self.assertLess(edges_per, 200)
        rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        print(f"\n[scale] requests=1000 logs={n_noise + len(chain)} "
              f"elapsed_ms={elapsed * 1000:.1f} "
              f"index_build_ms={report['timing']['index_build_ms']:.1f} "
              f"requests_ms={report['timing']['requests_ms']:.1f} "
              f"peak_rss_kb={rss_kb}")
        print(f"[scale] lookups={lookups} rows_returned={rows} "
              f"nodes_total={summary['graph_nodes_total']} "
              f"edges_total={summary['graph_edges_total']} "
              f"index_size={report['index']['size_bytes']} "
              f"peak_python_bytes={report['peak_python_bytes']} "
              f"peak_rss_bytes={report['peak_rss_bytes']}")
        self.assertLess(report["peak_python_bytes"], 64 * 1024 * 1024)
        # 进程级峰值 RSS 含索引建库与 SQLite 页缓存，仍不得随日志总量线性膨胀
        self.assertLess(report["peak_rss_bytes"], 1024 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
