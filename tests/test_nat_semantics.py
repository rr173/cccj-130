"""离线 NAT 关联的语义测试。

覆盖需求点名的每个场景：

* 端到端经现有 import 真正入仓（合成 IPFIX 消息）
* 同一原始候选经两条链汇合（只算一个候选，两路依据都保留）
* 一个完整支路旁有断支路 -> incomplete（不删断支路）
* 无首跳 -> unmapped
* 观察点就是原始域
* 完全不同域却五元组相同（域名称是身份的一部分）
* 端口复用、目的地址也发生转换
* 企业同号字段不能顶替标准 IE
* 八字节时间超过 2^53 仍精确
* 混入 invalid_flow 不妨碍其他请求
* 独立枚举原始链 + 有效期求交的参考器核对（不调用正式关联函数）
* 打乱日志排列：业务片段与 mapping_id 图不变，物理行号跟随新原件
"""

import json
import os
import socket
import tempfile
import unittest

from ipfix_offline import wire
from ipfix_offline.ingestor import CaptureEntry, Ingestor
from ipfix_offline.nat_correlate import (
    NatCorrelator,
    load_config,
    load_requests,
)

OBS = 501
EXP = "exporter-edge"
SESS = "session-1"
LINK_LAYOUT = [
    wire.field_spec(4, 1),
    wire.field_spec(8, 4),
    wire.field_spec(7, 2),
    wire.field_spec(12, 4),
    wire.field_spec(11, 2),
    wire.field_spec(152, 8),
    wire.field_spec(153, 8),
]


def _flow_body(five, start, end):
    proto, sip, sport, dip, dport = five
    return (bytes([proto]) + socket.inet_aton(sip) + sport.to_bytes(2, "big")
            + socket.inet_aton(dip) + dport.to_bytes(2, "big")
            + start.to_bytes(8, "big") + end.to_bytes(8, "big"))


class Scene:
    """一个临时目录里的库 + 配置 + 日志 + 请求，全部由测试自己构造。"""

    def __init__(self, config, layouts=None):
        self.tmp = tempfile.TemporaryDirectory(prefix="nat_sem_")
        self.dir = self.tmp.name
        self.db = os.path.join(self.dir, "store.db")
        self.config = config
        self.config_path = os.path.join(self.dir, "topology.json")
        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(config, fh, ensure_ascii=False)
        self._pos = 0
        self._layouts = layouts or {}

    def cleanup(self):
        self.tmp.cleanup()

    def ingest_flow(self, five, start, end, *, layout=None, template_id=300,
                    exporter=EXP, session=SESS, obs=OBS, extra_sets=None):
        layout = layout or LINK_LAYOUT
        tpl = wire.message(1, self._pos, obs, [wire.template_set(
            [wire.template_record(template_id, layout)])])
        data = wire.message(1, self._pos + 1, obs, [
            wire.data_set(template_id, [_flow_body(five, start, end)])])
        ids = []
        with Ingestor(self.db, max_waiting_bytes=1_000_000,
                      max_waiting_messages_k=10) as ing:
            for blob in (tpl, data):
                path = os.path.join(self.dir, f"m{self._pos}.bin")
                with open(path, "wb") as fh:
                    fh.write(blob)
                ing.import_manifest([CaptureEntry(self._pos, exporter,
                                                  session, path)])
                self._pos += 1
            ids = [f["flow_id"] for f in ing.flows()]
        return ids[-1]

    def ingest_raw(self, blobs, *, exporter=EXP, session=SESS):
        out = []
        with Ingestor(self.db, max_waiting_bytes=1_000_000,
                      max_waiting_messages_k=10) as ing:
            for blob in blobs:
                path = os.path.join(self.dir, f"r{self._pos}.bin")
                with open(path, "wb") as fh:
                    fh.write(blob)
                ing.import_manifest([CaptureEntry(self._pos, exporter,
                                                  session, path)])
                self._pos += 1
            out = [f["flow_id"] for f in ing.flows()]
        return out

    def write_logs(self, name, rows):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        return path

    def write_requests(self, rows):
        path = os.path.join(self.dir, "requests.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        return path

    def run(self, logs, requests, **kwargs):
        req_path = self.write_requests(requests)
        with NatCorrelator(self.db, self.config_path, logs, self.dir,
                           measure_memory=False, **kwargs) as nc:
            report = nc.correlate_requests(load_requests(req_path))
        return report


def edge(mapping_id, from_realm, to_realm, before, after, start, end):
    return {"mapping_id": mapping_id, "from_realm": from_realm,
            "to_realm": to_realm, "before": before, "after": after,
            "start_ms": start, "end_ms": end}


def src(realm, five):
    return (realm, tuple(five))


def fragments_as_tuples(fragments):
    return [(f["start_ms"], f["end_ms"], f["status"],
             [(o["realm"], tuple(o["five_tuple"])) for o in f["origins"]],
             [(o["realm"], tuple(o["five_tuple"])) for o in f["frontiers"]],
             [e["mapping_id"] for e in f["graph"]["edges"]])
            for f in fragments]


# ---------------------------------------------------------------------------
# 独立参考器：枚举原始链并对有效期求交。只用于核对，不调用正式关联代码。
# ---------------------------------------------------------------------------
def reference_fragments(logs, cfg, observed_realm, observed_five, start, end):
    """把 [start,end) 用所有日志端点切开，逐段穷举“同一时刻全链有效”的来源。

    返回每段的 (lo, hi, status, origins, frontiers)，不计算边集合。
    """
    origins_ok = set(cfg["origins"])
    links = {tuple(x) for x in cfg["links"]}
    points = {start, end}
    for row in logs:
        if start < row["start_ms"] < end:
            points.add(row["start_ms"])
        if start < row["end_ms"] < end:
            points.add(row["end_ms"])
    points = sorted(points)
    out = []
    for lo, hi in zip(points, points[1:]):
        if lo >= hi:
            continue
        result = _ref_at(logs, origins_ok, links, observed_realm,
                         observed_five, lo)
        out.append((lo, hi, result[0], result[1], result[2]))
    # 合并相邻同结果片段（参考器同样按来源+frontier 合并）
    merged = []
    for item in out:
        if merged and merged[-1][2:] == item[2:]:
            merged[-1] = (merged[-1][0], item[1], *item[2:])
        else:
            merged.append(item)
    return merged


def _ref_at(logs, origins_ok, links, realm, five, at):
    # 返回 (status, origins, frontiers)
    seen = set()
    stack = [(realm, tuple(five), True)]
    origins = set()
    frontiers = set()
    initial_has_edge = False
    visited = set()
    while stack:
        cur_realm, cur_five, is_initial = stack.pop()
        state = (cur_realm, cur_five)
        if state in visited:
            continue
        visited.add(state)
        usable = [row for row in logs
                  if row["to_realm"] == cur_realm
                  and tuple(row["after"]) == cur_five
                  and row["start_ms"] <= at < row["end_ms"]
                  and (row["from_realm"], row["to_realm"]) in links]
        if not usable:
            if cur_realm in origins_ok:
                origins.add(state)
            else:
                frontiers.add(state)
            continue
        if is_initial:
            initial_has_edge = True
        for row in usable:
            stack.append((row["from_realm"], tuple(row["before"]), False))
    if not initial_has_edge and realm not in origins_ok:
        return ("unmapped", [], [((realm, tuple(five)))])
    if frontiers:
        return ("incomplete", sorted(origins), sorted(frontiers))
    if len(origins) == 1:
        return ("unique", sorted(origins), [])
    if len(origins) > 1:
        return ("ambiguous", sorted(origins), [])
    return ("incomplete", sorted(origins), sorted(frontiers))


class SemanticsTests(unittest.TestCase):
    def setUp(self):
        self.scenes = []

    def tearDown(self):
        for scene in self.scenes:
            scene.cleanup()

    def scene(self, config, layouts=None):
        sc = Scene(config, layouts)
        self.scenes.append(sc)
        return sc

    # ------------------------------------------------------------------ 1
    def test_two_chain_convergence_counts_once_but_keeps_both_evidence(self):
        # H->M->W；Z 在 M 有两个前驱 X1、X2，二者又都回到同一个原始 A
        cfg = {"realms": ["H", "M", "W"], "links": [["H", "M"], ["M", "W"]],
               "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        A = [6, "10.1.0.1", 1111, "198.51.100.9", 80]
        X1 = [6, "10.1.9.1", 2222, "198.51.100.9", 80]
        X2 = [6, "10.1.9.2", 3333, "198.51.100.9", 80]
        Z = [6, "198.51.100.9", 80, "203.0.113.5", 4444]
        flow_id = sc.ingest_flow(Z, 0, 10)
        logs = [
            edge("M1", "H", "M", A, X1, 0, 10),
            edge("M2", "H", "M", A, X2, 0, 10),
            edge("W1", "M", "W", X1, Z, 0, 10),
            edge("W2", "M", "W", X2, Z, 0, 10),
        ]
        path = sc.write_logs("logs.jsonl", logs)
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        fragments = report["requests"][0]["fragments"]
        self.assertEqual(len(fragments), 1)
        fragment = fragments[0]
        self.assertEqual(fragment["status"], "unique")
        self.assertEqual([(o["realm"], tuple(o["five_tuple"]))
                          for o in fragment["origins"]], [("H", tuple(A))])
        # 两路依据（四条边）都必须保留；节点只算一次
        self.assertEqual(sorted(e["mapping_id"] for e in fragment["graph"]["edges"]),
                         ["M1", "M2", "W1", "W2"])
        nodes = [(n["realm"], tuple(n["five_tuple"]))
                 for n in fragment["graph"]["nodes"]]
        self.assertEqual(len(nodes), len(set(nodes)))
        self.assertEqual(len(nodes), 4)   # A, X1, X2, Z

    # ------------------------------------------------------------------ 2
    def test_broken_branch_next_to_complete_branch_is_incomplete(self):
        cfg = {"realms": ["H", "M", "W"], "links": [["H", "M"], ["M", "W"]],
               "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        A = [6, "10.2.0.1", 1111, "198.51.100.9", 80]
        X1 = [6, "10.2.9.1", 2222, "198.51.100.9", 80]
        X2 = [6, "10.2.9.2", 3333, "198.51.100.9", 80]
        Z = [6, "198.51.100.9", 80, "203.0.113.6", 4444]
        flow_id = sc.ingest_flow(Z, 0, 10)
        logs = [
            edge("W1", "M", "W", X1, Z, 0, 10),
            edge("M1", "H", "M", A, X1, 0, 10),
            edge("W2", "M", "W", X2, Z, 0, 10),   # X2 在 M 没有前驱
        ]
        path = sc.write_logs("logs.jsonl", logs)
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        fragment = report["requests"][0]["fragments"][0]
        # 有一个完整支路，但旁的断支路使整段不能算已确定
        self.assertEqual(fragment["status"], "incomplete")
        self.assertEqual([tuple(o["five_tuple"]) for o in fragment["origins"]],
                         [tuple(A)])
        self.assertEqual([(f["realm"], tuple(f["five_tuple"]))
                          for f in fragment["frontiers"]], [("M", tuple(X2))])
        self.assertEqual(sorted(e["mapping_id"] for e in fragment["graph"]["edges"]),
                         ["M1", "W1", "W2"])

    # ------------------------------------------------------------------ 3
    def test_no_first_hop_is_unmapped(self):
        cfg = {"realms": ["H", "M", "W"], "links": [["H", "M"], ["M", "W"]],
               "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        Z = [17, "198.51.100.9", 53, "203.0.113.7", 5555]
        flow_id = sc.ingest_flow(Z, 0, 10)
        path = sc.write_logs("logs.jsonl", [])
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        fragment = report["requests"][0]["fragments"][0]
        self.assertEqual(fragment["status"], "unmapped")
        self.assertEqual(fragment["origins"], [])
        self.assertEqual([(f["realm"], tuple(f["five_tuple"]))
                          for f in fragment["frontiers"]], [("W", tuple(Z))])
        self.assertEqual(fragment["graph"]["edges"], [])

    # ------------------------------------------------------------------ 4
    def test_observer_is_origin_realm(self):
        cfg = {"realms": ["H", "M"], "links": [["H", "M"]], "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "H"}]}
        sc = self.scene(cfg)
        five = [6, "10.3.0.1", 1234, "198.51.100.1", 8080]
        flow_id = sc.ingest_flow(five, 100, 200)
        path = sc.write_logs("logs.jsonl", [])
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        fragment = report["requests"][0]["fragments"][0]
        self.assertEqual((fragment["start_ms"], fragment["end_ms"]),
                         (100, 200))
        self.assertEqual(fragment["status"], "unique")
        self.assertEqual([(o["realm"], tuple(o["five_tuple"]))
                          for o in fragment["origins"]], [("H", tuple(five))])
        self.assertEqual(fragment["frontiers"], [])
        self.assertEqual(fragment["graph"]["edges"], [])

    # ------------------------------------------------------------------ 5
    def test_same_five_tuple_in_different_realm_is_not_shared(self):
        # H->M->W 与 H2->W2（观察域 W 的两条链），同一五元组出现在 M 与 W2：
        # 域名称是身份的一部分，不能跨域借用前驱。
        cfg = {"realms": ["H", "M", "W", "N"],
               "links": [["H", "M"], ["M", "W"], ["N", "W"]],
               "origins": ["H", "N"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        shared = [6, "10.4.9.9", 7777, "198.51.100.2", 443]
        A = [6, "10.4.0.1", 1111, "198.51.100.2", 443]
        Z = [6, "198.51.100.2", 443, "203.0.113.8", 6666]
        flow_id = sc.ingest_flow(Z, 0, 10)
        logs = [
            # M 域里 shared -> Z
            edge("W-M", "M", "W", shared, Z, 0, 10),
            # H 域里 A -> shared（M 域的状态）
            edge("M-H", "H", "M", A, shared, 0, 10),
            # N 域里 N 状态也等于 shared，且 N 是原始域：同一五元组、不同域，
            # 不能因为 shared 相同就借用 H/M 的链
            edge("W-N", "N", "W", shared, Z, 0, 10),
        ]
        path = sc.write_logs("logs.jsonl", logs)
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        fragment = report["requests"][0]["fragments"][0]
        self.assertEqual(fragment["status"], "ambiguous")
        self.assertEqual(sorted((o["realm"], tuple(o["five_tuple"]))
                                for o in fragment["origins"]),
                         [("H", tuple(A)), ("N", tuple(shared))])
        self.assertEqual(fragment["frontiers"], [])

    # ------------------------------------------------------------------ 6
    def test_port_reuse_and_destination_rewrite(self):
        # 同一个公网端口 40000 在时间上先属于 A、后属于 B；目的地址也被改写。
        cfg = {"realms": ["H", "M", "W"], "links": [["H", "M"], ["M", "W"]],
               "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        Z = [6, "203.0.113.20", 40000, "192.0.2.99", 80]
        flow_id = sc.ingest_flow(Z, 0, 20)
        A = [6, "10.5.0.1", 9000, "192.0.2.99", 80]
        B = [6, "10.5.0.2", 9001, "192.0.2.50", 80]
        X = [6, "10.5.9.1", 40000, "192.0.2.99", 80]
        Y = [6, "10.5.9.2", 40000, "192.0.2.50", 80]
        logs = [
            edge("A-M", "H", "M", A, X, 0, 20),
            edge("B-M", "H", "M", B, Y, 0, 20),
            edge("X-W", "M", "W", X, Z, 0, 10),
            edge("Y-W", "M", "W", Y, Z, 10, 20),
        ]
        path = sc.write_logs("logs.jsonl", logs)
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        fragments = report["requests"][0]["fragments"]
        got = fragments_as_tuples(fragments)
        self.assertEqual([(g[0], g[1], g[2]) for g in got],
                         [(0, 10, "unique"), (10, 20, "unique")])
        # 目的地址两端都变了：X/Y 与 Z 的 dst 不同，但都被正确串联
        self.assertEqual(got[0][3], [("H", (6, "10.5.0.1", 9000,
                                           "192.0.2.99", 80))])
        self.assertEqual(got[1][3], [("H", (6, "10.5.0.2", 9001,
                                           "192.0.2.50", 80))])
        self.assertEqual(got[0][5], ["A-M", "X-W"])
        self.assertEqual(got[1][5], ["B-M", "Y-W"])

    # ------------------------------------------------------------------ 7
    def test_enterprise_ie_cannot_substitute_standard(self):
        cfg = {"realms": ["H", "W"], "links": [["H", "W"]], "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        # 标准 4/7/8/11/12/152/153 中故意不给标准 IE152，改给企业版同号 IE152
        layout = [
            wire.field_spec(4, 1),
            wire.field_spec(8, 4),
            wire.field_spec(7, 2),
            wire.field_spec(12, 4),
            wire.field_spec(11, 2),
            wire.field_spec(152, 8, enterprise_number=999),
            wire.field_spec(153, 8),
            wire.field_spec(99, 8),
        ]
        body = (bytes([6]) + socket.inet_aton("198.51.100.3")
                + (80).to_bytes(2, "big") + socket.inet_aton("203.0.113.9")
                + (9999).to_bytes(2, "big")
                + (0).to_bytes(8, "big") + (10).to_bytes(8, "big")
                + b"12345678")
        tpl = wire.message(1, 0, OBS, [wire.template_set(
            [wire.template_record(310, layout)])])
        data = wire.message(1, 1, OBS, [wire.data_set(310, [body])])
        flow_id = sc.ingest_raw([tpl, data])[0]
        path = sc.write_logs("logs.jsonl", [])
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        item = report["requests"][0]
        self.assertEqual(item["outcome"], "invalid_flow")
        self.assertEqual(item["reason"], "enterprise_ie_cannot_substitute")
        self.assertIn("152", item["detail"])

    # ---------------------------------------------------------------- 6b
    def test_identical_logs_with_distinct_ids_are_independent_evidence(self):
        cfg = {"realms": ["H", "W"], "links": [["H", "W"]], "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        A = [6, "10.0.0.7", 1111, "198.51.100.1", 80]
        Z = [6, "198.51.100.1", 80, "203.0.113.1", 5000]
        flow_id = sc.ingest_flow(Z, 0, 10)
        row = edge("dup-A", "H", "W", A, Z, 0, 10)
        twin = dict(row, mapping_id="dup-B")     # 描述完全相同、ID 不同
        path = sc.write_logs("logs.jsonl", [row, twin])
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        fragment = report["requests"][0]["fragments"][0]
        self.assertEqual(fragment["status"], "unique")
        # 一个候选，但两条依据都在
        self.assertEqual(len(fragment["origins"]), 1)
        self.assertEqual([e["mapping_id"] for e in fragment["graph"]["edges"]],
                         ["dup-A", "dup-B"])
        self.assertEqual(len(fragment["graph"]["nodes"]), 2)

    # ---------------------------------------------------------------- 7b
    def test_enterprise_field_alongside_standard_is_ignored(self):
        # 标准 IE152 存在，同时另有企业号 152：必须取标准字段的时间
        cfg = {"realms": ["H", "W"], "links": [["H", "W"]], "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        layout = [
            wire.field_spec(4, 1),
            wire.field_spec(8, 4),
            wire.field_spec(7, 2),
            wire.field_spec(12, 4),
            wire.field_spec(11, 2),
            wire.field_spec(152, 8),                       # 标准开始时间
            wire.field_spec(152, 8, enterprise_number=7),   # 企业号同号干扰
            wire.field_spec(153, 8),
        ]
        body = (bytes([6]) + socket.inet_aton("198.51.100.4")
                + (80).to_bytes(2, "big") + socket.inet_aton("203.0.113.9")
                + (9999).to_bytes(2, "big")
                + (100).to_bytes(8, "big")                 # 标准 start=100
                + (999_999).to_bytes(8, "big")             # 企业号 152 干扰值
                + (200).to_bytes(8, "big"))                # 标准 end=200
        tpl = wire.message(1, 0, OBS, [wire.template_set(
            [wire.template_record(320, layout)])])
        data = wire.message(1, 1, OBS, [wire.data_set(320, [body])])
        flow_id = sc.ingest_raw([tpl, data])[0]
        path = sc.write_logs("logs.jsonl", [])
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        item = report["requests"][0]
        self.assertEqual(item["outcome"], "associated")
        self.assertEqual((item["observed"]["start_ms"],
                          item["observed"]["end_ms"]), (100, 200))

    # ------------------------------------------------------------------ 8
    def test_eight_byte_time_beyond_2_to_53(self):
        cfg = {"realms": ["H", "M", "W"], "links": [["H", "M"], ["M", "W"]],
               "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        base = (1 << 53) + 1_234_567_890_123
        end = base + 10
        A = [6, "10.6.0.1", 1111, "198.51.100.4", 80]
        X = [6, "10.6.9.1", 2222, "198.51.100.4", 80]
        Z = [6, "198.51.100.4", 80, "203.0.113.10", 7777]
        flow_id = sc.ingest_flow(Z, base, end)
        logs = [
            edge("A-M", "H", "M", A, X, base, end),
            edge("X-W", "M", "W", X, Z, base + 4, end),
        ]
        path = sc.write_logs("logs.jsonl", logs)
        report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
        item = report["requests"][0]
        self.assertEqual(item["outcome"], "associated")
        self.assertEqual(item["observed"]["start_ms"], base)
        self.assertEqual(item["observed"]["end_ms"], end)
        # 时间精确：精度损失会破坏分段端点
        self.assertEqual([(f["start_ms"], f["end_ms"], f["status"])
                          for f in item["fragments"]],
                         [(base, base + 4, "unmapped"),
                          (base + 4, end, "unique")])
        # [base,base+4) 观察点 Z 在 W 没有可用首跳日志
        first = item["fragments"][0]
        self.assertEqual([(f["realm"], tuple(f["five_tuple"]))
                          for f in first["frontiers"]], [("W", tuple(Z))])
        # 证据里 8 字节原字节也完整
        times = {ie["element_id"]: ie for ie in item["flow_evidence"]["ies"]}
        self.assertEqual(times[152]["value"], base)
        self.assertEqual(times[152]["raw_hex"], base.to_bytes(8, "big").hex())

    # ------------------------------------------------------------------ 9
    def test_invalid_flow_does_not_block_others(self):
        cfg = {"realms": ["H", "W"], "links": [["H", "W"]], "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        good = [6, "198.51.100.5", 80, "203.0.113.11", 8888]
        good_id = sc.ingest_flow(good, 0, 10)
        # 没有观测域绑定：不同 obs domain
        unbound_id = sc.ingest_flow([6, "198.51.100.6", 80,
                                    "203.0.113.12", 8888], 0, 10,
                                   obs=OBS + 1)
        # 非 TCP/UDP
        udp_ok = sc.ingest_flow([17, "198.51.100.7", 80,
                                "203.0.113.13", 8888], 0, 10)
        icmp_id = sc.ingest_flow([1, "198.51.100.8", 80,
                                 "203.0.113.14", 8888], 0, 10)
        # 起止非法
        bad_time_id = sc.ingest_flow([6, "198.51.100.9", 80,
                                     "203.0.113.15", 8888], 5, 5)
        path = sc.write_logs("logs.jsonl", [])
        report = sc.run([path], [
            {"request_id": "ok", "flow_id": good_id},
            {"request_id": "unbound", "flow_id": unbound_id},
            {"request_id": "icmp", "flow_id": icmp_id},
            {"request_id": "time", "flow_id": bad_time_id},
            {"request_id": "gone", "flow_id": 999999},
            {"request_id": "udp", "flow_id": udp_ok},
        ])
        by_id = {r["request_id"]: r for r in report["requests"]}
        self.assertEqual(by_id["ok"]["outcome"], "associated")
        self.assertEqual(by_id["udp"]["outcome"], "associated")
        self.assertEqual(by_id["unbound"]["reason"], "no_observation_realm")
        self.assertEqual(by_id["icmp"]["reason"], "protocol_not_tcp_udp")
        self.assertEqual(by_id["time"]["reason"], "bad_time_range")
        self.assertEqual(by_id["gone"]["reason"], "flow_not_found")
        self.assertEqual(report["summary"]["invalid_flow_count"], 4)
        self.assertEqual(report["summary"]["associated_count"], 2)
        self.assertTrue(report["complete"])
        self.assertEqual(report["summary"]["status"], "complete")

    # ---------------------------------------------------------------- 10
    def test_reference_enumeration_matches_on_random_cases(self):
        import random
        rng = random.Random(20261116)
        cfg = {"realms": ["H", "M", "W"], "links": [["H", "M"], ["M", "W"]],
               "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        for trial in range(6):
            sc = self.scene(cfg)
            Z = [6, "198.51.100.20", 80, "203.0.113.20", 5000 + trial]
            start, end = 0, 12
            flow_id = sc.ingest_flow(Z, start, end)
            logs = []
            n = 0
            mid = []
            for i in range(rng.randint(1, 3)):
                before = [6, f"10.7.{trial}.{i + 1}", 1000 + i,
                          "198.51.100.20", 80]
                s = rng.randint(0, 8)
                e = rng.randint(max(s + 1, 6), 12)
                mid.append((before, s, e))
            for before, s, e in mid:
                n += 1
                logs.append(edge(f"H{n}", "H", "M", before,
                                 [6, "10.7.99.1", 80, "198.51.100.20", 80],
                                 s, e))
            # 最多两个 M 侧前驱；有的只给日志不给首跳，制造 frontier
            for j in range(rng.randint(1, 2)):
                s = rng.randint(0, 8)
                e = rng.randint(max(s + 1, 8), 12)
                n += 1
                if j == 0:
                    logs.append(edge(f"W{n}", "M", "W",
                                     [6, "10.7.99.1", 80,
                                      "198.51.100.20", 80], Z, s, e))
                else:
                    logs.append(edge(f"W{n}", "M", "W",
                                     [6, f"10.7.98.{trial}", 80,
                                      "198.51.100.20", 80], Z, s, e))
            path = sc.write_logs("logs.jsonl", logs)
            report = sc.run([path], [{"request_id": "r", "flow_id": flow_id}])
            actual = fragments_as_tuples(
                report["requests"][0]["fragments"])
            expected = reference_fragments(logs, cfg, "W", tuple(Z),
                                           start, end)
            expected_simple = [
                (lo, hi, status,
                 [(realm, tuple(five)) for realm, five in sorted(origins)],
                 [(realm, tuple(five)) for realm, five in sorted(frontiers)])
                for lo, hi, status, origins, frontiers in expected]
            got_simple = [(a[0], a[1], a[2], a[3], a[4]) for a in actual]
            # 参考器按来源集合排序；正式实现按 (realm, ip, port) 排序，
            # 这里把两边都归一化为排序后的集合比较
            norm = lambda rows: sorted((r[0], r[1]) for r in rows)
            self.assertEqual(
                [(lo, hi, st, norm(o), norm(f)) for lo, hi, st, o, f in got_simple],
                [(lo, hi, st, norm(o), norm(f))
                 for lo, hi, st, o, f in expected_simple],
                f"trial {trial} 与独立枚举参考器不一致")

    # ---------------------------------------------------------------- 11
    def test_shuffling_log_order_keeps_semantics_but_moves_line_numbers(self):
        cfg = {"realms": ["H", "M", "W"], "links": [["H", "M"], ["M", "W"]],
               "origins": ["H"],
               "observations": [{"exporter": EXP, "transport_session": SESS,
                                 "observation_domain_id": OBS, "realm": "W"}]}
        sc = self.scene(cfg)
        A = [6, "10.8.0.1", 1111, "198.51.100.30", 80]
        X = [6, "10.8.9.1", 2222, "198.51.100.30", 80]
        Z = [6, "198.51.100.30", 80, "203.0.113.30", 6000]
        flow_id = sc.ingest_flow(Z, 0, 10)
        rows = [edge("A-M", "H", "M", A, X, 0, 10),
                edge("X-W", "M", "W", X, Z, 4, 10)]
        p1 = sc.write_logs("one.jsonl", rows)
        r1 = sc.run([p1], [{"request_id": "r", "flow_id": flow_id}])
        p2 = sc.write_logs("two.jsonl", list(reversed(rows)))
        r2 = sc.run([p2], [{"request_id": "r", "flow_id": flow_id}])
        f1 = r1["requests"][0]["fragments"]
        f2 = r2["requests"][0]["fragments"]
        self.assertEqual(fragments_as_tuples(f1), fragments_as_tuples(f2))
        # 物理行号跟随新原件
        lines1 = {e["mapping_id"]: (os.path.basename(e["log_file"]),
                                    e["log_line"])
                  for f in f1 for e in f["graph"]["edges"]}
        lines2 = {e["mapping_id"]: (os.path.basename(e["log_file"]),
                                    e["log_line"])
                  for f in f2 for e in f["graph"]["edges"]}
        self.assertEqual(lines1["X-W"], ("one.jsonl", 2))
        self.assertEqual(lines2["X-W"], ("two.jsonl", 1))
        self.assertEqual(lines1["A-M"], ("one.jsonl", 1))
        self.assertEqual(lines2["A-M"], ("two.jsonl", 2))


if __name__ == "__main__":
    unittest.main()
