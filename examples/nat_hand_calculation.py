#!/usr/bin/env python3
"""交接演示：错误关联是怎么被挡住的。

场景（需求正文中的例子）：H -> M -> W，H 为原始域，W 为观察域：

  A -> X  [0,8)     A 是内侧原始五元组（H），X 是 M 域五元组
  X -> Z  [4,10)
  B -> Y  [5,10)
  Y -> Z  [0,7)
  流 Z 在 W 覆盖 [0,10)

关键点：如果只看“每条日志都和整段流 [0,10) 有交集”，A->X 与 X->Z 会被串成
一条来源链，`B` 与 `Y` 也会被串起来，于是会得到 A/B 两个来源——但任何时刻都
不存在一条同时包含 A->X 与 X->Z 的链（两者只在 [4,8) 同时有效），也不会存在
“A 与 Y 同时有效”这样的路径。正确做法是**逐时刻求所有日志同时有效的链**。

脚本逐段打印“手算预期 vs 实际”，并给出每段的完整反向证据图（节点是
(realm, 五元组)，边标 mapping_id）。随后把 A->X 的终点从 8 改成 4，验证端点
相碰（[4,4) 为空）不算同时有效，A 在整条流上都不再出现。

运行：python3 -I examples/nat_hand_calculation.py
只读本地临时文件，不接网络；预期值全部手写为字面量。
"""

import json
import os
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipfix_offline import wire                      # noqa: E402
from ipfix_offline.ingestor import CaptureEntry, Ingestor  # noqa: E402
from ipfix_offline.nat_correlate import (           # noqa: E402
    NatCorrelator, load_requests)

OBS_DOMAIN = 707
EXPORTER = "exporter-border"
SESSION = "session-0701"

# 观察到的外侧连接 Z；流在 W 覆盖 [0, 10)
PROTO = 6
Z = [PROTO, "203.0.113.10", 443, "198.51.100.7", 51515]
FLOW_START, FLOW_END = 0, 10

# 手工给定的日志（顺序刻意打乱，且分属两份不同 ID 的日志文件）
A = [PROTO, "10.0.0.1", 1000, "203.0.113.10", 443]
X = [PROTO, "10.0.10.1", 2000, "203.0.113.10", 443]
B = [PROTO, "10.0.0.2", 3000, "203.0.113.10", 443]
Y = [PROTO, "10.0.10.2", 4000, "203.0.113.10", 443]

LOGS_BASE = [
    # mapping_id, from_realm, to_realm, before, after, start, end, 文件
    ("X-1", "M", "W", X, Z, 4, 10, "log_b.jsonl"),
    ("A-1", "H", "M", A, X, 0, 8, "log_a.jsonl"),
    ("Y-1", "M", "W", Y, Z, 0, 7, "log_b.jsonl"),
    ("B-1", "H", "M", B, Y, 5, 10, "log_a.jsonl"),
]

CONFIG = {
    "realms": ["H", "M", "W"],
    "links": [["H", "M"], ["M", "W"]],
    "origins": ["H"],
    "observations": [{
        "exporter": EXPORTER,
        "transport_session": SESSION,
        "observation_domain_id": OBS_DOMAIN,
        "realm": "W",
    }],
}

FLOW_LAYOUT = [
    wire.field_spec(4, 1),      # protocol
    wire.field_spec(8, 4),      # sourceIPv4Address
    wire.field_spec(7, 2),      # sourceTransportPort
    wire.field_spec(12, 4),     # destinationIPv4Address
    wire.field_spec(11, 2),     # destinationTransportPort
    wire.field_spec(152, 8),    # flowStartMilliseconds
    wire.field_spec(153, 8),    # flowEndMilliseconds
]


def flow_record(five, start, end):
    proto, sip, sport, dip, dport = five
    return (bytes([proto]) + socket.inet_aton(sip) + sport.to_bytes(2, "big")
            + socket.inet_aton(dip) + dport.to_bytes(2, "big")
            + start.to_bytes(8, "big") + end.to_bytes(8, "big"))


def short(state_obj):
    realm = state_obj["realm"]
    proto, sip, sport, dip, dport = state_obj["five_tuple"]
    return f"{realm}:{sip}:{sport}->{dip}:{dport}"


def render_graph(fragment):
    lines = []
    node_ids = {short(n): short(n) for n in fragment["graph"]["nodes"]}
    lines.append("      节点: " + ", ".join(node_ids.values()))
    for edge in fragment["graph"]["edges"]:
        lines.append(f"      {edge['mapping_id']}: {short(edge['from'])}"
                     f"  ==>  {short(edge['to'])}"
                     f"   (log {os.path.basename(edge['log_file'])}"
                     f":{edge['log_line']}, 有效 {edge['valid']})")
    if not fragment["graph"]["edges"]:
        lines.append("      (无边：观察状态没有可用前驱)")
    return lines


def expected_fragments(disjoint_end: bool):
    """手算预期。disjoint_end=True 时 A->X 的终点改为 4。"""
    if not disjoint_end:
        return [
            (0, 4, "incomplete", [], ["M:10.0.10.2:4000->203.0.113.10:443"],
             ["Y-1"]),
            (4, 5, "incomplete", ["H:10.0.0.1:1000->203.0.113.10:443"],
             ["M:10.0.10.2:4000->203.0.113.10:443"],
             ["A-1", "X-1", "Y-1"]),
            (5, 7, "ambiguous",
             ["H:10.0.0.1:1000->203.0.113.10:443",
              "H:10.0.0.2:3000->203.0.113.10:443"], [],
             ["A-1", "B-1", "X-1", "Y-1"]),
            (7, 8, "unique", ["H:10.0.0.1:1000->203.0.113.10:443"],
             [], ["A-1", "X-1"]),
            (8, 10, "incomplete", [],
             ["M:10.0.10.1:2000->203.0.113.10:443"], ["X-1"]),
        ]
    # A->X 只覆盖 [0,4)：A 在整条流上都不出现，其余分段被切开。
    # [7,10) 起 Y->Z 已失效，Z 只能回到 X，而 X 的前驱 A->X 也只在 [0,4) 有效，
    # 因此该段既无候选也只保留指向 X 的 frontier。
    return [
        (0, 4, "incomplete", [], ["M:10.0.10.2:4000->203.0.113.10:443"],
         ["Y-1"]),
        (4, 5, "incomplete", [], ["M:10.0.10.1:2000->203.0.113.10:443",
                                  "M:10.0.10.2:4000->203.0.113.10:443"],
         ["X-1", "Y-1"]),
        (5, 7, "incomplete", ["H:10.0.0.2:3000->203.0.113.10:443"],
         ["M:10.0.10.1:2000->203.0.113.10:443"], ["B-1", "X-1", "Y-1"]),
        (7, 10, "incomplete", [],
         ["M:10.0.10.1:2000->203.0.113.10:443"], ["X-1"]),
    ]


def actual_fragments(fragments):
    out = []
    for fragment in fragments:
        out.append((
            fragment["start_ms"],
            fragment["end_ms"],
            fragment["status"],
            [short(o) for o in fragment["origins"]],
            [short(f) for f in fragment["frontiers"]],
            [e["mapping_id"] for e in fragment["graph"]["edges"]],
        ))
    return out


def check(step, expected, actual):
    ok = expected == actual
    print(f"[{'PASS' if ok else 'FAIL'}] {step}")
    print(f"        预期={expected!r}")
    print(f"        实际={actual!r}")
    if not ok:
        raise SystemExit(f"交接演示失败：{step}")


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def run_case(tmp, label, log_rows, flow_start, flow_end, disjoint_end):
    case_dir = os.path.join(tmp, label)
    os.makedirs(case_dir)
    # 1) 用现有 import 真正入仓一条流
    db = os.path.join(case_dir, "store.db")
    tpl_path = os.path.join(case_dir, "m0.bin")
    with open(tpl_path, "wb") as fh:
        fh.write(wire.message(1000, 1, OBS_DOMAIN, [wire.template_set(
            [wire.template_record(300, FLOW_LAYOUT)])]))
    data_path = os.path.join(case_dir, "m1.bin")
    with open(data_path, "wb") as fh:
        fh.write(wire.message(1000, 2, OBS_DOMAIN, [wire.data_set(
            300, [flow_record(Z, flow_start, flow_end)])]))
    with Ingestor(db, max_waiting_bytes=100_000,
                  max_waiting_messages_k=10) as ing:
        ing.import_manifest([
            CaptureEntry(0, EXPORTER, SESSION, tpl_path),
            CaptureEntry(1, EXPORTER, SESSION, data_path),
        ])
        flow = ing.flows()[0]
        flow_id = flow["flow_id"]
        print(f"  入仓流 flow_id={flow_id}，模板版本={flow['version_seq']}，"
              f"来源={flow['origin']}")

    config_path = os.path.join(case_dir, "topology.json")
    with open(config_path, "w", encoding="utf-8") as fh:
        json.dump(CONFIG, fh, ensure_ascii=False)

    # 2) 两份不同 mapping_id 的日志文件；行内顺序刻意打乱
    files = {}
    for mapping_id, from_realm, to_realm, before, after, start, end, name in log_rows:
        files.setdefault(name, []).append({
            "mapping_id": mapping_id,
            "from_realm": from_realm,
            "to_realm": to_realm,
            "before": before,
            "after": after,
            "start_ms": start,
            "end_ms": end,
        })
    log_paths = []
    for name in sorted(files):
        path = os.path.join(case_dir, name)
        write_jsonl(path, files[name])
        log_paths.append(path)

    request_path = os.path.join(case_dir, "requests.jsonl")
    write_jsonl(request_path, [{"request_id": "r1", "flow_id": flow_id}])

    with NatCorrelator(db, config_path, log_paths, case_dir,
                       measure_memory=False) as nc:
        report = nc.correlate_requests(load_requests(request_path))
    return report["requests"][0]["fragments"]


def main():
    tmp = tempfile.mkdtemp(prefix="nat_hand_demo_")

    print("== 例 1) 原场景：H->M->W，四条日志，流 [0,10) ==")
    fragments = run_case(tmp, "case1", LOGS_BASE, FLOW_START, FLOW_END, False)
    for fragment in fragments:
        print(f"  片段 [{fragment['start_ms']},{fragment['end_ms']}) "
              f"状态={fragment['status']}")
        print("      来源: " + (", ".join(short(o) for o in fragment["origins"])
                                  or "（无）"))
        print("      frontier: " + (", ".join(short(f) for f in fragment["frontiers"])
                                    or "（无）"))
        for line in render_graph(fragment):
            print(line)
    check("逐段状态/来源/frontier/边",
          expected_fragments(False), actual_fragments(fragments))

    print("\n== 例 2) 把 A->X 终点改成 4：端点相碰不算同时有效 ==")
    disjoint = []
    for row in LOGS_BASE:
        mapping_id, from_realm, to_realm, before, after, start, end, name = row
        if mapping_id == "A-1":
            end = 4
        disjoint.append((mapping_id, from_realm, to_realm, before, after,
                         start, end, name))
    fragments2 = run_case(tmp, "case2", disjoint, FLOW_START, FLOW_END, True)
    for fragment in fragments2:
        print(f"  片段 [{fragment['start_ms']},{fragment['end_ms']}) "
              f"状态={fragment['status']}")
        print("      来源: " + (", ".join(short(o) for o in fragment["origins"])
                                  or "（无）"))
        print("      frontier: " + (", ".join(short(f) for f in fragment["frontiers"])
                                    or "（无）"))
        for line in render_graph(fragment):
            print(line)
    check("A 在整条流上都不出现",
          expected_fragments(True), actual_fragments(fragments2))
    all_sources = [short(o) for f in fragments2 for o in f["origins"]]
    check("全流不再有任何 A 来源", [], [s for s in all_sources if "10.0.0.1" in s])

    print("\n== 例 3) 日志顺序打乱、跨文件后，业务片段与图不变 ==")
    shuffled = [LOGS_BASE[3], LOGS_BASE[1], LOGS_BASE[0], LOGS_BASE[2]]
    fragments3 = run_case(tmp, "case3", shuffled, FLOW_START, FLOW_END, False)
    check("业务片段与 mapping_id 图不变",
          actual_fragments(fragments), actual_fragments(fragments3))

    print("\n全部交接演示通过。重演材料目录：", tmp)


if __name__ == "__main__":
    main()
