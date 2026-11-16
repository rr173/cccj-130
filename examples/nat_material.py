#!/usr/bin/env python3
"""生成可重演的离线 NAT 关联材料目录。

用法：python3 -I examples/nat_material.py [输出目录]

输出目录内容：

  topology.json        观测域拓扑配置（H/N 原始域 -> M -> W 观察域）
  logs/alpha.jsonl     转换日志 A（顺序刻意打乱）
  logs/beta.jsonl      转换日志 B（不同 mapping_id，独立证据）
  capture/*.ipfix      合成 IPFIX 消息（模板 + 数据）
  store.db             经现有 import 真正入仓的流库
  requests.jsonl       请求（含 invalid_flow 用例）
  expected.json        手写的每段预期（状态/来源/frontier/边）
  report.json          本次运行输出
  rebuild.py           仅用 capture/ 重建 store.db
  run.sh               从临时目录重演：重建库 + 重新运行关联

场景：主例两链汇合 + 断支路 + 端口复用 + 目的地址改写、观察点即原始域、
异域同五元组、8 字节时间超过 2^53、企业同号字段冒充标准 IE、非 TCP/UDP、
起止非法、流不存在。

脚本最后把实际结果与手写预期逐项比对；不一致即非零退出。
"""

import json
import os
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipfix_offline import wire                              # noqa: E402
from ipfix_offline.ingestor import CaptureEntry, Ingestor   # noqa: E402
from ipfix_offline.nat_correlate import run_job             # noqa: E402

OBS = 8001
OBS_N = OBS + 1          # 第二个观测域，绑定到原始域 N
EXP = "exporter-lab"
SESS = "session-lab"

LAYOUT = [
    wire.field_spec(4, 1),
    wire.field_spec(8, 4),
    wire.field_spec(7, 2),
    wire.field_spec(12, 4),
    wire.field_spec(11, 2),
    wire.field_spec(152, 8),
    wire.field_spec(153, 8),
]
LAYOUT_ENT_152 = [
    wire.field_spec(4, 1),
    wire.field_spec(8, 4),
    wire.field_spec(7, 2),
    wire.field_spec(12, 4),
    wire.field_spec(11, 2),
    wire.field_spec(152, 8, enterprise_number=999),  # 企业号 999 的同号字段
    wire.field_spec(153, 8),
    wire.field_spec(99, 8),
]


def body(five, start, end):
    proto, sip, sport, dip, dport = five
    return (bytes([proto]) + socket.inet_aton(sip) + sport.to_bytes(2, "big")
            + socket.inet_aton(dip) + dport.to_bytes(2, "big")
            + start.to_bytes(8, "big") + end.to_bytes(8, "big"))


def edge(mapping_id, from_realm, to_realm, before, after, start, end):
    return {"mapping_id": mapping_id, "from_realm": from_realm,
            "to_realm": to_realm, "before": before, "after": after,
            "start_ms": start, "end_ms": end}


TOPOLOGY = {
    "realms": ["H", "N", "M", "W"],
    "links": [["H", "M"], ["M", "W"], ["N", "W"]],
    "origins": ["H", "N"],
    "observations": [
        {"exporter": EXP, "transport_session": SESS,
         "observation_domain_id": OBS, "realm": "W"},
        {"exporter": EXP, "transport_session": SESS,
         "observation_domain_id": OBS_N, "realm": "N"},
    ],
}

# --- 主例：Z1 观察流覆盖 [0,20) ---------------------------------------------
Z1 = [6, "203.0.113.30", 443, "198.51.100.30", 51515]
S1_A1 = [6, "10.0.0.1", 1000, "203.0.113.30", 443]
S1_X1 = [6, "10.0.10.1", 2000, "203.0.113.30", 443]
S1_A2 = [6, "10.0.0.2", 3000, "203.0.113.30", 443]
S1_X2 = [6, "10.0.10.2", 4000, "203.0.113.30", 443]
S1_BREAK = [6, "10.0.10.9", 9000, "203.0.113.30", 443]
S1_A3 = [6, "10.0.0.3", 5000, "203.0.113.50", 80]     # 目的地址也改写
S1_X3 = [6, "10.0.10.3", 6000, "203.0.113.50", 80]

# --- 观察点即原始域：N 域观察，无需日志 -------------------------------------
Z2 = [17, "203.0.113.31", 53, "198.51.100.31", 40000]

# --- 异域同五元组：SHARED 同时出现在 M 与 N 域 ------------------------------
SHARED = [6, "10.0.20.5", 7000, "203.0.113.32", 443]
Z3 = [6, "203.0.113.32", 443, "198.51.100.32", 60000]
S3_A = [6, "10.0.0.9", 9000, "203.0.113.32", 443]

# --- 八字节时间超过 2^53 ----------------------------------------------------
BASE = (1 << 53) + 123_456_789_012
Z4 = [6, "203.0.113.33", 8080, "198.51.100.33", 9000]
S4_A = [6, "10.0.0.11", 1100, "203.0.113.33", 8080]
S4_X = [6, "10.0.30.1", 2200, "203.0.113.33", 8080]

LOGS = [
    # 顺序刻意打乱，且分属两份不同 ID 的日志
    edge("s1-X1", "M", "W", S1_X1, Z1, 4, 10),
    edge("s1-A2", "H", "M", S1_A2, S1_X2, 5, 10),
    edge("s1-A1", "H", "M", S1_A1, S1_X1, 0, 8),
    edge("s1-X2", "M", "W", S1_X2, Z1, 0, 7),
    edge("s1-BRK", "M", "W", S1_BREAK, Z1, 0, 10),
    edge("s1-A3", "H", "M", S1_A3, S1_X3, 10, 20),
    edge("s1-X3", "M", "W", S1_X3, Z1, 10, 20),
    edge("s3-N", "N", "W", SHARED, Z3, 0, 10),
    edge("s3-M", "M", "W", SHARED, Z3, 0, 10),
    edge("s3-A", "H", "M", S3_A, SHARED, 0, 10),
    # H 域里以 SHARED 结尾的日志：不能被 N 观察点借用
    edge("s3-H2", "H", "M", SHARED, [6, "10.0.20.6", 7100,
                                     "203.0.113.32", 443], 0, 10),
    edge("s4-X", "M", "W", S4_X, Z4, BASE + 4, BASE + 10),
    edge("s4-A", "H", "M", S4_A, S4_X, BASE, BASE + 10),
]

# --- 手写预期 ---------------------------------------------------------------
EXPECTED = {
    "z1": [
        {"start_ms": 0, "end_ms": 4, "status": "incomplete", "origins": [],
         "frontiers": [["M", S1_X2], ["M", S1_BREAK]],
         "edges": ["s1-BRK", "s1-X2"]},
        {"start_ms": 4, "end_ms": 5, "status": "incomplete",
         "origins": [["H", S1_A1]],
         "frontiers": [["M", S1_X2], ["M", S1_BREAK]],
         "edges": ["s1-A1", "s1-BRK", "s1-X1", "s1-X2"]},
        {"start_ms": 5, "end_ms": 7, "status": "incomplete",
         "origins": [["H", S1_A1], ["H", S1_A2]],
         "frontiers": [["M", S1_BREAK]],
         "edges": ["s1-A1", "s1-A2", "s1-BRK", "s1-X1", "s1-X2"]},
        {"start_ms": 7, "end_ms": 8, "status": "incomplete",
         "origins": [["H", S1_A1]], "frontiers": [["M", S1_BREAK]],
         "edges": ["s1-A1", "s1-BRK", "s1-X1"]},
        {"start_ms": 8, "end_ms": 10, "status": "incomplete", "origins": [],
         "frontiers": [["M", S1_X1], ["M", S1_BREAK]],
         "edges": ["s1-BRK", "s1-X1"]},
        {"start_ms": 10, "end_ms": 20, "status": "unique",
         "origins": [["H", S1_A3]], "frontiers": [],
         "edges": ["s1-A3", "s1-X3"]},
    ],
    "z2": [
        {"start_ms": 0, "end_ms": 10, "status": "unique",
         "origins": [["N", Z2]], "frontiers": [], "edges": []},
    ],
    "z3": [
        {"start_ms": 0, "end_ms": 10, "status": "ambiguous",
         "origins": [["H", S3_A], ["N", SHARED]], "frontiers": [],
         "edges": ["s3-A", "s3-M", "s3-N"]},
        {"start_ms": 10, "end_ms": 20, "status": "unmapped", "origins": [],
         "frontiers": [["W", Z3]], "edges": []},
    ],
    "z4": [
        {"start_ms": BASE, "end_ms": BASE + 4, "status": "unmapped",
         "origins": [], "frontiers": [["W", Z4]], "edges": []},
        {"start_ms": BASE + 4, "end_ms": BASE + 10, "status": "unique",
         "origins": [["H", S4_A]], "frontiers": [],
         "edges": ["s4-A", "s4-X"]},
        {"start_ms": BASE + 10, "end_ms": BASE + 20, "status": "unmapped",
         "origins": [], "frontiers": [["W", Z4]], "edges": []},
    ],
}
INVALID = {
    "ent": "enterprise_ie_cannot_substitute",
    "icmp": "protocol_not_tcp_udp",
    "badtime": "bad_time_range",
    "missing": "flow_not_found",
}


def compare(actual_fragments, expected_fragments):
    got = [(f["start_ms"], f["end_ms"], f["status"],
            [[o["realm"], list(o["five_tuple"])] for o in f["origins"]],
            [[o["realm"], list(o["five_tuple"])] for o in f["frontiers"]],
            [e["mapping_id"] for e in f["graph"]["edges"]])
           for f in actual_fragments]
    want = [(f["start_ms"], f["end_ms"], f["status"], f["origins"],
             f["frontiers"], f["edges"]) for f in expected_fragments]
    return got == want, got, want


def write_rebuild_script(out_dir, manifest):
    lines = [
        '#!/usr/bin/env python3',
        '"""仅用 capture/ 重建 store.db（重演材料）。用法：rebuild.py REPO"""',
        'import json, os, sys',
        'HERE = os.path.dirname(os.path.abspath(__file__))',
        'sys.path.insert(0, sys.argv[1])',
        'from ipfix_offline.ingestor import CaptureEntry, Ingestor',
        'MANIFEST = json.loads(%r)' % json.dumps(manifest),
        'DB = os.path.join(HERE, "store.db")',
        'if os.path.exists(DB): os.unlink(DB)',
        'with Ingestor(DB, max_waiting_bytes=1_000_000,',
        '              max_waiting_messages_k=10) as ing:',
        '    ing.import_manifest([CaptureEntry(*row) for row in MANIFEST])',
        '    print("rebuilt", DB, "flows", len(ing.flows()))',
        '',
    ]
    path = os.path.join(out_dir, "rebuild.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    os.chmod(path, 0o755)
    return path


def main():
    out_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                              tempfile.mkdtemp(prefix="nat_material_"))
    os.makedirs(out_dir, exist_ok=True)
    cap_dir = os.path.join(out_dir, "capture")
    logs_dir = os.path.join(out_dir, "logs")
    os.makedirs(cap_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)
    db = os.path.join(out_dir, "store.db")
    if os.path.exists(db):
        os.unlink(db)

    with open(os.path.join(out_dir, "topology.json"), "w",
              encoding="utf-8") as fh:
        json.dump(TOPOLOGY, fh, ensure_ascii=False, indent=2)

    # --- 入仓 ------------------------------------------------------------
    manifest = []
    pos = 0

    def feed(blob, name, exporter=EXP, session=SESS):
        nonlocal pos
        path = os.path.join(cap_dir, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        ing.import_manifest([CaptureEntry(pos, exporter, session, path)])
        manifest.append([pos, exporter, session, path])
        pos += 1

    with Ingestor(db, max_waiting_bytes=1_000_000,
                  max_waiting_messages_k=10) as ing:
        feed(wire.message(1, 0, OBS, [wire.template_set(
            [wire.template_record(300, LAYOUT)])]), "tpl300.ipfix")
        feed(wire.message(1, 1, OBS_N, [wire.template_set(
            [wire.template_record(400, LAYOUT)])]), "tpl400.ipfix")
        feed(wire.message(1, 2, OBS, [wire.template_set(
            [wire.template_record(500, LAYOUT_ENT_152)])]), "tpl500.ipfix")
        for i, (z, lo, hi) in enumerate([(Z1, 0, 20), (Z3, 0, 20),
                                         (Z4, BASE, BASE + 20)]):
            feed(wire.message(1, 10 + i, OBS,
                              [wire.data_set(300, [body(z, lo, hi)])]),
                 f"flow_{i}.ipfix")
        feed(wire.message(1, 20, OBS_N,
                          [wire.data_set(400, [body(Z2, 0, 10)])]),
             "flow_origin_obs.ipfix")
        ent_body = (bytes([6]) + socket.inet_aton("203.0.113.40")
                    + (80).to_bytes(2, "big")
                    + socket.inet_aton("198.51.100.40")
                    + (9000).to_bytes(2, "big")
                    + (0).to_bytes(8, "big") + (10).to_bytes(8, "big")
                    + b"ABCDEFGH")
        feed(wire.message(1, 21, OBS,
                          [wire.data_set(500, [ent_body])]),
             "flow_enterprise_ie.ipfix")
        feed(wire.message(1, 22, OBS, [wire.data_set(300, [
            body([1, "203.0.113.41", 80, "198.51.100.41", 1], 0, 10)])]),
             "flow_icmp.ipfix")
        feed(wire.message(1, 23, OBS, [wire.data_set(300, [
            body([6, "203.0.113.42", 80, "198.51.100.42", 1], 5, 5)])]),
             "flow_bad_time.ipfix")
        flows = ing.flows()
        flow_ids = {
            "z1": flows[0]["flow_id"], "z3": flows[1]["flow_id"],
            "z4": flows[2]["flow_id"], "z2": flows[3]["flow_id"],
            "ent": flows[4]["flow_id"], "icmp": flows[5]["flow_id"],
            "badtime": flows[6]["flow_id"],
        }

    # --- 日志：两份文件，顺序打乱 ---------------------------------------
    half = len(LOGS) // 2
    with open(os.path.join(logs_dir, "alpha.jsonl"), "w",
              encoding="utf-8") as fh:
        for row in LOGS[half:]:
            fh.write(json.dumps(row) + "\n")
    with open(os.path.join(logs_dir, "beta.jsonl"), "w",
              encoding="utf-8") as fh:
        for row in LOGS[:half]:
            fh.write(json.dumps(row) + "\n")
    log_paths = [os.path.join(logs_dir, "alpha.jsonl"),
                 os.path.join(logs_dir, "beta.jsonl")]

    # --- 请求 ------------------------------------------------------------
    req_path = os.path.join(out_dir, "requests.jsonl")
    with open(req_path, "w", encoding="utf-8") as fh:
        for key in ("z1", "z3", "z4", "z2", "ent", "icmp", "badtime",
                    "missing"):
            fh.write(json.dumps({"request_id": key,
                                 "flow_id": flow_ids.get(key, 999999)})
                     + "\n")

    # --- 运行 ------------------------------------------------------------
    report = run_job(db, os.path.join(out_dir, "topology.json"), log_paths,
                     req_path, os.path.join(out_dir, "report.json"), out_dir)
    by_id = {r["request_id"]: r for r in report["requests"]}
    failures = []
    for key, expected in EXPECTED.items():
        item = by_id[key]
        if item["outcome"] != "associated":
            failures.append(f"{key}: 期望 associated，实际 {item['outcome']}")
            continue
        ok, got, want = compare(item["fragments"], expected)
        if not ok:
            failures.append(f"{key}: 片段不符\n  实际={got!r}\n  预期={want!r}")
    for key, reason in INVALID.items():
        item = by_id[key]
        if item["outcome"] != "invalid_flow" or item["reason"] != reason:
            failures.append(f"{key}: 期望 invalid_flow/{reason}，"
                            f"实际 {item['outcome']}/{item.get('reason')}")

    # --- 打印 ------------------------------------------------------------
    for key in ("z1", "z2", "z3", "z4", "ent", "icmp", "badtime", "missing"):
        item = by_id[key]
        if item["outcome"] == "invalid_flow":
            print(f"{key}: invalid_flow ({item['reason']})")
            continue
        print(f"{key}: {len(item['fragments'])} 片段")
        for fragment in item["fragments"]:
            origins = ", ".join(
                f"{o['realm']}:{o['five_tuple'][1]}:{o['five_tuple'][2]}"
                for o in fragment["origins"]) or "-"
            frontiers = ", ".join(
                f"{f['realm']}:{f['five_tuple'][1]}:{f['five_tuple'][2]}"
                for f in fragment["frontiers"]) or "-"
            ids = ",".join(e["mapping_id"]
                           for e in fragment["graph"]["edges"]) or "-"
            print(f"  [{fragment['start_ms']},{fragment['end_ms']}) "
                  f"{fragment['status']}: origins={origins} "
                  f"frontiers={frontiers} edges={ids}")

    with open(os.path.join(out_dir, "expected.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"fragments": EXPECTED, "invalid_flow": INVALID},
                  fh, ensure_ascii=False, indent=2)

    write_rebuild_script(out_dir, manifest)
    run_sh = os.path.join(out_dir, "run.sh")
    with open(run_sh, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nset -eu\n")
        fh.write("# 用法：sh run.sh /path/to/ipfix_offline/repo\n")
        fh.write('ROOT=${1:-%s}\n' %
                 os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        fh.write('HERE=$(cd "$(dirname "$0")" && pwd)\n')
        fh.write('python3 -I "$HERE/rebuild.py" "$ROOT"\n')
        # -I 不把当前目录加入 sys.path，因此直接用脚本路径运行（本模块无
        # 包内相对导入，可独立执行）
        fh.write('python3 -I "$ROOT/ipfix_offline/nat_correlate.py" '
                 '--db "$HERE/store.db" --config "$HERE/topology.json"')
        for path in log_paths:
            fh.write(f' --log "{path}"')
        fh.write(' --requests "$HERE/requests.jsonl" '
                 '--out "$HERE/report2.json" --work-dir "$HERE"\n')
    os.chmod(run_sh, 0o755)

    if failures:
        print("\n材料核对失败：")
        for failure in failures:
            print(" -", failure)
        return 1
    print(f"\n材料核对通过。目录：{out_dir}")
    print(f"报告：{os.path.join(out_dir, 'report.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
