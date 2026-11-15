#!/usr/bin/env python3
"""验收主链：逐步打印“预期 vs 实际”，对应需求中的端到端场景。

运行：python3 -I examples/acceptance.py
仅离线处理本地临时文件，不接网络。所有预期为手工给定的字面量。
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipfix_offline import wire  # noqa: E402
from ipfix_offline.ingestor import Ingestor, CaptureEntry  # noqa: E402

ALICE, BOB = "exporter-alice", "exporter-bob"
SESS_A, SESS_B = "session-alpha", "session-beta"
DOM_A, DOM_B = 11, 22
K, CAPACITY = 3, 100_000

LAYOUT_A = [wire.field_spec(1, 4), wire.field_spec(8, 4)]
LAYOUT_B = [wire.field_spec(1, 8), wire.field_spec(99, 6)]


def check(step, expected, actual):
    ok = expected == actual
    print(f"[{'PASS' if ok else 'FAIL'}] {step}")
    print(f"        预期={expected!r}")
    print(f"        实际={actual!r}")
    if not ok:
        raise SystemExit(f"验收步骤失败：{step}")


def rec_a(u, ip):
    return u.to_bytes(4, "big") + bytes(ip)


def rec_b(u, b6):
    return u.to_bytes(8, "big") + bytes(b6)


def main():
    tmp = tempfile.mkdtemp(prefix="ipfix_accept_")
    pos = {"n": 0}
    db = os.path.join(tmp, "store.db")

    def feed(ing, exporter, session, blob):
        p = os.path.join(tmp, f"m_{pos['n']}.bin")
        with open(p, "wb") as fh:
            fh.write(blob)
        r = ing.import_manifest(
            [CaptureEntry(pos["n"], exporter, session, p)])[0]
        pos["n"] += 1
        return r

    with Ingestor(db, max_waiting_bytes=CAPACITY,
                  max_waiting_messages_k=K) as ing:
        print("== 1) 甲/A 模板300未知数据先到 ==")
        r = feed(ing, ALICE, SESS_A, wire.message(
            100, 1, DOM_A, [wire.data_set(300, [rec_a(7, (10, 0, 0, 1))])]))
        check("未知集合入等待", "imported", r.status)
        check("等待集合数", 1, ing.pending().unresolved_count)
        check("等待字节(头4+正文8)", 12, ing.waiting_bytes())

        print("\n== 2) 甲/B 发布同号300不同布局，甲/A 仍等待 ==")
        feed(ing, ALICE, SESS_A, wire.message(
            100, 2, DOM_B,
            [wire.template_set([wire.template_record(300, LAYOUT_B)])]))
        check("甲/A 仍 unresolved", 1, ing.pending().unresolved_count)
        check("尚未产生任何流", 0, len(ing.flows()))

        print("\n== 3) 甲/A 发布可解码模板，旧集合被首份定义接走 ==")
        feed(ing, ALICE, SESS_A, wire.message(
            100, 3, DOM_A,
            [wire.template_set([wire.template_record(300, LAYOUT_A)])]))
        flow0 = ing.flows()[0]
        check("接走后无 unresolved", 0, ing.pending().unresolved_count)
        check("绑定首份定义版本", 2, flow0["version_seq"])
        check("来源标记 pending/原位置0",
              ("pending", 0), (flow0["origin"], flow0["origin_pos"]))
        check("字段值", [7, "10.0.0.1"],
              [f["value"] for f in flow0["fields"]])

        print("\n== 4) 再发数据即时解码，仍绑版本2；随后更新300 ==")
        feed(ing, ALICE, SESS_A, wire.message(
            100, 4, DOM_A, [wire.data_set(300, [rec_a(80, (192, 168, 1, 2))])]))
        check("即时流版本", 2, ing.flows()[1]["version_seq"])
        feed(ing, ALICE, SESS_A, wire.message(
            100, 5, DOM_A,
            [wire.template_set([wire.template_record(300, LAYOUT_B)])]))
        feed(ing, ALICE, SESS_A, wire.message(
            100, 6, DOM_A, [wire.data_set(300, [rec_b(999, b"ABCDEF")])]))
        check("新版数据绑版本3", 3, ing.flows()[2]["version_seq"])
        check("旧两流保留版本2", [2, 2],
              [f["version_seq"] for f in ing.flows()[:2]])
        check("非语义元素按原字节", b"ABCDEF",
              ing.flows()[2]["fields"][1]["value"])

        print("\n== 5) 合法撤销切断等待资格；坏尾部消息不改变状态 ==")
        feed(ing, ALICE, SESS_A, wire.message(
            100, 7, DOM_A,
            [wire.template_set([wire.withdrawal_record(300)])]))
        feed(ing, ALICE, SESS_A, wire.message(
            100, 8, DOM_A, [wire.data_set(300, [rec_a(500, (1, 1, 1, 1))])]))
        check("撤销后新未知重新等待", 1, ing.pending().unresolved_count)
        broken = wire.message(
            100, 9, DOM_A,
            [wire.template_set([wire.withdrawal_record(300)]), b"\x00\x00"])
        r_bad = feed(ing, ALICE, SESS_A, broken)
        check("坏消息整体失败", "failed", r_bad.status)
        check("坏消息不清等待", 1, ing.pending().unresolved_count)

        print("\n== 6) 新定义只接走屏障后的等待 ==")
        feed(ing, ALICE, SESS_A, wire.message(
            100, 10, DOM_A,
            [wire.template_set([wire.template_record(300, LAYOUT_A)])]))
        new_flow = [f for f in ing.flows() if f["origin_pos"] == 7][0]
        check("屏障后集合绑新版本4", 4, new_flow["version_seq"])
        check("其值正确", [500, "1.1.1.1"],
              [f["value"] for f in new_flow["fields"]])

        print("\n== 7) 会话乙复用域A/300，不能借甲的定义 ==")
        r = feed(ing, ALICE, SESS_B, wire.message(
            100, 11, DOM_A, [wire.data_set(300, [rec_a(777, (8, 8, 8, 8))])]))
        check("乙的未知集合独立等待", 1, r.sets_enqueued)
        feed(ing, ALICE, SESS_B, wire.message(
            100, 12, DOM_A,
            [wire.template_set([wire.template_record(300, LAYOUT_A)])]))
        bob_flow = [f for f in ing.flows()
                    if f["transport_session"] == SESS_B][0]
        check("乙靠自己的定义接走", [777, "8.8.8.8"],
              [f["value"] for f in bob_flow["fields"]])

        print("\n== 8) 等待数据不适合首份模板 -> 隔离，不等第二份 ==")
        feed(ing, BOB, SESS_A, wire.message(
            100, 13, DOM_A, [wire.data_set(400, [rec_a(1, (1, 2, 3, 4))])]))
        # 首份定义为不兼容的 LAYOUT_B
        feed(ing, BOB, SESS_A, wire.message(
            100, 14, DOM_A,
            [wire.template_set([wire.template_record(400, LAYOUT_B)])]))
        ended = [e for e in ing.pending().ended
                 if e["exporter"] == BOB and e["template_id"] == 400]
        check("不匹配集合被隔离", "bad_field_isolated",
              ended[0]["end_reason"])
        # 第二份定义改回 LAYOUT_A，也不能捡回被隔离集合
        feed(ing, BOB, SESS_A, wire.message(
            100, 15, DOM_A,
            [wire.template_set([wire.template_record(400, LAYOUT_A)])]))
        check("隔离集合不复活", 0,
              len([f for f in ing.flows() if f["exporter"] == BOB]))

        print("\n== 9) explain 来源链（字段起止字节可回切原文件）==")
        ex = ing.explain(flow0["flow_id"])
        check("模板定义位置", 2, ex["template_defined_pos"])
        f0 = ex["fields"][0]
        check("字段0绝对字节范围", (20, 24), (f0["field_offset"], f0["field_end"]))

    print("\n全部验收步骤通过。数据库：", db)


if __name__ == "__main__":
    main()
