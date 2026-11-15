"""验收主链：按需求逐场景给明确预期，而非只统计通过数。

会话甲/域 A、域 B、会话乙之间的模板键隔离；首份定义接走、版本绑定不回溯、
撤销屏障、坏尾部原子失败、会话隔离、首份模板坏字段隔离。
所有预期值均为手工字面量；wire 构造器仅用于造输入报文。
"""

import unittest

from tests._helpers import (CaptureDir, db_path, LAYOUT_A, LAYOUT_B,
                            make_data_msg, make_template_msg)
from ipfix_offline import wire
from ipfix_offline.ingestor import Ingestor

ALICE = "exporter-alice"
BOB = "exporter-bob"
SESS_A = "session-alpha"
SESS_B = "session-beta"
DOMAIN_A = 11
DOMAIN_B = 22


def layout_a_record(u32: int, ipv4: bytes) -> bytes:
    return u32.to_bytes(4, "big") + ipv4


def layout_b_record(u64: int, six_bytes: bytes) -> bytes:
    assert len(six_bytes) == 6
    return u64.to_bytes(8, "big") + six_bytes


class AcceptanceChainTests(unittest.TestCase):
    def setUp(self):
        self.cdir = CaptureDir()
        self.files = []

    def tearDown(self):
        self.cdir.cleanup()

    def _ingest(self, ing: Ingestor, pos: int, exporter: str, session: str,
                blob: bytes):
        path = self.cdir.write_msg(blob)
        return ing.import_manifest(
            [self.cdir.entry(pos, exporter, session, path)])[0]

    def test_full_acceptance_chain(self):
        # K=3（到期位置=origin+3），容量给足，先排除容量干扰
        with Ingestor(db_path(self.cdir), max_waiting_bytes=100_000,
                      max_waiting_messages_k=3) as ing:
            # pos0：甲/A，模板300 的未知数据先到 -> 等待，甲/A 保持 unresolved
            r0 = self._ingest(
                ing, 0, ALICE, SESS_A,
                make_data_msg(DOMAIN_A, 300,
                              [layout_a_record(7, bytes([10, 0, 0, 1]))]))
            self.assertEqual(r0.status, "imported")
            self.assertEqual(r0.sets_enqueued, 1)
            self.assertEqual(ing.flows(), [])
            pend = ing.pending()
            self.assertEqual(pend.unresolved_count, 1)
            self.assertEqual(pend.unresolved_bytes, 4 + 8)  # 集合头4 + 正文8
            self.assertEqual(ing.waiting_bytes(), 12)

            # pos1：甲/B 发布同号 300 但不同布局（域不同 -> 不同模板键）
            r1 = self._ingest(
                ing, 1, ALICE, SESS_A,
                make_template_msg(DOMAIN_B, [
                    wire.template_record(300, LAYOUT_B)]))
            self.assertEqual(r1.status, "imported")
            # 甲/A 仍等待，没有任何流被错误解码
            self.assertEqual(ing.pending().unresolved_count, 1)
            self.assertEqual(ing.flows(), [])
            b_versions = ing.conn.execute(
                "SELECT version_seq FROM template_versions"
                " WHERE observation_domain_id=? AND template_id=300",
                (DOMAIN_B,)).fetchall()
            self.assertEqual([r["version_seq"] for r in b_versions], [1])

            # pos2：甲/A 在到期位置（2-0=2 < K=3，尚未到期）发布可解码模板 A
            r2 = self._ingest(
                ing, 2, ALICE, SESS_A,
                make_template_msg(DOMAIN_A, [
                    wire.template_record(300, LAYOUT_A)]))
            self.assertEqual(r2.sets_picked, 1)
            flows = ing.flows()
            self.assertEqual(len(flows), 1)
            f0 = flows[0]
            # 旧集合被“首份定义”接走，绑定版本2，来源标记 pending + 原位置0
            self.assertEqual(f0["version_seq"], 2)
            self.assertEqual(f0["origin"], "pending")
            self.assertEqual(f0["origin_pos"], 0)
            self.assertEqual(f0["capture_pos"], 0)
            self.assertEqual(f0["template_defined_pos"], 2)
            self.assertEqual([x["value"] for x in f0["fields"]],
                             [7, "10.0.0.1"])
            self.assertEqual(ing.pending().unresolved_count, 0)

            # pos3：同键再发一批数据，即时解码，仍绑定版本2
            r3 = self._ingest(
                ing, 3, ALICE, SESS_A,
                make_data_msg(DOMAIN_A, 300,
                              [layout_a_record(80, bytes([192, 168, 1, 2]))]))
            f1 = ing.flows()[1]
            self.assertEqual(f1["version_seq"], 2)
            self.assertEqual(f1["origin"], "immediate")
            self.assertEqual([x["value"] for x in f1["fields"]],
                             [80, "192.168.1.2"])

            # pos4：更新 300 定义为新布局 B（新版本，改版不回溯已绑定的旧流）
            self._ingest(
                ing, 4, ALICE, SESS_A,
                make_template_msg(DOMAIN_A, [
                    wire.template_record(300, LAYOUT_B)]))
            v_after_redef = ing.conn.execute(
                "SELECT MAX(version_seq) FROM template_versions"
                " WHERE observation_domain_id=? AND template_id=300",
                (DOMAIN_A,)).fetchone()[0]
            self.assertEqual(v_after_redef, 3)
            # 前后两批保留不同版本：旧两流仍是版本2
            self.assertEqual([f["version_seq"] for f in ing.flows()], [2, 2])

            # pos5：新布局 B 的数据即时解码 -> 绑定版本3
            r5 = self._ingest(
                ing, 5, ALICE, SESS_A,
                make_data_msg(DOMAIN_A, 300,
                              [layout_b_record(999, b"ABCDEF")]))
            f2 = ing.flows()[2]
            self.assertEqual(f2["version_seq"], 3)
            # 元素99 非语义子集 -> 原字节
            self.assertEqual(f2["fields"][1]["value_type"], "bytes")
            self.assertEqual(f2["fields"][1]["value"], b"ABCDEF")
            self.assertEqual(f2["fields"][0]["value"], 999)

            # pos6：合法撤销 300（field_count=0），切断后续等待资格
            self._ingest(
                ing, 6, ALICE, SESS_A,
                make_template_msg(DOMAIN_A, [wire.withdrawal_record(300)]))
            withdrawn = ing.conn.execute(
                "SELECT withdrawn_pos FROM template_versions"
                " WHERE version_seq=3").fetchone()[0]
            self.assertEqual(withdrawn, 6)

            # pos7：撤销后未知数据 -> 重新等待（不受旧版本影响）
            r7 = self._ingest(
                ing, 7, ALICE, SESS_A,
                make_data_msg(DOMAIN_A, 300,
                              [layout_a_record(500, bytes([1, 1, 1, 1]))]))
            self.assertEqual(r7.sets_enqueued, 1)
            self.assertEqual(ing.pending().unresolved_count, 1)

            # pos8：一条含合法撤销 + 坏尾部的消息必须整体失败，
            # 不改变已接受状态（pos7 仍等待，版本3 仍只在 pos6 撤销一次）
            good_withdraw = wire.template_set([wire.withdrawal_record(300)])
            bad_tail = b"\x00\x00"  # 残缺集合头
            broken = wire.message(1, 1, DOMAIN_A, [good_withdraw, bad_tail])
            r8 = self._ingest(ing, 8, ALICE, SESS_A, broken)
            self.assertEqual(r8.status, "failed")
            self.assertTrue(r8.error_code in
                            ("set_declared_out_of_bounds", "padding_or_trailing_bytes"))
            self.assertEqual(ing.pending().unresolved_count, 1)  # 没被清
            # 没有新增撤销行/新版本
            self.assertEqual(ing.conn.execute(
                "SELECT COUNT(*) FROM template_versions"
                " WHERE defined_pos=8").fetchone()[0], 0)

            # pos9：新定义（版本4）只接走屏障后的 pos7，pos6 之前的无等待
            r9 = self._ingest(
                ing, 9, ALICE, SESS_A,
                make_template_msg(DOMAIN_A, [
                    wire.template_record(300, LAYOUT_A)]))
            self.assertEqual(r9.sets_picked, 1)
            f3 = [f for f in ing.flows() if f["origin_pos"] == 7][0]
            self.assertEqual(f3["version_seq"], 4)
            self.assertEqual([x["value"] for x in f3["fields"]],
                             [500, "1.1.1.1"])

            # pos10：会话乙复用域 A 和 300，不能借甲的定义 -> 未知即等待
            r10 = self._ingest(
                ing, 10, ALICE, SESS_B,
                make_data_msg(DOMAIN_A, 300,
                              [layout_a_record(777, bytes([8, 8, 8, 8]))]))
            self.assertEqual(r10.sets_enqueued, 1)
            summary = ing.pending()
            self.assertEqual(summary.unresolved_count, 1)
            self.assertEqual(summary.unresolved_bytes, 12)
            # 乙随后发布自己的定义，接走自己那份（版本序列继续递增但键独立）
            r11 = self._ingest(
                ing, 11, ALICE, SESS_B,
                make_template_msg(DOMAIN_A, [
                    wire.template_record(300, LAYOUT_A)]))
            self.assertEqual(r11.sets_picked, 1)
            f4 = [f for f in ing.flows()
                  if f["transport_session"] == SESS_B][0]
            self.assertEqual([x["value"] for x in f4["fields"]],
                             [777, "8.8.8.8"])
            self.assertEqual(f4["origin"], "pending")

    def test_bad_first_template_isolates_waiting_set(self):
        """等待数据不适合首份模板 -> 隔离，不等第二个模板碰运气。"""
        with Ingestor(db_path(self.cdir, "iso.db"), max_waiting_bytes=100_000,
                      max_waiting_messages_k=10) as ing:
            # pos0：按布局 A 的 8 字节记录入队等待 300
            self._ingest(
                ing, 0, ALICE, SESS_A,
                make_data_msg(DOMAIN_A, 300,
                              [layout_a_record(7, bytes([10, 0, 0, 1]))]))
            # pos1：首份定义却是布局 B（8+6=14 字节/记录），旧集合解不开
            self._ingest(
                ing, 1, ALICE, SESS_A,
                make_template_msg(DOMAIN_A, [
                    wire.template_record(300, LAYOUT_B)]))
            summary = ing.pending()
            self.assertEqual(summary.unresolved_count, 0)
            self.assertEqual(len(summary.ended), 1)
            self.assertEqual(summary.ended[0]["end_reason"],
                             "bad_field_isolated")
            self.assertEqual(summary.ended[0]["bound_version_seq"], 1)
            # 新定义保留且有效
            self.assertIsNotNone(ing._active_version(
                (ALICE, SESS_A, DOMAIN_A, 300)))
            # pos2：再来一份恰好匹配布局 B 的数据，证明没有等“第二份模板”
            r2 = self._ingest(
                ing, 2, ALICE, SESS_A,
                make_data_msg(DOMAIN_A, 300,
                              [layout_b_record(5, b"ZZ9999"[:6])]))
            self.assertEqual(r2.flows_inserted, 1)
            # 被隔离的旧集合永远不会复活
            self.assertEqual(
                [f["origin_pos"] for f in ing.flows()], [2])
            # 第二份定义（版本2，改回 A）也不能把它捡回来
            self._ingest(
                ing, 3, ALICE, SESS_A,
                make_template_msg(DOMAIN_A, [
                    wire.template_record(300, LAYOUT_A)]))
            self.assertEqual(
                [f["origin_pos"] for f in ing.flows()], [2])


if __name__ == "__main__":
    unittest.main()
