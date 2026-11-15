"""等待区容量与 K 到期测试：容量恰满、超一字节、只隔离新集合、
到期定义先接走、失败消息仍跑到期扫描、已结束集合不再取得资格。
预期字节数均手工计算。
"""

import struct
import unittest

from tests._helpers import CaptureDir, db_path, LAYOUT_A, make_data_msg
from ipfix_offline import wire
from ipfix_offline.ingestor import Ingestor

ALICE = "ex"
SESS = "s1"
DOM = 5


def rec_a(u32: int) -> bytes:
    return u32.to_bytes(4, "big") + bytes([10, 0, 0, 1])  # 8 字节正文


class CapacityAndTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.cdir = CaptureDir()

    def tearDown(self):
        self.cdir.cleanup()

    def _ing(self, ing, pos, blob):
        p = self.cdir.write_msg(blob)
        return ing.import_manifest(
            [self.cdir.entry(pos, ALICE, SESS, p)])[0]

    def test_exact_capacity_fits_one_byte_over_isolates(self):
        # 每个未知集合：集合头4 + 正文8 = 12 字节
        # 容量恰为 12：第一份入队成功；第二份需 12 -> 24 > 12，隔离
        with Ingestor(db_path(self.cdir), max_waiting_bytes=12,
                      max_waiting_messages_k=100) as ing:
            r0 = self._ing(ing, 0, make_data_msg(DOM, 300, [rec_a(1)]))
            self.assertEqual(r0.sets_enqueued, 1)
            self.assertEqual(ing.waiting_bytes(), 12)  # 恰满
            r1 = self._ing(ing, 1, make_data_msg(DOM, 300, [rec_a(2)]))
            self.assertEqual(r1.sets_isolated, 1)
            self.assertEqual(r1.sets_enqueued, 0)
            # 旧集合不被淘汰，仍只有一份在等待
            self.assertEqual(ing.waiting_bytes(), 12)
            self.assertEqual(ing.waiting_ids().__len__(), 1)
            ended = ing.pending().ended
            cap_rows = [e for e in ended if e["end_reason"] ==
                        "capacity_isolated"]
            self.assertEqual(len(cap_rows), 1)
            self.assertEqual(cap_rows[0]["set_length"], 12)  # 超的那份证据保留

    def test_capacity_one_byte_over_only_new_set_isolated(self):
        # 容量 11：第一份就需要 12 > 11 -> 立即隔离，等待区保持空
        with Ingestor(db_path(self.cdir, "one.db"), max_waiting_bytes=11,
                      max_waiting_messages_k=100) as ing:
            r0 = self._ing(ing, 0, make_data_msg(DOM, 300, [rec_a(1)]))
            self.assertEqual(r0.sets_isolated, 1)
            self.assertEqual(ing.waiting_bytes(), 0)
            self.assertEqual(ing.pending().unresolved_count, 0)

    def test_timeout_sweep_with_and_without_definition_at_expiry(self):
        # K=2：origin=0 的集合在 current_pos-0>=2 即 pos2 到期
        with Ingestor(db_path(self.cdir, "t.db"), max_waiting_bytes=100_000,
                      max_waiting_messages_k=2) as ing:
            self._ing(ing, 0, make_data_msg(DOM, 300, [rec_a(1)]))
            # pos1 无相关定义，差 1 未到期
            self._ing(ing, 1, make_data_msg(DOM, 999, [b"\x01\x02"]))
            self.assertEqual(ing.pending().unresolved_count, 2)
            # pos2 到期：无定义 -> timeout
            self._ing(ing, 2, make_data_msg(DOM, 998, [b"\x03"]))
            ended = {e["template_id"]: e["end_reason"]
                     for e in ing.pending().ended}
            self.assertEqual(ended.get(300), "timeout")
            # 差 1 的 999 在 pos2 时 2-1=1 <2，仍等待；998 刚入也等待
            self.assertEqual(ing.pending().unresolved_count, 2)
            # pos3：999 差2到期
            self._ing(ing, 3, make_data_msg(DOM, 997, [b"\x04"]))
            ended = {e["template_id"]: e["end_reason"]
                     for e in ing.pending().ended}
            self.assertEqual(ended.get(999), "timeout")

    def test_definition_at_expiry_position_picks_up_before_timeout(self):
        # K=2，origin=0；pos2 既是到期位置又出现首份定义 -> 必须先接走
        with Ingestor(db_path(self.cdir, "e.db"), max_waiting_bytes=100_000,
                      max_waiting_messages_k=2) as ing:
            self._ing(ing, 0, make_data_msg(DOM, 300, [rec_a(42)]))
            self._ing(ing, 1, make_data_msg(DOM, 999, [b"\x09"]))
            define = wire.message(1, 1, DOM, [wire.template_set([
                wire.template_record(300, LAYOUT_A)])])
            r2 = self._ing(ing, 2, define)
            self.assertEqual(r2.sets_picked, 1)
            # 接走而非 timeout
            reasons = [e["end_reason"] for e in ing.pending().ended]
            self.assertIn("picked", reasons)
            self.assertNotIn("timeout",
                             [e["end_reason"] for e in ing.pending().ended
                              if e["template_id"] == 300])
            flow = ing.flows()[0]
            self.assertEqual(flow["fields"][0]["value"], 42)
            self.assertEqual(flow["version_seq"], 1)

    def test_failed_message_still_runs_timeout_sweep(self):
        # 失败消息不安装模板、不清旧等待，但该位置末尾仍按 K 处理到期
        with Ingestor(db_path(self.cdir, "f.db"), max_waiting_bytes=100_000,
                      max_waiting_messages_k=2) as ing:
            self._ing(ing, 0, make_data_msg(DOM, 300, [rec_a(1)]))
            # pos1 一条坏消息（长度不一致），仍占 capture_pos
            bad = wire.message(1, 1, DOM, [], declared_length=20)  # 实际16
            r1 = self._ing(ing, 1, bad)
            self.assertEqual(r1.status, "failed")
            self.assertEqual(ing.pending().unresolved_count, 1)  # 等待未清
            # pos2 又一条坏消息：此时 2-0>=2，pos0 的等待应到期
            r2 = self._ing(ing, 2, bad)
            self.assertEqual(r2.status, "failed")
            ended = ing.pending().ended
            self.assertTrue(any(e["end_reason"] == "timeout" for e in ended))
            self.assertEqual(ing.pending().unresolved_count, 0)
            # 两条失败位置都在未解释清单中
            self.assertEqual(len(ing.pending().unexplained), 2)

    def test_ended_sets_never_become_eligible_again(self):
        with Ingestor(db_path(self.cdir, "g.db"), max_waiting_bytes=12,
                      max_waiting_messages_k=100) as ing:
            # 占满容量后第二份被隔离
            self._ing(ing, 0, make_data_msg(DOM, 300, [rec_a(1)]))
            self._ing(ing, 1, make_data_msg(DOM, 300, [rec_a(2)]))
            # 后来定义 300：只接走等待中的那份，隔离的那份不复活
            define = wire.message(1, 1, DOM, [wire.template_set([
                wire.template_record(300, LAYOUT_A)])])
            r2 = self._ing(ing, 2, define)
            self.assertEqual(r2.sets_picked, 1)
            reasons = sorted(e["end_reason"] for e in ing.pending().ended)
            self.assertEqual(reasons, ["capacity_isolated", "picked"])
            # 再定义一次也不会捡回隔离集合
            define2 = wire.message(1, 1, DOM, [wire.template_set([
                wire.template_record(300, LAYOUT_A)])])
            self._ing(ing, 3, define2)
            self.assertEqual(
                len([e for e in ing.pending().ended
                     if e["end_reason"] == "capacity_isolated"]), 1)


if __name__ == "__main__":
    unittest.main()
