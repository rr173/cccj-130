"""大样本行为与内存占用测试。

场景：多数数据集合在模板发布前到达而进入等待；设置紧张容量使一部分被隔离。
验证：
1. waiting_bytes() 永远不超过调用方容量；
2. 已 picked / timeout / withdrawn / capacity_isolated 的集合，其正文字节
   不再被 Ingestor 的 Python 容器引用（只剩 SQLite 中的原始证据）；
3. 用 tracemalloc 测量峰值，随消息数增长趋于平稳而不是线性膨胀；
4. 即时/等待两条解码路径产出的类型与来源表示一致。
"""

import gc
import os
import sys
import tempfile
import tracemalloc
import unittest

from tests._helpers import CaptureDir, db_path, LAYOUT_A
from ipfix_offline import wire
from ipfix_offline.ingestor import Ingestor

ALICE = "ex"
SESS = "s1"
DOM = 3
N_WAITING_MSGS = 400
SET_PAYLOAD = 64                      # 每条数据集合正文 64 字节
SET_TOTAL = 4 + SET_PAYLOAD           # 含集合头 68 字节
CAPACITY = 20 * SET_TOTAL             # 最多同时容纳 20 份等待
# 确定性不兼容布局：单字段变长文本。64 字节正文以 0xC8(=200) 为长度前缀，
# 但前缀之后只剩 63 字节 -> 确定性 varlen_value_out_of_bounds，
# 全部等待集合走到 bad_field_isolated，不可能出现恰好对齐的 picked。
BAD_LAYOUT = [wire.field_spec(82, wire.VARLEN)]


def _data_msg(i: int) -> bytes:
    # 与任何已发布模板无关的未知模板 900；64 字节正文首字节 0xC8=200，
    # 声称 200 字节但仅剩 63 字节，确定性变长越界。
    payload = bytes([0xC8]) + bytes([i & 0xFF]) * (SET_PAYLOAD - 1)
    return wire.message(1000 + i, i, DOM,
                        [wire.data_set(900, [payload])])


class LargeSampleMemoryTests(unittest.TestCase):
    def setUp(self):
        self.cdir = CaptureDir()

    def tearDown(self):
        self.cdir.cleanup()

    def test_waiting_bytes_bounded_and_blob_releases(self):
        """容量有界 + 终态集合正文字节不留在 Ingestor 的 Python 容器。"""
        db = db_path(self.cdir, "large.db")
        peak_waiting_bytes = 0
        with Ingestor(db, max_waiting_bytes=CAPACITY,
                      max_waiting_messages_k=10_000) as ing:
            for i in range(N_WAITING_MSGS):
                p = self.cdir.write_msg(_data_msg(i))
                r = ing.import_manifest(
                    [self.cdir.entry(i, ALICE, SESS, p)])[0]
                # 不变量：任何时刻等待区计量都不超过容量
                self.assertLessEqual(ing.waiting_bytes(), CAPACITY)
                peak_waiting_bytes = max(peak_waiting_bytes,
                                         ing.waiting_bytes())
                # 内存等待对象数 == SQL 中 end_reason='waiting' 行数
                self.assertEqual(len(ing.waiting_ids()),
                                 ing.pending().unresolved_count)

            # 发布首份不兼容定义：等待集合全部 bad_field_isolated，新定义保留
            define = wire.message(1, 1, DOM, [wire.template_set([
                wire.template_record(900, BAD_LAYOUT)])])
            pd = self.cdir.write_msg(define)
            ing.import_manifest([self.cdir.entry(
                N_WAITING_MSGS, ALICE, SESS, pd)])

            # 全部结束后 Python 等待容器必须清空，字节只存在于 SQLite
            self.assertEqual(ing.waiting_bytes(), 0)
            self.assertEqual(ing.waiting_ids(), [])
            summary = ing.pending()
            self.assertEqual(summary.unresolved_count, 0)
            ended = summary.ended
            self.assertEqual(len(ended), N_WAITING_MSGS)
            n_cap = sum(1 for e in ended
                        if e["end_reason"] == "capacity_isolated")
            n_bad = sum(1 for e in ended
                        if e["end_reason"] == "bad_field_isolated")
            self.assertGreater(n_cap, 0)       # 紧张容量确实触发隔离
            self.assertGreater(n_bad, 0)
            self.assertEqual(n_cap + n_bad, N_WAITING_MSGS)
            # 原始证据仍可从 SQLite 取回，长度为完整集合字节
            row = ing.conn.execute(
                "SELECT length(set_bytes) AS lb FROM waiting_sets"
                " ORDER BY id LIMIT 1").fetchone()
            self.assertEqual(row["lb"], SET_TOTAL)
            # 直接断言 Ingestor 容器不再引用任何已结束集合的 bytes
            self.assertEqual([id(w.set_bytes) for w in ing._waiting], [])
        # 峰值等待字节恰为容量（容量是单集合大小的整数倍，会被打满）
        self.assertEqual(peak_waiting_bytes, CAPACITY)

    def test_resident_memory_does_not_grow_with_message_count(self):
        """处理 80 条与 400 条且全部终态后，Ingestor 相关驻留增量应趋近零。

        若被隔离/已落盘正文继续留在 Python 容器，400 条场景会比 80 条场景
        多占约 (400-80)*68 字节；正确实现下两者等待区都为空，增量为 0。
        """
        def resident_after(n: int) -> int:
            gc.collect()
            tracemalloc.start()
            local_dir = CaptureDir()
            try:
                with Ingestor(db_path(local_dir, f"m{n}.db"),
                              max_waiting_bytes=CAPACITY,
                              max_waiting_messages_k=10_000) as ing:
                    for i in range(n):
                        p = local_dir.write_msg(_data_msg(i))
                        ing.import_manifest([local_dir.entry(
                            i, ALICE, SESS, p)])
                    define = wire.message(1, 1, DOM, [wire.template_set([
                        wire.template_record(900, BAD_LAYOUT)])])
                    ing.import_manifest([local_dir.entry(
                        n, ALICE, SESS, local_dir.write_msg(define))])
                    self.assertEqual(ing.waiting_bytes(), 0)
                    # 仅统计 ingestor 模块的当前驻留（traced 内存快照）
                    snap = tracemalloc.take_snapshot()
                    ing_file = os.path.abspath(
                        os.path.join(os.path.dirname(__file__), "..",
                                     "ipfix_offline", "ingestor.py"))
                    total = sum(stat.size for stat in snap.statistics("lineno")
                                if stat.traceback
                                and os.path.abspath(
                                    stat.traceback[0].filename) == ing_file)
            finally:
                tracemalloc.stop()
                local_dir.cleanup()
            return total

        small = resident_after(80)
        large = resident_after(N_WAITING_MSGS)
        # 5 倍消息量后，ingestor 自身驻留不得线性膨胀；给固定结构留宽松余量
        self.assertLessEqual(
            large, small + 4 * SET_TOTAL,
            f"驻留随消息数增长：small={small} large={large}")

    def test_immediate_and_pending_share_same_representation(self):
        # 同一布局、同值的两条记录分别走即时解码与等待后解码，字段表示必须一致
        db = db_path(self.cdir, "repr.db")
        body = (0x01020304).to_bytes(4, "big") + bytes([172, 16, 0, 9])
        with Ingestor(db, max_waiting_bytes=10_000,
                      max_waiting_messages_k=10) as ing:
            # 等待路径
            p0 = self.cdir.write_msg(wire.message(
                1, 1, DOM, [wire.data_set(300, [body])]))
            ing.import_manifest([self.cdir.entry(0, ALICE, SESS, p0)])
            p1 = self.cdir.write_msg(wire.message(
                1, 2, DOM, [wire.template_set([
                    wire.template_record(300, LAYOUT_A)])]))
            ing.import_manifest([self.cdir.entry(1, ALICE, SESS, p1)])
            # 即时路径
            p2 = self.cdir.write_msg(wire.message(
                1, 3, DOM, [wire.data_set(300, [body])]))
            ing.import_manifest([self.cdir.entry(2, ALICE, SESS, p2)])

            flows = ing.flows()
            self.assertEqual(len(flows), 2)
            pending_flow, immediate_flow = flows
            self.assertEqual(pending_flow["origin"], "pending")
            self.assertEqual(immediate_flow["origin"], "immediate")
            # 类型、值、原字节、偏移口径完全一致（消息位置不同导致绝对偏移不同，
            # 但字段内字段相对结构一致；这里比较类型/值/长度）
            for key in ("value_type", "value", "value_length",
                        "prefix_offset", "prefix_length"):
                self.assertEqual(
                    [f[key] for f in pending_flow["fields"]],
                    [f[key] for f in immediate_flow["fields"]])
            self.assertEqual([f["raw"] for f in pending_flow["fields"]],
                             [f["raw"] for f in immediate_flow["fields"]])
            # 两条流绑定同一模板版本
            self.assertEqual(pending_flow["version_seq"],
                             immediate_flow["version_seq"])


if __name__ == "__main__":
    unittest.main()
