"""消息内顺序语义测试：定义生效位置包含集合与模板记录的原顺序。

* 同一消息内先出现未知数据集合、后出现同键模板定义 -> 必须被该消息的定义接走
* 同一消息内先定义、后数据 -> 即时绑定该消息内新版本
* 同消息内定义 -> 撤销 -> 再数据：数据在撤销后重新等待
* 一个数据集合含多条记录，record_index 按原顺序保留
"""

import unittest

from tests._helpers import CaptureDir, db_path, LAYOUT_A
from ipfix_offline import wire
from ipfix_offline.ingestor import Ingestor

ALICE, SESS, DOM = "ex", "s1", 7


def rec_a(u, ip):
    return u.to_bytes(4, "big") + bytes(ip)


class InMessageOrderTests(unittest.TestCase):
    def setUp(self):
        self.cdir = CaptureDir()

    def tearDown(self):
        self.cdir.cleanup()

    def _ing(self, ing, pos, blob):
        p = self.cdir.write_msg(blob)
        return ing.import_manifest(
            [self.cdir.entry(pos, ALICE, SESS, p)])[0]

    def test_unknown_then_definition_in_same_message_picks_up(self):
        # 单消息内：数据集合 300 在前，模板集合定义 300 在后
        dset = wire.data_set(300, [rec_a(7, (10, 0, 0, 1))])
        tset = wire.template_set([wire.template_record(300, LAYOUT_A)])
        msg = wire.message(1, 1, DOM, [dset, tset])  # 原顺序：数据先、模板后
        with Ingestor(db_path(self.cdir), max_waiting_bytes=10_000,
                      max_waiting_messages_k=10) as ing:
            r = self._ing(ing, 0, msg)
            # 同消息更晚的定义接走了同消息早先入队的集合
            self.assertEqual(r.sets_enqueued, 1)
            self.assertEqual(r.sets_picked, 1)
            self.assertEqual(ing.pending().unresolved_count, 0)
            flow = ing.flows()[0]
            self.assertEqual(flow["origin"], "pending")
            self.assertEqual(flow["origin_pos"], 0)
            self.assertEqual(flow["version_seq"], 1)
            self.assertEqual([f["value"] for f in flow["fields"]],
                             [7, "10.0.0.1"])

    def test_definition_then_data_in_same_message_binds_new_version(self):
        tset = wire.template_set([wire.template_record(300, LAYOUT_A)])
        dset = wire.data_set(300, [rec_a(9, (1, 2, 3, 4))])
        msg = wire.message(1, 1, DOM, [tset, dset])
        with Ingestor(db_path(self.cdir, "d.db"), max_waiting_bytes=10_000,
                      max_waiting_messages_k=10) as ing:
            r = self._ing(ing, 0, msg)
            self.assertEqual(r.flows_inserted, 1)
            flow = ing.flows()[0]
            self.assertEqual(flow["origin"], "immediate")
            self.assertEqual(flow["version_seq"], 1)

    def test_define_withdraw_then_data_rewaits_in_same_message(self):
        tset = wire.template_set([wire.template_record(300, LAYOUT_A)])
        wset = wire.template_set([wire.withdrawal_record(300)])
        dset = wire.data_set(300, [rec_a(5, (6, 6, 6, 6))])
        msg = wire.message(1, 1, DOM, [tset, wset, dset])
        with Ingestor(db_path(self.cdir, "w.db"), max_waiting_bytes=10_000,
                      max_waiting_messages_k=10) as ing:
            r = self._ing(ing, 0, msg)
            # 撤销后数据必须重新等待，不能用同消息早先定义即时解码
            self.assertEqual(r.sets_enqueued, 1)
            self.assertEqual(r.flows_inserted, 0)
            self.assertEqual(ing.pending().unresolved_count, 1)
            # 模板版本处于已撤销状态
            self.assertIsNone(ing._active_version(
                (ALICE, SESS, DOM, 300)))

    def test_multiple_records_keep_record_index_order(self):
        tset = wire.template_set([wire.template_record(300, LAYOUT_A)])
        dset = wire.data_set(300, [
            rec_a(1, (10, 0, 0, 1)),
            rec_a(2, (10, 0, 0, 2)),
            rec_a(3, (10, 0, 0, 3)),
        ])
        with Ingestor(db_path(self.cdir, "m.db"), max_waiting_bytes=10_000,
                      max_waiting_messages_k=10) as ing:
            self._ing(ing, 0, wire.message(1, 1, DOM, [tset, dset]))
            flows = ing.flows()
            self.assertEqual([f["record_index"] for f in flows], [0, 1, 2])
            self.assertEqual([f["fields"][0]["value"] for f in flows],
                             [1, 2, 3])
            # 三条记录的字段偏移连续（每条 8 字节）
            offsets = [f["fields"][0]["field_offset"] for f in flows]
            self.assertEqual(offsets, [offsets[0] + 8 * i for i in range(3)])

    def test_multiple_data_sets_in_one_message(self):
        # 模板 + 两个同键数据集合，同消息内都即时解码
        tset = wire.template_set([wire.template_record(300, LAYOUT_A)])
        d1 = wire.data_set(300, [rec_a(1, (1, 1, 1, 1))])
        d2 = wire.data_set(300, [rec_a(2, (2, 2, 2, 2))])
        with Ingestor(db_path(self.cdir, "ms.db"), max_waiting_bytes=10_000,
                      max_waiting_messages_k=10) as ing:
            r = self._ing(ing, 0,
                          wire.message(1, 1, DOM, [tset, d1, d2]))
            self.assertEqual(r.flows_inserted, 2)
            self.assertEqual([f["set_index"] for f in ing.flows()], [1, 2])


if __name__ == "__main__":
    unittest.main()
