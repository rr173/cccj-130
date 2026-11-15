"""分段追加导入的持久化一致性测试。

相同消息按相同顺序：一次导入 vs 分两段导入并重开数据库，查询结果必须逐行一致。
另验证重开时容量/K 参数不匹配会被拒绝。
"""

import copy
import unittest

from tests._helpers import CaptureDir, db_path, LAYOUT_A, LAYOUT_B
from ipfix_offline import wire
from ipfix_offline.ingestor import Ingestor, ManifestError

ALICE = "ex"
SESS = "s1"
DOM = 9


def build_sequence(cdir: CaptureDir):
    """构造一条含等待、接走、改版、撤销、再等待、隔离、到期、坏消息的混合序列。"""
    msgs = []

    def add(blob):
        msgs.append(cdir.write_msg(blob))

    rec_a = lambda u, ip: u.to_bytes(4, "big") + ip
    rec_b = lambda u, b6: u.to_bytes(8, "big") + b6
    # 0 未知等待 300
    add(wire.message(1, 1, DOM, [wire.data_set(300, [
        rec_a(7, bytes([10, 0, 0, 1]))])]))
    # 1 定义 A -> 接走
    add(wire.message(1, 2, DOM, [wire.template_set([
        wire.template_record(300, LAYOUT_A)])]))
    # 2 即时数据
    add(wire.message(1, 3, DOM, [wire.data_set(300, [
        rec_a(80, bytes([192, 168, 1, 2]))])]))
    # 3 改版 B
    add(wire.message(1, 4, DOM, [wire.template_set([
        wire.template_record(300, LAYOUT_B)])]))
    # 4 布局 B 数据
    add(wire.message(1, 5, DOM, [wire.data_set(300, [
        rec_b(999, b"ABCDEF")])]))
    # 5 另一未知模板 400 等待
    add(wire.message(1, 6, DOM, [wire.data_set(400, [b"\x01\x02\x03"])]))
    # 6 撤销 300
    add(wire.message(1, 7, DOM, [wire.template_set([
        wire.withdrawal_record(300)])]))
    # 7 坏消息（不支持集合）
    add(wire.message(1, 8, DOM, [
        wire.data_set(300, [rec_a(5, bytes([1, 1, 1, 1]))]),
        __import__("struct").pack("!HH", 3, 4)]))
    # 8 定义 400 接走 pos5
    add(wire.message(1, 9, DOM, [wire.template_set([
        wire.template_record(400, [wire.field_spec(99, 3)])])]))
    return msgs


def snapshot(db, capacity, k):
    with Ingestor(db, max_waiting_bytes=capacity,
                  max_waiting_messages_k=k) as ing:
        return {
            "capture": [dict(r) for r in ing.conn.execute(
                "SELECT capture_pos, exporter, transport_session, status,"
                " error_code, export_time, sequence_number,"
                " observation_domain_id FROM capture_positions ORDER BY 1")],
            "versions": [dict(r) for r in ing.conn.execute(
                "SELECT version_seq, exporter, transport_session,"
                " observation_domain_id, template_id, layout_json,"
                " defined_pos, withdrawn_pos FROM template_versions ORDER BY 1")],
            "flows": [dict(r) for r in ing.conn.execute(
                "SELECT capture_pos, template_id, version_seq, set_index,"
                " record_index, origin, origin_pos FROM flows ORDER BY 1, 7")],
            "fields": [dict(r) for r in ing.conn.execute(
                "SELECT flow_id, field_index, enterprise_number, element_id,"
                " value_type, value_int, value_text, value_blob, raw_blob,"
                " field_offset, field_end, value_offset, value_length,"
                " prefix_offset, prefix_length FROM flow_fields"
                " ORDER BY 1, 2")],
            "waiting": [dict(r) for r in ing.conn.execute(
                "SELECT origin_pos, template_id, set_index, end_reason,"
                " end_pos, bound_version_seq, decode_error_code,"
                " length(set_bytes) AS lb FROM waiting_sets ORDER BY id")],
        }


class TwoPhaseConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.cdir = CaptureDir()
        self.capacity, self.K = 64, 4

    def tearDown(self):
        self.cdir.cleanup()

    def test_split_import_reopen_matches_single_import(self):
        paths = build_sequence(self.cdir)
        entries = [self.cdir.entry(i, ALICE, SESS, p)
                   for i, p in enumerate(paths)]
        db_one = db_path(self.cdir, "one.db")
        db_two = db_path(self.cdir, "two.db")

        # 一次性导入
        with Ingestor(db_one, max_waiting_bytes=self.capacity,
                      max_waiting_messages_k=self.K) as ing:
            ing.import_manifest(copy.deepcopy(entries))
        snap_one = snapshot(db_one, self.capacity, self.K)

        # 分两段（0..4 / 5..8），中间关闭并重新打开数据库
        with Ingestor(db_two, max_waiting_bytes=self.capacity,
                      max_waiting_messages_k=self.K) as ing:
            ing.import_manifest(copy.deepcopy(entries[:5]))
        with Ingestor(db_two, max_waiting_bytes=self.capacity,
                      max_waiting_messages_k=self.K) as ing:
            ing.import_manifest(copy.deepcopy(entries[5:]))
        snap_two = snapshot(db_two, self.capacity, self.K)

        # 逐表逐行比对
        for table in ("capture", "versions", "flows", "fields", "waiting"):
            self.assertEqual(snap_one[table], snap_two[table],
                             f"表 {table} 两次导入结果不一致")
        # 关键语义抽查
        self.assertEqual(len(snap_one["flows"]), len(snap_two["flows"]))
        self.assertTrue(any(r["status"] == "failed"
                            for r in snap_one["capture"]))

    def test_reopen_with_different_params_rejected(self):
        paths = build_sequence(self.cdir)
        db = db_path(self.cdir, "p.db")
        with Ingestor(db, max_waiting_bytes=self.capacity,
                      max_waiting_messages_k=self.K) as ing:
            ing.import_manifest([self.cdir.entry(0, ALICE, SESS, paths[0])])
        with self.assertRaises(ManifestError):
            Ingestor(db, max_waiting_bytes=self.capacity + 1,
                     max_waiting_messages_k=self.K)
        with self.assertRaises(ManifestError):
            Ingestor(db, max_waiting_bytes=self.capacity,
                     max_waiting_messages_k=self.K + 1)
        # 原参数可正常重开且等待状态还在
        with Ingestor(db, max_waiting_bytes=self.capacity,
                      max_waiting_messages_k=self.K) as ing:
            self.assertEqual(ing.pending().unresolved_count, 1)

    def test_iter_flows_interface(self):
        paths = build_sequence(self.cdir)
        db = db_path(self.cdir, "it.db")
        entries = [self.cdir.entry(i, ALICE, SESS, p)
                   for i, p in enumerate(paths)]
        with Ingestor(db, max_waiting_bytes=self.capacity,
                      max_waiting_messages_k=self.K) as ing:
            ing.import_manifest(entries)
            all_flows = list(ing.iter_flows())
            self.assertEqual(all_flows, ing.flows())
            filtered = list(ing.iter_flows(capture_pos=4))
            self.assertTrue(all(f["capture_pos"] == 4 for f in filtered))
            # 迭代器惰性
            it = ing.iter_flows()
            self.assertEqual(next(it)["flow_id"], 1)


if __name__ == "__main__":
    unittest.main()
