"""清单规则、消息原子性与证据查询测试。

* 重传无操作、内容改变/身份改变/跳位置拒绝
* 坏消息原子性：前面的模板定义不提前替换已接受版本、失败不安装模板
* explain 来源链：捕获身份、消息/集合/记录位置、模板定义位置、字段起止字节
* 未解码与解码零值可区分；零值字段保留原字节
"""

import json
import os
import unittest

from tests._helpers import CaptureDir, db_path, LAYOUT_A, make_data_msg
from ipfix_offline import wire
from ipfix_offline.ingestor import Ingestor, ManifestError

ALICE = "ex"
SESS = "s1"
SESS2 = "s2"
DOM = 5


class ManifestAtomicityTests(unittest.TestCase):
    def setUp(self):
        self.cdir = CaptureDir()

    def tearDown(self):
        self.cdir.cleanup()

    def _path(self, blob):
        return self.cdir.write_msg(blob)

    def test_retransmit_noop_change_and_gap_rejected(self):
        p0 = self._path(make_data_msg(DOM, 300, [b"\x00" * 8]))
        with Ingestor(db_path(self.cdir), max_waiting_bytes=1000,
                      max_waiting_messages_k=10) as ing:
            r0 = ing.import_manifest(
                [self.cdir.entry(0, ALICE, SESS, p0)])[0]
            self.assertEqual(r0.status, "imported")
            # 同身份同字节重传 -> duplicate 无操作
            r0b = ing.import_manifest(
                [self.cdir.entry(0, ALICE, SESS, p0)])[0]
            self.assertEqual(r0b.status, "duplicate")
            # 跳位置拒绝
            with self.assertRaises(ManifestError):
                ing.import_manifest(
                    [self.cdir.entry(5, ALICE, SESS, p0)])
            # 身份改变拒绝（同位置换 session）
            with self.assertRaises(ManifestError):
                ing.import_manifest(
                    [self.cdir.entry(0, ALICE, SESS2, p0)])
            # 内容改变拒绝：同位置同身份但文件字节变了
            p0_changed = self._path(make_data_msg(DOM, 300, [b"\x01" * 8]))
            with self.assertRaises(ManifestError):
                ing.import_manifest(
                    [self.cdir.entry(0, ALICE, SESS, p0_changed)])

    def test_bad_message_atomic_no_template_installed(self):
        # pos0 先安装模板300并即时解码一条
        good_define = wire.message(1, 1, DOM, [wire.template_set([
            wire.template_record(300, LAYOUT_A)])])
        good_data = make_data_msg(DOM, 300,
                                  [(7).to_bytes(4, "big") + b"\x0a\x00\x00\x01"])
        with Ingestor(db_path(self.cdir), max_waiting_bytes=1000,
                      max_waiting_messages_k=10) as ing:
            p0 = self._path(good_define)
            ing.import_manifest([self.cdir.entry(0, ALICE, SESS, p0)])
            p1 = self._path(good_data)
            ing.import_manifest([self.cdir.entry(1, ALICE, SESS, p1)])
            versions_before = ing.conn.execute(
                "SELECT COUNT(*) FROM template_versions").fetchone()[0]
            flows_before = len(ing.flows())

            # pos2：含一个新模板定义 + 坏尾部 -> 整条失败
            new_define = wire.template_set([wire.template_record(
                400, [wire.field_spec(1, 4)])])
            broken = wire.message(1, 1, DOM, [new_define, b"\x00\x00"])
            p2 = self._path(broken)
            r2 = ing.import_manifest(
                [self.cdir.entry(2, ALICE, SESS, p2)])[0]
            self.assertEqual(r2.status, "failed")
            # 模板400 未安装，模板300 版本未增加，流数不变
            self.assertEqual(ing.conn.execute(
                "SELECT COUNT(*) FROM template_versions").fetchone()[0],
                versions_before)
            self.assertEqual(len(ing.flows()), flows_before)
            cap = ing.pending().unexplained[0]
            self.assertEqual(cap["capture_pos"], 2)
            # 坏文件仍占位置，下一条必须从 pos3 连续
            p3 = self._path(good_data)
            r3 = ing.import_manifest(
                [self.cdir.entry(3, ALICE, SESS, p3)])[0]
            self.assertEqual(r3.status, "imported")

    def test_explain_evidence_chain_and_byte_ranges(self):
        define = wire.message(0x01020304, 0x0A0B0C0D, DOM,
                              [wire.template_set([
                                  wire.template_record(300, LAYOUT_A)])])
        body = (0x11223344).to_bytes(4, "big") + bytes([192, 168, 0, 7])
        data = make_data_msg(DOM, 300, [body], export_time=0x01020304,
                             seq=0x0A0B0C0E)
        with Ingestor(db_path(self.cdir, "x.db"), max_waiting_bytes=1000,
                      max_waiting_messages_k=10) as ing:
            p0 = self._path(define)
            ing.import_manifest([self.cdir.entry(0, ALICE, SESS, p0)])
            p1 = self._path(data)
            ing.import_manifest([self.cdir.entry(1, ALICE, SESS, p1)])
            flow = ing.explain(1)
            self.assertIsNotNone(flow)
            ev = flow["evidence"]
            # 捕获身份
            self.assertEqual(ev["capture_identity"]["capture_pos"], 1)
            self.assertEqual(ev["capture_identity"]["exporter"], ALICE)
            # 消息头字段保存但不用于排序
            self.assertEqual(ev["message"]["export_time"], 0x01020304)
            self.assertEqual(ev["message"]["sequence_number"], 0x0A0B0C0E)
            self.assertEqual(ev["message"]["observation_domain_id"], DOM)
            # 模板定义位置与版本
            self.assertEqual(ev["template_defined_pos"], 0)
            self.assertEqual(ev["template_version"], 1)
            # 集合/记录位置
            self.assertEqual(ev["set_index"], 0)
            self.assertEqual(ev["record_index"], 0)
            # 字段字节范围手工核对：数据集合偏移16，集合头4 -> 字段0 @20
            f0, f1 = flow["fields"]
            self.assertEqual((f0["field_offset"], f0["field_end"]), (20, 24))
            self.assertEqual(f0["raw"], bytes([0x11, 0x22, 0x33, 0x44]))
            self.assertEqual(f0["value"], 0x11223344)
            self.assertEqual((f1["field_offset"], f1["field_end"]), (24, 28))
            self.assertEqual(f1["value"], "192.168.0.7")
            # 用 explain 返回的范围回切原文件，字节必须一致
            with open(p1, "rb") as fh:
                original = fh.read()
            self.assertEqual(original[f0["field_offset"]:f0["field_end"]],
                             f0["raw"])
            self.assertIsNone(ing.explain(9999))

    def test_zero_value_distinct_from_undecoded(self):
        # uint 零值、IPv4 0.0.0.0、空文本都是“已解码零值”，不是 unresolved
        layout = [wire.field_spec(1, 4), wire.field_spec(8, 4),
                  wire.field_spec(82, wire.VARLEN)]
        define = wire.message(1, 1, DOM, [wire.template_set([
            wire.template_record(310, layout)])])
        record = (0).to_bytes(4, "big") + b"\x00\x00\x00\x00" + b"\x00"
        data = make_data_msg(DOM, 310, [record])
        with Ingestor(db_path(self.cdir, "z.db"), max_waiting_bytes=1000,
                      max_waiting_messages_k=10) as ing:
            ing.import_manifest([self.cdir.entry(
                0, ALICE, SESS, self._path(define))])
            ing.import_manifest([self.cdir.entry(
                1, ALICE, SESS, self._path(data))])
            self.assertEqual(ing.pending().unresolved_count, 0)
            flow = ing.flows()[0]
            self.assertEqual([f["value"] for f in flow["fields"]],
                             [0, "0.0.0.0", ""])
            # 零值仍保留原字节与类型，可与“未解码（不出现在 flows）”区分
            self.assertEqual(flow["fields"][0]["raw"], b"\x00\x00\x00\x00")
            self.assertEqual(flow["fields"][2]["value_type"], "text")

    def test_undecoded_not_faked_as_empty_set(self):
        # 未知模板数据：pending 有一条 unresolved，flows 为空而不是假空集合
        data = make_data_msg(DOM, 700, [b"\xaa\xbb"])
        with Ingestor(db_path(self.cdir, "u.db"), max_waiting_bytes=1000,
                      max_waiting_messages_k=10) as ing:
            ing.import_manifest([self.cdir.entry(
                0, ALICE, SESS, self._path(data))])
            self.assertEqual(ing.flows(), [])
            summary = ing.pending()
            self.assertEqual(summary.unresolved_count, 1)
            self.assertTrue(summary.unresolved_bytes > 0)


if __name__ == "__main__":
    unittest.main()
