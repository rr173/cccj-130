"""语义子集测试：uint 4/8、IPv4、UTF-8、企业元素原字节、固定长度文本。"""

import unittest

from tests._helpers import CaptureDir, db_path
from ipfix_offline import wire
from ipfix_offline.ingestor import Ingestor

ALICE, SESS, DOM = "ex", "s1", 4


class SemanticSubsetTests(unittest.TestCase):
    def setUp(self):
        self.cdir = CaptureDir()

    def tearDown(self):
        self.cdir.cleanup()

    def test_uint64_enterprise_raw_and_fixed_text(self):
        layout = [
            wire.field_spec(1, 8),                       # 标准 uint64
            wire.field_spec(1, 4, enterprise_number=5),  # 企业同号 -> 原字节
            wire.field_spec(99, 3),                      # 未知标准元素 -> 原字节
            wire.field_spec(82, 5),                      # 固定长度 UTF-8
        ]
        tset = wire.template_set([wire.template_record(300, layout)])
        text = "héllo".encode("utf-8")  # é 占 2 字节，共 6 字节，不满足固定5
        # 改用恰好 5 字节的 ASCII 文本
        text = b"hello"
        record = (0x0102030405060708).to_bytes(8, "big")
        record += (9).to_bytes(4, "big") + b"abc" + text
        msg = wire.message(1, 1, DOM, [tset, wire.data_set(300, [record])])
        with Ingestor(db_path(self.cdir), max_waiting_bytes=10_000,
                      max_waiting_messages_k=10) as ing:
            p = self.cdir.write_msg(msg)
            ing.import_manifest([self.cdir.entry(0, ALICE, SESS, p)])
            flow = ing.flows()[0]
            f0, f1, f2, f3 = flow["fields"]
            self.assertEqual(f0["value_type"], "uint")
            self.assertEqual(f0["value"], 0x0102030405060708)
            self.assertEqual(f1["value_type"], "bytes")  # 企业元素不套 uint
            self.assertEqual(f1["value"], b"\x00\x00\x00\x09")
            self.assertEqual(f1["enterprise_number"], 5)
            self.assertEqual(f2["value"], b"abc")
            self.assertEqual(f3["value_type"], "text")
            self.assertEqual(f3["value"], "hello")
            self.assertIsNone(f3["prefix_offset"])  # 固定长度无变长前缀

    def test_multibyte_utf8_offsets(self):
        layout = [wire.field_spec(82, wire.VARLEN),
                  wire.field_spec(1, 4)]
        text = "中文"  # 6 个 UTF-8 字节
        record = wire.variable_field(text.encode("utf-8")) + (1234).to_bytes(4, "big")
        tset = wire.template_set([wire.template_record(301, layout)])
        msg = wire.message(1, 1, DOM, [tset, wire.data_set(301, [record])])
        with Ingestor(db_path(self.cdir, "u.db"), max_waiting_bytes=10_000,
                      max_waiting_messages_k=10) as ing:
            p = self.cdir.write_msg(msg)
            ing.import_manifest([self.cdir.entry(0, ALICE, SESS, p)])
            f0, f1 = ing.flows()[0]["fields"]
            self.assertEqual(f0["value"], "中文")
            self.assertEqual(f0["value_length"], 6)  # 字节长度不是字符数
            self.assertEqual(f0["prefix_length"], 1)
            # 正文偏移 = 前缀偏移 + 1；uint 紧跟其后
            self.assertEqual(f1["value_offset"], f0["value_offset"] + 6)
            self.assertEqual(f1["value"], 1234)


if __name__ == "__main__":
    unittest.main()
