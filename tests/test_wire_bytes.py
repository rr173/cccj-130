"""线格式字节级测试：所有数值与切片均手工计算并以字面量断言。

覆盖：16 字节消息头、变长 254/255 边界、企业位同号元素、零长度文本、
声明越界、坏版本/坏长度、不支持集合、填充残余、模板规则。
"""

import struct
import unittest

from tests._helpers import CaptureDir  # noqa: F401  (确保 sys.path)
from ipfix_offline import wire
from ipfix_offline.wire import MessageError


class HandcraftedWireTests(unittest.TestCase):
    def test_header_bytes_handcrafted(self):
        # 手工 16 字节头：version=10(0x000a) length=16, time=0x11223344,
        # seq=0x55667788, domain=0x99aabbcc；无集合
        raw = bytes.fromhex("000a0010112233445566778899aabbcc")
        self.assertEqual(len(raw), 16)
        parsed = wire.parse_message(raw)
        self.assertEqual(parsed.export_time, 0x11223344)
        self.assertEqual(parsed.sequence_number, 0x55667788)
        self.assertEqual(parsed.observation_domain_id, 0x99AABBCC)
        self.assertEqual(parsed.sets, ())
        # 头字段手工切片
        self.assertEqual(struct.unpack("!H", raw[0:2]), (10,))
        self.assertEqual(struct.unpack("!H", raw[2:4]), (16,))

    def test_bad_version_and_length(self):
        good = wire.message(1, 2, 3, [])
        self.assertEqual(len(good), 16)
        bad_ver = bytes([0, 9]) + good[2:]
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(bad_ver)
        self.assertEqual(cm.exception.code, wire.ERR_BAD_VERSION)

        bad_len = good[:2] + struct.pack("!H", len(good) + 1) + good[4:]
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(bad_len)
        self.assertEqual(cm.exception.code, wire.ERR_LENGTH_MISMATCH)

        with self.assertRaises(MessageError) as cm:
            wire.parse_message(b"\x00\x0a\x00\x10")
        self.assertEqual(cm.exception.code, wire.ERR_TOO_SHORT)

    def test_varlen_254_255_boundary(self):
        # 变长元素82，两种正文长度：254 -> 单字节前缀；255 -> 0xFF + 2字节长度
        text254 = "a" * 254
        text255 = "b" * 255
        rec254 = wire.variable_field(text254.encode())
        rec255 = wire.variable_field(text255.encode())
        # 手工断言前缀编码
        self.assertEqual(rec254[0], 254)
        self.assertEqual(len(rec254), 255)             # 1 前缀 + 254 正文
        self.assertEqual(rec255[:3], b"\xff\x00\xff")  # 3 前缀 + 255 正文
        self.assertEqual(len(rec255), 258)

        tset = wire.template_set([
            wire.template_record(301, [wire.field_spec(82, wire.VARLEN)])])
        dset = wire.data_set(301, [rec254, rec255])
        msg = wire.message(7, 1, 1, [tset, dset])
        parsed = wire.parse_message(msg)
        layout = parsed.sets[0].templates[0].fields
        decoded = wire.decode_data_set(
            msg[parsed.sets[1].set_offset:], parsed.sets[1].set_offset,
            parsed.sets[1].set_index, layout)
        self.assertEqual(len(decoded), 2)
        f0 = decoded[0][1][0]
        f1 = decoded[1][1][0]
        # 手工偏移：头16 + 模板集合(4+8=12) = 28；数据集合头 28..32
        ds_off = parsed.sets[1].set_offset
        self.assertEqual(ds_off, 28)
        # 记录0：前缀 @32(1B)，正文 33..287
        self.assertEqual((f0.prefix_offset, f0.prefix_length), (32, 1))
        self.assertEqual((f0.value_offset, f0.value_length), (33, 254))
        self.assertEqual((f0.field_offset, f0.field_end), (32, 287))
        self.assertEqual(f0.value, text254)
        # 记录1：前缀 @287(3B: ff 00 ff)，正文 290..545
        self.assertEqual((f1.prefix_offset, f1.prefix_length), (287, 3))
        self.assertEqual((f1.value_offset, f1.value_length), (290, 255))
        self.assertEqual(f1.field_end, 545)
        self.assertEqual(f1.value, text255)
        self.assertEqual(msg[f0.value_offset:f0.field_end], text254.encode())
        self.assertEqual(msg[f1.value_offset:f1.field_end], text255.encode())

    def test_zero_length_text_is_decodable_empty(self):
        # 零长度变长文本：单字节前缀 0x00，正文空；与“未解码”必须可区分
        rec = wire.variable_field(b"")
        self.assertEqual(rec, b"\x00")
        tset = wire.template_set([
            wire.template_record(302, [wire.field_spec(82, wire.VARLEN)])])
        dset = wire.data_set(302, [rec])
        msg = wire.message(1, 1, 1, [tset, dset])
        parsed = wire.parse_message(msg)
        decoded = wire.decode_data_set(
            msg[parsed.sets[1].set_offset:], parsed.sets[1].set_offset,
            parsed.sets[1].set_index,
            parsed.sets[0].templates[0].fields)
        f = decoded[0][1][0]
        self.assertEqual(f.value_type, "text")
        self.assertEqual(f.value, "")          # 已解码的空字符串
        self.assertEqual(f.value_length, 0)
        self.assertEqual(f.prefix_length, 1)
        self.assertEqual(f.raw, b"")

    def test_bad_utf8_fails_field_decode(self):
        rec = wire.variable_field(b"\xff\xfe\x00invalid")
        tset = wire.template_set([
            wire.template_record(303, [wire.field_spec(82, wire.VARLEN)])])
        dset = wire.data_set(303, [rec])
        msg = wire.message(1, 1, 1, [tset, dset])
        parsed = wire.parse_message(msg)
        with self.assertRaises(wire.FieldDecodeError) as cm:
            wire.decode_data_set(
                msg[parsed.sets[1].set_offset:], parsed.sets[1].set_offset,
                parsed.sets[1].set_index,
                parsed.sets[0].templates[0].fields)
        self.assertEqual(cm.exception.code, wire.ERR_BAD_TEXT)

    def test_enterprise_same_element_id_distinct_identity(self):
        # 标准元素 9 与企业 8/企业 9 的同号元素是不同身份；可同模板共存
        f_std = wire.field_spec(9, 2)
        f_ent8 = wire.field_spec(9, 2, enterprise_number=8)
        f_ent9 = wire.field_spec(9, 3, enterprise_number=9)
        tset = wire.template_set([
            wire.template_record(304, [f_std, f_ent8, f_ent9])])
        msg = wire.message(1, 1, 1, [tset])
        parsed = wire.parse_message(msg)
        specs = parsed.sets[0].templates[0].fields
        self.assertEqual([s.enterprise_number for s in specs], [None, 8, 9])
        self.assertEqual(len({s.identity for s in specs}), 3)
        # 手工核对企业位线字节
        self.assertEqual(msg[20] & 0x80, 0)       # 标准字段 head 高字节
        self.assertEqual(msg[28] & 0x80, 0x80)    # 企业字段 head 高字节
        # 重复完整身份必须报错（企业号与元素号都相同）
        dup = wire.template_set([wire.template_record(
            305, [wire.field_spec(9, 2, enterprise_number=8),
                  wire.field_spec(9, 4, enterprise_number=8)])])
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(wire.message(1, 1, 1, [dup]))
        self.assertEqual(cm.exception.code, wire.ERR_DUPLICATE_FIELD)

    def test_declared_set_out_of_bounds(self):
        # 数据集合 set_id=300，声明长度 40，但消息正文只有 5 字节
        body = b"\x01\x02\x03\x04\x05"
        dset = struct.pack("!HH", 300, 40) + body
        msg = wire.message(1, 1, 1, [dset], declared_length=16 + len(dset))
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(msg)
        self.assertEqual(cm.exception.code, wire.ERR_SET_TRUNCATED)

    def test_unsupported_set_and_padding_rejected(self):
        # set_id=3（选项模板）在本子集不支持
        opt = struct.pack("!HH", 3, 8) + b"\x00" * 4
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(wire.message(1, 1, 1, [opt]))
        self.assertEqual(cm.exception.code, wire.ERR_UNSUPPORTED_SET)
        # set_id=1 保留
        reserved = struct.pack("!HH", 1, 4)
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(wire.message(1, 1, 1, [reserved]))
        self.assertEqual(cm.exception.code, wire.ERR_UNSUPPORTED_SET)
        # 填充残余：合法集合之外再拼 2 字节。本子集无填充规则，残余字节在
        # 下一轮被当作残缺集合头 -> 按越界拒绝（绝不能静默忽略）。
        good = wire.data_set(300, [b"\x00" * 4])
        padded = good + b"\x00\x00"
        msg = wire.message(1, 1, 1, [padded])
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(msg)
        self.assertIn(cm.exception.code,
                      (wire.ERR_SET_TRUNCATED, wire.ERR_PADDING_TRAILER))

        # 另一种填充：模板集合长度虚报，记录解析完后仍有 2 残余字节。
        # 本子集不允许填充，残余必须报错而不是被忽略。
        trec = wire.template_record(300, [wire.field_spec(1, 4)])
        padded_tset = (struct.pack("!HH", 2, 4 + len(trec) + 2)
                       + trec + b"\x00\x00")
        msg2 = wire.message(1, 1, 1, [padded_tset])
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(msg2)
        self.assertIn(cm.exception.code,
                      (wire.ERR_TEMPLATE_TRAILER, wire.ERR_TEMPLATE_TRUNCATED))

    def test_template_rules(self):
        # template_id 低于 256：手工拼模板集合字节，绕开构造器的前置校验
        low = struct.pack("!HHH", 255, 1, 1) + struct.pack("!HH", 1, 4)
        tset_low = struct.pack("!HH", 2, 4 + len(low)) + low
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(wire.message(1, 1, 1, [tset_low]))
        self.assertEqual(cm.exception.code, wire.ERR_BAD_TEMPLATE_ID)
        # 元素1 长度 3 不在 4/8 之内
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(wire.message(1, 1, 1, [
                wire.template_set([wire.template_record(
                    256, [wire.field_spec(1, 3)])])]))
        self.assertEqual(cm.exception.code, wire.ERR_UNSUPPORTED_SEMANTIC)
        # 元素8 必须 4 字节
        with self.assertRaises(MessageError) as cm:
            wire.parse_message(wire.message(1, 1, 1, [
                wire.template_set([wire.template_record(
                    256, [wire.field_spec(8, 8)])])]))
        self.assertEqual(cm.exception.code, wire.ERR_UNSUPPORTED_SEMANTIC)

    def test_withdrawal_record_wire_bytes(self):
        # field_count=0 撤销记录手工字节：template_id=300, count=0
        wrec = wire.withdrawal_record(300)
        self.assertEqual(wrec, struct.pack("!HH", 300, 0))
        msg = wire.message(1, 1, 1, [wire.template_set([wrec])])
        parsed = wire.parse_message(msg)
        rec = parsed.sets[0].templates[0]
        self.assertTrue(rec.is_withdrawal)
        self.assertEqual(rec.template_id, 300)

    def test_field_crosses_set_boundary(self):
        # 模板要求 8 字节定长，数据只给 4 字节
        tset = wire.template_set([
            wire.template_record(256, [wire.field_spec(1, 8)])])
        dset = wire.data_set(256, [b"\x00" * 4])
        msg = wire.message(1, 1, 1, [tset, dset])
        parsed = wire.parse_message(msg)
        with self.assertRaises(wire.FieldDecodeError) as cm:
            wire.decode_data_set(
                msg[parsed.sets[1].set_offset:], parsed.sets[1].set_offset,
                parsed.sets[1].set_index,
                parsed.sets[0].templates[0].fields)
        self.assertEqual(cm.exception.code, wire.ERR_FIELD_OUT_OF_BOUNDS)

    def test_varlen_prefix_truncated_and_value_oob(self):
        # 0xff 后缺少 2 字节长度
        tset = wire.template_set([
            wire.template_record(257, [wire.field_spec(82, wire.VARLEN)])])
        dset1 = wire.data_set(257, [b"\xff\x00"])
        msg1 = wire.message(1, 1, 1, [tset, dset1])
        p1 = wire.parse_message(msg1)
        with self.assertRaises(wire.FieldDecodeError) as cm:
            wire.decode_data_set(
                msg1[p1.sets[1].set_offset:], p1.sets[1].set_offset,
                p1.sets[1].set_index, p1.sets[0].templates[0].fields)
        self.assertEqual(cm.exception.code, wire.ERR_VARLEN_TRUNCATED)
        # 前缀声称 10 字节，正文只有 2 字节
        dset2 = wire.data_set(257, [b"\x0aAB"])
        msg2 = wire.message(1, 1, 1, [tset, dset2])
        p2 = wire.parse_message(msg2)
        with self.assertRaises(wire.FieldDecodeError) as cm:
            wire.decode_data_set(
                msg2[p2.sets[1].set_offset:], p2.sets[1].set_offset,
                p2.sets[1].set_index, p2.sets[0].templates[0].fields)
        self.assertEqual(cm.exception.code, wire.ERR_VARLEN_OUT_OF_BOUNDS)


if __name__ == "__main__":
    unittest.main()
