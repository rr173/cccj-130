"""IPFIX capture-subset wire format: parser and synthetic message builder.

明确支持范围（离线工具，仅处理约定捕获子集，不接网络、不宣称兼容整个 RFC 7011）：

* 单文件单条 IPFIX 消息，真实 16 字节消息头；version 必须为 10，header.length
  必须等于文件字节长度。
* 集合：set_id == 2 的模板集合（含 field_count == 0 的撤销记录），以及
  set_id >= 256 的数据集合。其余 set_id 一律按消息错误处理。
* 字段说明：element_id + 长度；企业位存在时再读 4 字节 enterprise_number。
* 固定长度字段（正长度）与 RFC 7011 变长编码（模板长度 65535；正文首字节 <255
  即长度，==255 时后跟 2 字节大端长度）。
* 语义子集：标准元素 1 -> 4/8 字节无符号整数；标准元素 8 -> 4 字节 IPv4；
  标准元素 82 -> UTF-8 文本；其他元素（含任何企业元素）按原字节保存。

明确不支持：选项模板集合（set_id 3）、集合填充字节、采样/抽样、网络收发、
模板撤销全域清除、任何本文件之外的协议特性。
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

IPFIX_VERSION = 10
MESSAGE_HEADER_LENGTH = 16
SET_HEADER_LENGTH = 4
TEMPLATE_SET_ID = 2
MIN_DATA_SET_ID = 256
VARLEN = 65535
ENTERPRISE_BIT = 0x8000
ELEMENT_ID_MASK = 0x7FFF

# 语义子集：标准（无企业位）元素的固定解释规则。
SEMANTIC_UINT = 1
SEMANTIC_IPV4 = 8
SEMANTIC_TEXT = 82
_UINT_ALLOWED_LENGTHS = (4, 8)
_IPV4_FIXED_LENGTH = 4


class IPFIXError(Exception):
    """本包所有错误的基类。"""


class MessageError(IPFIXError):
    """单条消息层面的结构/字段错误。坏文件仍占据其 capture_pos。"""

    def __init__(self, code: str, detail: str = "", *, set_index: Optional[int] = None):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.set_index = set_index


class FieldDecodeError(IPFIXError):
    """数据集合按某模板解码字段时失败（调用方决定消息失败还是隔离等待集合）。"""

    def __init__(self, code: str, detail: str, *, set_index: int, record_index: int):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.set_index = set_index
        self.record_index = record_index


# ---- 消息错误码（稳定标识，README 有对照表）--------------------------------
ERR_FILE_READ = "file_read_error"
ERR_TOO_SHORT = "header_too_short"
ERR_BAD_VERSION = "bad_version"
ERR_LENGTH_MISMATCH = "length_mismatch"
ERR_UNSUPPORTED_SET = "unsupported_set_id"
ERR_SET_TRUNCATED = "set_declared_out_of_bounds"
ERR_SET_TOO_SHORT = "set_length_too_short"
ERR_PADDING_TRAILER = "padding_or_trailing_bytes"
ERR_TEMPLATE_TRUNCATED = "template_record_truncated"
ERR_BAD_TEMPLATE_ID = "template_id_below_256"
ERR_DUPLICATE_FIELD = "duplicate_field_identity"
ERR_BAD_FIELD_LENGTH = "field_length_invalid"
ERR_UNSUPPORTED_SEMANTIC = "unsupported_semantic_length"
ERR_TEMPLATE_TRAILER = "template_set_trailing_bytes"
ERR_EMPTY_DATA_SET = "empty_data_set"
ERR_BAD_TEXT = "bad_utf8_text"
ERR_FIELD_OUT_OF_BOUNDS = "field_crosses_set_boundary"
ERR_VARLEN_TRUNCATED = "varlen_prefix_truncated"
ERR_VARLEN_OUT_OF_BOUNDS = "varlen_value_out_of_bounds"
ERR_PARTIAL_RECORD = "partial_record_at_set_end"


# ---------------------------------------------------------------------------
# 线格式数据模型
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FieldSpec:
    """模板中的一条字段说明。enterprise_number 为 None 表示企业位不存在。"""

    enterprise_number: Optional[int]
    element_id: int
    length: int  # 正固定长度，或 65535 表示变长

    @property
    def is_variable(self) -> bool:
        return self.length == VARLEN

    @property
    def identity(self) -> Tuple[int, int]:
        return (self.enterprise_number or 0, self.element_id)


@dataclass(frozen=True)
class TemplateRecord:
    template_id: int
    fields: Tuple[FieldSpec, ...]

    @property
    def is_withdrawal(self) -> bool:
        return len(self.fields) == 0


@dataclass(frozen=True)
class ParsedSet:
    set_index: int
    set_id: int
    set_offset: int          # 集合头在消息中的绝对偏移
    set_length: int          # 含集合头
    body_offset: int
    body_length: int
    templates: Tuple[TemplateRecord, ...]  # 仅模板集合非空


@dataclass(frozen=True)
class ParsedMessage:
    raw: bytes
    export_time: int
    sequence_number: int
    observation_domain_id: int
    sets: Tuple[ParsedSet, ...]


@dataclass(frozen=True)
class DecodedField:
    field_index: int
    enterprise_number: Optional[int]
    element_id: int
    value_type: str          # 'uint' | 'ipv4' | 'text' | 'bytes'
    value: object            # int | str(IP) | str(text) | bytes
    raw: bytes
    field_offset: int        # 字段起点绝对偏移（变长字段为长度前缀起点）
    field_end: int           # 字段结束绝对偏移（不含）
    value_offset: int        # 正文起点绝对偏移
    value_length: int
    prefix_offset: Optional[int]
    prefix_length: Optional[int]


# ---------------------------------------------------------------------------
# 合成消息构造器
# ---------------------------------------------------------------------------
def field_spec(element_id: int, length: int, enterprise_number: Optional[int] = None) -> FieldSpec:
    """构造字段说明；enterprise_number 给整数（>=0）即置企业位，None 表示标准元素。"""
    if not 0 <= element_id <= ELEMENT_ID_MASK:
        raise ValueError("element_id 超出 15 位范围")
    if length != VARLEN and not 1 <= length <= VARLEN - 1:
        raise ValueError("固定长度必须为 1..65534，或使用 65535 变长")
    if enterprise_number is not None and not 0 <= enterprise_number <= 0xFFFFFFFF:
        raise ValueError("enterprise_number 超出 32 位范围")
    return FieldSpec(enterprise_number, element_id, length)


def template_record(template_id: int, fields: Sequence[FieldSpec]) -> bytes:
    """编码一条模板记录（field_count == len(fields)）。"""
    if template_id < MIN_DATA_SET_ID:
        raise ValueError("模板编号至少 256")
    out = struct.pack("!HH", template_id, len(fields))
    for f in fields:
        head = f.element_id | (ENTERPRISE_BIT if f.enterprise_number is not None else 0)
        out += struct.pack("!HH", head, f.length)
        if f.enterprise_number is not None:
            out += struct.pack("!I", f.enterprise_number)
    return out


def withdrawal_record(template_id: int) -> bytes:
    """编码一条撤销记录（field_count == 0，仅撤销指定模板）。"""
    if template_id < MIN_DATA_SET_ID:
        raise ValueError("模板编号至少 256")
    return struct.pack("!HH", template_id, 0)


def template_set(records: Sequence[bytes]) -> bytes:
    body = b"".join(records)
    return struct.pack("!HH", TEMPLATE_SET_ID, SET_HEADER_LENGTH + len(body)) + body


def variable_field(payload: bytes) -> bytes:
    """按 RFC 7011 变长规则编码：<255 单字节长度，否则 0xFF + 2 字节大端长度。"""
    n = len(payload)
    if n < 255:
        return struct.pack("!B", n) + payload
    if n <= 0xFFFF:
        return b"\xff" + struct.pack("!H", n) + payload
    raise ValueError("本子集变长正文不超过 65535 字节")


def data_set(template_id: int, record_bodies: Sequence[bytes]) -> bytes:
    if template_id < MIN_DATA_SET_ID:
        raise ValueError("数据集合 set_id 至少 256")
    body = b"".join(record_bodies)
    if not body:
        raise ValueError("本子集不允许空数据集合")
    return struct.pack("!HH", template_id, SET_HEADER_LENGTH + len(body)) + body


def message(export_time: int,
            sequence_number: int,
            observation_domain_id: int,
            sets: Sequence[bytes],
            *,
            version: int = IPFIX_VERSION,
            declared_length: Optional[int] = None) -> bytes:
    """拼装一条单消息 IPFIX 报文。declared_length 可用于制造长度不一致的坏消息。"""
    body = b"".join(sets)
    length = declared_length if declared_length is not None else MESSAGE_HEADER_LENGTH + len(body)
    return struct.pack("!HHIII", version, length, export_time, sequence_number,
                       observation_domain_id) + body


# ---------------------------------------------------------------------------
# 解析（纯结构校验；数据记录的语义解码在 decode_data_set）
# ---------------------------------------------------------------------------
def _validate_field_spec(f: FieldSpec) -> None:
    if f.is_variable:
        if f.enterprise_number is None and f.element_id == SEMANTIC_IPV4:
            raise MessageError(ERR_UNSUPPORTED_SEMANTIC,
                               "元素 8 仅支持 4 字节固定长度 IPv4")
        return
    if f.enterprise_number is None:
        if f.element_id == SEMANTIC_UINT and f.length not in _UINT_ALLOWED_LENGTHS:
            raise MessageError(ERR_UNSUPPORTED_SEMANTIC,
                               "元素 1 仅支持 4 或 8 字节无符号数")
        if f.element_id == SEMANTIC_IPV4 and f.length != _IPV4_FIXED_LENGTH:
            raise MessageError(ERR_UNSUPPORTED_SEMANTIC,
                               "元素 8 仅支持 4 字节 IPv4")


def _parse_template_set(pset: ParsedSet, raw: bytes) -> List[TemplateRecord]:
    rel = pset.body_offset
    body_end = pset.set_offset + pset.set_length
    records: List[TemplateRecord] = []
    while rel < body_end:
        if rel + 4 > body_end:
            raise MessageError(ERR_TEMPLATE_TRUNCATED, "模板记录头不完整",
                               set_index=pset.set_index)
        template_id, field_count = struct.unpack_from("!HH", raw, rel)
        rel += 4
        if template_id < MIN_DATA_SET_ID:
            raise MessageError(ERR_BAD_TEMPLATE_ID,
                               f"template_id={template_id} 小于 256",
                               set_index=pset.set_index)
        fields: List[FieldSpec] = []
        seen = set()
        for _ in range(field_count):
            if rel + 4 > body_end:
                raise MessageError(ERR_TEMPLATE_TRUNCATED, "字段说明不完整",
                                   set_index=pset.set_index)
            head, flen = struct.unpack_from("!HH", raw, rel)
            rel += 4
            ent_flag = bool(head & ENTERPRISE_BIT)
            element_id = head & ELEMENT_ID_MASK
            enterprise_number: Optional[int] = None
            if ent_flag:
                if rel + 4 > body_end:
                    raise MessageError(ERR_TEMPLATE_TRUNCATED,
                                       "企业号字段不完整", set_index=pset.set_index)
                (enterprise_number,) = struct.unpack_from("!I", raw, rel)
                rel += 4
            if flen != VARLEN and not 1 <= flen <= VARLEN - 1:
                raise MessageError(ERR_BAD_FIELD_LENGTH,
                                   f"字段长度 {flen} 非法", set_index=pset.set_index)
            spec = FieldSpec(enterprise_number, element_id, flen)
            if spec.identity in seen:
                raise MessageError(ERR_DUPLICATE_FIELD,
                                   f"同模板内重复字段身份 {spec.identity}",
                                   set_index=pset.set_index)
            seen.add(spec.identity)
            _validate_field_spec(spec)
            fields.append(spec)
        if rel > body_end:
            raise MessageError(ERR_TEMPLATE_TRUNCATED, "模板记录越界",
                               set_index=pset.set_index)
        records.append(TemplateRecord(template_id, tuple(fields)))
    if rel != body_end:
        raise MessageError(ERR_TEMPLATE_TRAILER, "模板集合存在残余字节",
                           set_index=pset.set_index)
    return records


def parse_message(raw: bytes) -> ParsedMessage:
    """对整条消息做结构校验并返回解析结果；不做任何状态变更。"""
    if len(raw) < MESSAGE_HEADER_LENGTH:
        raise MessageError(ERR_TOO_SHORT,
                           f"仅 {len(raw)} 字节，不足 16 字节消息头")
    version, length, export_time, sequence_number, obs_domain = struct.unpack_from(
        "!HHIII", raw, 0)
    if version != IPFIX_VERSION:
        raise MessageError(ERR_BAD_VERSION, f"version={version}，必须为 10")
    if length != len(raw):
        raise MessageError(ERR_LENGTH_MISMATCH,
                           f"头长度 {length} != 文件长度 {len(raw)}")

    sets: List[ParsedSet] = []
    offset = MESSAGE_HEADER_LENGTH
    set_index = 0
    total = len(raw)
    while offset < total:
        if offset + SET_HEADER_LENGTH > total:
            raise MessageError(ERR_SET_TRUNCATED,
                               "集合头超出消息边界", set_index=set_index)
        set_id, set_length = struct.unpack_from("!HH", raw, offset)
        if set_length < SET_HEADER_LENGTH:
            raise MessageError(ERR_SET_TOO_SHORT,
                               f"set_length={set_length} 小于 4",
                               set_index=set_index)
        end = offset + set_length
        if end > total:
            raise MessageError(ERR_SET_TRUNCATED,
                               f"集合声明结束 {end} 超出消息 {total}",
                               set_index=set_index)
        if set_id == TEMPLATE_SET_ID:
            if set_length == SET_HEADER_LENGTH:
                raise MessageError(ERR_EMPTY_DATA_SET,
                                   "模板集合不含任何模板记录",
                                   set_index=set_index)
            pset = ParsedSet(set_index, set_id, offset, set_length,
                             offset + SET_HEADER_LENGTH,
                             set_length - SET_HEADER_LENGTH, ())
            records = tuple(_parse_template_set(pset, raw))
            sets.append(ParsedSet(set_index, set_id, offset, set_length,
                                  offset + SET_HEADER_LENGTH,
                                  set_length - SET_HEADER_LENGTH, records))
        elif set_id >= MIN_DATA_SET_ID:
            if set_length == SET_HEADER_LENGTH:
                raise MessageError(ERR_EMPTY_DATA_SET,
                                   "数据集合正文为空且无填充字节允许",
                                   set_index=set_index)
            sets.append(ParsedSet(set_index, set_id, offset, set_length,
                                  offset + SET_HEADER_LENGTH,
                                  set_length - SET_HEADER_LENGTH, ()))
        else:
            raise MessageError(ERR_UNSUPPORTED_SET,
                               f"不支持的 set_id={set_id}", set_index=set_index)
        offset = end
        set_index += 1
    if offset != total:
        # 本子集不允许集合填充字节：任何残余都按错误处理。
        raise MessageError(ERR_PADDING_TRAILER,
                           f"消息尾部残余 {total - offset} 字节")
    return ParsedMessage(raw, export_time, sequence_number, obs_domain, tuple(sets))


# ---------------------------------------------------------------------------
# 数据集合解码（即时解码与等待区解码共用，保证类型/来源表示一致）
# ---------------------------------------------------------------------------
def _convert(spec: FieldSpec, raw: bytes) -> Tuple[str, object]:
    if spec.enterprise_number is None:
        if spec.element_id == SEMANTIC_UINT:
            return "uint", int.from_bytes(raw, "big", signed=False)
        if spec.element_id == SEMANTIC_IPV4:
            return "ipv4", socket.inet_ntoa(raw)
        if spec.element_id == SEMANTIC_TEXT:
            try:
                return "text", raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise IPFIXError(ERR_BAD_TEXT) from exc
    return "bytes", bytes(raw)


def decode_data_set(set_bytes: bytes,
                    set_offset: int,
                    set_index: int,
                    layout: Sequence[FieldSpec]) -> List[Tuple[int, List[DecodedField]]]:
    """按给定布局解码一个完整数据集合（set_bytes 含 4 字节集合头）。

    所有偏移均为相对原消息的绝对偏移；变长字段的长度前缀与正文偏移分别保留。
    任何字段跨集合边界、变长前缀截断、残余半条记录均抛 FieldDecodeError。
    """
    end = len(set_bytes)
    rel = SET_HEADER_LENGTH
    out: List[Tuple[int, List[DecodedField]]] = []
    record_index = 0
    while rel < end:
        rec: List[DecodedField] = []
        for field_index, spec in enumerate(layout):
            if spec.is_variable:
                if rel >= end:
                    raise FieldDecodeError(ERR_VARLEN_TRUNCATED,
                                           "变长长度前缀缺失",
                                           set_index=set_index, record_index=record_index)
                first = set_bytes[rel]
                prefix_abs = set_offset + rel
                if first < 255:
                    prefix_len, value_len = 1, first
                else:
                    if rel + 3 > end:
                        raise FieldDecodeError(ERR_VARLEN_TRUNCATED,
                                               "0xFF 后 2 字节长度越界",
                                               set_index=set_index,
                                               record_index=record_index)
                    value_len = int.from_bytes(set_bytes[rel + 1:rel + 3], "big")
                    prefix_len = 3
                value_rel = rel + prefix_len
                if value_rel + value_len > end:
                    raise FieldDecodeError(ERR_VARLEN_OUT_OF_BOUNDS,
                                           f"变长正文 {value_rel}+{value_len} 越界",
                                           set_index=set_index,
                                           record_index=record_index)
                raw_value = bytes(set_bytes[value_rel:value_rel + value_len])
                try:
                    value_type, value = _convert(spec, raw_value)
                except IPFIXError as exc:
                    raise FieldDecodeError(exc.args[0], "UTF-8 文本解码失败",
                                           set_index=set_index,
                                           record_index=record_index) from exc
                rec.append(DecodedField(
                    field_index=field_index,
                    enterprise_number=spec.enterprise_number,
                    element_id=spec.element_id,
                    value_type=value_type,
                    value=value,
                    raw=raw_value,
                    field_offset=prefix_abs,
                    field_end=set_offset + value_rel + value_len,
                    value_offset=set_offset + value_rel,
                    value_length=value_len,
                    prefix_offset=prefix_abs,
                    prefix_length=prefix_len,
                ))
                rel = value_rel + value_len
            else:
                length = spec.length
                if rel + length > end:
                    raise FieldDecodeError(ERR_FIELD_OUT_OF_BOUNDS,
                                           f"字段 {field_index} 声明 {length} 字节跨集合边界",
                                           set_index=set_index,
                                           record_index=record_index)
                raw_value = bytes(set_bytes[rel:rel + length])
                try:
                    value_type, value = _convert(spec, raw_value)
                except IPFIXError as exc:
                    raise FieldDecodeError(exc.args[0], "UTF-8 文本解码失败",
                                           set_index=set_index,
                                           record_index=record_index) from exc
                abs_off = set_offset + rel
                rec.append(DecodedField(
                    field_index=field_index,
                    enterprise_number=spec.enterprise_number,
                    element_id=spec.element_id,
                    value_type=value_type,
                    value=value,
                    raw=raw_value,
                    field_offset=abs_off,
                    field_end=abs_off + length,
                    value_offset=abs_off,
                    value_length=length,
                    prefix_offset=None,
                    prefix_length=None,
                ))
                rel += length
        if not rec:
            raise FieldDecodeError(ERR_PARTIAL_RECORD, "空布局记录不可解码",
                                   set_index=set_index, record_index=record_index)
        out.append((record_index, rec))
        record_index += 1
    if rel != end:
        raise FieldDecodeError(ERR_PARTIAL_RECORD,
                               f"集合末尾残余 {end - rel} 字节半条记录",
                               set_index=set_index, record_index=record_index)
    return out
