"""离线 NAT 关联作业：从已入仓的流记录回溯可能的原始五元组。

本模块只回答一个问题：**对一段已观测到的 (realm, 五元组) 连接，在其有效时间
区间内，按地址转换日志，哪些原始 (realm, 五元组) 可能同时成立？证据是否追完整？**

它不是租户计费、流量统计或路径概率工具，也不使用“最近一条日志”猜测来源。
几个刻意坚持的语义：

* 证据必须是**同一时刻所有日志同时有效**的一条链，而不是“每条日志都与整段流
  有交集”。五元组按有向连接比较，域名称是身份的一部分。
* 到达非原始域而该时刻没有任何可用前驱日志时，保留这个 frontier，并把片段
  标为 incomplete；不删除断支路后宣称剩余来源已确定。
* 观察域本身就是原始域时，来源就是观察五元组，无需任何日志。
* 同一原始 (realm, 五元组) 经多条链到达只算一个候选，但所有路径的边都保留。
* 日志缺失只能说明“本库这条证据链没追完”，不能证明没有别的来源。

输入：配置 JSON、若干 UTF-8 JSONL 转换日志、请求 JSONL、现有 ipfix_offline
SQLite 库。索引建在调用者指定的工作目录，作业结束只删除本次创建的临时目录；
原库以只读事务读取，绝不写入。

时间与顺序约定（也是报告中的稳定顺序）：

* 日志有效区间为 ``[start_ms, end_ms)``；时刻是 0..2^64-1 的整数毫秒。
  SQLite 的 INTEGER 是有符号 64 位，索引中时间以 16 位零填充十六进制文本保存，
  定宽十六进制串的字典序等于整数序，从而 2^63 以上仍精确。
* 候选 / frontier / 图节点按 ``(realm, protocol, src_ip 数值, src_port,
  dst_ip 数值, dst_port)`` 升序；边按 ``mapping_id`` 升序；片段按时间升序。
* 每个边给出 ``mapping_id`` 与日志原件路径、物理行号。
* 结构错误（配置/日志/请求文件/库）与业务结论严格分开：前者在写出任何请求答案
  前失败（退出码 2）；``invalid_flow`` 只影响该请求（退出码 1，报告仍完整）；
  ``unmapped / incomplete / ambiguous / unique`` 都是成功作答的一部分。
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import tracemalloc
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1

# 业务结论（都不是程序错误）
STATUS_UNIQUE = "unique"
STATUS_AMBIGUOUS = "ambiguous"
STATUS_INCOMPLETE = "incomplete"
STATUS_UNMAPPED = "unmapped"
ALL_STATUSES = (STATUS_UNIQUE, STATUS_AMBIGUOUS, STATUS_INCOMPLETE,
                STATUS_UNMAPPED)

# 标准 IE（enterprise_number 必须为 NULL）
IE_PROTOCOL = 4
IE_SRC_PORT = 7
IE_SRC_IPV4 = 8
IE_DST_PORT = 11
IE_DST_IPV4 = 12
IE_START_MS = 152
IE_END_MS = 153
REQUIRED_IESS = (IE_PROTOCOL, IE_SRC_PORT, IE_SRC_IPV4, IE_DST_PORT,
                 IE_DST_IPV4, IE_START_MS, IE_END_MS)
_REQUIRED_IE_LENGTHS = {
    IE_PROTOCOL: 1,
    IE_SRC_PORT: 2,
    IE_SRC_IPV4: 4,
    IE_DST_PORT: 2,
    IE_DST_IPV4: 4,
    IE_START_MS: 8,
    IE_END_MS: 8,
}

FiveTuple = Tuple[int, str, int, str, int]
State = Tuple[str, int, str, int, str, int]   # realm + five-tuple


# ---------------------------------------------------------------------------
# 错误类型：结构错误（无法开始作业）与业务结论（invalid_flow 等）分开
# ---------------------------------------------------------------------------
class NatError(Exception):
    """本模块所有结构错误的基类。"""

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": "nat_error", "detail": str(self)}


class ConfigError(NatError):
    def __init__(self, code: str, detail: str, location: Optional[str] = None):
        super().__init__(f"{code}: {detail}" + (f" @ {location}" if location else ""))
        self.code = code
        self.detail = detail
        self.location = location

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": "config_error", "code": self.code,
                "detail": self.detail, "location": self.location}


class NatLogError(NatError):
    def __init__(self, code: str, detail: str, *, file: Optional[str] = None,
                 line: Optional[int] = None):
        super().__init__(f"{code}: {detail}"
                         + (f" @ {file}:{line}" if file is not None else ""))
        self.code = code
        self.detail = detail
        self.file = file
        self.line = line

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": "log_error", "code": self.code, "detail": self.detail,
                "file": self.file, "line": self.line}


class RequestFileError(NatError):
    def __init__(self, code: str, detail: str, *, file: Optional[str] = None,
                 line: Optional[int] = None):
        super().__init__(f"{code}: {detail}"
                         + (f" @ {file}:{line}" if file is not None else ""))
        self.code = code
        self.detail = detail
        self.file = file
        self.line = line

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": "request_error", "code": self.code,
                "detail": self.detail, "file": self.file, "line": self.line}


class StoreError(NatError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": "store_error", "code": self.code, "detail": self.detail}


class _InvalidFlow(Exception):
    """某一条请求的业务结论：流无法作为关联输入（不是程序错误）。"""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------------------
# 基础校验
# ---------------------------------------------------------------------------
def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_ipv4(value: Any, location: str) -> str:
    if not isinstance(value, str):
        raise ConfigError("bad_ipv4", "IPv4 必须以规范点分十进制字符串给出", location)
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ConfigError("bad_ipv4", f"非法 IPv4 {value!r}: {exc}", location) from None
    canonical = str(addr)
    if canonical != value:
        raise ConfigError("bad_ipv4",
                          f"IPv4 不是规范点分十进制：{value!r}（应为 {canonical!r}）",
                          location)
    return canonical


def _parse_port(value: Any, location: str) -> int:
    if not _is_int(value) or not 0 <= value <= 65535:
        raise ConfigError("bad_port",
                          f"端口必须为 0..65535 的整数，得到 {value!r}", location)
    return value


def _parse_protocol(value: Any, location: str) -> int:
    if not _is_int(value) or value not in (6, 17):
        raise ConfigError("bad_protocol",
                          f"本版仅接受 protocol=6 或 17，得到 {value!r}", location)
    return value


def _parse_five_tuple(value: Any, location: str) -> FiveTuple:
    if not isinstance(value, (list, tuple)) or len(value) != 5:
        raise ConfigError(
            "bad_five_tuple",
            "五元组必须是 [protocol, src_ip, src_port, dst_ip, dst_port]",
            location)
    return (_parse_protocol(value[0], location + "[0]"),
            _parse_ipv4(value[1], location + "[1]"),
            _parse_port(value[2], location + "[2]"),
            _parse_ipv4(value[3], location + "[3]"),
            _parse_port(value[4], location + "[4]"))


def _parse_time(value: Any, location: str, code: str = "bad_time") -> int:
    if not _is_int(value) or not 0 <= value <= UINT64_MAX:
        raise ConfigError(code,
                          f"毫秒时刻必须为 0..2^64-1 的整数（不接受布尔/浮点），"
                          f"得到 {value!r}", location)
    return value


def _hex_time(value: int) -> str:
    return f"{value:016x}"


def _unhex_time(value: Any) -> int:
    return int(value, 16)


def _state_to_obj(state: State) -> Dict[str, Any]:
    return {"realm": state[0], "five_tuple": list(state[1:])}


def _state_sort_key(state: State):
    proto, sip, sport, dip, dport = state[1:]
    return (state[0], proto, int(ipaddress.IPv4Address(sip)), sport,
            int(ipaddress.IPv4Address(dip)), dport)


def _jsonable_state(state: State) -> List[Any]:
    return [state[0], *state[1:]]


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class NatConfig:
    realms: Tuple[str, ...]
    links: Tuple[Tuple[str, str], ...]          # (inner, outer)
    origins: Tuple[str, ...]
    observations: Dict[Tuple[str, str, int], str]
    link_set: frozenset = field(repr=False)
    origin_set: frozenset = field(repr=False)


def load_config(path: str) -> Tuple[NatConfig, str]:
    """读取并校验配置；返回 (配置, 文件 SHA-256)。任何引用/身份错误定位拒绝。"""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ConfigError("config_read_error", str(exc), path) from None
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError("config_not_utf8", str(exc), path) from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError("config_bad_json", exc.msg,
                          f"{path}:{exc.lineno}:{exc.colno}") from None
    if not isinstance(data, dict):
        raise ConfigError("config_not_object", "配置顶层必须是 JSON 对象", path)
    for key in ("realms", "links", "origins", "observations"):
        if key not in data:
            raise ConfigError("config_missing_key", f"缺少 {key}", path)

    realms_raw = data["realms"]
    if not isinstance(realms_raw, list):
        raise ConfigError("bad_realms", "realms 必须是数组", "realms")
    realms: List[str] = []
    seen_realms: Set[str] = set()
    for index, name in enumerate(realms_raw):
        loc = f"realms[{index}]"
        if not isinstance(name, str) or name == "":
            raise ConfigError("bad_realm_name", "观测域名称必须是非空字符串", loc)
        if name in seen_realms:
            raise ConfigError("duplicate_realm", f"观测域 {name!r} 重复", loc)
        seen_realms.add(name)
        realms.append(name)
    if not realms:
        raise ConfigError("empty_realms", "realms 不能为空", "realms")

    links_raw = data["links"]
    if not isinstance(links_raw, list):
        raise ConfigError("bad_links", "links 必须是数组", "links")
    links: List[Tuple[str, str]] = []
    seen_links: Set[Tuple[str, str]] = set()
    in_degree: Dict[str, int] = {r: 0 for r in realms}
    adjacency: Dict[str, List[str]] = {r: [] for r in realms}
    for index, item in enumerate(links_raw):
        loc = f"links[{index}]"
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ConfigError("bad_link", "link 必须是 [内侧域, 外侧域]", loc)
        inner, outer = item
        if not isinstance(inner, str) or inner not in seen_realms:
            raise ConfigError("unknown_realm", f"未知内侧域 {inner!r}", loc + "[0]")
        if not isinstance(outer, str) or outer not in seen_realms:
            raise ConfigError("unknown_realm", f"未知外侧域 {outer!r}", loc + "[1]")
        if inner == outer:
            raise ConfigError("self_link", f"links 不能自连：{inner!r}", loc)
        if (inner, outer) in seen_links:
            raise ConfigError("duplicate_link",
                              f"重复的 link {inner!r}->{outer!r}", loc)
        seen_links.add((inner, outer))
        links.append((inner, outer))
        adjacency[inner].append(outer)
        in_degree[outer] += 1

    # 环检测（Kahn）。links 有向“内侧 -> 外侧”，环会让回溯没有尽头。
    indeg = dict(in_degree)
    queue = [r for r in realms if indeg[r] == 0]
    visited = 0
    while queue:
        node = queue.pop()
        visited += 1
        for nxt in adjacency[node]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                queue.append(nxt)
    if visited != len(realms):
        raise ConfigError("link_cycle", "links 中存在有向环", "links")

    origins_raw = data["origins"]
    if not isinstance(origins_raw, list):
        raise ConfigError("bad_origins", "origins 必须是数组", "origins")
    origins: List[str] = []
    seen_origins: Set[str] = set()
    for index, name in enumerate(origins_raw):
        loc = f"origins[{index}]"
        if not isinstance(name, str) or name not in seen_realms:
            raise ConfigError("unknown_realm", f"未知原始域 {name!r}", loc)
        if name in seen_origins:
            raise ConfigError("duplicate_origin", f"原始域 {name!r} 重复", loc)
        if in_degree[name] != 0:
            raise ConfigError("origin_has_incoming_edge",
                              f"{name!r} 有入边，不能作为原始域", loc)
        seen_origins.add(name)
        origins.append(name)
    expected_origins = {r for r in realms if in_degree[r] == 0}
    if seen_origins != expected_origins:
        missing = sorted(expected_origins - seen_origins)
        extra = sorted(seen_origins - expected_origins)
        raise ConfigError(
            "origins_not_exact",
            f"origins 必须恰好等于没有入边的域；缺少 {missing}，多出 {extra}",
            "origins")
    if not origins:
        raise ConfigError("empty_origins", "至少需要一个原始域", "origins")

    observations_raw = data["observations"]
    if not isinstance(observations_raw, list):
        raise ConfigError("bad_observations",
                          "observations 必须是数组", "observations")
    observations: Dict[Tuple[str, str, int], str] = {}
    for index, item in enumerate(observations_raw):
        loc = f"observations[{index}]"
        if not isinstance(item, dict):
            raise ConfigError("bad_observation", "observation 必须是对象", loc)
        for key in ("exporter", "transport_session",
                    "observation_domain_id", "realm"):
            if key not in item:
                raise ConfigError("observation_missing_key", f"缺少 {key}", loc)
        exporter = item["exporter"]
        session = item["transport_session"]
        domain = item["observation_domain_id"]
        realm = item["realm"]
        if not isinstance(exporter, str) or exporter == "":
            raise ConfigError("bad_exporter", "exporter 必须是非空字符串",
                              loc + ".exporter")
        if not isinstance(session, str) or session == "":
            raise ConfigError("bad_transport_session",
                              "transport_session 必须是非空字符串",
                              loc + ".transport_session")
        if not _is_int(domain) or not 0 <= domain <= UINT32_MAX:
            raise ConfigError("bad_observation_domain_id",
                              "observation_domain_id 必须为 0..2^32-1 的整数",
                              loc + ".observation_domain_id")
        if not isinstance(realm, str) or realm not in seen_realms:
            raise ConfigError("unknown_realm",
                              f"未知观测域 {realm!r}", loc + ".realm")
        triple = (exporter, session, domain)
        if triple in observations:
            raise ConfigError(
                "duplicate_observation",
                f"({exporter!r}, {session!r}, {domain}) 已绑定到 "
                f"{observations[triple]!r}；不支持通配或跨会话借用", loc)
        observations[triple] = realm

    return (NatConfig(tuple(realms), tuple(links), tuple(origins),
                      observations, frozenset(seen_links),
                      frozenset(seen_origins)), digest)


# ---------------------------------------------------------------------------
# 转换日志：流式校验 + 磁盘索引
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class LogEdge:
    mapping_id: str
    from_state: State
    outer_state: State
    start_ms: int
    end_ms: int
    file_path: str
    line_no: int


@dataclass
class LogFileDigest:
    path: str
    sha256: str
    entries: int
    bytes_read: int


_LOG_COLUMNS = (
    "mapping_id, file_path, line_no, from_realm, from_proto, from_sip,"
    " from_sport, from_dip, from_dport, to_realm, to_proto, to_sip,"
    " to_sport, to_dip, to_dport, start_hex, end_hex"
)
_INSERT_LOG = ("INSERT INTO nat_logs(" + _LOG_COLUMNS + ") VALUES ("
               + ",".join("?" * 17) + ")")


def _read_jsonl_lines(path: str) -> Iterator[Tuple[int, bytes]]:
    """按物理行产出 (1 起始行号, 原始字节)。"""
    try:
        fh = open(path, "rb")
    except OSError as exc:
        raise NatLogError("log_read_error", str(exc), file=path) from None
    with fh:
        line_no = 0
        for raw in fh:
            line_no += 1
            yield line_no, raw


def _decode_json_line(raw: bytes, *, file: str, line_no: int,
                      error_cls) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise error_cls("bad_utf8", str(exc), file=file, line=line_no) from None
    if text.startswith("﻿"):
        text = text[1:]
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise error_cls("bad_json", exc.msg, file=file, line=line_no) from None


def _validate_log_object(obj: Any, *, file: str, line_no: int,
                         cfg: NatConfig) -> Dict[str, Any]:
    def fail(code: str, detail: str):
        raise NatLogError(code, detail, file=file, line=line_no)

    if not isinstance(obj, dict):
        fail("log_not_object", "每行必须是 JSON 对象")
    for key in ("mapping_id", "from_realm", "to_realm", "before", "after",
                "start_ms", "end_ms"):
        if key not in obj:
            fail("log_missing_field", f"缺少字段 {key}")
    mapping_id = obj["mapping_id"]
    if not isinstance(mapping_id, str) or mapping_id == "":
        fail("bad_mapping_id", "mapping_id 必须是非空字符串")
    from_realm = obj["from_realm"]
    to_realm = obj["to_realm"]
    if not isinstance(from_realm, str) or from_realm not in cfg.realms:
        fail("unknown_realm", f"未知 from_realm {from_realm!r}")
    if not isinstance(to_realm, str) or to_realm not in cfg.realms:
        fail("unknown_realm", f"未知 to_realm {to_realm!r}")
    if (from_realm, to_realm) not in cfg.link_set:
        fail("not_a_link",
             f"域对 {from_realm!r}->{to_realm!r} 不是配置中的 link")
    try:
        before = _parse_five_tuple(obj["before"], "before")
        after = _parse_five_tuple(obj["after"], "after")
    except ConfigError as exc:
        fail(exc.code, f"{exc.detail} @ {exc.location}")
    if before[0] != after[0]:
        fail("protocol_changed",
             f"NAT 不得改变协议：before={before[0]}, after={after[0]}")
    try:
        start_ms = _parse_time(obj["start_ms"], "start_ms")
        end_ms = _parse_time(obj["end_ms"], "end_ms")
    except ConfigError as exc:
        fail(exc.code, f"{exc.detail} @ {exc.location}")
    if not start_ms < end_ms:
        fail("bad_interval",
             f"要求 start_ms < end_ms，得到 [{start_ms},{end_ms})")
    return {
        "mapping_id": mapping_id,
        "from_realm": from_realm,
        "to_realm": to_realm,
        "before": before,
        "after": after,
        "start_ms": start_ms,
        "end_ms": end_ms,
    }


_INDEX_SCHEMA = """
CREATE TABLE nat_logs (
    mapping_id  TEXT PRIMARY KEY,
    file_path   TEXT NOT NULL,
    line_no     INTEGER NOT NULL,
    from_realm  TEXT NOT NULL,
    from_proto  INTEGER NOT NULL,
    from_sip    TEXT NOT NULL,
    from_sport  INTEGER NOT NULL,
    from_dip    TEXT NOT NULL,
    from_dport  INTEGER NOT NULL,
    to_realm    TEXT NOT NULL,
    to_proto    INTEGER NOT NULL,
    to_sip      TEXT NOT NULL,
    to_sport    INTEGER NOT NULL,
    to_dip      TEXT NOT NULL,
    to_dport    INTEGER NOT NULL,
    start_hex   TEXT NOT NULL,
    end_hex     TEXT NOT NULL
);
CREATE INDEX idx_nat_lookup ON nat_logs(
    to_realm, to_proto, to_sip, to_sport, to_dip, to_dport, start_hex);
"""


def build_index(cfg: NatConfig, log_paths: Sequence[str], index_path: str,
                *, batch_size: int = 1000) -> Tuple[List[LogFileDigest], int]:
    """流式读取日志并建磁盘索引；任何错误使作业在输出请求答案前失败。

    返回 (各日志摘要, 日志条数)。索引同时约束域、外侧五元组和 start_hex：
    查询只用等值前六列 + start_hex 范围，再由 end_hex 过滤，不扫描整表。
    """
    conn = sqlite3.connect(index_path)
    digests: List[LogFileDigest] = []
    total = 0
    try:
        conn.executescript(_INDEX_SCHEMA)
        with conn:
            for path in log_paths:
                sha = hashlib.sha256()
                entries = 0
                bytes_read = 0
                batch: List[Tuple[Any, ...]] = []
                last_line = 0
                batch_last_line = 0
                for line_no, raw in _read_jsonl_lines(path):
                    sha.update(raw)
                    bytes_read += len(raw)
                    last_line = line_no
                    stripped = raw.rstrip(b"\r\n")
                    if not stripped.strip():
                        raise NatLogError("empty_line",
                                          "转换日志不允许空行",
                                          file=path, line=line_no)
                    obj = _decode_json_line(stripped, file=path, line_no=line_no,
                                            error_cls=NatLogError)
                    item = _validate_log_object(obj, file=path,
                                                line_no=line_no, cfg=cfg)
                    before = item["before"]
                    after = item["after"]
                    batch.append((
                        item["mapping_id"], path, line_no,
                        item["from_realm"], before[0], before[1], before[2],
                        before[3], before[4],
                        item["to_realm"], after[0], after[1], after[2],
                        after[3], after[4],
                        _hex_time(item["start_ms"]),
                        _hex_time(item["end_ms"]),
                    ))
                    batch_last_line = line_no
                    entries += 1
                    total += 1
                    if len(batch) >= batch_size:
                        _insert_log_batch(conn, batch, path, batch_last_line)
                        batch.clear()
                if batch:
                    _insert_log_batch(conn, batch, path, batch_last_line)
                digests.append(LogFileDigest(path, sha.hexdigest(), entries,
                                             bytes_read))
            conn.execute("ANALYZE")
    finally:
        conn.close()
    return digests, total


def _insert_log_batch(conn: sqlite3.Connection, batch: List[Tuple[Any, ...]],
                      path: str, line_no: int) -> None:
    """批量插入；重复 mapping_id 时定位到两处日志行并中止整个作业。"""
    conn.execute("SAVEPOINT nat_batch")
    try:
        conn.executemany(_INSERT_LOG, batch)
        conn.execute("RELEASE nat_batch")
        return
    except sqlite3.IntegrityError:
        conn.execute("ROLLBACK TO nat_batch")
        conn.execute("RELEASE nat_batch")
    for row in batch:
        try:
            conn.execute(_INSERT_LOG, row)
        except sqlite3.IntegrityError:
            prior = conn.execute(
                "SELECT file_path, line_no FROM nat_logs WHERE mapping_id=?",
                (row[0],)).fetchone()
            raise NatLogError(
                "duplicate_mapping_id",
                f"mapping_id {row[0]!r} 重复；首次出现于 "
                f"{prior[0]}:{prior[1]}",
                file=row[1], line=row[2]) from None


# ---------------------------------------------------------------------------
# 请求文件
# ---------------------------------------------------------------------------
def load_requests(path: str) -> List[Tuple[str, int]]:
    """读取请求 JSONL；结构错误（重复 request_id、非正整数 flow_id 等）中止作业。"""
    requests: List[Tuple[str, int]] = []
    seen: Dict[str, int] = {}
    try:
        fh = open(path, "rb")
    except OSError as exc:
        raise RequestFileError("request_read_error", str(exc),
                               file=path) from None
    with fh:
        for line_no, raw in enumerate(fh, 1):
            stripped = raw.rstrip(b"\r\n")
            if not stripped.strip():
                raise RequestFileError("empty_line", "请求文件不允许空行",
                                       file=path, line=line_no)
            obj = _decode_json_line(stripped, file=path, line_no=line_no,
                                    error_cls=RequestFileError)
            if not isinstance(obj, dict):
                raise RequestFileError("request_not_object",
                                       "每行必须是 JSON 对象",
                                       file=path, line=line_no)
            for key in ("request_id", "flow_id"):
                if key not in obj:
                    raise RequestFileError("request_missing_field",
                                           f"缺少字段 {key}",
                                           file=path, line=line_no)
            request_id = obj["request_id"]
            flow_id = obj["flow_id"]
            if not isinstance(request_id, str) or request_id == "":
                raise RequestFileError("bad_request_id",
                                       "request_id 必须是非空字符串",
                                       file=path, line=line_no)
            if request_id in seen:
                raise RequestFileError(
                    "duplicate_request_id",
                    f"request_id {request_id!r} 重复；首次出现于第 "
                    f"{seen[request_id]} 行", file=path, line=line_no)
            if not _is_int(flow_id) or flow_id <= 0:
                raise RequestFileError("bad_flow_id",
                                       f"flow_id 必须是正整数，得到 {flow_id!r}",
                                       file=path, line=line_no)
            seen[request_id] = line_no
            requests.append((request_id, flow_id))
    return requests


# ---------------------------------------------------------------------------
# 只读流字段提取
# ---------------------------------------------------------------------------
@dataclass
class ObservedFlow:
    flow_id: int
    realm: str
    five_tuple: FiveTuple
    start_ms: int
    end_ms: int
    evidence: Dict[str, Any]


class NatCorrelator:
    """构建一次索引，随后在同一只读事务里回答一批请求。

    用法::

        from ipfix_offline.nat_correlate import (
            NatCorrelator, load_requests)

        with NatCorrelator("store.db", "topology.json",
                           ["nat1.jsonl", "nat2.jsonl"],
                           work_dir="/tmp/job") as nc:
            report = nc.correlate_requests(load_requests("requests.jsonl"))
    """

    def __init__(self, db_path: str, config_path: str,
                 log_paths: Sequence[str], work_dir: str, *,
                 measure_memory: bool = True, keep_index: bool = False):
        if not os.path.isdir(work_dir):
            raise StoreError("work_dir_missing",
                             f"工作目录不存在：{work_dir}")
        if not log_paths:
            raise NatLogError("no_logs", "至少需要一份转换日志")
        self.db_path = db_path
        self.work_dir = work_dir
        self.keep_index = keep_index
        self.index_path: Optional[str] = None
        self._tmpdir: Optional[str] = None
        self._own_tmpdir = False
        self.stats: Dict[str, Any] = {
            "lookups": 0,
            "log_rows_returned": 0,
        }
        self._flow_conn: Optional[sqlite3.Connection] = None
        self.index_conn: Optional[sqlite3.Connection] = None
        self._mem_started = False
        self.index_build_ms = 0.0

        started = time.monotonic()
        try:
            self._tmpdir = tempfile.mkdtemp(prefix=".ipfix_nat_", dir=work_dir)
            self._own_tmpdir = True
            self.index_path = os.path.join(self._tmpdir, "nat_index.sqlite")
            self.config, self.config_sha256 = load_config(config_path)
            self.log_digests, self.log_entry_count = build_index(
                self.config, log_paths, self.index_path)
            # 日志不进入 Python 容器（流式写索引），因此请求阶段的工作集只有
            # 单个可达子图；tracemalloc 只量这一段，避免给索引扫描加常数开销。
            if measure_memory:
                tracemalloc.start()
                self._mem_started = True
            self.index_conn = sqlite3.connect(self.index_path)
            self.index_conn.row_factory = sqlite3.Row
            self._check_index_plan()
            self._flow_conn = _open_flow_db(db_path)
            self._begin_read_transaction()
        except BaseException:
            self.close()
            raise
        self.index_build_ms = (time.monotonic() - started) * 1000.0
        self._cache: Dict[Tuple[State, int, int], List[LogEdge]] = {}

    # ---------------------------------------------------------------- 生命周期
    def _check_index_plan(self) -> None:
        assert self.index_conn is not None
        row = self.index_conn.execute(
            "EXPLAIN QUERY PLAN SELECT mapping_id FROM nat_logs"
            " INDEXED BY idx_nat_lookup"
            " WHERE to_realm=? AND to_proto=? AND to_sip=? AND to_sport=?"
            " AND to_dip=? AND to_dport=? AND start_hex < ? AND end_hex > ?",
            ("r", 6, "0.0.0.0", 0, "0.0.0.0", 0,
             "f" * 16, "0" * 16)).fetchall()
        plan = " | ".join(str(r[3]) for r in row)
        self.stats["index_plan"] = plan
        if "idx_nat_lookup" not in plan:
            raise NatError(f"日志索引未生效（计划为 {plan}），拒绝全表扫描")

    def _begin_read_transaction(self) -> None:
        """一个只读事务覆盖整批请求的读取状态；不写原库。"""
        assert self._flow_conn is not None
        tables = {r[0] for r in self._flow_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "flows" not in tables or "flow_fields" not in tables:
            raise StoreError("not_an_ingest_db",
                             "数据库不是 ipfix_offline 接入库（缺少 flows/"
                             "flow_fields）")
        self._flow_conn.execute("BEGIN")
        # 触发一次读取以固定快照
        self._flow_conn.execute("SELECT flow_id FROM flows LIMIT 1").fetchone()

    def close(self) -> None:
        if self._mem_started:
            tracemalloc.stop()
            self._mem_started = False
        for attr in ("_flow_conn", "index_conn"):
            conn = getattr(self, attr, None)
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                setattr(self, attr, None)
        tmpdir = self._tmpdir
        if (self._own_tmpdir and tmpdir and not self.keep_index
                and os.path.isdir(tmpdir)):
            # 只删除本次创建的唯一临时目录；工作目录里其它文件不动
            shutil.rmtree(tmpdir, ignore_errors=True)
        self._tmpdir = None
        self._own_tmpdir = False

    def __enter__(self) -> "NatCorrelator":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --------------------------------------------------------------- 流字段提取
    def extract_flow(self, flow_id: int) -> ObservedFlow:
        assert self._flow_conn is not None
        row = self._flow_conn.execute(
            "SELECT * FROM flows WHERE flow_id=?", (flow_id,)).fetchone()
        if row is None:
            raise _InvalidFlow("flow_not_found", f"flow_id {flow_id} 不存在")
        fields = self._flow_conn.execute(
            "SELECT * FROM flow_fields WHERE flow_id=? ORDER BY field_index",
            (flow_id,)).fetchall()
        standard: Dict[int, sqlite3.Row] = {}
        enterprise_elements: Set[int] = set()
        for f in fields:
            if f["enterprise_number"] is not None:
                enterprise_elements.add(f["element_id"])
                continue
            standard[f["element_id"]] = f
        raw: Dict[int, bytes] = {}
        for element_id in REQUIRED_IESS:
            f = standard.get(element_id)
            if f is None:
                if element_id in enterprise_elements:
                    raise _InvalidFlow(
                        "enterprise_ie_cannot_substitute",
                        f"IE {element_id} 仅有企业字段，不能顶替标准 IE")
                raise _InvalidFlow("missing_standard_ie",
                                   f"缺少标准 IE {element_id}")
            blob = f["raw_blob"]
            if blob is None:
                raise _InvalidFlow("missing_standard_ie",
                                   f"标准 IE {element_id} 无原字节")
            blob = bytes(blob)
            expected = _REQUIRED_IE_LENGTHS[element_id]
            if len(blob) != expected:
                raise _InvalidFlow(
                    "bad_ie_length",
                    f"IE {element_id} 正文长度 {len(blob)}，要求 {expected}")
            raw[element_id] = blob
        protocol = raw[IE_PROTOCOL][0]
        if protocol not in (6, 17):
            raise _InvalidFlow("protocol_not_tcp_udp",
                               f"IE 4 协议为 {protocol}，本版仅 6/17")
        sip = str(ipaddress.IPv4Address(raw[IE_SRC_IPV4]))
        dip = str(ipaddress.IPv4Address(raw[IE_DST_IPV4]))
        sport = int.from_bytes(raw[IE_SRC_PORT], "big", signed=False)
        dport = int.from_bytes(raw[IE_DST_PORT], "big", signed=False)
        start_ms = int.from_bytes(raw[IE_START_MS], "big", signed=False)
        end_ms = int.from_bytes(raw[IE_END_MS], "big", signed=False)
        if not start_ms < end_ms:
            raise _InvalidFlow("bad_time_range",
                               f"IE152/153 起止非法：[{start_ms},{end_ms})")
        triple = (row["exporter"], row["transport_session"],
                  row["observation_domain_id"])
        realm = self.config.observations.get(triple)
        if realm is None:
            raise _InvalidFlow(
                "no_observation_realm",
                f"({triple[0]!r}, {triple[1]!r}, {triple[2]}) "
                f"没有精确观测域绑定")

        five: FiveTuple = (protocol, sip, sport, dip, dport)
        evidence = self._flow_evidence(row, fields, standard, five)
        return ObservedFlow(flow_id, realm, five, start_ms, end_ms, evidence)

    def _flow_evidence(self, row: sqlite3.Row, fields: Sequence[sqlite3.Row],
                       standard: Dict[int, sqlite3.Row],
                       five: FiveTuple) -> Dict[str, Any]:
        assert self._flow_conn is not None
        tv = self._flow_conn.execute(
            "SELECT * FROM template_versions WHERE version_seq=?",
            (row["version_seq"],)).fetchone()
        cap = self._flow_conn.execute(
            "SELECT file_path, sha256 FROM capture_positions WHERE capture_pos=?",
            (row["capture_pos"],)).fetchone()
        values: Dict[int, Any] = {
            IE_PROTOCOL: five[0],
            IE_SRC_IPV4: five[1],
            IE_SRC_PORT: five[2],
            IE_DST_IPV4: five[3],
            IE_DST_PORT: five[4],
            IE_START_MS: int.from_bytes(
                bytes(standard[IE_START_MS]["raw_blob"]), "big"),
            IE_END_MS: int.from_bytes(
                bytes(standard[IE_END_MS]["raw_blob"]), "big"),
        }
        ies = []
        for element_id in REQUIRED_IESS:
            f = standard[element_id]
            blob = bytes(f["raw_blob"])
            ies.append({
                "element_id": element_id,
                "raw_hex": blob.hex(),
                "raw_length": len(blob),
                "value": values[element_id],
                "field_offset": f["field_offset"],
                "field_end": f["field_end"],
                "value_offset": f["value_offset"],
                "value_length": f["value_length"],
            })
        return {
            "flow_id": row["flow_id"],
            "capture_pos": row["capture_pos"],
            "exporter": row["exporter"],
            "transport_session": row["transport_session"],
            "observation_domain_id": row["observation_domain_id"],
            "template_id": row["template_id"],
            "version_seq": row["version_seq"],
            "template_defined_pos": tv["defined_pos"] if tv else None,
            "template_layout": json.loads(tv["layout_json"]) if tv else None,
            "set_index": row["set_index"],
            "record_index": row["record_index"],
            "origin": row["origin"],
            "origin_pos": row["origin_pos"],
            "capture": ({"file_path": cap["file_path"],
                         "sha256": cap["sha256"]} if cap else None),
            "ies": ies,
        }

    # --------------------------------------------------------------- 索引查询
    def _logs_for_state(self, state: State, flow_start: int,
                        flow_end: int) -> List[LogEdge]:
        """按 (域, 五元组) 等值 + 时间相交查索引；每条日志至多被取一次。"""
        key = (state, flow_start, flow_end)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        assert self.index_conn is not None
        realm = state[0]
        proto, sip, sport, dip, dport = state[1:]
        rows = self.index_conn.execute(
            "SELECT " + _LOG_COLUMNS + " FROM nat_logs"
            " INDEXED BY idx_nat_lookup"
            " WHERE to_realm=? AND to_proto=? AND to_sip=? AND to_sport=?"
            " AND to_dip=? AND to_dport=? AND start_hex < ? AND end_hex > ?"
            " ORDER BY mapping_id",
            (realm, proto, sip, sport, dip, dport,
             _hex_time(flow_end), _hex_time(flow_start))
        ).fetchall()
        self.stats["lookups"] += 1
        self.stats["log_rows_returned"] += len(rows)
        out = [LogEdge(
            mapping_id=r["mapping_id"],
            from_state=(r["from_realm"], r["from_proto"], r["from_sip"],
                        r["from_sport"], r["from_dip"], r["from_dport"]),
            outer_state=state,
            start_ms=_unhex_time(r["start_hex"]),
            end_ms=_unhex_time(r["end_hex"]),
            file_path=r["file_path"], line_no=r["line_no"],
        ) for r in rows]
        self._cache[key] = out
        return out

    # ---------------------------------------------------------------- 关联核心
    def _overlapping_edges(self, flow: ObservedFlow) -> List[LogEdge]:
        """粗遍历：收集与流区间有交集、且由重叠日志可达的所有边。

        不读整份日志，逐状态用 (域, 五元组) 等值 + 时间相交查索引。结果是真实
        分段端点的超集；多出的端点由签名合并收敛。
        """
        initial: State = (flow.realm,) + flow.five_tuple
        seen: Set[State] = set()
        seen_edges: Set[Tuple[str, State]] = set()
        edges: List[LogEdge] = []
        stack = [initial]
        while stack:
            state = stack.pop()
            if state in seen:
                continue
            seen.add(state)
            for edge in self._logs_for_state(state, flow.start_ms, flow.end_ms):
                marker = (edge.mapping_id, state)
                if marker in seen_edges:
                    continue
                seen_edges.add(marker)
                edges.append(edge)
                stack.append(edge.from_state)
        return edges

    def _evaluate(self, flow: ObservedFlow, at_ms: int,
                  active_ids: Optional[Set[str]] = None) -> Dict[str, Any]:
        """时刻 at_ms 的反向证据图；只沿该时刻有效的日志走。"""
        initial: State = (flow.realm,) + flow.five_tuple
        nodes: Set[State] = set()
        edges: List[LogEdge] = []
        candidates: Set[State] = set()
        frontiers: Set[State] = set()
        visited: Set[State] = set()
        stack = [initial]
        initial_has_edge = False
        while stack:
            state = stack.pop()
            if state in visited:
                continue
            visited.add(state)
            nodes.add(state)
            active = [e for e in self._logs_for_state(
                state, flow.start_ms, flow.end_ms)
                if e.start_ms <= at_ms < e.end_ms
                and (active_ids is None or e.mapping_id in active_ids)]
            if not active:
                if state[0] in self.config.origin_set:
                    candidates.add(state)
                else:
                    frontiers.add(state)
                continue
            if state == initial:
                initial_has_edge = True
            for edge in active:
                edges.append(edge)
                stack.append(edge.from_state)

        if not initial_has_edge and initial[0] not in self.config.origin_set:
            status = STATUS_UNMAPPED
        elif frontiers:
            status = STATUS_INCOMPLETE
        elif len(candidates) == 1:
            status = STATUS_UNIQUE
        elif len(candidates) > 1:
            status = STATUS_AMBIGUOUS
        else:
            # 没有 frontier 也没有候选：证据链没有落脚点，按未追完处理
            status = STATUS_INCOMPLETE

        ordered_nodes = sorted(nodes, key=_state_sort_key)
        ordered_candidates = sorted(candidates, key=_state_sort_key)
        ordered_frontiers = sorted(frontiers, key=_state_sort_key)
        edge_rows = sorted(
            ({"mapping_id": e.mapping_id,
              "from": _state_to_obj(e.outer_state),
              "to": _state_to_obj(e.from_state),
              "log_file": e.file_path,
              "log_line": e.line_no,
              "valid": [e.start_ms, e.end_ms]} for e in edges),
            key=lambda e: e["mapping_id"])
        signature = (
            status,
            tuple(ordered_candidates),
            tuple(ordered_frontiers),
            tuple(ordered_nodes),
            tuple((e["mapping_id"], tuple(_jsonable_state(
                (e["from"]["realm"],) + tuple(e["from"]["five_tuple"]))),
                tuple(_jsonable_state(
                    (e["to"]["realm"],) + tuple(e["to"]["five_tuple"]))))
                for e in edge_rows),
        )
        return {
            "status": status,
            "candidates": [_state_to_obj(s) for s in ordered_candidates],
            "frontiers": [_state_to_obj(s) for s in ordered_frontiers],
            "nodes": [_state_to_obj(s) for s in ordered_nodes],
            "edges": edge_rows,
            "signature": signature,
        }

    def correlate_flow(self, flow: ObservedFlow) -> List[Dict[str, Any]]:
        """把流切成连续、不重叠、覆盖整个区间的片段，并给出每段的反向图。

        做法：先做一次**只沿重叠日志可达状态**的粗遍历，得到与流区间有交集的
        全部边；这些边的端点就是分段端点（真实端点的超集）。每个片段起点取该
        时刻有效边集合做反向图。整个过程只展开单个可达子图，不枚举完整来源链。
        """
        overlapping = self._overlapping_edges(flow)
        start, end = flow.start_ms, flow.end_ms
        points: Set[int] = {start, end}
        for edge in overlapping:
            if start < edge.start_ms < end:
                points.add(edge.start_ms)
            if start < edge.end_ms < end:
                points.add(edge.end_ms)
        ordered_points = sorted(points)
        ordered_edges = sorted(overlapping, key=lambda e: (e.start_ms, e.end_ms))
        fragments: List[Dict[str, Any]] = []
        cursor = 0            # ordered_edges[:cursor] 的 start_ms 都 <= lo
        for lo, hi in zip(ordered_points, ordered_points[1:]):
            if lo >= hi:      # 端点不产生零长度片段
                continue
            while cursor < len(ordered_edges) and ordered_edges[cursor].start_ms <= lo:
                cursor += 1
            active_ids = {e.mapping_id for e in ordered_edges[:cursor]
                          if e.end_ms > lo}
            result = self._evaluate(flow, lo, active_ids)
            sig = result.pop("signature")
            if fragments and fragments[-1]["_sig"] == sig:
                fragments[-1]["end_ms"] = hi
                continue
            fragment = {
                "start_ms": lo,
                "end_ms": hi,
                "status": result["status"],
                "origins": result["candidates"],
                "frontiers": result["frontiers"],
                "graph": {
                    "nodes": result["nodes"],
                    "edges": result["edges"],
                },
                "_sig": sig,
            }
            fragments.append(fragment)
        for fragment in fragments:
            fragment.pop("_sig", None)
        return fragments

    # ------------------------------------------------------------------ 批处理
    def correlate_requests(self, requests: Sequence[Tuple[str, int]],
                           *, include_evidence: bool = True) -> Dict[str, Any]:
        """逐请求给出 invalid_flow 或完整片段与图；业务结论不是程序错误。"""
        started = time.monotonic()
        results: List[Dict[str, Any]] = []
        counts = {status: 0 for status in ALL_STATUSES}
        invalid = 0
        fragment_count = 0
        determined = 0
        undetermined = 0
        for request_id, flow_id in requests:
            # 工作集上限：缓存只保留最近若干状态的 (域, 五元组, 时间) 查询结果，
            # 不保留整份日志；超过阈值即丢弃，随后按需重新走索引。
            if len(self._cache) > 4096:
                self._cache.clear()
            try:
                flow = self.extract_flow(flow_id)
            except _InvalidFlow as exc:
                invalid += 1
                results.append({
                    "request_id": request_id,
                    "flow_id": flow_id,
                    "outcome": "invalid_flow",
                    "reason": exc.reason,
                    "detail": exc.detail,
                })
                continue
            fragments = self.correlate_flow(flow)
            for fragment in fragments:
                counts[fragment["status"]] = counts.get(
                    fragment["status"], 0) + 1
                if fragment["status"] == STATUS_UNIQUE:
                    determined += 1
                else:
                    undetermined += 1
            fragment_count += len(fragments)
            item = {
                "request_id": request_id,
                "flow_id": flow_id,
                "outcome": "associated",
                "observed": {
                    "realm": flow.realm,
                    "five_tuple": list(flow.five_tuple),
                    "start_ms": flow.start_ms,
                    "end_ms": flow.end_ms,
                },
                "fragments": fragments,
            }
            if include_evidence:
                item["flow_evidence"] = flow.evidence
            results.append(item)
        elapsed_ms = (time.monotonic() - started) * 1000.0
        if self._mem_started:
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            self._mem_started = False
        else:
            peak = None
        graph_nodes = sum(len(f["graph"]["nodes"])
                          for r in results if r["outcome"] == "associated"
                          for f in r["fragments"])
        graph_edges = sum(len(f["graph"]["edges"])
                          for r in results if r["outcome"] == "associated"
                          for f in r["fragments"])
        report = {
            "complete": True,
            "requests": results,
            "summary": {
                "status": "complete",
                "request_count": len(requests),
                "associated_count": len(requests) - invalid,
                "invalid_flow_count": invalid,
                "fragment_count": fragment_count,
                "determined_fragment_count": determined,
                "undetermined_fragment_count": undetermined,
                "status_counts": counts,
                "graph_nodes_total": graph_nodes,
                "graph_edges_total": graph_edges,
            },
            "inputs": {
                "config_sha256": self.config_sha256,
                "topology": {
                    "realms": list(self.config.realms),
                    "links": [list(x) for x in self.config.links],
                    "origins": list(self.config.origins),
                },
                "logs": [{
                    "path": d.path, "sha256": d.sha256,
                    "entries": d.entries, "bytes": d.bytes_read,
                } for d in self.log_digests],
                "log_entries": self.log_entry_count,
                "database": os.path.abspath(self.db_path),
            },
            "index": {
                "lookups": self.stats["lookups"],
                "log_rows_returned": self.stats["log_rows_returned"],
                "plan": self.stats.get("index_plan"),
                "size_bytes": self.index_size_bytes(),
                "path": (self.index_path if self.keep_index else None),
            },
            "timing": {
                "index_build_ms": round(self.index_build_ms, 3),
                "requests_ms": round(elapsed_ms, 3),
            },
            # 峰值内存：请求阶段的 Python 分配峰值 + 进程级峰值 RSS（含索引
            # 建库与 SQLite 页缓存）。日志全文从不进入 Python 容器。
            "peak_python_bytes": peak,
            "peak_rss_bytes": _peak_rss_bytes(),
        }
        return report

    def export_mapping_index(self, path: str) -> int:
        """把 mapping_id -> (日志原件, 物理行号) 定位表流式写成 JSONL。

        逐行读取磁盘索引，不在 Python 容器里保留整表；返回写出条数。
        """
        assert self.index_conn is not None
        count = 0
        with open(path, "w", encoding="utf-8") as fh:
            cursor = self.index_conn.execute(
                "SELECT mapping_id, file_path, line_no FROM nat_logs"
                " ORDER BY mapping_id")
            for mapping_id, file_path, line_no in cursor:
                fh.write(json.dumps({
                    "mapping_id": mapping_id,
                    "file_path": file_path,
                    "line_no": line_no,
                }, ensure_ascii=False) + "\n")
                count += 1
        return count

    def index_size_bytes(self) -> int:
        if not self.index_path:
            return 0
        try:
            return os.path.getsize(self.index_path)
        except OSError:
            return 0


# ---------------------------------------------------------------------------
# 打开原库（只读）
# ---------------------------------------------------------------------------
def _open_flow_db(db_path: str) -> sqlite3.Connection:
    if not os.path.isfile(db_path):
        raise StoreError("db_not_found", f"数据库不存在：{db_path}")
    quoted = urllib.parse.quote(os.path.abspath(db_path))
    try:
        conn = sqlite3.connect(f"file:{quoted}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise StoreError("db_open_error", str(exc)) from None
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


# ---------------------------------------------------------------------------
# 便捷入口与命令行
# ---------------------------------------------------------------------------
def run_job(db_path: str, config_path: str, log_paths: Sequence[str],
            request_path: str, out_path: Optional[str], work_dir: str, *,
            measure_memory: bool = True,
            keep_index: bool = False,
            mapping_index_path: Optional[str] = None) -> Dict[str, Any]:
    """执行一次离线关联作业；结构错误在写任何请求答案前抛出。

    out_path 为 None 时不落盘；否则在全部请求完成后原子写入一个 JSON 文档。
    mapping_index_path 给出时额外写 mapping_id -> 日志文件/物理行号 的 JSONL。
    """
    requests = load_requests(request_path)
    with NatCorrelator(db_path, config_path, log_paths, work_dir,
                       measure_memory=measure_memory,
                       keep_index=keep_index) as nc:
        report = nc.correlate_requests(requests)
        if mapping_index_path:
            report["mapping_index"] = {
                "path": os.path.abspath(mapping_index_path),
                "entries": nc.export_mapping_index(mapping_index_path),
            }
    if out_path:
        _atomic_write_json(out_path, report)
    return report


def _peak_rss_bytes() -> Optional[int]:
    try:
        import resource
    except ImportError:      # 非 POSIX 平台
        return None
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux 以 KiB 计，macOS 以字节计
    if sys.platform == "darwin":
        return int(usage)
    return int(usage) * 1024


def _atomic_write_json(path: str, payload: Dict[str, Any]) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".nat_report_", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m ipfix_offline.nat_correlate",
        description="离线 NAT 关联：从 IPFIX 流按转换日志回溯原始五元组")
    p.add_argument("--db", required=True,
                   help="现有 ipfix_offline SQLite 库（只读）")
    p.add_argument("--config", required=True, help="观测域拓扑配置 JSON")
    p.add_argument("--log", action="append", default=[], required=True,
                   help="转换日志 JSONL，可重复给出多份")
    p.add_argument("--requests", required=True, help="请求 JSONL")
    p.add_argument("--out", required=True, help="输出 JSON 报告路径")
    p.add_argument("--work-dir", required=True,
                   help="临时索引用工作目录（只清理本次创建的文件）")
    p.add_argument("--keep-index", action="store_true",
                   help="保留本次临时索引（默认作业结束删除）")
    p.add_argument("--mapping-index", metavar="PATH",
                   help="额外输出 mapping_id -> 日志文件/物理行号 的 JSONL")
    p.add_argument("--no-memory", action="store_true",
                   help="关闭 tracemalloc 峰值统计")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run_job(args.db, args.config, args.log, args.requests,
                         args.out, args.work_dir,
                         measure_memory=not args.no_memory,
                         keep_index=args.keep_index,
                         mapping_index_path=args.mapping_index)
    except (ConfigError, NatLogError, RequestFileError,
            StoreError, NatError) as exc:
        print(json.dumps({"complete": False, "error": exc.as_dict()},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 2
    summary = report["summary"]
    print(json.dumps({
        "complete": True,
        "out": os.path.abspath(args.out),
        "summary": summary,
        "timing": report["timing"],
        "index": report["index"],
        "peak_python_bytes": report["peak_python_bytes"],
        "peak_rss_bytes": report["peak_rss_bytes"],
        "mapping_index": report.get("mapping_index"),
    }, ensure_ascii=False, indent=2))
    return 0 if summary["invalid_flow_count"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
