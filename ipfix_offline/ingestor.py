"""离线 IPFIX 模板解码接入器引擎。

解释模型（要点，详见 README）：

* 模板键 = (exporter, transport_session, observation_domain_id, template_id)。
  一次重启使用新 transport_session；同 exporter 的两个会话天然不共用模板。
* 一个消息内按集合与模板记录的原顺序解释，定义生效位置也包含该顺序；每次新定义
  （即使布局相同）都生成新版本号。数据集合绑定当时有效模板版本，之后改版不回溯。
* 无有效模板的数据集合以原字节入等待区，只能由同键的下一次定义接走（首份定义，
  不挑布局）；撤销形成屏障，此前等待以 template_withdrawn 结束；清单结束仍等待
  为 unresolved；容量隔离为 capacity_isolated；K 规则到期为 timeout。
* 消息原子性：先完整验证整条消息，再让模板变化/解码/接走/撤销生效；失败消息
  不安装模板、不清旧等待，仅在该位置末尾照常跑 K 到期扫描。
* 容量按集合头 + 正文总长计算，入队即检查，只隔离超限的新集合，不淘汰旧集合；
  同一消息内更晚的定义不挽救已隔离集合。
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from .wire import (
    DecodedField,
    FieldDecodeError,
    FieldSpec,
    IPFIXError,
    MessageError,
    ParsedMessage,
    ParsedSet,
    TemplateRecord,
    decode_data_set,
    parse_message,
)

# 等待集合的结束原因
END_UNRESOLVED = "unresolved"
END_TIMEOUT = "timeout"
END_WITHDRAWN = "template_withdrawn"
END_CAPACITY = "capacity_isolated"
END_BAD_FIELDS = "bad_field_isolated"
END_PICKED = "picked"   # 已被某版本接走并解码落盘（pending() 的 ended 中可查）
_ENDED_REASONS = (END_TIMEOUT, END_WITHDRAWN, END_CAPACITY,
                  END_BAD_FIELDS, END_PICKED)


class ManifestError(IPFIXError):
    """清单顺序/身份/内容冲突，本次导入被拒绝（位置未被占用）。"""


@dataclass(frozen=True)
class CaptureEntry:
    capture_pos: int
    exporter: str
    transport_session: str
    file_path: str


@dataclass
class WaitingEntry:
    id: int
    origin_pos: int
    exporter: str
    transport_session: str
    observation_domain_id: int
    template_id: int
    set_index: int
    set_offset: int
    set_bytes: bytes
    # 以下为消息处理过程中写入的终态（None=仍等待）
    end_reason: Optional[str] = None
    end_pos: Optional[int] = None
    bound_version_seq: Optional[int] = None
    decode_error_code: Optional[str] = None

    @property
    def key(self) -> Tuple[str, str, int, int]:
        return (self.exporter, self.transport_session,
                self.observation_domain_id, self.template_id)

    @property
    def size(self) -> int:
        return len(self.set_bytes)


@dataclass
class ImportResult:
    capture_pos: int
    status: str                      # imported | duplicate | failed
    error_code: Optional[str] = None
    error_detail: Optional[str] = None
    flows_inserted: int = 0
    sets_enqueued: int = 0
    sets_picked: int = 0
    sets_isolated: int = 0


@dataclass
class PendingSummary:
    unresolved_count: int
    unresolved_bytes: int
    ended: List[Dict[str, Any]]
    unexplained: List[Dict[str, Any]]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS template_version_seq (
    seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
    stub   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS capture_positions (
    capture_pos        INTEGER PRIMARY KEY,
    exporter           TEXT NOT NULL,
    transport_session  TEXT NOT NULL,
    file_path          TEXT NOT NULL,
    sha256             TEXT NOT NULL,
    length             INTEGER NOT NULL,
    status             TEXT NOT NULL,           -- imported | duplicate | failed
    error_code         TEXT,
    error_detail       TEXT,
    export_time        INTEGER,
    sequence_number    INTEGER,
    observation_domain_id INTEGER
);
CREATE TABLE IF NOT EXISTS template_versions (
    version_seq        INTEGER PRIMARY KEY,
    exporter           TEXT NOT NULL,
    transport_session  TEXT NOT NULL,
    observation_domain_id INTEGER NOT NULL,
    template_id        INTEGER NOT NULL,
    layout_json        TEXT NOT NULL,
    defined_pos        INTEGER NOT NULL,
    withdrawn_pos      INTEGER                  -- NULL = 当时有效（可被后续撤销）
);
CREATE TABLE IF NOT EXISTS waiting_sets (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    origin_pos         INTEGER NOT NULL,
    exporter           TEXT NOT NULL,
    transport_session  TEXT NOT NULL,
    observation_domain_id INTEGER NOT NULL,
    template_id        INTEGER NOT NULL,
    set_index          INTEGER NOT NULL,
    set_offset         INTEGER NOT NULL,
    set_bytes          BLOB NOT NULL,
    end_reason         TEXT NOT NULL,           -- waiting | timeout | ...
    end_pos            INTEGER,
    bound_version_seq  INTEGER,
    decode_error_code  TEXT
);
CREATE TABLE IF NOT EXISTS flows (
    flow_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_pos        INTEGER NOT NULL,
    exporter           TEXT NOT NULL,
    transport_session  TEXT NOT NULL,
    observation_domain_id INTEGER NOT NULL,
    template_id        INTEGER NOT NULL,
    version_seq        INTEGER NOT NULL,
    set_index          INTEGER NOT NULL,
    record_index       INTEGER NOT NULL,
    origin             TEXT NOT NULL,           -- immediate | pending
    origin_pos         INTEGER NOT NULL,
    FOREIGN KEY(version_seq) REFERENCES template_versions(version_seq)
);
CREATE TABLE IF NOT EXISTS flow_fields (
    flow_id            INTEGER NOT NULL,
    field_index        INTEGER NOT NULL,
    enterprise_number  INTEGER,
    element_id         INTEGER NOT NULL,
    value_type         TEXT NOT NULL,
    value_int          INTEGER,
    value_text         TEXT,
    value_blob         BLOB,
    raw_blob           BLOB NOT NULL,
    field_offset       INTEGER NOT NULL,
    field_end          INTEGER NOT NULL,
    value_offset       INTEGER NOT NULL,
    value_length       INTEGER NOT NULL,
    prefix_offset      INTEGER,
    prefix_length      INTEGER,
    PRIMARY KEY(flow_id, field_index),
    FOREIGN KEY(flow_id) REFERENCES flows(flow_id)
);
CREATE INDEX IF NOT EXISTS idx_flows_query
    ON flows(exporter, transport_session, capture_pos);
CREATE INDEX IF NOT EXISTS idx_waiting_key
    ON waiting_sets(exporter, transport_session, observation_domain_id,
                    template_id, end_reason);
CREATE INDEX IF NOT EXISTS idx_tv_lookup
    ON template_versions(exporter, transport_session,
                         observation_domain_id, template_id, version_seq);
"""


class Ingestor:
    """SQLite 支持的离线接入器。同一数据库重开时容量/K 必须与首次一致。"""

    def __init__(self, db_path: str, *, max_waiting_bytes: int, max_waiting_messages_k: int):
        if not isinstance(max_waiting_messages_k, int) or max_waiting_messages_k <= 0:
            raise ValueError("K 必须为正整数")
        if max_waiting_bytes < 0:
            raise ValueError("等待区容量不能为负")
        self.db_path = db_path
        self.max_waiting_bytes = max_waiting_bytes
        self.K = max_waiting_messages_k
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        # 独立连接推进模板版本序列：其事务不受消息事务回滚影响，
        # 保证失败消息不会让版本号被后续定义重用。
        self._seq_conn = sqlite3.connect(db_path)
        self.conn.executescript(_SCHEMA)
        self._check_meta()
        self._waiting: List[WaitingEntry] = self._load_waiting()

    # ------------------------------------------------------------------ 元数据
    def _check_meta(self) -> None:
        meta = dict(self.conn.execute("SELECT key, value FROM meta").fetchall())
        wanted = {
            "max_waiting_bytes": str(self.max_waiting_bytes),
            "max_waiting_messages_k": str(self.K),
        }
        if not meta:
            self.conn.executemany(
                "INSERT INTO meta(key, value) VALUES (?, ?)", wanted.items())
            self.conn.commit()
        else:
            for k, v in wanted.items():
                if meta.get(k) != v:
                    raise ManifestError(
                        f"数据库参数 {k} 首次为 {meta.get(k)!r}，重开传入 {v!r}，拒绝")

    def _load_waiting(self) -> List[WaitingEntry]:
        rows = self.conn.execute(
            "SELECT * FROM waiting_sets WHERE end_reason = 'waiting' "
            "ORDER BY id").fetchall()
        return [WaitingEntry(r["id"], r["origin_pos"], r["exporter"],
                             r["transport_session"], r["observation_domain_id"],
                             r["template_id"], r["set_index"], r["set_offset"],
                             bytes(r["set_bytes"])) for r in rows]

    # ------------------------------------------------------------- 清单/导入
    def import_manifest(self, entries: Sequence[Any]) -> List[ImportResult]:
        """按 capture_pos 顺序导入一段清单；可分段追加。

        每个 entry 可为 CaptureEntry、四元组/列表或对应 dict。
        重传（同位置同清单身份同字节）无操作；身份/内容改变或跳位置抛 ManifestError。
        """
        normalized = [self._normalize_entry(e) for e in entries]
        results: List[ImportResult] = []
        for entry in normalized:
            results.append(self._import_one(entry))
        return results

    @staticmethod
    def _normalize_entry(e: Any) -> CaptureEntry:
        if isinstance(e, CaptureEntry):
            return e
        if isinstance(e, dict):
            return CaptureEntry(int(e["capture_pos"]), str(e["exporter"]),
                                str(e["transport_session"]), str(e["file_path"]))
        if isinstance(e, (tuple, list)) and len(e) == 4:
            return CaptureEntry(int(e[0]), str(e[1]), str(e[2]), str(e[3]))
        raise ManifestError(f"无法识别的清单条目: {e!r}")

    def _check_manifest_identity(self, entry: CaptureEntry, sha256_hex: str,
                                 length: int) -> str:
        row = self.conn.execute(
            "SELECT * FROM capture_positions WHERE capture_pos = ?",
            (entry.capture_pos,)).fetchone()
        if row is not None:
            same_identity = (row["exporter"] == entry.exporter
                             and row["transport_session"] == entry.transport_session
                             and row["file_path"] == entry.file_path)
            if not same_identity:
                raise ManifestError(
                    f"capture_pos {entry.capture_pos} 清单身份与首次导入不一致，拒绝")
            if row["sha256"] != sha256_hex:
                raise ManifestError(
                    f"capture_pos {entry.capture_pos} 文件内容改变，拒绝")
            return row["status"]  # 同身份同字节重传：无操作
        max_pos = self.conn.execute(
            "SELECT COALESCE(MAX(capture_pos), -1) FROM capture_positions").fetchone()[0]
        if entry.capture_pos != max_pos + 1:
            raise ManifestError(
                f"跳位置：下一位置应为 {max_pos + 1}，清单给出 {entry.capture_pos}")
        return ""

    def _import_one(self, entry: CaptureEntry) -> ImportResult:
        import hashlib
        try:
            with open(entry.file_path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            raw = b""
            sha256_hex = hashlib.sha256(raw).hexdigest()
            return self._record_failure(entry, raw, sha256_hex,
                                        "file_read_error", str(exc))
        sha256_hex = hashlib.sha256(raw).hexdigest()
        prior_status = self._check_manifest_identity(entry, sha256_hex, len(raw))
        if prior_status:
            return ImportResult(entry.capture_pos, "duplicate")

        try:
            parsed = parse_message(raw)
            result = self._apply_message(entry, raw, sha256_hex, parsed)
        except (MessageError, FieldDecodeError) as exc:
            # 消息自身结构/字段损坏：回滚已由 _apply_message 完成，登记失败位置，
            # 不安装模板、不清旧等待，末尾仍按 K 规则处理到期。
            headers = self._peek_headers(raw)
            set_index = getattr(exc, "set_index", None)
            detail = getattr(exc, "detail", "") or ""
            if set_index is not None:
                detail = f"{detail} (set_index={set_index})".strip()
            return self._record_failure(entry, raw, sha256_hex,
                                        getattr(exc, "code", "message_error"),
                                        detail, headers)
        return result

    @staticmethod
    def _peek_headers(raw: bytes) -> Optional[Tuple[int, int, int]]:
        import struct as _struct
        if len(raw) >= 16:
            version, _length, export_time, seq, obs = _struct.unpack_from(
                "!HHIII", raw, 0)
            if version == 10:
                return export_time, seq, obs
        return None

    def _record_failure(self, entry: CaptureEntry, raw: bytes, sha256_hex: str,
                        code: str, detail: str,
                        parsed_headers: Optional[Tuple[int, int, int]]) -> ImportResult:
        """坏文件仍占 capture_pos；失败不安装模板、不清旧等待，仅跑 K 到期。"""
        export_time = seq = obs = None
        if parsed_headers is not None:
            export_time, seq, obs = parsed_headers
        with self.conn:  # 独立事务，保证失败证据落盘
            self.conn.execute(
                "INSERT INTO capture_positions(capture_pos, exporter, transport_session,"
                " file_path, sha256, length, status, error_code, error_detail,"
                " export_time, sequence_number, observation_domain_id)"
                " VALUES (?,?,?,?,?,?,'failed',?,?,?,?,?)",
                (entry.capture_pos, entry.exporter, entry.transport_session,
                 entry.file_path, sha256_hex, len(raw), code, detail,
                 export_time, seq, obs))
        self._timeout_sweep(entry.capture_pos)
        return ImportResult(entry.capture_pos, "failed", code, detail)

    # ----------------------------------------------------------- 消息应用核心
    def _active_version(self, key: Tuple[str, str, int, int],
                        overlay: Optional[Dict[Tuple[str, str, int, int],
                                               Optional[sqlite3.Row]]] = None
                        ) -> Optional[sqlite3.Row]:
        """取当前有效模板版本。overlay 反映本消息内按原顺序已生效的定义/撤销。

        覆盖层中的 None 表示“本消息内已撤销”，直接返回 None；键不在覆盖层时
        以数据库已提交状态为准（上一消息的撤销已落库，不会复活旧版本）。
        """
        if overlay is not None and key in overlay:
            return overlay[key]
        rows = self.conn.execute(
            "SELECT * FROM template_versions WHERE exporter=? AND transport_session=?"
            " AND observation_domain_id=? AND template_id=? AND withdrawn_pos IS NULL"
            " ORDER BY version_seq DESC LIMIT 1", key).fetchall()
        return rows[0] if rows else None

    @staticmethod
    def _key_of(entry_exporter: str, session: str, obs: int, tid: int):
        return (entry_exporter, session, obs, tid)

    def _apply_message(self, entry: CaptureEntry, raw: bytes, sha256_hex: str,
                       parsed: ParsedMessage) -> ImportResult:
        # 暂存区：全部验证通过、事务提交后才成为事实
        staged_new_versions: List[Tuple[Tuple[str, str, int, int], int, str]] = []
        staged_withdrawals: List[int] = []          # version_seq
        staged_enqueue: List[WaitingEntry] = []
        # 本消息内被结束（接走/撤销/坏字段隔离）的旧等待对象
        staged_resolved: List[WaitingEntry] = []
        staged_flows: List[Dict[str, Any]] = []
        isolated = 0
        enqueued = 0
        picked = 0

        # 消息内临时等待表（含本消息已入队集合），保持 FIFO
        working_waiting = list(self._waiting)
        # 消息内定义/撤销覆盖层：key -> 有效版本行（撤销记 None）
        overlay: Dict[Tuple[str, str, int, int], Optional[sqlite3.Row]] = {}

        with self.conn:  # 任何异常整体回滚 -> 消息原子性
            for pset in parsed.sets:
                key = self._key_of(entry.exporter, entry.transport_session,
                                   parsed.observation_domain_id, pset.set_id)
                if pset.set_id == 2:
                    for trec in pset.templates:
                        tkey = self._key_of(entry.exporter,
                                            entry.transport_session,
                                            parsed.observation_domain_id,
                                            trec.template_id)
                        if trec.is_withdrawal:
                            self._apply_withdrawal(
                                tkey, entry.capture_pos, overlay,
                                working_waiting, staged_withdrawals,
                                staged_resolved)
                        else:
                            version_seq = self._install_definition(trec, entry.capture_pos)
                            layout_json = json.dumps(
                                [self._spec_dict(f) for f in trec.fields])
                            staged_new_versions.append((tkey, version_seq, layout_json))
                            synthetic_row = self._overlay_row(
                                tkey, version_seq, layout_json, trec)
                            overlay[tkey] = synthetic_row
                            n_pickup = self._pickup_waiting(
                                tkey, synthetic_row, trec, entry.capture_pos,
                                working_waiting, staged_resolved, staged_flows)
                            picked += n_pickup
                else:
                    active = self._active_version(key, overlay)
                    if active is not None:
                        self._decode_immediate(
                            key, active, pset, parsed, entry, staged_flows)
                    else:
                        set_bytes = bytes(raw[pset.set_offset:
                                              pset.set_offset + pset.set_length])
                        w = self._enqueue(
                            entry, parsed, pset, set_bytes,
                            working_waiting, staged_enqueue)
                        if w is not None:
                            enqueued += 1
                        else:
                            isolated += 1

            # 提交 capture_positions
            self.conn.execute(
                "INSERT INTO capture_positions(capture_pos, exporter,"
                " transport_session, file_path, sha256, length, status,"
                " error_code, error_detail, export_time, sequence_number,"
                " observation_domain_id) VALUES (?,?,?,?,?,?,'imported',"
                " NULL, NULL, ?, ?, ?)",
                (entry.capture_pos, entry.exporter, entry.transport_session,
                 entry.file_path, sha256_hex, len(raw),
                 parsed.export_time, parsed.sequence_number,
                 parsed.observation_domain_id))
            # 提交模板版本/撤销
            for (k, vseq, layout_json) in staged_new_versions:
                self.conn.execute(
                    "INSERT INTO template_versions(version_seq, exporter,"
                    " transport_session, observation_domain_id, template_id,"
                    " layout_json, defined_pos, withdrawn_pos)"
                    " VALUES (?,?,?,?,?,?,?,NULL)",
                    (vseq, k[0], k[1], k[2], k[3], layout_json,
                     entry.capture_pos))
            for vseq in staged_withdrawals:
                self.conn.execute(
                    "UPDATE template_versions SET withdrawn_pos=? WHERE version_seq=?",
                    (entry.capture_pos, vseq))
            # 提交新等待集合（容量隔离行已在 _enqueue 内写成终态）
            for w in staged_enqueue:
                cur = self.conn.execute(
                    "INSERT INTO waiting_sets(origin_pos, exporter,"
                    " transport_session, observation_domain_id, template_id,"
                    " set_index, set_offset, set_bytes, end_reason, end_pos,"
                    " bound_version_seq, decode_error_code)"
                    " VALUES (?,?,?,?,?,?,?,?,'waiting',NULL,NULL,NULL)",
                    (w.origin_pos, w.exporter, w.transport_session,
                     w.observation_domain_id, w.template_id, w.set_index,
                     w.set_offset, w.set_bytes))
                w.id = cur.lastrowid
            # 本消息内结束的旧等待：统一按对象上的终态更新（接走/撤销/坏字段）
            for w in staged_resolved:
                self.conn.execute(
                    "UPDATE waiting_sets SET end_reason=?, end_pos=?,"
                    " bound_version_seq=?, decode_error_code=? WHERE id=?",
                    (w.end_reason, w.end_pos, w.bound_version_seq,
                     w.decode_error_code, w.id))
            # 提交流记录
            for fl in staged_flows:
                self._insert_flow(fl)

        # 提交成功后才以数据库为事实来源重建内存等待区，再跑 K 到期扫描
        self._waiting = self._load_waiting()
        self._timeout_sweep(entry.capture_pos)
        return ImportResult(entry.capture_pos, "imported",
                            flows_inserted=len(staged_flows),
                            sets_enqueued=enqueued, sets_picked=picked,
                            sets_isolated=isolated)

    @staticmethod
    def _overlay_row(key: Tuple[str, str, int, int], version_seq: int,
                     layout_json: str, trec: TemplateRecord) -> sqlite3.Row:
        """构造与 sqlite3.Row 同接口（键索引 + 位置索引）的临时版本行。"""
        class _Row:
            __slots__ = ("_d", "_cols")

            def __init__(self, data):
                self._d = data
                self._cols = list(data.keys())

            def __getitem__(self, item):
                if isinstance(item, int):
                    return self._d[self._cols[item]]
                return self._d[item]

            def keys(self):
                return self._cols

        return _Row({"version_seq": version_seq,
                     "template_id": trec.template_id,
                     "layout_json": layout_json})

    # ------------------------------------------------------------- 模板操作
    @staticmethod
    def _spec_dict(f: FieldSpec) -> Dict[str, Any]:
        return {"enterprise_number": f.enterprise_number,
                "element_id": f.element_id, "length": f.length}

    def _install_definition(self, trec: TemplateRecord, pos: int) -> int:
        # 每次新定义都生成新版本，即使布局与历史完全相同也不做去重。
        # 独立连接/事务推进序列：消息事务若随后回滚，该版本号会成为“空号”而
        # 不是被回收重用，从而杜绝失败消息导致后续定义撞号、错绑旧流。
        cur = self._seq_conn.execute(
            "INSERT INTO template_version_seq(stub) VALUES (1)")
        self._seq_conn.commit()
        return cur.lastrowid

    def _apply_withdrawal(self, key, pos, overlay, working_waiting,
                          staged_withdrawals, staged_resolved) -> None:
        active = self._active_version(key, overlay)
        if active is not None:
            # 撤销该键下所有仍有效的历史版本（不只是当前版本），保证撤销后
            # 数据库里不存在任何 withdrawn_pos IS NULL 的同键版本。
            rows = self.conn.execute(
                "SELECT version_seq FROM template_versions"
                " WHERE exporter=? AND transport_session=?"
                " AND observation_domain_id=? AND template_id=?"
                " AND withdrawn_pos IS NULL ORDER BY version_seq", key).fetchall()
            for r in rows:
                staged_withdrawals.append(r["version_seq"])
            # 同消息内刚定义、尚在暂存区未入库的版本也必须一并撤销：
            # 它不在 DB 查询结果里，但存在于覆盖层。
            overlay_row = overlay.get(key)
            if overlay_row is not None:
                vseq = overlay_row["version_seq"]
                if vseq not in staged_withdrawals:
                    staged_withdrawals.append(vseq)
            overlay[key] = None  # 撤销后本消息后续同键集合必须重新等待
            # 撤销屏障：此前等待的同键集合全部 template_withdrawn，不再等新定义
            for w in list(working_waiting):
                if w.key == key:
                    working_waiting.remove(w)
                    w.end_reason = END_WITHDRAWN
                    w.end_pos = pos
                    staged_resolved.append(w)
        # field_count==0 仅撤销指定模板；无有效模板时也是合法屏障（无等待可结束）

    def _pickup_waiting(self, key, active_row, trec, pos,
                        working_waiting, staged_resolved,
                        staged_flows) -> int:
        """首份定义按 FIFO 接走同键全部等待集合；坏字段隔离但保留新定义。

        不能跳过第一份定义去等下一份，因此解码失败的等待集合以
        bad_field_isolated 结束，并记录它曾绑定尝试的版本号。
        """
        layout = trec.fields
        n_pickup = 0
        for w in list(working_waiting):
            if w.key != key:
                continue
            working_waiting.remove(w)
            try:
                decoded = decode_data_set(w.set_bytes, w.set_offset,
                                          w.set_index, layout)
            except FieldDecodeError as exc:
                w.end_reason = END_BAD_FIELDS
                w.end_pos = pos
                w.bound_version_seq = active_row["version_seq"]
                w.decode_error_code = exc.code
                staged_resolved.append(w)
                continue
            n_pickup += 1
            w.end_reason = END_PICKED
            w.end_pos = pos
            w.bound_version_seq = active_row["version_seq"]
            staged_resolved.append(w)
            for record_index, fields in decoded:
                staged_flows.append(self._flow_dict(
                    w, active_row["version_seq"], trec, record_index, fields,
                    origin="pending", origin_pos=w.origin_pos))
        return n_pickup

    def _decode_immediate(self, key, active_row, pset: ParsedSet,
                          parsed: ParsedMessage, entry: CaptureEntry,
                          staged_flows) -> None:
        layout = tuple(FieldSpec(s["enterprise_number"], s["element_id"], s["length"])
                       for s in json.loads(active_row["layout_json"]))
        set_bytes = bytes(parsed.raw[pset.set_offset:
                                     pset.set_offset + pset.set_length])
        # 即时解码失败属于消息自身结构损坏 -> 抛错触发整条消息回滚
        decoded = decode_data_set(set_bytes, pset.set_offset,
                                  pset.set_index, layout)
        trec = TemplateRecord(active_row["template_id"], layout)
        for record_index, fields in decoded:
            staged_flows.append({
                "capture_pos": entry.capture_pos,
                "exporter": entry.exporter,
                "transport_session": entry.transport_session,
                "observation_domain_id": parsed.observation_domain_id,
                "template_id": pset.set_id,
                "version_seq": active_row["version_seq"],
                "set_index": pset.set_index,
                "record_index": record_index,
                "origin": "immediate",
                "origin_pos": entry.capture_pos,
                "fields": fields,
            })

    def _enqueue(self, entry, parsed, pset, set_bytes,
                 working_waiting, staged_enqueue) -> Optional[WaitingEntry]:
        """入队即检查容量；超限只隔离这份新集合，不淘汰旧集合。

        容量隔离行在当前事务内直接写成 capacity_isolated 终态（仍保留全部
        原始字节、位置与原因），不进入工作等待表，本消息后续定义也不挽救它。
        """
        current_bytes = sum(w.size for w in working_waiting)
        if current_bytes + len(set_bytes) > self.max_waiting_bytes:
            self.conn.execute(
                "INSERT INTO waiting_sets(origin_pos, exporter, transport_session,"
                " observation_domain_id, template_id, set_index, set_offset,"
                " set_bytes, end_reason, end_pos, bound_version_seq,"
                " decode_error_code) VALUES (?,?,?,?,?,?,?,?,?,?,"
                "NULL, NULL)",
                (entry.capture_pos, entry.exporter, entry.transport_session,
                 parsed.observation_domain_id, pset.set_id, pset.set_index,
                 pset.set_offset, set_bytes, END_CAPACITY, entry.capture_pos))
            return None
        w = WaitingEntry(id=-1, origin_pos=entry.capture_pos,
                         exporter=entry.exporter,
                         transport_session=entry.transport_session,
                         observation_domain_id=parsed.observation_domain_id,
                         template_id=pset.set_id, set_index=pset.set_index,
                         set_offset=pset.set_offset, set_bytes=set_bytes)
        working_waiting.append(w)
        staged_enqueue.append(w)
        return w

    def _flow_dict(self, w: WaitingEntry, version_seq: int,
                   trec: TemplateRecord, record_index: int,
                   fields: List[DecodedField], *, origin: str,
                   origin_pos: int) -> Dict[str, Any]:
        return {
            "capture_pos": w.origin_pos if origin == "pending" else origin_pos,
            "exporter": w.exporter,
            "transport_session": w.transport_session,
            "observation_domain_id": w.observation_domain_id,
            "template_id": w.template_id,
            "version_seq": version_seq,
            "set_index": w.set_index,
            "record_index": record_index,
            "origin": origin,
            "origin_pos": origin_pos,
            "fields": fields,
        }

    def _insert_flow(self, fl: Dict[str, Any]) -> None:
        cur = self.conn.execute(
            "INSERT INTO flows(capture_pos, exporter, transport_session,"
            " observation_domain_id, template_id, version_seq, set_index,"
            " record_index, origin, origin_pos) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (fl["capture_pos"], fl["exporter"], fl["transport_session"],
             fl["observation_domain_id"], fl["template_id"], fl["version_seq"],
             fl["set_index"], fl["record_index"], fl["origin"], fl["origin_pos"]))
        flow_id = cur.lastrowid
        for f in fl["fields"]:
            value_int = f.value if f.value_type == "uint" else None
            value_text = f.value if f.value_type in ("ipv4", "text") else None
            value_blob = f.value if f.value_type == "bytes" else None
            self.conn.execute(
                "INSERT INTO flow_fields(flow_id, field_index, enterprise_number,"
                " element_id, value_type, value_int, value_text, value_blob,"
                " raw_blob, field_offset, field_end, value_offset, value_length,"
                " prefix_offset, prefix_length) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (flow_id, f.field_index, f.enterprise_number, f.element_id,
                 f.value_type, value_int, value_text, value_blob, f.raw,
                 f.field_offset, f.field_end, f.value_offset, f.value_length,
                 f.prefix_offset, f.prefix_length))

    # --------------------------------------------------------------- K 到期
    def _timeout_sweep(self, current_pos: int) -> List[int]:
        """仍等待且 current_pos - origin_pos >= K 的集合记 timeout。

        在消息全部处理之后运行，因此到期位置出现的定义先接走、剩余的才到期。
        已 timeout/撤销/隔离的记录不再取得资格（end_reason != waiting 不参与）。
        """
        timed_out: List[int] = []
        with self.conn:
            rows = self.conn.execute(
                "SELECT id, origin_pos FROM waiting_sets WHERE end_reason='waiting'"
            ).fetchall()
            for r in rows:
                if current_pos - r["origin_pos"] >= self.K:
                    self.conn.execute(
                        "UPDATE waiting_sets SET end_reason=?, end_pos=?"
                        " WHERE id=?",
                        (END_TIMEOUT, current_pos, r["id"]))
                    timed_out.append(r["id"])
        self._waiting = self._load_waiting()
        return timed_out

    # ------------------------------------------------------------------ 查询
    def iter_flows(self, *, exporter: Optional[str] = None,
                   transport_session: Optional[str] = None,
                   capture_pos: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """Python 迭代接口；未解码集合不会出现在这里（它们在 pending 中区分）。"""
        sql = "SELECT * FROM flows WHERE 1=1"
        params: List[Any] = []
        if exporter is not None:
            sql += " AND exporter=?"
            params.append(exporter)
        if transport_session is not None:
            sql += " AND transport_session=?"
            params.append(transport_session)
        if capture_pos is not None:
            sql += " AND capture_pos=?"
            params.append(capture_pos)
        sql += " ORDER BY flow_id"
        for frow in self.conn.execute(sql, params).fetchall():
            yield self._hydrate_flow(frow)

    def flows(self, **filters) -> List[Dict[str, Any]]:
        return list(self.iter_flows(**filters))

    def _hydrate_flow(self, frow: sqlite3.Row) -> Dict[str, Any]:
        fields = []
        for r in self.conn.execute(
                "SELECT * FROM flow_fields WHERE flow_id=? ORDER BY field_index",
                (frow["flow_id"],)).fetchall():
            if r["value_type"] == "uint":
                value: Any = r["value_int"]
            elif r["value_type"] in ("ipv4", "text"):
                value = r["value_text"]
            else:
                value = bytes(r["value_blob"])
            fields.append({
                "field_index": r["field_index"],
                "enterprise_number": r["enterprise_number"],
                "element_id": r["element_id"],
                "value_type": r["value_type"],
                "value": value,
                "raw": bytes(r["raw_blob"]),
                "field_offset": r["field_offset"],
                "field_end": r["field_end"],
                "value_offset": r["value_offset"],
                "value_length": r["value_length"],
                "prefix_offset": r["prefix_offset"],
                "prefix_length": r["prefix_length"],
            })
        tv = self.conn.execute(
            "SELECT * FROM template_versions WHERE version_seq=?",
            (frow["version_seq"],)).fetchone()
        layout = json.loads(tv["layout_json"]) if tv else None
        return {
            "flow_id": frow["flow_id"],
            "capture_pos": frow["capture_pos"],
            "exporter": frow["exporter"],
            "transport_session": frow["transport_session"],
            "observation_domain_id": frow["observation_domain_id"],
            "template_id": frow["template_id"],
            "version_seq": frow["version_seq"],
            "template_defined_pos": tv["defined_pos"] if tv else None,
            "set_index": frow["set_index"],
            "record_index": frow["record_index"],
            "origin": frow["origin"],          # immediate | pending
            "origin_pos": frow["origin_pos"],
            "layout": layout,
            "fields": fields,
        }

    def explain(self, flow_id: int) -> Optional[Dict[str, Any]]:
        """返回某条值的完整来源链：捕获身份、消息/集合/记录位置、模板定义位置、
        每个字段的起止字节与原字节。flow_id 不存在返回 None。"""
        frow = self.conn.execute(
            "SELECT * FROM flows WHERE flow_id=?", (flow_id,)).fetchone()
        if frow is None:
            return None
        flow = self._hydrate_flow(frow)
        cap = self.conn.execute(
            "SELECT * FROM capture_positions WHERE capture_pos=?",
            (flow["capture_pos"],)).fetchone()
        flow["evidence"] = {
            "capture_identity": {
                "capture_pos": cap["capture_pos"],
                "exporter": cap["exporter"],
                "transport_session": cap["transport_session"],
                "file_path": cap["file_path"],
                "sha256": cap["sha256"],
            },
            "message": {
                "export_time": cap["export_time"],
                "sequence_number": cap["sequence_number"],
                "observation_domain_id": cap["observation_domain_id"],
            },
            "set_index": flow["set_index"],
            "record_index": flow["record_index"],
            "template_version": flow["version_seq"],
            "template_defined_pos": flow["template_defined_pos"],
        }
        return flow

    def pending(self) -> PendingSummary:
        """返回 unresolved、已结束等待集合（含原因）和未解释消息清单。"""
        unresolved = [dict(r) for r in self.conn.execute(
            "SELECT id, origin_pos, exporter, transport_session,"
            " observation_domain_id, template_id, set_index, set_offset,"
            " length(set_bytes) AS set_length, end_reason FROM waiting_sets"
            " WHERE end_reason='waiting' ORDER BY id").fetchall()]
        ended = [dict(r) for r in self.conn.execute(
            "SELECT id, origin_pos, exporter, transport_session,"
            " observation_domain_id, template_id, set_index, end_reason,"
            " end_pos, bound_version_seq, decode_error_code,"
            " length(set_bytes) AS set_length FROM waiting_sets"
            " WHERE end_reason != 'waiting' ORDER BY id").fetchall()]
        unexplained = [dict(r) for r in self.conn.execute(
            "SELECT capture_pos, exporter, transport_session, file_path,"
            " length, error_code, error_detail FROM capture_positions"
            " WHERE status='failed' ORDER BY capture_pos").fetchall()]
        return PendingSummary(
            unresolved_count=len(unresolved),
            unresolved_bytes=sum(r["set_length"] for r in unresolved),
            ended=ended,
            unexplained=unexplained,
        )

    def waiting_bytes(self) -> int:
        """当前仍在等待区的原始集合字节（容量计量口径：集合头+正文）。"""
        return sum(w.size for w in self._waiting)

    def waiting_ids(self) -> List[int]:
        return [w.id for w in self._waiting]

    def close(self) -> None:
        self._seq_conn.close()
        self.conn.close()

    def __enter__(self) -> "Ingestor":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
