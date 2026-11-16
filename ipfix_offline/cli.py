"""命令行接口：import / flows / pending / explain 四个子命令，以及离线 NAT
关联的 nat 子命令。

清单文件为 JSON，元素为
{"capture_pos": N, "exporter": ..., "transport_session": ..., "file_path": ...}
或四元组 [N, exporter, transport_session, file_path]。
所有输出为 JSON，不接网络，只读本地文件。
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List

from .ingestor import Ingestor


def _load_manifest(path: str) -> List[Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise SystemExit("清单必须是 JSON 数组")
    return data


def _require_ingest_args(args: argparse.Namespace) -> None:
    missing = [name for name in ("db", "capacity", "k")
               if getattr(args, name) is None]
    if missing:
        raise SystemExit(
            "子命令 " + args.command + " 需要 " +
            " ".join("--" + m.replace("_", "-") for m in missing))


def cmd_import(args: argparse.Namespace) -> int:
    _require_ingest_args(args)
    entries = _load_manifest(args.manifest)
    with Ingestor(args.db, max_waiting_bytes=args.capacity,
                  max_waiting_messages_k=args.k) as ing:
        results = ing.import_manifest(entries)
        summary = ing.pending()
    payload = {
        "results": [r.__dict__ for r in results],
        "unresolved_count": summary.unresolved_count,
        "unresolved_bytes": summary.unresolved_bytes,
        "ended_count": len(summary.ended),
        "unexplained_count": len(summary.unexplained),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_flows(args: argparse.Namespace) -> int:
    _require_ingest_args(args)
    with Ingestor(args.db, max_waiting_bytes=args.capacity,
                  max_waiting_messages_k=args.k) as ing:
        filters: Dict[str, Any] = {}
        if args.exporter:
            filters["exporter"] = args.exporter
        if args.session:
            filters["transport_session"] = args.session
        if args.pos is not None:
            filters["capture_pos"] = args.pos
        flows = []
        for flow in ing.iter_flows(**filters):
            flows.append(_jsonable_flow(flow))
    print(json.dumps(flows, ensure_ascii=False, indent=2))
    return 0


def cmd_pending(args: argparse.Namespace) -> int:
    _require_ingest_args(args)
    with Ingestor(args.db, max_waiting_bytes=args.capacity,
                  max_waiting_messages_k=args.k) as ing:
        summary = ing.pending()
    print(json.dumps({
        "unresolved_count": summary.unresolved_count,
        "unresolved_bytes": summary.unresolved_bytes,
        "ended": summary.ended,
        "unexplained": summary.unexplained,
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    _require_ingest_args(args)
    with Ingestor(args.db, max_waiting_bytes=args.capacity,
                  max_waiting_messages_k=args.k) as ing:
        flow = ing.explain(args.flow_id)
    if flow is None:
        print(json.dumps({"error": f"flow_id {args.flow_id} 不存在"},
                         ensure_ascii=False))
        return 1
    print(json.dumps(_jsonable_flow(flow), ensure_ascii=False, indent=2))
    return 0


def _jsonable_flow(flow: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(flow)
    for f in out.get("fields", []):
        if isinstance(f.get("value"), (bytes, bytearray)):
            f["value_hex"] = bytes(f["value"]).hex()
            f["value"] = None
        if "raw" in f:
            f["raw_hex"] = bytes(f["raw"]).hex()
            del f["raw"]
    return out


def cmd_nat(args: argparse.Namespace) -> int:
    """离线 NAT 关联：结构错误返回 2；有 invalid_flow 返回 1 但答案齐全。"""
    from .nat_correlate import (ConfigError, NatError, NatLogError,
                                RequestFileError, StoreError, run_job)

    if args.db is None:
        raise SystemExit("子命令 nat 需要 --db（现有接入库，只读）")
    try:
        report = run_job(args.db, args.config, args.log, args.requests,
                         args.out, args.work_dir,
                         measure_memory=not args.no_memory,
                         keep_index=args.keep_index,
                         mapping_index_path=args.mapping_index)
    except (ConfigError, NatLogError, RequestFileError, StoreError,
            NatError) as exc:
        print(json.dumps({"complete": False, "error": exc.as_dict()},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 2
    summary = report["summary"]
    print(json.dumps({
        "complete": True,
        "out": args.out,
        "summary": summary,
        "timing": report["timing"],
        "index": report["index"],
        "peak_python_bytes": report["peak_python_bytes"],
        "peak_rss_bytes": report["peak_rss_bytes"],
        "mapping_index": report.get("mapping_index"),
    }, ensure_ascii=False, indent=2))
    return 0 if summary["invalid_flow_count"] == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m ipfix_offline.cli",
        description="离线 IPFIX 捕获子集模板解码接入器")
    p.add_argument("--db", help="SQLite 数据库路径")
    p.add_argument("--capacity", type=int,
                   help="等待区总容量（原始集合字节，含集合头）")
    p.add_argument("--k", type=int,
                   help="最大等待消息数 K（正整数）")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("import", help="按清单导入一段捕获")
    pi.add_argument("manifest", help="JSON 清单文件")
    pi.set_defaults(func=cmd_import)

    pf = sub.add_parser("flows", help="查询已解码流记录")
    pf.add_argument("--exporter")
    pf.add_argument("--session")
    pf.add_argument("--pos", type=int)
    pf.set_defaults(func=cmd_flows)

    pp = sub.add_parser("pending", help="查看 unresolved/已结束等待/未解释消息")
    pp.set_defaults(func=cmd_pending)

    pe = sub.add_parser("explain", help="按 flow_id 输出来源链与字段字节范围")
    pe.add_argument("flow_id", type=int)
    pe.set_defaults(func=cmd_explain)

    pn = sub.add_parser(
        "nat", help="离线 NAT 关联：回溯流片段可能的原始五元组与证据图")
    pn.add_argument("--config", required=True, help="观测域拓扑配置 JSON")
    pn.add_argument("--log", action="append", required=True,
                    help="转换日志 JSONL，可重复")
    pn.add_argument("--requests", required=True, help="请求 JSONL")
    pn.add_argument("--out", required=True, help="输出 JSON 报告路径")
    pn.add_argument("--work-dir", required=True,
                    help="临时索引用工作目录（只清理本次创建的文件）")
    pn.add_argument("--keep-index", action="store_true")
    pn.add_argument("--mapping-index", metavar="PATH",
                    help="额外输出 mapping_id -> 日志文件/物理行号 的 JSONL")
    pn.add_argument("--no-memory", action="store_true",
                    help="关闭 tracemalloc 峰值统计")
    pn.set_defaults(func=cmd_nat)
    return p


def main(argv: List[str] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
