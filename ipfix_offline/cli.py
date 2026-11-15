"""命令行接口：import / flows / pending / explain 四个子命令。

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


def cmd_import(args: argparse.Namespace) -> int:
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m ipfix_offline.cli",
        description="离线 IPFIX 捕获子集模板解码接入器")
    p.add_argument("--db", required=True, help="SQLite 数据库路径")
    p.add_argument("--capacity", type=int, required=True,
                   help="等待区总容量（原始集合字节，含集合头）")
    p.add_argument("--k", type=int, required=True,
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
    return p


def main(argv: List[str] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
