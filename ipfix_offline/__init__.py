"""离线 IPFIX 模板解码接入器（仅支持约定捕获子集）。

公开接口：
    Ingestor, CaptureEntry, ImportResult, PendingSummary
    wire 子模块的解析器与合成消息构造器
"""

from .ingestor import (
    CaptureEntry,
    ImportResult,
    Ingestor,
    ManifestError,
    PendingSummary,
    WaitingEntry,
)
from .wire import (
    IPFIXError,
    MessageError,
    FieldDecodeError,
    FieldSpec,
    ParsedMessage,
    TemplateRecord,
    decode_data_set,
    parse_message,
)

__all__ = [
    "CaptureEntry",
    "ImportResult",
    "Ingestor",
    "ManifestError",
    "PendingSummary",
    "WaitingEntry",
    "IPFIXError",
    "MessageError",
    "FieldDecodeError",
    "FieldSpec",
    "ParsedMessage",
    "TemplateRecord",
    "decode_data_set",
    "parse_message",
]
