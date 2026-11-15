"""测试公共工具：写捕获文件、构造清单、独立临时目录。

注意：本文件只使用 wire 的合成构造器制造“输入报文”，任何解码预期值均为手工
计算的字面量，不调用 parse_message/decode_data_set/Ingestor 来生成预期。
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipfix_offline import wire  # noqa: E402
from ipfix_offline.ingestor import CaptureEntry  # noqa: E402


class CaptureDir:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ipfix_caps_")
        self._next = 0

    @property
    def path(self) -> str:
        return self.tmp.name

    def write_msg(self, blob: bytes) -> str:
        name = f"msg_{self._next:04d}.ipfix"
        self._next += 1
        full = os.path.join(self.tmp.name, name)
        with open(full, "wb") as fh:
            fh.write(blob)
        return full

    def entry(self, pos: int, exporter: str, session: str, file_path: str):
        return CaptureEntry(pos, exporter, session, file_path)

    def cleanup(self):
        self.tmp.cleanup()


def db_path(cdir: CaptureDir, name: str = "store.db") -> str:
    return os.path.join(cdir.tmp.name, name)


# --- 常用手工模板布局 -------------------------------------------------------
# 模板 300 布局 A：uint32 元素1 + IPv4 元素8
LAYOUT_A = [wire.field_spec(1, 4), wire.field_spec(8, 4)]
# 模板 300 布局 B：uint64 元素1 + 原始字节元素99（6 字节）
LAYOUT_B = [wire.field_spec(1, 8), wire.field_spec(99, 6)]
# 变长文本模板 301：元素82 变长 + 元素1 定长4
LAYOUT_TEXT = [wire.field_spec(82, wire.VARLEN), wire.field_spec(1, 4)]


def make_template_msg(obs_domain: int, records, *, export_time=1000, seq=1):
    return wire.message(export_time, seq, obs_domain,
                        [wire.template_set(records)])


def make_data_msg(obs_domain: int, template_id: int, record_bodies, *,
                  export_time=1000, seq=1, sets=None):
    parts = sets if sets is not None else [wire.data_set(template_id, record_bodies)]
    return wire.message(export_time, seq, obs_domain, parts)
