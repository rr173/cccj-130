# 离线 IPFIX 模板解码接入器

面向采集机留存的 **IPFIX 二进制消息文件** 的离线解码入库工具。用 Python 标准库
+ SQLite 实现，**不接网络、不做协议协商、不宣称兼容整个 RFC 7011**，只处理本
项目约定的捕获子集。核心解决的问题是：模板编号被复用后，绝不能把此前等待的旧
消息套成新结构；每条流都能追溯到“用的是哪一版模板、字段原字节在消息里的哪个
范围、为什么有些消息至今无法解释”。

## 1. 明确支持与不支持的范围

### 支持（仅此子集）

- 单文件 = 单条 IPFIX 消息，真实 16 字节消息头：
  `version(2) length(2) export_time(4) sequence_number(4) observation_domain_id(4)`。
  `version` 必须为 10；`length` 必须等于文件字节长度。
- 模板集合 `set_id == 2`（含 `field_count == 0` 的指定模板撤销记录）。
- 数据集合 `set_id >= 256`。
- 字段说明：`element_id` + 长度；企业位（最高位）存在时再读 4 字节
  `enterprise_number`。
- 固定长度字段（正长度）与 RFC 7011 变长编码（模板长度 `65535`；正文首字节
  `<255` 即正文长度，`==255` 时后跟 2 字节大端长度）。长度前缀与正文分别记录
  偏移。
- 语义子集（仅对无企业位的标准元素生效）：
  | element_id | 含义 | 支持的线格式 | 存储类型 |
  |---|---|---|---|
  | 1 | 无符号整数 | 4 或 8 字节 | `uint`（Python int） |
  | 8 | IPv4 地址 | 固定 4 字节 | `ipv4`（点分字符串） |
  | 82 | UTF-8 文本 | 固定或变长 | `text`（Python str） |
  | 其他（含任何企业元素） | 不解释语义 | 任意合法长度 | `bytes`（原字节） |

### 明确不支持（遇到即按消息错误处理）

- 选项模板集合（`set_id == 3`）及任何 `4..255` 的保留 set_id。
- 集合填充字节：消息尾部任何不被完整集合消费的残余字节一律拒绝。
- 全域模板撤销：`field_count == 0` 只撤销记录里指定的那一个 `template_id`。
- 网络收发、采样/抽样、流关联、SCTP/TCP 会话管理等任何线外特性。

## 2. 数据模型与模板键

- **模板键**：`(exporter, transport_session, observation_domain_id, template_id)`。
  清单显式给出会话身份；一次重启使用新的 `transport_session`，因此同一 exporter
  的两个会话天然不能共用模板；不同 observation domain 下的同号模板也是不同键。
- **模板版本**：每次出现新定义（即使布局与上一版完全相同）都分配一个单调的
  `version_seq`，记录定义位置 `defined_pos`；撤销时写 `withdrawn_pos`。版本号由
  独立 SQLite 序列推进，**消息事务回滚不会回收版本号**，避免失败消息造成版本重用。
- 数据集合在被解释的那一刻绑定当时有效的模板版本；后续改版**不会回溯**重新解释
  已落盘的流。

## 3. 消息的原子解释规则

每条消息是一个解释单元，处理顺序：

1. 读文件并完整解析 16 字节头与全部集合（纯结构校验，不改任何状态）。
2. 在**一个 SQLite 事务**内按集合与模板记录的原顺序应用：定义/撤销生效、即时
   解码、等待集合接走、新集合入队。
3. 任一步骤抛错 → 整个事务回滚：**不安装模板、不写入流、不清空旧等待**。
4. 事务提交后重建内存等待区，再在该位置末尾执行 K 到期扫描。

因此“一条含撤销和坏尾部的消息”整体失败，前面的撤销也不会提前替换已接受状态。
坏文件仍然占据它的 `capture_pos`，并以失败原因登记在 `capture_positions`。

### 两类“坏字段”的区别（容易混淆，单独说明）

- **新消息自身结构/字段损坏**（例如即时解码时字段跨集合边界、UTF-8 坏编码）：
  整条消息失败回滚，不安装任何模板。
- **新定义去解一份历史等待集合时解出坏字段**：这不是新消息的结构错误。新模板
  定义照常安装保留，那份等待集合以 `bad_field_isolated` 结束并记录尝试绑定的
  版本号，不会跳过第一份定义去等第二份模板碰运气。

## 4. 等待区资格与全部结束原因

无有效模板的数据集合以**原始集合字节（含 4 字节集合头）**进入等待区，只能被
**同模板键的下一次定义**接走。等待集合的生命周期终态：

| end_reason | 触发条件 | 还能否再被接走 |
|---|---|---|
| `waiting`（查询中显示为 unresolved） | 清单当前末尾仍在等待 | 可以，后续追加的定义可接走 |
| `picked` | 被某版定义成功解码，流已落盘 | 否（终态，保留绑定版本） |
| `template_withdrawn` | 撤销屏障：撤销时仍在等待的同键集合 | 否；屏障之后的新未知集合可重新等待后来的新定义 |
| `timeout` | 消息处理完后仍等待且 `current_pos - origin_pos >= K` | 否 |
| `capacity_isolated` | 入队会使等待字节超过调用方容量 | 否；只隔离这份新集合，绝不淘汰旧集合 |
| `bad_field_isolated` | 首份定义无法把它解成合法字段 | 否；新定义保留，隔离集合不复活 |

规则要点：

- **撤销是屏障**：撤销切断的是“此前”等待集合的资格；屏障之后到达的未知数据可以
  等待撤销之后重新发布的新定义。
- **到期位置出现定义仍可接走**：定义/接走在消息事务内先发生，K 到期扫描在消息
  末尾才跑，因此恰好在到期位置发布的首份定义会先接走，剩余的才记 timeout。
- **失败消息也跑 K 扫描**：失败不安装模板、不清旧等待，但该 `capture_pos` 结束
  时仍按 K 规则把到期集合标记 timeout。
- **unresolved 不会伪装成空集合**：未解码集合只出现在 `pending()` 中，绝不产生
  空的流记录；已解码的零值（uint 0、`0.0.0.0`、空文本）正常出现在 `flows()` 中，
  二者可明确区分。
- 容量按“集合头 + 正文”的总长计量，入队即检查；同一消息内更晚的定义**不挽救**
  本消息已因容量被隔离的集合。

## 5. 证据与可查询性

每条流（`flows` + `flow_fields` 表）都保存：

- 捕获身份：`capture_pos / exporter / transport_session` 及文件 SHA-256；
- 消息位置：`export_time / sequence_number / observation_domain_id`（仅保存证据，
  排序一律以 `capture_pos` 为准，不用会回绕的 sequence_number 或时间戳）；
- 集合/记录位置：`set_index / record_index`，来源 `origin`（`immediate` 即时解码 /
  `pending` 等待后接走）与 `origin_pos`；
- 模板版本：`version_seq` 与模板定义位置 `template_defined_pos`；
- 每个字段的原字节 `raw_blob`、绝对起止 `field_offset/field_end`、正文范围
  `value_offset/value_length`，变长字段另有 `prefix_offset/prefix_length`。

`explain(flow_id)` 一次返回上述完整来源链；用返回的偏移回切原始文件即可逐字节
复核。所有未解释消息（含错误码）在 `pending().unexplained` 中列出。

### 消息错误码对照

| code | 含义 |
|---|---|
| `file_read_error` | 文件无法读取（仍登记该 capture_pos） |
| `header_too_short` | 不足 16 字节消息头 |
| `bad_version` | version 不是 10 |
| `length_mismatch` | 头声明长度不等于文件长度 |
| `unsupported_set_id` | set_id 落在不支持区间（如 1、3） |
| `set_declared_out_of_bounds` | 集合声明长度超出消息边界 |
| `set_length_too_short` | 集合长度小于 4 |
| `padding_or_trailing_bytes` | 消息尾部存在不被集合消费的残余 |
| `template_record_truncated` | 模板记录/字段说明/企业号越界 |
| `template_id_below_256` | 模板编号小于 256 |
| `duplicate_field_identity` | 同模板内重复（企业号, 元素号） |
| `field_length_invalid` | 固定长度非正数等非法长度 |
| `unsupported_semantic_length` | 元素1 非 4/8 字节、元素8 非 4 字节等 |
| `template_set_trailing_bytes` | 模板集合记录解析后仍有残余字节 |
| `empty_data_set` | 空数据集合或空模板集合 |
| `bad_utf8_text` | 元素82 文本 UTF-8 解码失败 |
| `field_crosses_set_boundary` | 定长字段跨集合边界 |
| `varlen_prefix_truncated` | 变长长度前缀不完整 |
| `varlen_value_out_of_bounds` | 变长正文超出集合边界 |
| `partial_record_at_set_end` | 集合末尾残余半条记录 |

## 6. 清单规则与分段导入

- 清单按从 0 连续的 `capture_pos` 给出 `(exporter, transport_session, file_path)`，
  可以分段按原位置追加；下一条必须等于当前最大位置 + 1，跳位置抛 `ManifestError`。
- 同位置、同清单身份、同字节（SHA-256）的重传：无操作，返回 `duplicate`。
- 同位置身份改变或字节改变：拒绝，不覆盖原始证据。
- 同一数据库重开时，`max_waiting_bytes` 与 `K` 必须与首次一致，否则拒绝打开。
- 分两次导入后重开查询的结果与一次性同顺序导入**逐表逐行一致**
  （见 `tests/test_persistence.py`）。

## 7. 用法

### Python 接口

```python
from ipfix_offline.ingestor import Ingestor, CaptureEntry

with Ingestor("store.db", max_waiting_bytes=10_000, max_waiting_messages_k=10) as ing:
    ing.import_manifest([
        CaptureEntry(0, "exporter-a", "session-1", "/caps/0.ipfix"),
        CaptureEntry(1, "exporter-a", "session-1", "/caps/1.ipfix"),
    ])
    for flow in ing.iter_flows(exporter="exporter-a"):   # 迭代接口
        ...
    ing.flows(capture_pos=1)                             # 列表查询
    ing.pending()        # unresolved + 各终态等待集合 + 未解释消息
    ing.explain(flow_id) # 完整来源链与字段字节范围
```

### 合成消息构造器（仅用于离线造测试报文）

`ipfix_offline.wire` 提供 `message() / template_set() / template_record() /
withdrawal_record() / data_set() / variable_field() / field_spec()`，并内置
`parse_message()` 与 `decode_data_set()`。**测试中的期望值全部手工计算为字面量，
不调用正式模板绑定器生成预期。**

### 命令行

```bash
python3 -I -m ipfix_offline.cli --db store.db --capacity 10000 --k 10 import manifest.json
python3 -I -m ipfix_offline.cli --db store.db --capacity 10000 --k 10 flows [--exporter ...] [--pos N]
python3 -I -m ipfix_offline.cli --db store.db --capacity 10000 --k 10 pending
python3 -I -m ipfix_offline.cli --db store.db --capacity 10000 --k 10 explain 1
```

## 8. 目录与测试

```
ipfix_offline/
  wire.py       # 线格式解析 + 合成构造器（含明确支持范围声明）
  ingestor.py   # 原子解释、模板版本、等待区/容量/K、SQLite 落盘与查询
  cli.py        # import / flows / pending / explain
examples/
  acceptance.py # 验收主链，逐步打印“预期 vs 实际”
tests/
  test_wire_bytes.py        # 手工字节：254/255 边界、企业同号、零长度文本、越界等
  test_acceptance_chain.py  # 需求验收主链 + 首份模板坏字段隔离
  test_capacity_timeout.py  # 容量恰满/超一字节、到期定义、失败消息到期
  test_manifest_atomic.py   # 清单规则、原子性、explain 证据链、零值区分
  test_persistence.py       # 两段导入重开 vs 一次导入逐行一致、参数校验
  test_large_sample.py      # 大样本容量有界性与峰值/驻留内存证明
run_tests.py                # python3 -I run_tests.py
```

大样本测试（400 条、容量仅容 20 份等待）证明：等待字节任何时刻不超过容量；
`picked / timeout / withdrawn / capacity_isolated / bad_field_isolated` 之后，
集合正文不再被 Ingestor 的 Python 容器引用，只保留在 SQLite 证据表中；处理 80 条
与 400 条且全部终态后，`ingestor.py` 自身的驻留内存增量趋近零而非随消息数线性
增长。
