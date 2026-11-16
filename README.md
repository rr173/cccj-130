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

## 8. 离线 NAT 关联作业

从**已入仓**的流记录出发，按地址转换日志回溯“这段连接在各个时段有哪些可能的
原始 (域, 五元组)，证据是否追完整”。用于采集数据溯源；**不计算租户流量、服务
账单或路径概率，也不以最近一条日志猜来源**。原有 `import / flows / pending /
explain` 的含义（含等待裁定）不因本作业改变。

### 8.1 输入文件外形

**配置 JSON**（UTF-8）：

```json
{
  "realms": ["H", "M", "W"],
  "links": [["H", "M"], ["M", "W"]],
  "origins": ["H"],
  "observations": [
    {"exporter": "exporter-a", "transport_session": "session-1",
     "observation_domain_id": 11, "realm": "W"}
  ]
}
```

- `realms`：不重复的非空观测域名称。
- `links`：有向二元组 `[内侧域, 外侧域]`。不能自连、重号或成环。
- `origins`：必须**恰好**是没有入边的域。日志暂缺的中间域不能被当原始域；
  反之有入边的域也不能冒充原始域。
- `observations`：每项用 `(exporter, transport_session, observation_domain_id)`
  的**精确组合**绑定一个 realm；不支持通配、前缀匹配或跨会话借用。同一组合重复
  绑定即拒绝。

任何引用/身份错误（未知域、重复、环、origins 不精确等）都定位到
`realms[i] / links[i] / origins[i] / observations[i].字段` 拒绝，作业在输出任何
请求答案前失败。

**转换日志 JSONL**（UTF-8，每行一个对象，不允许空行）：

```json
{"mapping_id": "m-1", "from_realm": "H", "to_realm": "M",
 "before": [6, "10.0.0.1", 1000, "203.0.113.10", 443],
 "after":  [6, "10.0.10.1", 2000, "203.0.113.10", 443],
 "start_ms": 0, "end_ms": 8}
```

- `mapping_id` 非空字符串，**全文件（所有日志文件合计）唯一**；重复即输入错误，
  错误信息给出两处文件与物理行号。
- 五元组 = `[protocol, src_ip, src_port, dst_ip, dst_port]`。本版仅接受
  `protocol ∈ {6, 17}`、规范点分十进制 IPv4（`010.0.0.1` 这类非规范写法拒绝）、
  `0..65535` 的整数端口。`before` 与 `after` 的协议必须相同（NAT 不改协议）。
- 域对必须是配置中的一条 `link`。
- `start_ms / end_ms` 是 `0..2^64-1` 的整数毫秒，`start_ms < end_ms`，适用范围
  为 `[start_ms, end_ms)`。整数不接受布尔值，不经浮点转换。
- 不同 `mapping_id` 的日志即使描述完全相同也各算独立证据；外侧同一五元组可能
  对应多个内侧候选，必须一起保留。

坏 JSON、坏地址、缺字段、非法引用、重复 `mapping_id`、空行，**包括最后一行**的
错误，都使本次作业无法开始；不会先输出部分答案。

**请求 JSONL**：

```json
{"request_id": "r-1", "flow_id": 42}
```

`request_id` 非空字符串且全文件唯一；`flow_id` 正整数。请求文件自身的结构错误
（坏 JSON、重复 request_id、非正整数 flow_id）同样中止整批；而“某条流不可用作
关联输入”只是该请求的 `invalid_flow` 业务结论，其余请求照常处理。

### 8.2 流字段来源与 invalid_flow

只读当前接入库，从每条流的标准字段取身份（**enterprise_number 必须为 NULL**，
企业号同号字段不能顶替）：

| IE | 含义 | 正文长度 | 解释 |
|---|---|---|---|
| 4 | protocolIdentifier | 1 | 必须 6 或 17 |
| 7 / 11 | source/destinationTransportPort | 2 | 大端无符号 |
| 8 / 12 | source/destinationIPv4Address | 4 | 点分 IPv4 |
| 152 / 153 | flowStart/EndMilliseconds | 8 | 大端无符号毫秒 |

时间用流自身的 IE152/153，不用 `capture_pos`、`export_time` 或模板发布时间。
读取现有 `raw_blob`，不要求扩大旧解码器的协议范围。以下情形该请求为
`invalid_flow` 并给出具体原因，其他合法请求仍处理：

| reason | 触发条件 |
|---|---|
| `flow_not_found` | flow_id 不存在 |
| `no_observation_realm` | `(exporter, transport_session, observation_domain_id)` 没有精确绑定 |
| `missing_standard_ie` | 缺某个必需标准 IE（或该字段无原字节） |
| `enterprise_ie_cannot_substitute` | 缺标准 IE，只有企业号同号字段 |
| `bad_ie_length` | 字段正文长度不符合上表 |
| `protocol_not_tcp_udp` | IE4 不是 6/17 |
| `bad_time_range` | IE152/153 起止非法（`start >= end`） |

### 8.3 关联语义

对于流区间里的某个时刻，从观察到的 `(realm, 五元组)` 向内回溯：

- 本时刻所有 `to_realm` 与 `after` 都精确相同的日志均可用，分别进入其
  `from_realm` 和 `before`，再继续。域名称与五元组方向都是身份的一部分。
- 一条完整来源必须是**同一条所有日志在该时刻都有效的链**并最终到达 origins。
  “每条日志都与整段流有交集”不构成来源链。
- 到达非原始域而该时刻没有任何可用前驱日志：该状态记为 **frontier**，片段为
  `incomplete`。即使另一支已追到来源也是如此——断支路不会被删掉。
- 观察域本身就是原始域：来源就是观察五元组，无需日志。
- 同一原始 `(realm, 五元组)` 经多条链到达只算一个候选，但两路日志依据都保留。

### 8.4 片段与四种状态

每条合法流被分成**连续、不重叠、覆盖整个 `[start_ms, end_ms)`** 的片段；时间
端点不产生零长度片段。每段有去重后的 origins、frontiers 及状态：

| 状态 | 边界 |
|---|---|
| `unmapped` | 初始观察状态在**该时刻**没有任何可用前驱日志，且自身不是原始域。此时 frontiers 只含观察状态本身，没有来源 |
| `incomplete` | 已沿日志走过，但该时刻存在至少一个 frontier；即使另一支已到达来源也仍为 incomplete |
| `unique` | 没有 frontier，且去重后恰好一个原始来源 |
| `ambiguous` | 没有 frontier，且去重后多于一个原始来源 |

`unmapped / incomplete / ambiguous` 都是一次**成功**得到的业务结论：它们不是
程序错误，也**不计为已确定来源**（`determined_fragment_count` 只统计 `unique`）。
日志缺失不能证明没有别的来源，只能说明本库证据没追完——这是本作业的固有限制。

相邻两段只有在**候选集合、frontier 集合以及证据图（节点 + 带 mapping_id 的边）
都相同**时才合并。来源没变但支撑日志换了（例如 `mapping_id` 变化），保留切口，
便于解释当时的依据。

### 8.5 反向证据图

每片段交出从观察状态出发的反向可达子图：

- 节点是完整的 `(realm, 五元组)`，共享中间状态只表示一次。
- 边标 `mapping_id`，从外侧状态指向内侧状态，并附日志原件路径、物理行号与该
  日志的有效区间；可直接回查日志原行。
- 保留该片段**所有**可达的有效边，包括通向缺日志前沿的边；不删断支路。
- 稳定顺序：候选 / frontier / 节点按 `(realm, protocol, src_ip 数值, src_port,
  dst_ip 数值, dst_port)` 升序；边按 `mapping_id` 升序；片段按时间升序。
- 图的规模是可达状态数，不是完整路径数。共享路径再多也不展开成条条完整链；
  但也不会把不同时间的边压成一条可行链。

### 8.6 索引与资源边界

转换日志流式写入工作目录下的临时 SQLite 索引（`nat_logs` 表），**不会把日志全文
装进 Python 容器**。索引 `idx_nat_lookup` 同时约束六列等值（`to_realm,
to_proto, to_sip, to_sport, to_dip, to_dport`）与 `start_hex` 范围：

```sql
SELECT ... FROM nat_logs
 WHERE to_realm=? AND to_proto=? AND to_sip=? AND to_sport=?
   AND to_dip=? AND to_dport=? AND start_hex < ? AND end_hex > ?
```

- 时间以 16 位零填充十六进制文本存索引：SQLite INTEGER 是有符号 64 位，定宽
  十六进制串的字典序等于整数序，因此 `2^63` 以上仍精确。
- 只把**与流区间相交**的日志按 (域, 五元组) 等值取出，再按时刻过滤；每条请求
  不能从头扫描整份日志。作业启动时用 `EXPLAIN QUERY PLAN` 确认索引生效，否则
  拒绝运行。
- 粗遍历只扩展由重叠日志可达的状态，得到分段端点（真实端点的超集）；每段的
  证据图是单个可达子图。
- 原库以只读 URI（`mode=ro` + `PRAGMA query_only=ON`）打开，一个只读事务覆盖
  整批请求，**绝不写原库**。临时索引放在 `--work-dir` 下本次创建的
  `.ipfix_nat_*` 目录，作业结束只删除该目录；工作目录里的其它文件不动。
  `--keep-index` 可保留本次索引。

`index.log_rows_returned` / `index.lookups` 记录真实访问范围；`peak_python_bytes`
是请求阶段 Python 分配峰值，`peak_rss_bytes` 是进程级峰值 RSS。

需要一棵可回查全部 mapping_id 的定位表时加 `--mapping-index PATH`：作业会把
`{"mapping_id", "file_path", "line_no"}` 逐行流式写成 JSONL（`file_path` 与
`line_no` 指向日志原件的 1 起始物理行号），并在报告 `mapping_index` 中给出
条数与路径。索引临时目录被清理后，用它配合原日志即可重新定位每一条依据。

### 8.7 命令与退出码

```bash
# 独立 CLI
python3 -I ipfix_offline/nat_correlate.py \
  --db store.db --config topology.json \
  --log logs/a.jsonl --log logs/b.jsonl \
  --requests requests.jsonl --out report.json --work-dir /tmp/nat-work
# 也可： python3 -m ipfix_offline.nat_correlate ...（同上参数）

# 或用既有 CLI 的 nat 子命令
python3 -m ipfix_offline.cli --db store.db nat \
  --config topology.json --log logs/a.jsonl --requests requests.jsonl \
  --out report.json --work-dir /tmp/nat-work
```

```python
from ipfix_offline.nat_correlate import NatCorrelator, load_requests, run_job

report = run_job("store.db", "topology.json", ["logs/a.jsonl", "logs/b.jsonl"],
                 "requests.jsonl", "report.json", work_dir="/tmp/nat-work")

# 或分步：一次建索引，多次按需查询
with NatCorrelator("store.db", "topology.json", ["logs/a.jsonl"], "/tmp/work") as nc:
    flow = nc.extract_flow(42)          # invalid_flow 时抛 _InvalidFlow
    fragments = nc.correlate_flow(flow)
    report = nc.correlate_requests(load_requests("requests.jsonl"))
```

退出码：`0` 全部请求合法且已作答；`1` 有 `invalid_flow`（报告仍完整写出，
每条合法请求的片段与图齐全）；`2` 配置/日志/请求文件/库结构错误（此时不写报告）。
报告顶层固定 `"complete": true` 且 `summary.status == "complete"`，与业务结论
（`unique / ambiguous / incomplete / unmapped`）分开。

### 8.8 交接演示：错误关联是怎样被挡住的

`examples/nat_hand_calculation.py` 按需求正文的例子手算并核对：H→M→W，四条
日志 `A→X[0,8)`、`X→Z[4,10)`、`B→Y[5,10)`、`Y→Z[0,7)`，流 Z 在 W 覆盖
`[0,10)`。若只看“每条日志与整段流有交集”，会把 `A→X` 与 `X→Z` 串成来源、
把 `B` 与 `Y` 串成另一来源；逐时刻求“全链同时有效”后得到：

| 片段 | 状态 | 来源 | frontier | 依据边 |
|---|---|---|---|---|
| `[0,4)` | incomplete | — | Y | Y→Z |
| `[4,5)` | incomplete | A | Y | A→X, X→Z, Y→Z |
| `[5,7)` | ambiguous | A, B | — | A→X, X→Z, B→Y, Y→Z |
| `[7,8)` | unique | A | — | A→X, X→Z |
| `[8,10)` | incomplete | — | X | X→Z |

把 `A→X` 的终点从 8 改成 4 后，`[4,4)` 是空区间，端点相碰不算同时有效，A 在
整条流上都不再出现。脚本同时演示：日志顺序打乱、跨文件后业务片段与
`mapping_id` 图不变，物理行号跟随新原件。

完整可重演材料由 `examples/nat_material.py [目录]` 生成：配置、两份打乱顺序的
日志、合成 IPFIX 消息、经现有 `import` 真正入仓的 `store.db`、请求、手写
`expected.json`，以及 `rebuild.py` / `run.sh`。`run.sh <仓库根>` 会删库重建并
重跑关联，写出 `report2.json`；材料里故意含 4 条 invalid_flow 请求，因此该命令
按约定返回 1（业务结论，不是结构错误）。材料生成时即与手写预期逐项比对，不一致
则非零退出。

## 9. 目录与测试

```
ipfix_offline/
  wire.py            # 线格式解析 + 合成构造器（含明确支持范围声明）
  ingestor.py        # 原子解释、模板版本、等待区/容量/K、SQLite 落盘与查询
  cli.py             # import / flows / pending / explain / nat
  nat_correlate.py   # 离线 NAT 关联：配置/日志/请求校验、磁盘索引、片段与证据图
examples/
  acceptance.py           # 导入/等待/解释的验收主链
  nat_hand_calculation.py # 逐段手算 vs 实际，含端点相碰与顺序无关
  nat_material.py         # 生成可重演材料目录（配置/日志/库/请求/重演脚本）
tests/
  test_wire_bytes.py          # 手工字节：254/255 边界、企业同号、零长度文本、越界等
  test_acceptance_chain.py    # 需求验收主链 + 首份模板坏字段隔离
  test_capacity_timeout.py    # 容量恰满/超一字节、到期定义、失败消息到期
  test_manifest_atomic.py     # 清单规则、原子性、explain 证据链、零值区分
  test_persistence.py         # 两段导入重开 vs 一次导入逐行一致、参数校验
  test_large_sample.py        # 大样本容量有界性与峰值/驻留内存证明
  test_nat_semantics.py       # 两链汇合、断支路、无首跳、观察点即原始域、异域同
                              # 五元组、端口复用+目的改写、企业同号、2^53 时间、
                              # invalid_flow 隔离、独立枚举参考器、顺序无关
  test_nat_inputs.py          # 配置/日志/请求的结构错误拒绝与定位
  test_nat_integrity.py       # 只读保证、临时文件清理、依据变化保留切口
  test_nat_cli.py             # 命令行退出码、报告落盘、keep-index
  test_nat_entrypoints.py     # 模块入口与既有 CLI 的 nat 子命令
  test_nat_scale.py           # 2^24 条完整链的可压缩证据图、20 万日志 + 1000 请求
run_tests.py        # python3 -I run_tests.py
```

大样本测试（400 条、容量仅容 20 份等待）证明：等待字节任何时刻不超过容量；
`picked / timeout / withdrawn / capacity_isolated / bad_field_isolated` 之后，
集合正文不再被 Ingestor 的 Python 容器引用，只保留在 SQLite 证据表中；处理 80 条
与 400 条且全部终态后，`ingestor.py` 自身的驻留内存增量趋近零而非随消息数线性
增长。

NAT 规模测试（`test_nat_scale.py`）实测：

- 24 层、每层 2 分支的分叉再汇合：完整来源链 `2^24 = 16,777,216` 条，证据图
  只有 73 个节点 / 96 条边，单请求约 40 ms 给出 `unique` 来源与全部依据；
- 200,036 条日志（其中 200,000 条与请求无关）+ 1000 个请求：日志索引访问
  `lookups=25`、`log_rows_returned=36`，总耗时约 10 s（建索引约 7 s，
  请求约 2 s），索引约 52 MB，请求阶段 Python 峰值约 48 MB，进程峰值 RSS
  约 137 MB。日志全文从不进入 Python 容器；每条请求只展开单个可达子图。

这些数字是本次运行观测值，不作为语义正确性的替代——语义由上面的手算与独立
枚举参考器逐项核对。
