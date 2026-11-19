# 离线区域文本包导入 v1

离线交付方在本地维护"区域文本包"：一个逻辑入口片段加上它引用的若干原始文本片段。本导入器把文本包编译成 [contract.md](contract.md) 现有单区审计可直接读取的 JSON 快照，并为每条记录保留完整行级来源（哪个片段的哪一行、经由哪条引用链产生）。这是 `dns_zone_audit.zone_import.compile_bundle` 与 `python -m dns_zone_audit.zone_import_cli` 的契约。只实现本文描述的内部文本方言，不做完整 master-file 兼容；不读包外文件、不查询 DNS、不修改服务器。

## 输入契约

顶层严格为 `{"origin", "default_ttl", "entry", "fragments"}`，沿用 `common.py` 的严格读取（8 MB 上限、拒绝重复键与非有限数值）。

- `origin`、`default_ttl` 与现有快照规则完全相同；快照顶层的这两项永远来自包头，片段内的 `$ORIGIN`/`$TTL` 不改变它们。
- `fragments` 为 1–128 项的对象。键是区分大小写的片段 ID，只允许 `[A-Za-z0-9_-]{1,64}`；值是原始文本字符串。所有键值对都校验，包括从未被引用的片段。
- `entry` 必须命名一个存在的片段，解释只从入口开始；未引用片段的正文不被解析。

## 文本方言

物理行按 LF 或 CRLF 划分，从 1 编号；行末换行不产生额外空行，不支持续行。ASCII 空格与 tab 分隔词元；`;` 在引号外开始注释；空行与纯注释不改变状态。指令与类型必须大写；有缩进的指令仍是指令。

- 指令恰有一个参数：`$ORIGIN name`（按当前 origin 规范化，结果必须是快照 apex 或其标签边界内子域）、`$TTL seconds`、`$INCLUDE id`（在当前位置展开片段）。
- 无缩进记录行为 `OWNER [TTL] TYPE RDATA`；以空格或 tab 起始的行为 `[TTL] TYPE RDATA`，没有最近显式 owner 时报错。数字词元为无符号 ASCII 十进制，TTL 与 RDATA 数值沿用现有各字段范围。
- 类型与载荷：`A`/`AAAA` 各一地址，`NS`/`CNAME` 各一名称，`MX` 为 `preference exchange`，`SOA` 为 `mname rname serial refresh retry expire minimum`，`TXT` 恰一个双引号词元。其他类型、多余字段、非法载荷均报错。显式 owner 沿用受限首标签 `*` 规则；名称型 RDATA 不接受 `*`。
- 只有 TXT 载荷使用双引号：允许空字符串与引号内分号，只支持 `\"` 与 `\\`；其他转义、未闭合引号、引号后紧邻非分隔内容均报错。

## 作用域规则

每个片段展开携带三项状态：当前 origin、当前 TTL、最近显式 owner（已绝对化）。入口初始为快照 origin、default_ttl、无最近 owner。`$INCLUDE` 时被引用片段继承调用点这三项；片段返回后调用方三项原样恢复（嵌套时先恢复外层片段，再恢复入口）。`@` 指当前作用域 origin；变更 `$ORIGIN` 不重绑先前 owner。省略 owner 用继承的绝对名，省略 TTL 用当前作用域 TTL；相对 owner 与名称型 RDATA 都按当前作用域解析。owner 的区内归属按顶层 origin 校验，记录 TTL 物化为整数。

同一片段可合法重复引用，不因曾访问而跳过；只有当前活动引用链成环才报错。入口计深度 1，上限 16；展开预算最多 20,000 个物理行（含空白、注释、指令行，按实际出现次数累计）与 10,000 条记录。引用不存在的片段、成环、深度超限定位到触发的引用行；行或记录超限定位到首次超限的行。按入口顺序在引用点深度优先进入子片段，报告此顺序下的首个正文错误。

## 输出契约

`compile_bundle(data)` 返回 `{"zone": {...}, "sources": [...]}`：

- `zone` 严格为 `origin`/`default_ttl`/`records`，可直接传给 `model.analyze`；`records` 使用模型的规范化列表及顺序（按 `(owner, type, RDATA)` 排序），模型 `issues` 不导致导入失败，也不进入结果。
- `sources[i]` 是 `records[i]`（排序后）的完整位置，不是展开顺序。位置固定为 `{"fragment": id, "line": n, "include_chain": [...]}`；链按入口到当前片段排列，每项 `{"fragment": 调用方ID, "line": 引用行号}`，入口行的链为空。

规范化身份（`(owner, type, RDATA)`，TTL 不参与）碰撞即重复记录：报错并同时给出首次与再次发生的完整位置——同一片段同一物理行可经不同引用链在多处产生记录，位置由完整引用链加本地行号区分。正文错误（语法、载荷、模型校验、预算）都在异常 `SourceError` 及其 CLI 诊断中指出完整位置；`SourceError.positions` 以结构化形式携带同样的位置。片段键顺序不影响结果；片段内文本行的移动如实反映在来源行号中。

## 设计：递归解释而非预展开

所选方式是**在引用点递归解释**：读到 `$INCLUDE` 立即进入子片段，子片段拿到调用方三项状态的副本，返回时调用方对象从未被改动，恢复自然成立。位置对象在每条物理行展开时快照当时的引用链，因此同一物理行的多次出现各自携带不同链条；展开顺序天然是契约要求的深度优先序，首个正文错误即首个被抛出的错误。该方式需维护的约束是：状态必须按值下行（任何可共享的可变状态都会破坏恢复语义）；位置链必须逐行快照（否则后续展开会污染已产生记录的来源）；预算计数器全局共享且按出现次数累计。

另一种可行方式是**两阶段预展开**：先把整个包展开成扁平逻辑行流（每行附带预先算好的作用域与位置），再统一解析记录。它把"作用域"和"来源"从解释器状态变成行流属性，需维护的约束相应变为：展开阶段就必须为每一行物化 origin/TTL/owner 三元组（否则相对名与省略 owner 无法在该行所属作用域解析）；行流顺序必须严格等于深度优先展开序，否则"首个正文错误"的定义改变；同一物理行的每次出现都要复制成行流中独立元素并各自快照引用链，内存中同时持有至多 20,000 行及其位置。两种方式都同样要求：重复访问不跳过、仅活动链成环报错、预算按出现次数累计；递归方式以调用栈直接表达这些约束，预展开方式则以行流复制表达，本实现选择状态恢复与来源快照更难出错的递归解释。

## 结果与 CLI

```sh
python -m dns_zone_audit.zone_import_cli --source fixtures/zone-import-input.json --output run/import-report.json
dns-zone-import --source fixtures/zone-import-input.json --output run/import-report.json
```

报告严格为 `{"schema_version": 1, "source_sha256": 原始包字节SHA256, "result": 接口结果}`，stdout 输出同一对象。沿用 `common.py` 的严格读取与原子发布：坏输入退出 2、保留旧报告、不写部分快照；拒绝输入输出同路径与符号链接输出。既有 `dns-zone-audit`、`dns-zone-bootstrap`、`dns-zone-change`、`dns-zone-wildcard` 的行为与契约不变。结果不含时间、随机值或绝对路径；同输入重跑输出逐字节相同。运行只依赖标准库，全程离线。

## 联动样例

`fixtures/zone-import-input.json` 从两个不同作用域引用同一 `shared` 片段，片段首行是缩进的 `  MX 10 relay`：入口先在 `one.example.test.`、`$TTL 300`、最近 owner `www.one.example.test.` 下引用它，再在 `two.example.test.`、`$TTL 600`、最近 owner `mail.two.example.test.` 下引用它。产物中两条 MX 记录分别落在 `www.one.example.test.`（exchange `relay.one.example.test.`、TTL 300）与 `mail.two.example.test.`（exchange `relay.two.example.test.`、TTL 600），来源同为 `shared` 第 1 行但引用链分别为 `main:5` 与 `main:9`；排序后 `sources` 与 `records` 一一对齐。该区域经现有 `dns-zone-audit` 复核为 `valid=true`。
