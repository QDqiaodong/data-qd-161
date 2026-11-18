# DNS 区域快照发布变更审计 v1

输入是一个严格 JSON 对象，顶层必须且只能包含 `current` 与 `candidate` 两个字段；两者各是一份现有单区域快照（`origin`、`default_ttl`、`records`），完全复用 [contract.md](contract.md) 的名称、TTL、记录载荷、IP、重复记录与大小限制规则并分别规范化。两份快照的规范化 origin 必须相同；每份快照必须恰有一条 owner 为 apex 的 SOA（缺失、重复或仅存在于子域均拒绝）。重复 JSON 键、非有限数值、超限输入、非法记录或不合法 SOA 均失败。

## 序列比较

SOA serial 按 RFC 1982 的 32 位序列空间比较：`delta = (candidate_serial - current_serial) % 2**32`。

| delta | relation | can_publish |
| --- | --- | --- |
| `0` | `same` | `false` |
| `1 .. 2**31-1` | `newer` | `true` |
| `2**31` | `ambiguous` | `false` |
| `2**31+1 .. 2**32-1` | `older` | `false` |

只有两份输入均合法、origin 相同、且关系恰为 `newer` 时 `can_publish` 才为 `true`。相同 serial 即使记录不同也仍是 `same`，不构成新发布；serial 较旧或半空间歧义时，记录级新增/删除不会使候选变为可发布。

## 记录差异

RDATA 先按现有模型规范化（名称小写绝对化、IP 压缩、TXT 原样等），记录身份键为 `(owner, type, canonical RDATA)`；TTL 不参与身份匹配，继承 `default_ttl` 后再比较。同一身份两侧都存在时，TTL 相同为 `unchanged`、不同为 `ttl_changed`（同时输出两侧 TTL）；仅当前存在为 `removed`，仅候选存在为 `added`。RDATA 改变表现为一条 `removed` 加一条 `added`，不做替换猜测或合并。

每条差异含 `change`、`identity`、`before`、`after`；不存在的一侧为 `null`。`identity` 为 `owner`/`type`/`data`，`before`/`after` 为 `ttl`/`data`。所有差异按 `(owner, type, canonical RDATA, change)` 排序，字段集合固定且不随类别变化。

注意：SOA serial 属于 RDATA，serial 改变本身就会产生一对 `removed`/`added`——这是契约要求的事实记录，不参与 `can_publish` 判定。

## 结果与 CLI

业务结果严格为 `origin`、`serial`、`can_publish`、`changes`、`summary`；`serial` 严格为 `current`/`candidate`/`delta`/`relation`；`summary` 严格为四类计数。结果不含时间、随机值或绝对路径。

```sh
python -m dns_zone_audit.change_cli --source fixtures/change-input.json --output run/change-report.json
dns-zone-change --source fixtures/change-input.json --output run/change-report.json
```

报告严格为 `{"schema_version":1,"source_sha256":原始输入字节SHA256,"result":接口结果}`，stdout 输出同一对象。沿用 `common.py` 的严格读取与原子发布：失败退出 2 并保留旧报告，拒绝输入输出同路径与符号链接输出；合法但不可发布的输入仍成功生成报告。既有 `dns-zone-audit`、`dns-zone-bootstrap` 的参数与输出不变。全程不发起 DNS 查询、不修改任何服务器。
