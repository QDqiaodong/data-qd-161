# 离线 DNS 区域结构脱敏导出 v1

支持人员核对一个区域的记录分布与名称引用时，不应拿到原始域名和记录载荷。本导出把 [contract.md](contract.md) 的现有单区快照编译成一份**结构数据集**：顶点、每个记录 owner 和每个名称型 RDATA 目标都变成不透明别名，记录按 `(owner, 类型, 目标)` 汇成计数分组。这是 `dns_zone_audit.redact.analyze` 与 `python -m dns_zone_audit.redact_cli` / `dns-zone-redact` 的契约。产物供支持工单附件使用，**不是可加载的区域文件**，也不承诺隐藏可由结构或计数推断的信息（见下文"能恢复什么"）。不访问网络、不查询 DNS、不修改服务器。

## 输入契约

输入就是现有单区快照，严格为 `{"origin", "default_ttl", "records"}`，字段、类型、校验与规范化完全沿用 `model.py`（含 owner 的受限首标签 `*` 规则、记录去重、地址规范化）；局部一致性 findings（如缺 glue、apex SOA 数量异常）不阻止合法快照导出。沿用 `common.py` 的严格读取：8 MB 上限、拒绝重复 JSON 键与非有限数值。

## 别名契约

别名是对象 `{"space": "zone"|"external", "path": [...]}`，两个命名空间互不相交：

- 规范化顶点是 `zone` 空间的根，路径为空 `[]`；区内名称（顶点本身或顶点在完整标签边界内的后代）每标签一步、从根到叶延伸路径。区内归属只按完整标签边界判断：`ns.notexample.test.` 这类近似后缀是区外名称。
- 区外名称属于 `external` 空间，从区外命名空间根起编码**完整**名称（每一步对应一个标签，含 TLD 一侧）。
- 路径的每一步是正整数；原 owner 左端的完整通配标签 `*` 不编号，在路径末尾保留为字符串 `"*"`。
- 整数按 `(空间, 父路径)` 分组、在每组内按标签排序后从 1 分配。因此导出只依赖规范化后的名称集合：同一输入的记录重排、等价名称拼写（大小写、`@`、相对/绝对写法）和 TTL 差异都不改变结果。同一空间内，输出路径相等当且仅当原规范化名称相等；一条路径是另一条的真前缀当且仅当原名称是另一名称的标签级严格祖先。
- 整条别名仅在本次快照内有意义；独立快照之间不承诺同号，产物中也不存在别名反查表。

## 输出契约

`analyze(data)` 的结果严格为 `{"names": [...], "groups": [...]}`：

- `names` 每项严格为 `{name, has_records}`，`name` 是别名。名称表包含顶点、全部实际 owner 和全部名称型 RDATA 目标（NS/CNAME 的 target、MX 的 exchange、SOA 的 mname 与 rname）；纯中间路径不另列。只有实际拥有原始记录的节点 `has_records` 为 `true`；仅被引用的名称即使是其他记录 owner 的祖先，也保持 `false`。
- `groups` 每项严格为 `{owner, type, targets, count}`。每条规范记录计一次且只计入一个分组：owner 与类型相同、有角色目标也相同的记录汇成一组，`count` 为记录条数。`targets` 是角色到别名的映射：NS、CNAME 用 `target`，MX 用 `exchange`，SOA 用 `mname` 与 `rname`，A、AAAA、TXT 为空对象。地址、TXT 文本、TTL、SOA 数字参数与 MX preference 一律不进入分组键，也不出现在产物中。
- 分组与名称表引用同一批别名：任何 `owner` 或 `targets` 值都能在名称表中找到同一对象。
- 排序：名称项按 `(space, path)`；分组按 `(owner.space, owner.path, type, targets)`，其中 `targets` 按角色名排序后逐项比较 `(角色名, space, path)`。路径逐项比较，`"*"` 排在整数之前，真前缀排在较长路径之前；`space` 按字符串比较（`external` 在 `zone` 前）。

## 能从报告恢复什么 / 不能恢复什么

**能恢复**（这是报告的用途，不视为泄漏）：

- 记录按 `(owner, 类型, 目标组合)` 的分布与计数；每个名称是否持有记录。
- 名称树的结构：名称数量、深度（标签数）、祖先/后代关系、共享同一目标的记录、通配 owner 的存在与位置、名称在区内还是区外。
- 同一快照内名称的相等性（哪些引用指向同一名称）。
- 兄弟标签的相对字典序：整数步骤按排序后的标签分配，因此同父兄弟的编号顺序反映原标签的字母顺序（但推不出标签内容）。
- 同输入重跑结果逐字节相同，可比对两次导出是否来自同一快照。

**不能恢复**：

- 任何原始名称标签、顶点文本、地址、TXT 载荷、TTL、SOA 数字参数、MX preference。
- 输入字节摘要与任何别名反查表（产物不含 `source_sha256`，也没有名称到别名的逆映射）。
- 未作为顶点、owner 或目标出现的名称的任何信息。
- 区外名称的具体归属；不同快照之间别名的对应关系。

## 结果与 CLI

```sh
python -m dns_zone_audit.redact_cli --source fixtures/redact-input.json --output run/redact-report.json
dns-zone-redact --source fixtures/redact-input.json --output run/redact-report.json
```

报告严格为 `{"schema_version": 1, "result": 接口结果}`，stdout 输出同一对象（同值 JSON）。与其他工具不同，本报告**不携带** `source_sha256`。沿用 `common.py` 的严格读取与原子发布：非法输入或写入失败退出 2、保留旧报告、不向 stdout 写部分结果；拒绝输入输出同路径与符号链接输出。错误诊断不回显输入内容（重复键名、不可解码字节等均替换为通用描述）。既有 `dns-zone-audit`、`dns-zone-bootstrap`、`dns-zone-change`、`dns-zone-wildcard`、`dns-zone-import`、`dns-zone-cache-replay` 的行为与契约不变。运行只依赖标准库，全程离线。

## 联动样例

`fixtures/redact-input.json` 为完全合成数据：顶点两条 MX 仅 preference（10/20）与 TTL 不同、都指向有 A 记录的 `mail.ops`，汇成计数 2 的一组，`exchange` 指向 `mail.ops` 的别名（路径 `[1, 3]`，`has_records=true`）；`alias.ops` 的 CNAME 指向无记录的 `ghost.ops`（路径 `[1, 2]`，`has_records=false`），而 `leaf.ghost.ops` 有 TXT（路径 `[1, 2, 1]`），目标路径是其真前缀；`*.ops` 的 owner 路径为 `[1, "*"]`；SOA 的 `mname` 在区内（`[1, 4]`，与 NS target 同一别名）、`rname` 在区外（`external` 空间 `[1, 2, 1]`）；`www` 的 CNAME 指向区外 `[1, 1, 1]`。整份导出含 10 个名称项、9 个分组，计数合计等于记录数 10。
