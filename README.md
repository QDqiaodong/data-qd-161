# data-qd-161 · 权威DNS区域一致性审计

Offline authoritative DNS zone semantic validation and delegation checks。业务输入、计算和当前边界详见 [数据契约](docs/contract.md)；多区域离线引导可达性审计见 [bootstrap 契约](docs/bootstrap.md)；同源候选快照的发布变更审计见 [change 契约](docs/change.md)；单区 wildcard 有效答案审计见 [wildcard 契约](docs/wildcard.md)；离线区域文本包导入见 [zone-import 契约](docs/zone-import.md)。

## 安装与演示

Python >=3.11，运行和测试仅用标准库；建议 Python 3.12。使用 uv 建立独立环境，构建工具锁版本。首次安装无公共缓存时需要访问包索引；业务运行不访问网络。

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements-build.lock
uv pip install --python .venv/bin/python --no-build-isolation --no-deps .
uv pip check --python .venv/bin/python
.venv/bin/dns-zone-audit --source fixtures/input.json --output run/report.json
.venv/bin/dns-zone-bootstrap --source fixtures/bootstrap-input.json --output run/bootstrap-report.json
.venv/bin/dns-zone-change --source fixtures/change-input.json --output run/change-report.json
.venv/bin/dns-zone-wildcard --source fixtures/wildcard-input.json --output run/wildcard-report.json
.venv/bin/dns-zone-import --source fixtures/zone-import-input.json --output run/import-report.json
.venv/bin/python -m unittest discover -s tests -v
```

修改源码后重新安装。演示应报告 `valid=false` 和一条 `in_zone_glue_missing` 发现；这是样例预期，不是CLI失败。bootstrap 演示应报告 `all_reachable=true`，`a.example.test.` 第1轮以 glue 成立、`b.example.test.` 第2轮以 authority 成立。change 演示的候选 serial 从 `0xffffffff` 回绕到 `0`，应报告 `relation=newer`、`can_publish=true`，并把仅 TTL 变化的 A 记录列为 `ttl_changed`。wildcard 演示应报告 `anything` 由 apex `*` 合成、`x.branch` 由更近的 `*.branch` 合成、`branch` 为 empty non-terminal、`x.child` 为 delegated。import 演示把共享片段从两个作用域各引用一次，应产生 `www.one.example.test.`（TTL 300）与 `mail.two.example.test.`（TTL 600）两条 MX 记录，来源同为 `shared` 第 1 行但引用链分别为 `main:5` 与 `main:9`，导入区域经现有审计复核为 `valid=true`。本仓不共享其他仓环境，不依赖Docker、外部账号或持续服务。

输入JSON最多8MB，拒绝重复键、非有限数值和未定义字段；源字节SHA256随结果保留。
输出是可独立读取的JSON；成功后原子替换，输入/计算失败退出2并保留旧报告。
输入和输出不得相同，输出符号链接拒绝。单操作者批处理，不承诺并发发布或断电恢复。
同输入重跑不累加。测试使用临时目录，运行产物在忽略的run/。

src/dns_zone_audit/model.py 为业务模型，common.py 提供受限JSON及报告发布，
cli.py 衔接数据链路。bootstrap.py 复用单区域规范化，按显式依赖规则求根区域支持的最小闭包，
bootstrap_cli.py 以同一发布语义输出多区域可达性报告。change.py 在同一规范化之上按 RDATA 身份匹配两份快照并做 RFC 1982 serial 判定，
change_cli.py 以相同发布语义输出变更审计报告。wildcard.py 在单区节点集合上按显式/委派/ENT/wildcard 顺序判定有效答案，
wildcard_cli.py 复用同一发布语义输出单区 wildcard 审计报告。zone_import.py 把离线文本包递归解释为单区快照并保留逐记录来源，
zone_import_cli.py 以相同发布语义输出导入报告。fixtures 为明确自制样例，代码与样例采用MIT许可。
