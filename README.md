# 读写仲裁交集分析器

该服务枚举存储实例中所有可行的读、写仲裁集，并判断：

1. 读侧是否仍能形成满足权重门槛和机房覆盖要求的仲裁集；
2. 写侧是否仍能形成满足权重门槛和机房覆盖要求的仲裁集；
3. 两侧均可行时，所有可行读写对的最小交集大小；
4. 若最小交集为 0，按规则返回一对真实不相交的读写反例。

离线副本不会进入任何仲裁集。权重阈值之和不是充分判据：机房覆盖会迫使不同仲裁集选择不同副本，因此必须枚举可行仲裁集后检查交集。

## 输入协议

`POST /analyze` 接收 UTF-8 JSON：

```json
{
  "replicas": [
    {"id": "a1", "weight": 6, "datacenter": "A", "online": true},
    {"id": "a2", "weight": 6, "datacenter": "A", "online": true},
    {"id": "b1", "weight": 6, "datacenter": "B", "online": true},
    {"id": "b2", "weight": 6, "datacenter": "B", "online": true}
  ],
  "read": {"weight_threshold": 12, "required_datacenters": ["A", "B"]},
  "write": {"weight_threshold": 12, "required_datacenters": ["A", "B"]}
}
```

约束：

- `replicas`：2～12 个对象；
- `id`：非空 ASCII 字符串，且在实例内唯一；
- `weight`：1～9 的整数；
- `datacenter`：非空 ASCII 字符串；
- `online`：布尔值；
- `read.weight_threshold`、`write.weight_threshold`：非负整数，缺省为 0；
- `required_datacenters`：非空 ASCII 机房名数组，同层不得重复，缺省为空，且每个机房都必须在 `replicas` 中出现；
- `recovery`：可选布尔值，为 `true` 时在结果中追加恢复规划，缺省为 `false`；
- `maintenance_rehearsal`：可选，格式为 `{"replica_ids": [...]}`，也可直接传副本 ID 列表。列表最多 5 个互异且存在的副本 ID；为空列表时只检查初态。

阈值为 0 且没有机房要求时，空仲裁集可行。

## 输出协议

两侧均可行时：

- `minimum_intersection`：所有可行读写对的最小交集成员数；
- `witness_read`、`witness_write`：达到该最小交集的一对仲裁集；
- `safe`：仅当最小交集大于 0 时为 `true`。

若任意一侧没有可行仲裁集，最小交集为 `null`，`safe` 保持 `false`，避免无可行仲裁集时误报安全。

当最小交集为 0，`disjoint_counterexample` 提供实际不相交反例。多个并列反例按以下顺序选择：

1. 两集合总成员数最少；
2. 读侧排序后的 id 列表字典序最小；
3. 写侧排序后的 id 列表字典序最小。

示例：

```json
{
  "read_possible": true,
  "write_possible": true,
  "minimum_intersection": 0,
  "witness_read": {"replica_ids": ["a1", "b1"]},
  "witness_write": {"replica_ids": ["a2", "b2"]},
  "disjoint_counterexample": {
    "read": {"replica_ids": ["a1", "b1"]},
    "write": {"replica_ids": ["a2", "b2"]}
  },
  "safe": false
}
```

非法请求返回 HTTP 400 和 `{"error": "..."}`。

## 恢复规划

请求带 `"recovery": true` 时，响应追加 `recovery_plan` 字段，回答“最少恢复哪些离线副本才能重新形成读写仲裁，并保证任意可行读写仲裁仍相交”：

- 候选仅为当前离线副本；每个候选恢复集合都按原权重、机房和在线语义重新完整裁决；
- 安全指恢复后读、写两侧均可行且最小交集大于 0，仅两侧各自可行不算安全；
- 交集安全性关于恢复集合不是单调的：多恢复副本可能启用新的不相交仲裁对，因此枚举全部子集，不做贪心假设；
- 选择恢复数量最少的安全集合，并列时取副本 id 列表字典序最小者，结果唯一。

字段含义：

- `already_safe`：当前状态已安全时为 `true`，此时 `restore` 为空数组；
- `reachable`：是否存在安全的恢复集合；
- `restore`：建议恢复的副本 id 列表；不可达时为 `null`；
- `read_possible`、`write_possible`、`minimum_intersection`、`witness_read`、`witness_write`：恢复后状态下的真实裁决结果与见证；不可达时均为 `null`。

未启用规划时（缺省或 `"recovery": false`），响应不包含 `recovery_plan`，与原输出完全一致。示例见 `examples/recovery.json`。

## 维护顺序预演

请求带 `"maintenance_rehearsal"` 时，响应追加同名字段，用于在值班员逐台维护前预演切换顺序：

- 每个指定副本恰好切换一次在线状态：在线变离线、离线变在线；
- 起始状态以及完整顺序中的每一步切换后，都必须同时存在可行读、写仲裁；
- 每个被检查状态下，所有可行读写对都必须至少相交一台（即 `safe: true`）；
- 在所有完整、全程安全的顺序中，取副本 ID 序列字典序最小者；
- 恢复一台离线副本可能增加新的可选仲裁并引入不相交对，因此每个前缀都重新完整裁决，不能只看最终状态，也不能假设安全性随在线副本数量单调改善。

成功时：

```json
{
  "possible": true,
  "failure_reason": null,
  "order": ["a1"],
  "steps": [
    {
      "step": 1,
      "replica_id": "a1",
      "safe": true,
      "read_possible": true,
      "write_possible": true,
      "minimum_intersection": 3,
      "witness_read": {"replica_ids": ["a2", "b1", "b2"]},
      "witness_write": {"replica_ids": ["a2", "b1", "b2"]}
    }
  ]
}
```

`replica_id` 是这一步切换的副本；成功计划中的每一步 `safe` 都为 `true`。见证对展示该步真实可行且达到最小交集的读写仲裁，便于复核。

初态不安全时返回：

```json
{"possible": false, "failure_reason": "initial_state_unsafe", "order": null, "steps": null}
```

初态安全但不存在全程安全的完整顺序时返回：

```json
{"possible": false, "failure_reason": "no_safe_complete_order", "order": null, "steps": null}
```

失败时不输出任何可执行的部分计划；即使某个排列的前几步暂时安全，也不会把该前缀作为计划返回。未提供 `maintenance_rehearsal` 时，响应不包含该字段，普通分析及恢复规划响应保持不变。`maintenance_rehearsal` 可与 `recovery` 同时启用，两者独立追加各自字段。示例见 `examples/maintenance.json`。

## 本地命令行

从标准输入读取：

```bash
python3 -m quorum < examples/disjoint.json
```

或指定文件：

```bash
python3 -m quorum examples/safe.json
```

CLI 在输入无效时向 stderr 输出错误并返回退出码 2。

## Docker Compose 服务

启动：

```bash
docker compose up --build
```

请求：

```bash
curl -fsS http://127.0.0.1:8080/analyze \
  -H 'Content-Type: application/json' \
  --data-binary @examples/disjoint.json
```

健康检查：

```bash
curl -fsS http://127.0.0.1:8080/health
```

## 算法

副本数最多为 12，所以每侧最多只有 `2^12 = 4096` 个候选集合。服务用位掩码枚举全部在线子集，检查权重和以及所有必需机房是否至少有一个副本被选中，然后对两侧可行集合求交集。

可行掩码按 `(成员数, 掩码数值)` 排序；按 id 排序后，相同成员数掩码的数值递增等价于 id 列表字典序递增。反例枚举据此实现总成员数和两侧 id 列表的裁决规则。

恢复规划复用同一枚举：把候选子集中的离线副本标记为在线后重新执行完整裁决，按子集大小递增找到第一个存在安全集合的规模，并在该规模内取 id 列表字典序最小的安全集合。

维护预演同样复用该裁决：所选副本先按 id 排序，最多 5 个时完整排列不超过 `5! = 120`；按字典序枚举排列，并对每个排列的初态和每一步前缀都重新枚举仲裁。首个每个前缀均安全的排列即答案，失败时丢弃整个排列而不是返回部分前缀。

## 开发与测试

开发依赖见 `requirements-dev.txt`：

```bash
python3 -m pip install -r requirements-dev.txt
pytest
```

测试包含：

- 小实例位掩码枚举对拍；
- 随机实例对拍；
- 离线副本；
- 机房约束；
- 相等权重并列；
- 总成员数优先于字典序；
- 恢复规划：跨机房恢复、空仲裁集不可达、并列最优、恢复更多反而不相交的非单调场景，以及随机实例的独立子集枚举对拍；
- 维护预演：小实例枚举全部切换排列，对拍字典序并列顺序、跨机房限制、恢复副本后新出现不相交仲裁，以及中途失守；
- CLI 和 HTTP 服务。
