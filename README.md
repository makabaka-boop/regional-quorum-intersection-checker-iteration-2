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
- `maintenance_rehearsal`：可选的副本 ID 数组，最多 5 个且必须互异；出现时追加维护顺序预演，空数组表示只检查起始状态。

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

请求带 `maintenance_rehearsal` 副本 ID 数组时，响应追加 `maintenance_rehearsal_plan` 字段。数组中的每个副本都会且只会切换一次在线状态：在线副本下线、离线副本恢复。

预演从原始 `online` 状态开始，要求：

1. 起始状态已经同时存在可行读、写仲裁，且任意可行读写对至少共享一台副本；
2. 每一次切换后的状态也都必须满足同样条件；
3. 在所有完整安全的切换顺序中，返回副本 ID 序列字典序最小者。

恢复一台副本不是单调改善：新增在线副本可能让原本不存在的仲裁变为可行，也可能产生新的不相交读写对。因此算法枚举最多 `5! = 120` 个排列，并对每个排列的每个前缀都复用解析层和仲裁枚举重新完整裁决，不能只检查最终状态。

成功时：

```json
{
  "feasible": true,
  "order": ["a", "x"],
  "steps": [
    {
      "replica_id": "a",
      "online_after": false,
      "read_possible": true,
      "write_possible": true,
      "minimum_intersection": 1,
      "witness_read": {"replica_ids": ["b", "c"]},
      "witness_write": {"replica_ids": ["b", "x"]},
      "safe": true
    }
  ]
}
```

每一步的两个见证是切换后真实可行的读、写仲裁，并达到该状态下所有可行读写对的最小交集；空请求在起始状态安全时返回空 `order` 和空 `steps`。

起始状态不安全，或不存在每一步都安全的完整顺序时，只返回明确失败，不返回可执行的部分计划：

```json
{
  "feasible": false,
  "order": null,
  "steps": null,
  "reason": "no complete safe toggle order exists"
}
```

未提供 `maintenance_rehearsal` 字段时，响应不包含 `maintenance_rehearsal_plan` 字段，原分析及恢复规划输出保持不变。该字段可以与 `recovery: true` 同时出现，两者分别报告。示例见 `examples/maintenance_rehearsal.json`。

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

维护顺序预演同样复用该裁决：按 id 排序候选后枚举排列，使第一个完整可行排列就是字典序最小序列；逐个前缀切换副本在线状态并重新枚举读、写仲裁。任一步不可行或最小交集为 0 即放弃该排列，失败响应不保留已经走过的前缀。

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
- 维护顺序预演：小实例枚举全部切换排列，对拍字典序并列顺序、跨机房限制、恢复引入新区裁、中途失守和失败时无部分计划；
- CLI 和 HTTP 服务。
