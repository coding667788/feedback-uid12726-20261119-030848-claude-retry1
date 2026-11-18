# 离线事件导出：授权证明与来源隔离

纯 Python 标准库、CPU、离线运行的事件导出器。原始事件携带租户、事件类型与 JSON 值；
版本化导出规格在原始事件之上声明**派生列**，每列只能是三种固定来源之一：
JSON Pointer 取值、固定连接字符串拼接、定长掩码。系统在导出时为每一列给出
**授权证明**——该列全部传递原始路径均被同一角色授权且未命中任何全局封锁，
否则按列省略或按事件拒绝，并保证错误、排序、审计信息只引用规格中**已配置**的
路径与原因码，绝不泄露未授权枝的键名、值或内容摘要。

## 1. 运行环境与命令

- Windows 原生 Python 3.12（实测 3.12.8），仅标准库，无第三方依赖，无网络/磁盘外访问。
- 两条题目规定的命令，在仓库根目录执行：

```bash
# 导出（输入支持单个任务对象，或 {"jobs": [...]} 批量回放文档）
python -m solution --input cases.json --output result.json

# 自动化测试（56 个用例）
python -m unittest discover -s tests -v
```

> 处理来源不可信的输入文件时，建议把输入放在独立目录并以隔离模式运行，避免同目录
> 被植入的 `json.py` 等模块被导入：`python -I -m solution ...`（注意 `-I` 不会把
> 当前目录加入 `sys.path`，此时需从仓库根目录运行或设置 `PYTHONSAFEPATH` 等价布局；
> 本仓库自带的 `cases.json` 为合成可信数据，测试使用普通 `-m` 调用）。

## 2. 输入结构

### 2.1 任务对象（单任务形态）

```jsonc
{
  "job_id": "job-main",          // 作业标识
  "role": "analyst",             // 本次导出绑定的角色名
  "policy": { ... },             // 固定的策略版本
  "views": [ ... ],              // 一个或多个版本化导出规格
  "events": [ ... ]              // 固定的输入事件集合
}
```

`cases.json` 是批量回放形态 `{"jobs": [任务, 任务, ...]}`，内含 3 个任务：
`job-main`（主功能与各类拒绝）、`job-pair-a` / `job-pair-b`（成对隐私验证）。

### 2.2 策略 `policy`

```jsonc
{
  "policy_id": "pol-standard",
  "version": "v1",
  "roles": {
    "analyst": {
      "tenants": ["tenant-a", "tenant-b"],   // 可省略：省略表示不限租户
      "event_types": ["order.created"],
      "paths": {                              // 精确授权，按事件类型分组
        "order.created": ["/order_id", "/customer/name", "/items"]
      }
    }
  },
  "global_blocks": [
    {"event_type": "order.created", "path": "/customer/secret"},  // 可省略 event_type：全局
    {"event_type": "order.created", "path": "/items/0/sk~1u"}     // ~1 -> /，按解码段匹配
  ]
}
```

授权模型是 **fail-closed 精确匹配**：角色只持有明确列出的原始路径，没有前缀继承。

### 2.3 导出规格 `views[]`

```jsonc
{
  "spec_id": "order-view",
  "version": "v3",
  "event_type": "order.created",
  "columns": [
    {"name": "order_id", "required": true,
     "source": {"type": "pointer", "path": "/order_id"}},
    {"name": "name_masked", "required": true,
     "source": {"type": "mask", "path": "/customer/name",
                "keep": 3, "side": "right", "char": "#"}},
    {"name": "contact", "required": false,
     "source": {"type": "concat",
                "parts": ["/customer/region", {"literal": "|"}, "$name_masked"]}}
  ],
  "sort": [{"column": "order_id", "direction": "asc"}]
}
```

来源（source）只允许三种**固定形态**，刻意不提供任何表达式能力：

| type | 形态 | 说明 |
|---|---|---|
| `pointer` | `{"type":"pointer","path":"/a/b"}` | RFC 6901 取值 |
| `mask` | `{"type":"mask","path":"/a","keep":2,"side":"left","char":"*"}` | 定长掩码，固定引用一个源字段 |
| `concat` | `{"type":"concat","parts":[...]}` | 按序连接，组成部分只能是 `/` 原始指针、`$` 派生列引用、`{"literal":"..."}` 固定字面量 |

- `required` 缺省为 `true`（fail-closed）。可选列写 `"required": false`。
- 派生引用 `$col` 只能引用本视图内另一个导出列；支持多层派生，按拓扑序求值。
- 掩码：长度 ≤ keep 时整体替换；`left` 保留前 keep 个、`right` 保留后 keep 个；
  `keep=0` 整体掩码；授权值为 `null` 时原样透传不掩码。

### 2.4 事件 `events[]`

```jsonc
{
  "event_id": "ev-order-01",
  "tenant": "tenant-a",
  "event_type": "order.created",
  "payload": { "order_id": "O-1001", "customer": {"name": "Zhang San"} }
}
```

## 3. 核心安全语义

1. **授权证明（逐列、逐路径）**：一个派生列可发布，当且仅当同一角色对该事件类型
   授权了该列**全部传递原始路径**（自身源 + 所有 `$` 依赖的闭包）。concat/mask
   固定引用若干源字段，无法借拼接或间接派生洗白未授权数据。
2. **全局封锁优先**：任何角色授权都不能绕过封锁；封锁按 **RFC 6901 解码后的段**
   匹配，三种命中关系都拒绝——相等、封锁路径是请求路径前缀（封锁后代枝）、
   请求路径是封锁路径前缀（读取的容器内含封锁后代，整容器不可读）。
3. **数组仅整体读取**：指针在实际事件中进入数组（数组节点后仍有段）即
   `PATH_ARRAY_BLOCKED`；数组任一子路径被封锁，整个数组的读取一并拒绝。
4. **数字字典键 ≠ 数组下标**：段 `"0"` 在对象上是普通键，在数组上才是下标，
   由运行时容器类型严格区分；转义编码不能改变段的数量与结构。
5. **快照固定**：单次导出深拷贝固定事件、角色、策略版本与规格版本，执行期不读
   外部状态；输出含配置面指纹 `config_sha256`、事件指纹 `events_sha256` 与总指纹
   `sha256`，用于重放核对。
6. **必需 vs 可选**：可选列不满足则从该行省略并记 `column_omitted`；必需列不满足
   则整事件拒绝并记 `event_rejected`。
7. **整版拒绝**：同名导出列冲突（`SPEC_COLUMN_NAME_CONFLICT`）、派生环
   （`SPEC_DERIVED_CYCLE`）、缺依赖（`SPEC_DEP_MISSING`）使该规格整版拒绝、零产出，
   不影响同作业内其他视图。
8. **来源隔离**：错误与审计只记录规格/策略里已配置的指针原文与稳定原因码；
   实际事件中未授权的键名、值、内容摘要一律不进入 `result.json`。

## 4. 错误码表

| 错误码 | 触发条件 | 级别 |
|---|---|---|
| `SPEC_EMPTY_COLUMNS` | 规格没有任何导出列 | 整版拒绝 |
| `SPEC_COLUMN_NAME_CONFLICT` | 两个导出列同名 | 整版拒绝 |
| `SPEC_DERIVED_CYCLE` | 派生列 `$` 引用存在环 | 整版拒绝 |
| `SPEC_DEP_MISSING` | `$` 引用了不存在的派生列 | 整版拒绝 |
| `SPEC_INVALID_POINTER` | 指针语法非法（如非法 `~` 转义） | 整版拒绝 |
| `SPEC_INVALID_SOURCE` | 非三种固定来源、裸表达式、非法字面量对象 | 整版拒绝 |
| `SPEC_INVALID_MASK` / `SPEC_INVALID_CONCAT` | mask/concat 参数非法 | 整版拒绝 |
| `SPEC_INVALID_SORT` | 排序引用不存在的列或方向非法 | 整版拒绝 |
| `SPEC_INVALID_META` | 规格/任务元数据缺失或类型错误 | 整版/任务拒绝 |
| `POLICY_INVALID_POINTER` / `POLICY_INVALID_STRUCTURE` | 策略指针或结构非法 | 任务拒绝 |
| `ROLE_UNKNOWN` | 快照绑定的角色不存在 | 事件拒绝 |
| `TENANT_DENIED` | 角色租户范围不含该租户 | 事件拒绝 |
| `EVENT_TYPE_DENIED` | 角色未授权该事件类型 | 事件拒绝 |
| `PATH_GLOBAL_BLOCKED` | 命中字典枝/容器全局封锁 | 列省略/事件拒绝 |
| `PATH_ARRAY_BLOCKED` | 进入数组内部，或数组含封锁子路径 | 列省略/事件拒绝 |
| `PATH_NOT_AUTHORIZED` | 角色未精确授权该原始路径 | 列省略/事件拒绝 |
| `POINTER_MISSING` | 路径已授权但事件中缺键（区别于授权 null） | 列省略/事件拒绝 |
| `POINTER_TYPE` | 穿过标量取值等结构类型错误 | 列省略/事件拒绝 |
| `CONCAT_TYPE_ERROR` | concat 组成部分不是字符串（不做隐式转换） | 列省略/事件拒绝 |
| `MASK_TYPE_ERROR` | mask 作用对象不是字符串 | 列省略/事件拒绝 |

审计记录形如：
`{"kind":"event_rejected","reason":"POINTER_MISSING","view_id":"order-view",
"event_id":"ev-order-04","column":"amount","path":"/amount","detail":"..."}`，
其中 `path` 必为配置面出现过的指针；`tests/test_cli.py` 会校验审计路径全部属于
配置面集合。

## 5. 边界示例（cases.json 实测覆盖）

| 边界 | 数据位置 | 实测行为 |
|---|---|---|
| 已授权 `null` 与缺失键并存 | `ev-order-03`：`phone=null`、无 `region` | null 原样导出；缺失使可选 `contact` 省略（`POINTER_MISSING`） |
| 必需列缺键 | `ev-order-04`：无 `amount` | 整事件拒绝，主视图 5 在 scope → 4 行导出 / 1 拒绝 |
| 数组整体读取 + 子路径封锁 | `order-view.items_whole`、封锁 `/items/0/sk~1u` | 整数组读被 `PATH_ARRAY_BLOCKED`，可选列省略 |
| 必需列深入数组 | `order-array-required-view` | 5 事件全部拒绝，零行 |
| 拼接未授权字段 | `order-concat-forbidden-view`（concat 引用 `/customer/secret`） | 5 事件全部 `PATH_GLOBAL_BLOCKED` |
| 间接派生洗白 | `order-indirect-derived-view`（`$holder` 持封锁字段再 concat） | 5 事件全部拒绝，第一现场为 holder 列封锁 |
| 数字字典键 | `ev-order-05`：`items` 是对象、键 `"0"` | 不当下标；未精确授权 → 可选探测列省略，事件本身正常导出 |
| 容器含封锁后代 | `payment-view.method_whole` 与封锁 `/method/token` | 整 `/method` 不可读，`PATH_GLOBAL_BLOCKED` |
| 编码歧义 | 封锁 `/items/0/sk~1u`（解码后含 `/`） | 按解码段命中，等价编码无法绕过 |
| 三个整版拒绝规格 | `bad-duplicate` / `bad-cycle` / `bad-missing-dep` | 视图 `status=rejected`、零行，原因码分别对应 |

### 成对隐私验证（核心验收）

`job-pair-a` 与 `job-pair-b` 的授权面（租户、类型、所有授权/封锁路径、规格、角色）
完全相同，**仅未授权枝不同**：A 是 `customer.secret="alpha-secret-value"`，
B 改为不同键名 `secret_renamed`、不同值并多出 `extra_unauthorized_branch` 子树。
实测：两作业归一化（去除作业标识与指纹）后的结果**逐字节一致**，各导出 1 行、
各省略 1 个被封锁可选列；对 `result.json` 全文扫描
`SHOULD-NEVER-LEAK / ALPHA-SECRET / DIFFERENT-secret-999 / tok-secret /
secret_renamed / extra_unauthorized_branch` 等特征，均不存在。

## 6. 实测结果（Windows 11 + Python 3.12.8）

`python -m solution --input cases.json --output result.json`：

```
批量导出完成: 3 个任务, 共 8 行
```

| 作业 / 视图 | 状态 | 在 scope | 导出行 | 拒绝事件 | 可选列省略 |
|---|---|---|---|---|---|
| job-main / order-view | ok | 5 | 4 | 1 | 13 |
| job-main / order-array-required-view | ok | 5 | 0 | 5 | 0 |
| job-main / order-concat-forbidden-view | ok | 5 | 0 | 5 | 0 |
| job-main / order-indirect-derived-view | ok | 5 | 0 | 5 | 0 |
| job-main / payment-view | ok | 2 | 2 | 0 | 3 |
| job-main / bad-duplicate | rejected (`SPEC_COLUMN_NAME_CONFLICT`) | 0 | 0 | 0 | 0 |
| job-main / bad-cycle | rejected (`SPEC_DERIVED_CYCLE`) | 0 | 0 | 0 | 0 |
| job-main / bad-missing-dep | rejected (`SPEC_DEP_MISSING`) | 0 | 0 | 0 | 0 |
| job-pair-a / pair-view | ok | 1 | 1 | 0 | 1 |
| job-pair-b / pair-view | ok | 1 | 1 | 0 | 1 |

主作业审计 35 条，全部只含配置面路径与稳定原因码；未授权特征全文扫描干净。

`python -m unittest discover -s tests -v`：

```
Ran 56 tests in 0.5s
OK
```

测试分布：`test_pointer.py`（RFC 6901 解析/取值/数组约束）、`test_policy.py`
（封锁优先、解码段、数组整体、数字字典键、租户/类型门槛）、`test_spec.py`
（三类整版拒绝、拓扑序、传递闭包独立核对）、`test_export.py`（掩码独立判定、
null/缺失区分、洗白防护、成对隐私、快照隔离、排序）、`test_cli.py`
（子进程端到端、回放一致性、审计卫生扫描）。

## 7. 期望值独立性说明

测试不允许从被测实现反推期望：

- 掩码期望值由测试内独立函数 `expected_mask`（最直白的切片重写）+ 纯字面量
  双重断言（见 `tests/test_export.py`）。
- 指针解码期望按 RFC 6901 规则手工列表；授权/封锁结论按题目规则逐条人工判定。
- 传递闭包期望在测试中按规格定义人工枚举后整体比对，不调用实现计算。
- 成对作业的“逐字节一致”和“秘密特征不存在”是对输出的独立断言，不依赖实现内部结构。

## 8. 目录结构

```
.
├── solution/            # 被测实现（纯标准库）
│   ├── __init__.py
│   ├── __main__.py      # python -m solution CLI
│   ├── errors.py        # 错误码与受控异常
│   ├── pointer.py       # RFC 6901 解析、解码段、取值
│   ├── policy.py        # 角色授权 + 全局封锁判定
│   ├── spec.py          # 规格校验、拓扑序、传递路径闭包
│   └── export.py        # 快照化导出引擎、掩码、排序、审计
├── tests/               # 56 个 unittest 用例
├── cases.json           # 可重放合成输入（3 个作业）
├── result.json          # 实测导出结果
└── README.md
```
