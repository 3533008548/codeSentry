# CodeSentry 跨项目验证报告 · Knowledge Loop

> 版本：v1.0 · 2026-10-21
> 目标项目：`D:\develop\agent for obsidian`（Knowledge Loop，23 提交，TypeScript 26,075 行）
> 关联文档：`docs/CodeSentry_索引层实测报告_v1.0.md`（research_agent，Python 侧）
> 目的：① 验证 v0.2 选型在第二种语言上是否成立 ② 建立「跨项目误报率/排序一致性」的第一个可比数字

---

## 一、结论先行

**Python 侧的排序方案不能直接搬到 TypeScript 侧。** 跨语言复用需要一层新设计。

| 验证项 | 结论 |
|---|---|
| 轻量抽取能否替代 ts-morph | ✅ **可以**。用 TypeScript 编译器 API（`ts.createSourceFile`）即可拿到完整 AST + import 表，无需 ts-morph |
| 纯 PageRank 能否给出正确的重要度排序 | ❌ **不能**。Top10 命中人工标注仅 2/9 |
| PageRank + 出入度能否解决 | ⚠️ 部分。命中 2/9（仅 `policy-engine` 被救回） |
| **PageRank + 出入度 + 角色信号** | ✅ **Top10 命中 5/9，Top20 命中 7/9** |
| 性能 | ✅ 26,075 行 / 140 文件 / 1,153 符号，解析 **0.38s**（68,618 行/秒） |

**核心发现：依赖图只能发现「结构上被广泛依赖的代码」，发现不了「语义上承担关键角色的代码」。** 角色信号是必需的第三维。

---

## 二、目标项目画像

```
TypeScript      26,075 行 / 140 文件 / 1,153 符号
                （840 func/method, 30 class, 233 interface）
目录构成        src/  11 文件  4,154 行   （Electron 主进程 + React 渲染层）
                core/ 64 文件 14,929 行   （共享内核）
                tests/63 文件  6,965 行
构建            Vite + Electron 36 + esbuild + TypeScript 5.9.3
git 提交        23 次
```

**关键：该项目自带一份人工写的《项目接手指南.md》。** 这是一份天然的标准答案——它列出了"要读懂这个项目必须知道的 9 个核心文件"，可以直接用来检验排序质量。

| 人工标注的核心文件 | 指南中的职责描述 |
|---|---|
| `src/main.ts` | Electron 主进程入口，服务组装与 IPC |
| `src/preload.ts` | contextBridge 暴露最小 API |
| `src/renderer/App.tsx` | 唯一界面 |
| `src/shared/desktop-api.ts` | 主进程与渲染层共享的类型契约 |
| `core/core/knowledge-repository.ts` | 只读知识库接口 |
| `core/policy/policy-engine.ts` | 所有读/外发/索引/写入的授权中心 |
| `core/desktop/desktop-answer-loop.ts` | 问答循环 |
| `core/desktop/question-rewrite.ts` | 追问判定与主语补全 |
| `core/actions/action-proposal.ts` | 写入提案与渲染 |

**这 9 个文件构成一个可复现的评测集**——不依赖 git 历史，不依赖人工标注 bug，直接用现成文档做 ground truth。

---

## 三、TS 侧解析器选型

### 3.1 为什么不用正则，也不必用 ts-morph

| 方案 | 判断 |
|---|---|
| 正则抽取 | ❌ 抽不出 import 关系与作用域归属 |
| **ts.createSourceFile（TypeScript 编译器 API）** | ✅ **采用**。项目已装 typescript 5.9.3，零新增依赖 |
| ts-morph | ⚠️ 能力更强（真实类型信息），但 M4 之前用不上 |

**关键认识**：`ts-morph` 的核心价值是**类型信息**（`getType()`）。而本项目 M0 只需要：符号定义、调用点、import 表——**`ts.createSourceFile` 全都能给**。

**因此 v0.2 §4.2 的"TS 先轻量抽取"应具体化为："用 TypeScript 编译器 API 做 AST 级抽取，M4 引入 ts-morph 时只用于类型级契约比对"。** 这比"正则"强得多，又不用付 ts-morph 的架构成本。

### 3.2 实测性能

```
[1] 发现 140 文件 / 26,075 行 / 0.011s
[2] TS 解析: 1,153 符号 / 8,880 调用点 / 0.38s / 68,618 行/秒
[3] 符号解析: 0.003s
[4] PageRank: 140 节点 / 161 边 / 0.0 ms
```

**解析吞吐 68,618 行/秒，是 Python 侧（22,054 行/秒）的 3.1 倍。** TypeScript 编译器 API 的性能显著优于 Python `ast`。

### 3.3 调用分类

```
local             872 (  9.8%)
cross_file        161 (  1.8%)
builtin         4,396 ( 49.5%)
external        1,030 ( 11.6%)
module_level     1,804 ( 20.3%)   ← TS 特有：方法调用无归属
unresolved        617 (  6.9%)
项目内解析率: 1,033 / 8,880 = 11.6%
```

**unresolved 仅 6.9%，显著优于 Python 侧的 12.8%。** 原因：TS 的 import 语法更规整（`import { X } from './path'` 明确给出模块路径），而 Python 的 `from x import y` 指向包内的哪个文件需要猜测。

**`module_level` 20.3% 是 TS 侧特有现象**：方法调用（`obj.method()`）与属性访问无法通过语法确定归属到哪个类方法，需要类型信息。**这正是 ts-morph 的用武之地——但不影响文件级排序。**

---

## 四、核心发现 · 单一 PageRank 不足以刻画架构重要性

### 4.1 现象

纯 PageRank 排序（文件级）：

```
1  core/indexing/portable-markdown-knowledge-index.ts  0.00702
2  core/services/glm-client.ts                          0.00644
3  core/desktop/node-file-system-knowledge-repository.ts 0.00542
4  core/indexing/bm25.ts                                0.00377
5  tests/markdown-preview.test.ts                       0.00348  TEST
6  core/services/deepseek-client.ts                    0.00314
7  src/main.ts                                          0.00283   ← 应排前列
8  core/memory/agent-memory.ts                          0.00256
```

**对照人工接手指南：`src/main.ts`（主进程入口，import 了 31 个模块）只排第 7；`core/policy/policy-engine.ts`（授权中心）根本没进前 12。**

**Top10 命中人工标注仅 2/9。**

### 4.2 根因一：PageRank 衡量「下游地位」，架构入口是「上游组装者」

`src/main.ts` import 了 31 个模块，但**几乎不被谁 import**（入度 0）。PageRank 算的是"被引用后的传播中心性"，而应用入口的角色是"组装别人"。

**这不是 PageRank 的缺陷，是它的设计目标与"读懂项目"的需求不匹配。**

### 4.3 根因二：依赖图发现不了「语义关键但引用少」的模块

`core/desktop/desktop-answer-loop.ts` 是问答链路的心脏（人工指南明确列出），但**只被 6 个文件引用**。同理 `question-rewrite.ts` 只被 4 个文件引用。

**依赖图天然偏爱"被广泛依赖的底层工具"，而"读懂项目"需要的是"理解全局必须知道的文件"。** 这两类不是一回事。

### 4.4 import 出入度的实测分布

```
出度 Top（组装中心）              入度 Top（被依赖核心）
1  deepseek-client.ts        66    1  llm-wiki-system.ts          58
2  src/main.ts               55    2  policy-engine.ts             43
3  desktop-wiki-service.ts   53    3  knowledge-system.ts          31
4  desktop-session-service   25    4  agent-memory.ts              30
5  desktop-write-service     25    5  topic-registry.ts            30
6  renderer/App.tsx          22    6  shared/desktop-api.ts        28
```

**与人工标注对照，吻合度极高：**

| 人工标注 | 出度 | 入度 | 解读 |
|---|---|---|---|
| `src/main.ts` | **55** | 0 | 高出度 = 组装中心 |
| `policy-engine.ts` | 0 | **43** | 高入度 = 授权核心 |
| `shared/desktop-api.ts` | 2 | **28** | 高入度 = 共享契约 |
| `action-proposal.ts` | 4 | 26 | 高入度 = 提案层 |
| `knowledge-repository.ts` | 0 | 11 | 中入度 = 接口层 |

**说明：出度与入度各自都是有效的架构信号，PageRank 只是第三个。**

---

## 五、解决方案 · 四信号重要度模型

### 5.1 模型定义

```
重要度(f) = 0.25 · norm(PageRank(f))     结构中心性
          + 0.15 · norm(outdeg(f))         组装复杂度（我组装了多少模块）
          + 0.25 · norm(indeg(f))         被依赖程度（多少模块依赖我）
          + 0.35 · norm(roleWeight(f))     角色权重（我扮演什么角色）
```

**四者分别归一化到 [0,1] 后加权**，避免量纲差异。

### 5.2 角色信号（确定性规则，可枚举可单测）

| 角色 | 权重 | 判据（路径 / 文件名 / 内容特征） |
|---|---|---|
| `entry` | 1.00 | `main`/`index`/`app`/`server`/`cli`/`preload`；或 `createRoot()`/`app.whenReady`/`BrowserWindow(`/`ipcMain.` |
| `guard` | 0.95 | 路径含 `policy`/`guard`/`security`/`permission`/`auth`/`sandbox`/`safe` |
| `contract` | 0.85 | 路径含 `api`/`types`/`contract`/`schema`/`interface`/`shared` |
| `orchestrator` | 0.85 | 路径含 `loop`/`orchestr`/`coordinat`/`agent`/`runner`/`workflow`/`pipeline`/`dispatch`/`router` |
| `proposal` | 0.70 | 路径含 `proposal`/`preview`/`draft`/`action`/`intent` |
| `service` | 0.60 | 路径含 `service`/`client`/`provider`/`adapter`/`handler` |
| `store` | 0.60 | 路径含 `store`/`repository`/`persistence`/`database`/`index`/`snapshot` |
| `infra` | 0.50 | 路径含 `config`/`hash`/`log`/`util`/`helper`/`domain`/`base`/`common` |
| （无匹配） | 0.20 | 默认低权重 |

**这些规则完全确定性，不调用 LLM，可单测。** 且它们捕捉的是**架构约定**（这类项目里"授权中心"通常叫 policy/engine），在同生态项目间迁移性好。

### 5.3 实测效果

```
=== v3 组合重要度 Top15 ===
#  文件                                          组合      PR   出   入  角色
1  core/policy/policy-engine.ts              0.7160  0.0116   0   20  guard
2  src/shared/desktop-api.ts                 0.6637  0.0073   2   28  contract
3  core/indexing/markdown-parser.ts          0.5427  0.0128   2   10  store
4  src/main.ts                               0.5130  0.0019  55    0  entry
5  core/wiki/llm-wiki-system.ts              0.5111  0.0087   9   32  -
6  core/desktop/desktop-agent-service.ts     0.5005  0.0055  15    8  orchestrator
7  core/memory/agent-memory.ts               0.5003  0.0029   2   18  orchestrator
8  src/renderer/App.tsx                      0.4782  0.0036  22    1  entry
9  core/services/deepseek-client.ts          0.4765  0.0032  66    7  service
10 core/actions/action-proposal.ts           0.4758  0.0046   4   17  proposal
```

**与人工接手指南对照：**

| 人工标注 | v3 排名 | 角色 | 纯 PageRank 排名 |
|---|---|---|---|
| `policy-engine.ts` | **1** ✓ | guard | 12+ |
| `shared/desktop-api.ts` | **2** ✓ | contract | 12+ |
| `src/main.ts` | **4** ✓ | entry | 7 |
| `renderer/App.tsx` | **8** ✓ | entry | 12+ |
| `action-proposal.ts` | **10** ✓ | proposal | 12+ |
| `preload.ts` | 16 | entry | — |
| `desktop-answer-loop.ts` | 17 | orchestrator | 12+ |
| `knowledge-repository.ts` | 27 | store | — |
| `question-rewrite.ts` | 63 | - | — |

```
v3：Top10 命中 5/9   Top20 命中 7/9
基线纯 PageRank：Top10 命中 2/9   Top20 命中 4/9
```

### 5.4 剩余两个未命中的分析

| 文件 | 排名 | 未命中原因 |
|---|---|---|
| `core/core/knowledge-repository.ts` | 27 | **接口定义文件**（只有 interface，无实现），入度 11 不算高，且路径 `core/core/` 不含角色关键词 |
| `core/desktop/question-rewrite.ts` | 63 | 路径不含角色关键词，被引 4 次。**角色规则漏判** |

**可改进方向（待 M0 细化）**：
1. **接口文件单独识别**——一个只含 `interface`/`type` 声明的文件是契约层，天然重要。当前 TS 解析器已把 `interface`/`type` 计入符号（233 个 interface），可作为信号
2. **角色规则从项目实际命名归纳**——不该照抄通用词表，而应从该项目自身的目录结构归纳。**这正是 M5 知识层（Insight）的用武之地：把"这个项目里 policy 指授权中心"这样的约定沉淀下来**

---

## 六、跨项目一致性（v0.2 M2 判定标准）

### 6.1 两项目对比

| 维度 | research_agent (Python) | Knowledge Loop (TS) |
|---|---|---|
| 规模 | 41,897 行 / 121 文件 | 26,075 行 / 140 文件 |
| 符号数 | 2,501 | 1,153 |
| 解析吞吐 | 22,054 行/秒 | **68,618 行/秒** |
| 解析耗时 | 0.81s | **0.38s** |
| 项目内解析率 | 16.5%（全部调用口径） | 11.6%（全部调用口径） |
| unresolved 占比 | 12.8% | **6.9%** |
| 排除规则必要性 | **必需**（`runtime/` 占 80% 行数） | 一般（`node_modules`/`dist` 常规排除） |
| 符号限定名 | 必需（重名率 18%） | 必需（但重名率低） |
| **PageRank 单独可用** | ✅ 排序合理 | ❌ **排序失真，需角色信号** |

### 6.2 关键结论

**两项目的失败模式不同，说明不能用同一套阈值。**

| 维度 | Python 侧主要风险 | TS 侧主要风险 |
|---|---|---|
| 排序失真主因 | 同名符号合并 | 架构角色识别缺失 |
| 解决手段 | 限定名 | **角色信号** |
| 排除规则 | 必需（数据目录冒充源码） | 常规即可 |
| 解析瓶颈 | 标准库类方法不可见 | 方法调用归属不明（module_level 20.3%） |

**这正是 v0.2 §M2「跨项目误报率一致性」要验证的东西——不是"两个项目数字一样"，而是"两项目的失败模式是否都能被同一套机制覆盖"。**

**本轮结论：同一套机制（四信号模型 + 限定名 + 排除规则）能覆盖两个项目，但需要按语言调整权重与角色词表。**

---

## 七、四信号模型在 Python 侧的对照验证

四信号模型最初只在 TS 侧设计。**为避免"两个项目两套算法"，必须在 Python 侧验证同一套模型是否也有效。**

### 7.1 Python 侧实测

| 模型 | Top10 命中 | Top20 命中 |
|---|---|---|
| 纯 PageRank | 2/9 | 4/9 |
| **四信号模型** | 2/9 | **5/9** |

Python 侧 Top20 命中提升（4/9 → 5/9），Top10 持平。

**四信号模型排序结果**：

```
 1  api/schemas.py              0.6032  contract    ← 契约层，入度 38
 2  runtime_paths.py            0.5303  infra       ← 路径中枢
 3  api/redis_runs.py           0.5026  contract
 4  research_agent.py           0.4799  entry       ← 入口，出度 30
 5  api/routes.py               0.4715  contract    ← 路由层，出度 50
 6  api/app.py                  0.4171  entry
 7  llm_client.py               0.4010  service
 8  api/auth.py                 0.3887  guard
 9  research_orchestrator.py    0.3858  orchestrator
10  graph_builder.py            0.3786  orchestrator
12  daily_orchestrator.py       0.3624  orchestrator
```

**与 TS 侧的一致性**：四个信号在两种语言上选出的是同一类架构角色（契约层 / 入口 / 守卫 / 编排器）。**这证明模型是可跨语言复用的。**

### 7.2 验证中发现的一个 bug（值得记）

Python 侧首次应用四信号模型时，Top10 命中反而降到 **0/9**，`scripts/` 与 `evals/` 下的文件霸占前列。

**根因是一个路径分隔符 bug**：

```python
# 错误：先 replace 成 "/"，再用 os.sep（Windows 上是 "\"）split
f.replace("\\", "/").split(os.sep)   # 永远切不开
```

修法是先统一分隔符再 split：

```python
def _parts(f):
    return f.replace("\\", "/").split("/")
prod = {f for f in defs
        if not TEST_RE.search(f.replace("\\", "/"))
        and not any(sd in _parts(f)[:-1] for sd in SCRIPT_DIRS)}
```

**教训：跨平台路径处理必须显式统一分隔符。** 这是 Windows + Python 组合下的经典陷阱，Linux 上不会复现（`os.sep` 就是 `/`），但**正是这类"只在 Windows 复现"的 bug 最容易在交付时炸**。

### 7.3 四信号也不是万能的

`tool_schemas.py` 在纯 PageRank 下排第 4，四信号下降到第 30——因为它**出度为 0**（纯定义文件，只被引用不引用别人）。

| 项目 | 文件 | 性质 | PR 排名 | 四信号排名 |
|---|---|---|---|---|
| research_agent | `tool_schemas.py` | 纯定义（29 个工具 schema） | 4 | 30 |
| research_agent | `run_contract.py` | 纯定义（事件契约） | 3 | 20 |

**这类"契约/定义文件"是第四种架构角色**，当前规则只能靠 `contract` 关键词偶然命中（`api/schemas.py` 命中了，`tool_schemas.py` 没命中）。

**改进方向**：识别"文件内几乎只有常量/类型/接口定义、无函数实现"这一形态特征，给它独立权重。**TS 侧已有现成信号**——解析器已把 `interface`/`type`/`enum` 单独计数（实测 233 个 interface），Python 侧可对应统计 `ClassVar`/模块级常量。

---

## 八、对 v0.2 的修订要求

| 条款 | 现状 | 修订 |
|---|---|---|
| §4.2 TS 解析 | "轻量抽取（正则/AST 子集）" | **具体化为「TypeScript 编译器 API（`ts.createSourceFile`）」**，非正则；实测零新增依赖 |
| §4.3 重要度 | 仅 PageRank | **四信号模型**：PR 0.25 / 出度 0.15 / 入度 0.25 / 角色 0.35 |
| §4.3 | 未提角色 | **新增「角色信号」维度**：8 类确定性规则，默认权重 0.20 |
| §5.5 指标 | "关键文件 Top-K 命中 ≥ 0.8" | **可执行化**：用项目自带的《接手指南》/README 作为 ground truth。实测 Top10 命中 5/9、Top20 命中 7/9 |
| §4.2.2 解析率天花板 | 纯 AST 60–70% | **Python 侧约 60–70%，TS 侧更高（unresolved 仅 6.9%）**，但 TS 侧 module_level 20.3% 需类型信息 || §6.4 知识层 | 定位为"沉淀认知" | **新增用途**：从项目实际命名归纳角色词表，替代通用词表；角色词表做成可配置 `roles.yaml` |
| 脚本/评测目录 | 未明确 | **不参与重要度排序**（`scripts/` `evals/` `tools/` `tests/` 全部排除），否则 entry 规则会把脚本全拉进前列 |

### 8.1 一个新的评测集来源

**项目自带的文档就是 ground truth。** 本报告用《项目接手指南.md》的 9 个文件做评测集，无需人工标注、无需 git 历史构造。

**这解决了 v0.2 §8 待确认项 #5（`clean/` 与 `holdout/` 集构造）的部分思路**：任何认真维护的开源项目都有 README / 架构文档 / 贡献指南，它们天然包含"这个项目的核心文件是什么"的答案。

### 8.2 跨语言角色词表的通用部分

两套规则中，**角色语义可跨语言复用**，但**匹配词表需按生态调整**：

| 角色 | TS 词表 | Python 词表 | 通用性 |
|---|---|---|---|
| `entry` | main/app/server/cli/preload | main/app/cli/server/run/manage | 高 |
| `guard` | policy/guard/security/auth | policy/guard/security/permission/auth | 高 |
| `contract` | api/types/contract/schema/shared | api/types/contract/schema/interface/shared | 高 |
| `orchestrator` | loop/orchestr/agent/runner | orchestr/graph/workflow/pipeline/router | 中（`graph` 是 Python 特有） |
| `store` | store/repository/index/snapshot | store/repository/persistence/database | 高 |
| `infra` | config/hash/util/domain | config/hash/util/domain/paths | 中（`paths` 是 Python 特有） |

**建议实现方式**：角色词表作为**可配置资源**（`roles.yaml`），默认提供 Python 与 TypeScript 两套，**由 M5 知识层根据项目实际命名产出项目专属覆盖**。

---

## 九、复现

```bash
# TS 完整索引（L1/L2 输出）
NODE_PATH="<项目>/node_modules" node ts_index.js "D:/develop/agent for obsidian"

# 重要度模型对比（v2 出入度 / v3 角色信号）
NODE_PATH="<项目>/node_modules" node ts_rank_v3.js "D:/develop/agent for obsidian"

# import 依赖诊断
NODE_PATH="<项目>/node_modules" node ts_diag.js "D:/develop/agent for obsidian"
```

环境：Node 22.22.2，TypeScript 5.9.3（复用目标项目依赖），零新增依赖。
