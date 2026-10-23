# CodeSentry 交接文档

> 版本：v1.0 · 2026-10-23
> 交接时项目状态：**M0–M1 已完成，M2 未开始**
> 代码位置：`D:\develop\project\codeSentry`
> GitHub：https://github.com/3533008548/codeSentry （公开 · MIT · 10 次提交）

---

## 一、这份文档写给谁

**给接手的开发者（或未来的自己）**，回答三个问题：

1. 这项目在做什么，现在做到哪一步了？
2. 我要接着做，先读什么、跑什么？
3. **哪些坑已经踩过了，别再踩一遍？**

第 3 点最重要。本项目在实现过程中**推翻过自己三次**，每次都是实测数据推翻了看似合理的设计。这些教训如果不写下来，下一个人（哪怕是我自己）会重新踩一遍。

---

## 二、项目是什么

> 一个本地优先的代码理解与审查 Agent：用确定性 AST 分析 + LLM 语义审查检查接口一致性、逻辑复杂度与规范偏离，输出可定位到行号的结论，并通过发布门禁阻断不合规改动。

### 两个场景，共用一套索引层

| 场景 | 命令 | 优先级 | 解决什么 |
|---|---|---|---|
| **A · 理解** | `onboard` | **最高** | 读懂陌生项目：入口在哪、核心模块是什么、按什么顺序读 |
| **B · 审查** | `scan` | 次之 | 提交前的问题检出与门禁阻断（M2 起） |

**为什么先做理解而不是审查**：多数代码审查工具假设你**已经熟悉这个项目**。但真正卡住人的往往是"我根本不知道从哪看起"。理解能力做出来后，符号图可以直接复用给审查做影响面分析——**理解 → 图索引 → 审查误报率下降**是一条因果链，不是拼凑。

### 当前状态一览

| 里程碑 | 状态 | 产出 |
|---|---|---|
| M0 索引层 | ✅ 完成 | 符号图 · PageRank · 入口点 · 增量缓存 |
| M1 阅读顺序 | ✅ 完成 | 入口 → 契约层 → 沿依赖 BFS |
| **M2 检查器** | ❌ **未开始** | 候选漏斗 · 负例集 · 真实误报率 |
| M3 LLM 语义裁决 | ❌ 未开始 | 只用于关键路径 |
| M4 跨语言影响面 | ❌ 未开始 | ts-morph 类型信息 |
| M5 知识层 | ❌ 未开始 | 项目专属角色词表沉淀 |
| M6 规则层自进化 | ❌ 未开始 | PR 形态提案 + 留出集零回归 |

**M2 是下一个战场**，也是整个项目最关键的一步——**在此之前，所有指标都只证明了"索引层能用"，没有证明"审查有用"**。

---

## 三、立刻上手

### 环境

```bash
# Python ≥ 3.11，依赖只有两个
pip install -e ".[dev]"

# TypeScript 侧需要目标项目已装 typescript（不额外安装）
# 找不到 node 时会依次尝试：node / node.exe / PATH
```

**不要引入 numpy / scipy / networkx**。scipy 在 Windows 上安装直接超时（实测）。PageRank 用纯 Python 实现，30,000 节点仅 169 ms，够用。

### 跑起来

```bash
# 理解一个项目（L1 定位 + L2 骨架）
codesentry onboard /path/to/project --level 2

# 显式重建索引（会清缓存）
codesentry index /path/to/project

# 查看索引是否过期
codesentry status /path/to/project

# 生成 policy.yaml
codesentry init /path/to/project
```

### 跑测试与验收

```bash
python -m pytest tests/ -q                    # 54 个单测

# 在真实项目上跑验收
python evals/extract_groundtruth.py <项目> --out evals/groundtruth/x.json
python evals/m0_acceptance.py <项目> evals/groundtruth/x.json
python evals/verify_cache.py <项目>
```

### 验证用的两个真实项目

| 项目 | 路径 | 规模 | 语言 |
|---|---|---|---|
| `research_agent` | `D:\develop\academic\research_agent` | 41.6k 行 · 85 提交 | Python + TS |
| `agent for obsidian` | `D:\develop\agent for obsidian` | 26.1k 行 · 23 提交 | TypeScript (Electron) |

**这两个项目是本项目的第一个被审查对象，也是"自举飞轮"的起点**——审查他人代码以理解规范，反过来审查自己的代码以真正改进它们。

---

## 四、代码地图

```
codesentry/
├── core/                    公共契约（两场景共用，M0 定型，别乱改）
│   ├── symbol.py            Symbol / SymbolEdge / FileMeta / CallSite
│   ├── finding.py           Finding / Evidence / Extraction / SuggestionType
│   ├── fingerprint.py       内容指纹（禁用行号）
│   └── policy.py            policy.yaml 加载与校验
├── parsers/                 解析层
│   ├── python_parser.py     标准库 ast，零依赖
│   ├── ts_parser.py         ts.createSourceFile，经 Node 子进程
│   └── _ts_extract.js       Node 侧抽取脚本（被 ts_parser 调起）
├── index/                   索引层
│   ├── discovery.py         文件发现 + 两类排除
│   ├── pagerank.py          纯 Python PageRank
│   ├── resolver.py          跨文件符号解析 + import 边
│   ├── entrypoint.py        入口点两级识别
│   ├── roles.py             角色标签（不参与排序）
│   ├── cache.py             增量缓存
│   ├── store.py             索引落盘 + 陈旧检测
│   └── builder.py           编排器（把上面所有串起来）
├── output/
│   ├── reading_order.py     L2 阅读顺序（BFS）
│   └── report.py            L1/L2 渲染
└── cli/main.py              onboard / scan / index / status / init
```

**代码量参考**：`ts_parser.py` 451 行 · `python_parser.py` 376 行 · `builder.py` 313 行 · 全部约 **4,000 行**（含注释与 docstring）。

### 数据流

```
discover（找文件 + 两类排除）
    ↓
parse（Python ast / TS 编译器）  ← 唯一走缓存的阶段
    ↓
resolve（符号解析 → 调用图）
    ↓
resolve_import_edges（import 关系 → 依赖图）
    ↓
pagerank（文件级 + 符号级，每次全量重算）
    ↓
entrypoint + roles
    ↓
reading_order（BFS 分层） → report（渲染）
```

**两张图是并行的，不是替代关系**——详见下面"被推翻的决策"。

---

## 五、⚠️ 被推翻的决策（最重要的一节）

这一节记录**实现过程中被实测数据推翻的设计**。每一条都曾"看起来很合理"。

### 5.1 四信号重要度模型 → 撤回，纯 PageRank

**原设计**：`重要度 = PageRank + 出度 + 入度 + 角色权重`

**实测**：用 9 个"角色多样"的文件测角色识别，得到"四信号 5/9 优于纯 PR 2/9"。

**问题**：**循环论证**——用角色词表测角色识别，而样本是主观挑的 9 个，挑选行为本身与被测机制相关。

**重测**：改用项目自带文档的**全量**标注清单（30 个文件）：

| 模型 | Python Top10 命中 | TS Top10 命中 |
|---|---|---|
| **纯 PageRank** | **8/30** | **2/9** |
| 四信号模型 | 5/30 | 4/9 |

**结论**：纯 PageRank 更优。角色权重经全局归一化后，同类文件集体霸榜（某项目 `api/` 下 7 个文件全部命中 `contract`，归一化后全部满分，把 Top15 里 9 个位置吃掉）。

**现状**：重要度 = **纯 PageRank**；角色信号保留但**降级为输出分组标签**，不参与排序。

### 5.2 「出度」作为入口识别信号 → 删除

**原设计**（v0.2 修订三）：出度保留为入口识别的独立信号，理由是 `src/main.ts` 出度 55 入度 0，纯 PR 排 74 但出度能指出它是组装中心。

**实测**：

| 文件 | 出度 | 被误判为应用入口 |
|---|---|---|
| `deepseek-client.ts` | 61 | ✅ |
| `desktop-wiki-service.ts` | 101 | ✅ |
| `llm_client.py` | 23 | ✅ |
| `daily_orchestrator.py` | 29 | ✅ |

它们排在真入口前面。**出度高只说明"它 import 了很多东西"，不说明"它是入口"**——依赖多的服务模块会冒充入口。

**现状**：入口判据只剩三个——文件名规律 / 框架注册 / 被生产模块导入。入口点从 11 个收敛到 4 个。

### 5.3 纯 PageRank 排序 → 入口优先 + 沿依赖 BFS

**实测**：PageRank 对入口/编排类文件**没有系统性偏好**。

| 项目 | 入口类排名中位 | 全部文件中位 | 编排类中位 |
|---|---|---|---|
| research_agent | 70 | 60 | 77 |
| Knowledge Loop | 33 | 21 | 64 |

**原因**：PageRank 衡量"被引用的中心性"，而入口与编排器是"引用别人"的一方。`research_agent.py` import 了 30 个模块却几乎不被 import，PageRank 给它 0.003。

**现状**：L2 阅读顺序 = `入口 → 契约层 → 沿依赖 BFS 展开`，层内按 PageRank 降序。

### 5.4 只建调用图 → 补上依赖图（import 边）

**实测**：Knowledge Loop 有 5 个核心文件在调用图里**入度出度全为 0**：

```
core/core/knowledge-repository.ts   只读接口
src/shared/desktop-api.ts            类型契约
core/services/json-post.ts           HTTP 工具
core/services/fetch-api-request.ts   HTTP 工具
src/preload.ts                       桥接
```

它们**只有 import 关系、没有任何函数调用**，是调用图里的孤立点。

**现状**：建两张图。import 边只用于阅读顺序与影响面分析，**不进 PageRank**（保持"重要度 = 调用结构中心性"的语义不变）。

---

## 六、当前实测数据

### 硬指标

| 指标 | 目标 | research_agent | Knowledge Loop |
|---|---|---|---|
| **幻觉符号率** | **0** | **0.00%** ✅ | **0.00%** ✅ |
| L1+L2 端到端 | <30s | **0.39s** ✅ | **0.23s** ✅ |
| 项目内符号解析率 | ≥0.6 | **81.9%** ✅ | — |
| 增量扫描（改 1 文件） | — | 0.46s（命中 153/154） | — |
| 冷启动 → 热缓存 | — | 1.6s → **0.27s（6.1x）** | — |

**增量结果与全量重建逐项一致**：符号数、边数、PageRank、入口点、调用分类全部相同。

### 阅读顺序质量

| 指标 | research_agent | Knowledge Loop |
|---|---|---|
| Top30 命中 | 22/40 (55.0%) | 8/11 (72.7%) |
| Top50 命中 | **33/40 (82.5%)** | 8/11 (72.7%) |
| **目录级覆盖** | **1/1** ✅ | **5/5** ✅ |

**主指标是「目录级覆盖」而不是文件级命中**。原因见下一节。

### ground truth 的性质（重要）

**《项目接手指南》是"导览"不是"全集"。**

- Knowledge Loop 的指南只列 13 个文件，项目有 77 个生产文件
- 核对原文确认：L2/L3 的内容（`bm25.ts`、`markdown-parser.ts`、`action-proposal.ts`）**指南里真的没提**，不是抽取器漏了
- 而指南本身用**目录聚合项**标注职责（`core/indexing/` = "Markdown 分块、检索、附件索引与批处理队列"）

**所以文件级判定天然不公，目录级覆盖才是匹配指南粒度的口径。** 这不是指标放水，是把度量对齐到 ground truth 的真实粒度。

---

## 七、⚠️ 评测方法论红线

**这一节比任何代码都重要。** 本项目犯过一次典型错误，写下来以免重犯。

### 红线

> **用主观挑选的少数样本当 ground truth 前，必须先问：这个样本的选择是否与被测机制相关？**
>
> - 相关 → 循环论证，指标虚高
> - 不相关 → 有效

### 真实案例

曾用 9 个"角色多样"的文件测「角色识别」机制，得出"四信号优于纯 PR"的结论。换用全量清单重测，结论**完全反转**。

### 正确做法

ground truth 用**项目自带文档的全量清单**（README 结构表 / 接手指南全表），让工具去比，**不由人挑**。

### M2 必须遵守的三条

1. `evals/cases/` 必须是**三个子集**：
   - `bugs/` —— 测 recall
   - `clean/` —— 测 precision
   - `debt/` —— 测报告质量
2. **没有负例集时 precision 数字无效**（什么都不报的检查器 precision = 1.0）
3. fix 提交与架构债样本**不可混列**：前者代码前后变化有正例，后者代码从未变、不是 bug

**M2 判定标准包含跨项目误报率一致性**——阈值不能过拟合到单个项目。

### ground truth 抽取的坑

`evals/extract_groundtruth.py` 已经处理了这些，**改动时别退回去**：

- **目录上下文跟踪**：README 的目录树里工具目录的条目常写成裸文件名（`search.py` 而非 `tools/search.py`）。不跟踪目录就分不清是 `tools/search.py`（按设计不参与排序）还是 `core/search.py`（核心模块）
- **只用架构类文档**：不用方案/日志类文档（"重构说明.md""需求决策日志.md"里提到的是"历史改动涉及的文件"，不是"必读文件"）
- **只统计参与排序的文件**：文档里提到的 `evals/benchmark.py`（同目录简写）属于 evals/ 目录，按设计不参与排序，算进分母等于要求工具给不该排名的文件排名

---

## 八、M2 怎么做（下一个战场）

### 已定的约束（v0.2 §5.5，不可推翻）

| 项 | 规则 |
|---|---|
| **LLM 角色** | 候选驱动为默认模式（确定性层定位、LLM 裁决是否成立）。`--explore` 自由扫描仅作演示，指标分开统计，**不得进阻断路径** |
| **回验边界** | verifier 只能挡幻觉型误报（行号/符号不存在），挡不住判断型误报。**精确率主要靠候选漏斗收敛，不靠回验** |
| **基线 key** | 内容指纹 `sha1(rule_id + normalized_symbol + normalized_snippet)`，**禁用行号**（否则插一行全部失效，门禁会被误报淹没而关掉） |
| **修复建议三级分类** | `structural`（仅参考）/ `patch`（过门禁后可用）/ `advisory`（主力）。确定性层必须提供 `extraction` 字段给出机器可读依据（子结构计数等），而非只报行数 |
| **置信度门禁** | 只有 deterministic + 回验通过才可阻断；LLM 结论与 explore 模式一律仅警告/展示 |

### 数据模型已经定型

`core/finding.py` 里 `Finding` / `Evidence` / `Extraction` / `SuggestionType` 都已定义好，**M2 直接用，不用重新设计**。一份 Pydantic 模型同时满足 LLM structured output、Web 报告序列化、policy.yaml 校验。

### 建议的推进顺序

1. **先建 `evals/cases/clean/` 负例集**——没它就没有 precision 基线，后面全是空转
2. 从 `research_agent` 的 12+ 个 fix 类提交里挖正例（`ad36172` 静默失效类最佳）
3. 实现候选生成（确定性层），跑 recall/precision
4. 只有在确定性层指标达标后，才接 LLM

**⚠️ 铁律**：规则准入只认确定性指标，**LLM 不参与判定规则好坏**（提案者不得自评）。

---

## 九、自进化的三条硬护栏（M5/M6 用）

即使现在用不上，接手的人要知道**为什么不做代码层自进化**：

1. **自进化产物不得进入自己的评分函数**——场景 A 的 Insight 只影响场景 A 输出，绝不影响场景 B 的门禁判定
2. **任何自进化必须过留出集且零回归**——进化只在 train 集做，`evals/holdout/` 进化过程不可读，任何指标下降即回滚
3. **进化只能改数据，不能改评分器**——禁止改 `gate_eval.py` 判定逻辑、`verifier.py` 回验逻辑、评测集、已入库基线。**规则提案必须是 PR 形态**（`rules/proposals/` → 人工 review → `rules/active/`）

**不做代码层自进化的实证依据**：arXiv 2609.17817 显示投毒评测集可致永久污染（DGM/SICA/Hyperagents 中毒后 30/30，用干净基准继续进化仍是 30/30），LLM 评审委员会拦不住（judge 反对的是复杂度不是安全），Sonnet 4.5 也会沦陷——**harness 决定成败，护栏必须写在架构里**。

---

## 十、已知问题与待修项

### 明确待修

| # | 问题 | 位置 | 备注 |
|---|---|---|---|
| 1 | **`evals/cases/` 是空的** | `evals/cases/` | **M2 的核心缺口**，见 §8 |
| 2 | **TS 侧符号解析率未测** | — | 只测了 Python 的 81.9%，TS 侧口径下的数字没算 |
| 3 | **research_agent 侧 Top30 只 55%** | `output/reading_order.py` | 分层精确率 L1 15/20、L2 11/20 有空间 |
| 4 | **没有 CI** | — | 54 个测试靠手动跑 |
| 5 | **"索引陈旧"说明未落到 README 用户视角** | — | v0.2 §4.5 要求显式回答，目前只有 `status` 命令 |

> 已修：`scan` 子命令的帮助文案原写"M3 起"，实际 M2 才是检查器阶段（2026-10-23 修正）。

### 已知但有意保留的取舍

| 取舍 | 原因 |
|---|---|
| **纯 AST 不做类型推导** | Python 侧纯 AST 天花板约 60–70% 解析率；上 mypy/pyright 会引入重依赖，M4 用 ts-morph |
| **不用 tree-sitter** | 各语言用各自最优工具（Python 标准库 ast；TS 编译器 API），跨语言能力做在规则层 |
| **PageRank 每次全量算** | 实测 30,000 节点 169 ms，局部近似 Top50 重合度仅 11/50 |
| **每次扫描全量读文件** | 内容哈希必须读文件才知道；缓存省的是 parse 不是读 |
| **TS 侧 import 边用正则抽 module 路径** | Node 侧已抽 import_map，但相对路径解析仍靠启发式匹配 |

### 环境相关的坑（Windows 专属）

| 坑 | 症状 | 解法 |
|---|---|---|
| **路径分隔符** | `f.replace("\\","/").split(os.sep)` **永远切不开**（os.sep 是 `\`） | 统一用 `_parts()`：先替换再 split |
| **`git cat-file --batch`** | **挂起等 EOF**（管道不关闭） | 用 `git archive`（0.31s vs 8.4s） |
| **`dataclass.field()`** | 不支持 `description` 参数（只有 Pydantic 支持） | 用注释代替 |
| **代理只放行 api.github.com** | `git push` → CONNECT tunnel failed 502 | 用 `evals/push_history.py` 走 Git Data API |
| **Python `ast` 解析失败** | 静默返回空 | 已改为记录 warning，不再静默 |

---

## 十一、流程约定（别违反）

这些是项目一开始就定下的，破坏它们的代价很高：

1. **分析器必须可单测**——每个解析器/规则都能单独测
2. **配置在加载时校验**，不在运行时失败
3. **基线用 git 跟踪的 JSON，不用 SQLite**——要能 diff / review / 回滚
4. **LLM 调用并发走 `asyncio` + `Semaphore`**
5. **不为尚未验证的能力提前支付架构成本**——但薄 dispatch 层（CLI 子命令结构）除外，真正的贵的是共享数据模型，那个必须现在定
6. **规则准入只认确定性指标，LLM 不参与判定规则好坏**（提案者不得自评）
7. **工具不该在被审查方留垃圾**——缓存与索引默认落用户目录
8. **验证脚本绝不原地改用户文件**——要制造变更必须在临时副本上做，且用二进制读写保留原始行尾符

第 7、8 条都是踩过坑才加的：
- 写进项目内会生成 4.7 MB 缓存并污染其 `git status`
- text 模式写回把用户的 CRLF 文件改成 LF，`git status` 显示 M 但 `git diff` 为空

---

## 十二、文档索引

| 文档 | 内容 | 什么时候看 |
|---|---|---|
| `docs/CodeSentry_技术选型定稿_v0.2.md` | **当前实施基准**，含 7 次修订记录 | **动手前必读** |
| `docs/CodeSentry_M0验收报告_v1.0.md` | 实测数据 + 失败案例 + 未达标项分析 | 想看"为什么这样设计" |
| `docs/CodeSentry_索引层实测报告_v1.0.md` | Python 侧解析能力边界（纯 AST 天花板） | 写解析器前 |
| `docs/CodeSentry_跨项目验证报告_KnowledgeLoop.md` | TS 侧验证 | 写 TS 相关代码前 |
| `docs/CodeSentry_开工前置检查清单_v1.0.md` | 开工前的 9 项核查 + 4 个待处理问题 | 了解背景 |
| `docs/CodeSentry_技术选型定稿_v0.1.md` | 已被 v0.2 取代，未被推翻的决策仍有效 | 查历史 |
| `interview/CodeSentry_项目方案.md` | 项目背景、命名理由、里程碑原案 | 了解"为什么做" |

**冲突时以 v0.2 定稿为准。**

---

## 十三、Git 提交历史（叙事版）

提交历史本身就是这个项目的论证过程：

```
4e9bf8d  M0: 索引层实现与两个真实项目验证
c2ed5cf  M0 修正：入口点信号、解析性能、ground truth 口径   ← 推翻自己
29ea3a2  M0 收尾：v0.2 修订五 + 验收报告 + memory 迁入
8dac117  M1: L2 阅读顺序改为 BFS + 补 import 边              ← 又一次修正
4f68f1b  M1 第二步：分层完整清单 + 目录级覆盖指标
bfae1d7  M1 第三步：增量缓存 + 索引落盘 + 陈旧检测
30d0cbc  添加 README、LICENSE、项目方案文档
efec771  清理构建产物与初始化占位
a032a07  添加 GitHub API 推送脚本（绕过 git 协议限制）
```

**注意 `c2ed5cf` 和 `8dac117` 两条**——它们记录的是"推翻自己方案"的过程。面试或 review 时，这两条比任何功能提交都更能说明问题。

**推送到 GitHub**（本地代理限制，不能用 `git push`）：

```bash
python evals/push_history.py 3533008548/codeSentry . --fresh
```

---

## 十四、一句话总结

**索引层已经能用且够快（0.2–0.4s，幻觉符号率 0），阅读顺序已经能给出真实的架构地图（目录级覆盖全中）。**

**下一步是把"能读懂"变成"能挑错"——而那需要负例集，需要真实误报率，需要跨项目一致的阈值。**

**最需要警惕的不是技术难度，是自欺。** 这个项目已经因为"循环论证的样本"误判过一次设计，也因为"看起来合理的信号"（出度）误判过两次。**M2 阶段的每一个数字，都要先问"这个 ground truth 是怎么来的"。**
