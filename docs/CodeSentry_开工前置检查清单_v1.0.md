# CodeSentry 开工前置检查清单

> 版本：v1.0 · 2026-10-21
> 目的：动手实现 M0 之前，把所有"可能推翻方案"的因素查一遍并落定
> 状态：已逐项核查，标注了 4 个需要处理的问题

---

## 一、结论摘要

| # | 事项 | 结论 | 状态 |
|---|---|---|---|
| 1 | 四信号重要度模型 | ❌ **撤回**。基于循环论证得出，改用全量 ground truth 后纯 PageRank 更优 | ✅ 已修正文档 |
| 2 | research_agent 工作区状态 | ⚠️ **不干净**（1 个已删文件 + 2 个未跟踪）→ bug-reintroduction 前需处理 | ⛔ 需处理 |
| 3 | research_agent LICENSE | ⚠️ **文件不存在**（方案 §7.2 声称"两项目均 MIT"）→ 对外发布前需补 | ⛔ 需处理 |
| 4 | git 历史可用 fix 提交 | ✅ **85 提交，12+ 个 fix 类**，比预期充足 | ✅ 无需处理 |
| 5 | 可迁移模块存在性 | ✅ 5/6 存在（`evals/gate_eval.py` 是目标文件，本就不存在） | ✅ 无需处理 |
| 6 | Python 侧 ground truth | ✅ **README「项目结构」章节含 30 个标注文件** | ✅ 可用 |
| 7 | TS 侧 ground truth | ⚠️ 仅 9 个（README 只有目录级描述） | ⚠️ 需扩充 |
| 8 | CI 环境 | ✅ `research_agent/.github/workflows/test.yml` 存在 | ✅ 可用 |
| 9 | 记忆/存档风险 | ✅ 无（AST 解析不读文件内容入库） | ✅ 无需处理 |

---

## 二、逐项详查

### 2.1 ⚠️ 最重要：上一轮的「四信号模型」是循环论证

**详细见 `CodeSentry_技术选型定稿_v0.2.md` §4.3.2。** 摘要：

- 上一轮用《项目接手指南》**手工挑的 9 个文件**当 ground truth，测出「四信号 5/9 vs 纯 PR 2/9」
- 那 9 个文件恰好覆盖入口/契约/守卫/提案几种角色，**而被测机制正是角色识别** → 用角色词表测角色词表
- 改用 README 的**全量 30 个**标注文件重测：纯 PR **8/10** 优于四信号 5/10
- TS 侧同口径复测：纯 PR / 纯出度最优，四信号负收益

**已做的修正**：
- v0.2 §4.3 重要度模型 → 回退为纯 PageRank
- 角色信号 → 不参与排序加权，改为**输出时的分组标签**
- 出度 → 保留为**入口识别的独立信号**（`src/main.ts` 出度 55 入度 0，纯 PR 排 74，但它是第一入口）
- 新增 §4.3.3 的方法论条款

### 2.2 ⚠️ research_agent 工作区不干净

```
$ git status --short
D  frontend/_extract.py
?? frontend/src/components/workspace/ChatPanel.tsx
?? 工程约定与经验沉淀.md
```

**影响**：
1. **bug-reintroduction 构造（M2）**——`git checkout <fix_commit>^` 会与未提交改动冲突
2. **实测基线**——当前扫描结果含未提交文件，与 git 历史版本不可比

**处理方案**（M2 开始前执行）：
```bash
cd research_agent
git stash push -u -m "codesentry-baseline"
# 或用 worktree 隔离，绝不动主工作区
git worktree add ../research_agent-baseline <commit>
```

> **建议用 worktree**：bug-reintroduction 需要反复 checkout 不同历史状态，worktree 隔离最干净，且**不污染主工作区**。

### 2.3 ⚠️ research_agent 缺 LICENSE

```
$ ls research_agent/LICENSE*
无结果
$ ls "agent for obsidian/LICENSE"
LICENSE          ← Knowledge Loop 有
```

**方案 §7.2 声称"两个项目均 MIT 协议"** —— 实际只有 Knowledge Loop 有 LICENSE 文件。research_agent 的 README 末尾有「## 📄 License」章节但**内容为空**。

**影响**：
- CodeSentry 若要开源并附"在 XX 项目上验证"，需要被审查项目的许可明确
- 简历里写"MIT 协议"若被追问会露馅

**处理**：M0 不阻塞，但**在写 README 与简历前必须补**。建议直接补 MIT LICENSE 文件。

### 2.4 ✅ git 历史：可用 fix 提交比预期多

`research_agent` 实际 **85 提交**（简历诊断报告写 62，方案 §3.4 写 8 个 fix 提交）。筛出 fix/bug 类：

| 提交 | 描述 | 可用性 |
|---|---|---|
| `ad36172` | fix(Qwen3): tokenize 兼容两种分词器形态，分块守卫不再静默失效 | ⭐ 方案已列，最佳 |
| `a5b3c4b` | fix: 离线质量门控在无模型缓存 / Python 3.11 环境下失败 | ⭐ 方案已列 |
| `45481ff` | fix: recover deep research from model timeouts | ⭐ 方案已列 |
| `42cba6d` | fix: preserve daily run resume semantics | ⭐ 方案已列 |
| `f212145` | fix: bound retrieval for engineering answers | ⭐ 方案已列 |
| `301258d` | 修掉 MCP Server 在事件循环内构建论文库的死锁 | ⭐ 并发/生命周期类 |
| `97078f9` | 修掉 CI 的 ModuleNotFoundError | ⭐ 依赖声明类 |
| `fd3faad` | 切换到 multilingual-e5-small：修中文检索 | ⭐ 静默失效类 |
| `0f5b134` | fix: allow CI jobs to resolve runtime path | 路径类 |
| `a14d559` | fix: isolate real evaluation sessions | 隔离类 |
| `4608d01` | fix: preserve mounted UI presentation | — |

**M2 评测集素材充足**（≥10 个），且 `ad36172` 仍是最佳样本（静默失效，人工 review 易漏）。

### 2.5 ✅ 可迁移模块存在性核对

| 方案 §7.1 列出的模块 | 实际 | 结论 |
|---|---|---|
| `evals/release_gate.py` | ✅ 存在 | 可迁移 |
| `evals/gate_eval.py` | ❌ 不存在 | 这是**目标**文件名，非源模块 |
| `evals/real_eval.py` | ✅ 存在 | 可迁移（脱敏函数） |
| `badcase_store.py` | ✅ 存在 | 可迁移（badcase 池） |
| `tool_runtime.py` | ✅ 存在 | 可迁移（执行边界参考） |
| `run_contract.py` | ✅ 存在 | 可迁移（事件契约参考） |
| `scripts/run_rag_retrieval_eval.py` | ✅ 存在 | 评测调度模式参考 |

**方案 §7.1 的迁移清单基本有效**，唯一"缺失"的是目标文件本身。

### 2.6 ✅ Python 侧 ground truth 充足

`research_agent/README.md` 的「📦 项目结构」章节逐行标注了 **30 个生产文件及其职责**，例如：

```
├── tool_runtime.py       # 工具授权/取消/限长/脱敏事件的统一执行边界
├── graph_builder.py      # LangGraph 图定义 + verify 分级
├── run_contract.py       # 对话、研究、每日任务共用的脱敏运行事件契约
```

**这是天然的全量 ground truth**，且带职责说明，可直接用于：
- 关键文件 Top-K 命中评测
- **角色分类的评测标准**（README 自己说了每个文件是什么角色）

### 2.7 ⚠️ TS 侧 ground truth 偏薄

`agent for obsidian/README.md` 的「目录结构」章节只有 3 行（`src/` / `core/` / `tests/`），**没有文件级清单**。

真正的文件级 ground truth 在《项目接手指南.md》§5「目录与关键文件」表，**只有 9 个文件**（其余是目录聚合项如 `core/indexing/`、`core/services/`）。

**影响**：TS 侧任何排序指标都建立在 9 个样本上，**统计意义有限**。

**处理方案（M1 补）**：
1. 用《项目接手指南》全文提取所有反引号包裹的 `.ts`/`.tsx` 文件名（实测可得 15 个）
2. 更彻底的做法：**用 CodeSentry 自己的 M0 扫一遍 TS 侧，产出"TS 项目的架构地图"，人工 review 后作为扩充后的 ground truth**——这本身就是自举。

### 2.8 ✅ CI 环境可用

`research_agent/.github/workflows/test.yml` 存在。CodeSentry 的门禁集成可参考其结构。

### 2.9 ✅ 记忆/存档风险：无

AST 解析只读源码提取符号与调用关系，**不把代码内容写进索引文件**。索引落盘的是符号名、位置、引用关系。脱敏风险仅存在于 LLM 调用环节（M3），由 v0.1 的 `redact_known_secrets` 迁移解决。

---

## 三、开工前要做的四件事

| # | 事项 | 时机 | 阻塞什么 |
|---|---|---|---|
| 1 | research_agent 加 LICENSE | 发布前 | 简历/README 表述 |
| 2 | research_agent 状态 stash 或建 worktree | M2 开始前 | bug-reintroduction 构造 |
| 3 | 扩充 TS 侧 ground truth | M1 验收前 | TS 侧指标可信度 |
| 4 | 更新 v0.2 §4.3（已做） | ✅ 已完成 | — |

---

## 四、仍然未知、但不影响 M0 的事

| 事项 | 为什么现在不重要 | 何时需要决定 |
|---|---|---|
| LLM 供应商与模型 | M0/M1 全确定性，不调 LLM | M3 语义裁决前 |
| Web 报告技术栈 | M5 才需要 | M5 前 |
| `clean/` 负例集的具体项目选择 | M2 才需要 | M2 开始前 |
| `holdout/` 留出集构造 | M6 才需要 | M6 前 |
| 项目是否开源 / 命名是否避开与现有项目冲突 | 不影响实现 | 发布前 |

---

## 五、一个尚未讨论但值得想的问题

**CodeSentry 自己要不要被自己审查？**

现在三个项目是 `research_agent`（被审查）、`agent for obsidian`（被审查）、`codeSentry`（审查者）。

**CodeSentry 的代码本身没有第三方审查**。这有两个后果：
1. 它的"自举"叙事不完整——一个自己不做质量控制的工具，审别人时凭什么可信
2. **但它天然是 M6 规则层自进化的最佳试验田**——CodeSentry 可以用自己审查自己产出的规则提案，形成闭环

**建议**：不作为 M0 的要求，但把它写进 README 的"roadmap"——**"CodeSentry 审查 CodeSentry"是自进化护栏最诚实的验证方式**：如果护栏有效，它自己的误报率必须能被自己的指标测出来。

这一点与 v0.2 §6 的三条硬护栏直接呼应：**自进化产物不得进入自己的评分函数**——在 CodeSentry 自身上，这条护栏最难实现也最有价值。
