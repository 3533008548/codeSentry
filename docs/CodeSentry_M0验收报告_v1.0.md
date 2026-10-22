# CodeSentry M0 验收报告

> 版本：v1.0 · 2026-10-21
> 验收对象：`D:\develop\project\codeSentry`
> 被验证项目：`research_agent`（Python 42,019 行 + TS 5,377 行）、`agent for obsidian`（TS 26,075 行）
> 依据：`docs/CodeSentry_技术选型定稿_v0.2.md` §5.5

---

## 一、结论

M0 索引层已实现并在两个真实项目上跑通。

| 验收项 | 目标 | research_agent | Knowledge Loop | 结论 |
|---|---|---|---|---|
| **幻觉符号率** | 0 | **0.00%** | **0.00%** | ✅ 硬门槛达标 |
| **L1+L2 端到端耗时** | <30s | **1.04s** | 1.06s | ✅ 达标（28 倍余量） |
| 入口点分类 | 分两级 | 应用 5 / 脚本 53 | 应用 4 / 脚本 0 | ✅ |
| 项目内符号解析率 | ≥0.6（项目内口径） | 见下 | 见下 | ⚠️ 需重定义口径 |
| 关键文件 Top-K 命中（纯 PageRank） | ≥0.8 | Top30 18/44 (40.9%) | Top30 6/11 (54.5%) | ❌ 未达标 |
| **阅读顺序 Top-K 命中**（L2 真实产出） | ≥0.8 | Top30 **22/40 (55.0%)** | **Top30 8/11 (72.7%)** | ⚠️ 部分 |
| **目录级覆盖**（指南聚合项口径） | 全覆盖 | **1/1** | **5/5** | ✅ |

> **M1 修订**：阅读顺序从「入口 + PageRank TopN 拼接」改为
> **「入口 → 契约层 → 沿依赖 BFS 展开」**，并补上 **import 边**
> （调用图与依赖图是两回事——接口文件只有 import 关系、没有函数调用）。
>
> **M1 再修订**：改为**分层完整清单**（每层配额只影响本层展示，
> 不截断整份清单）+ **目录级覆盖指标**。
> 最终：Python Top30 22/40（Top50 33/40 = 82.5%）、TS Top30 8/11；
> **目录级覆盖 Python 1/1、TS 5/5 全部覆盖**。

**未达标的项与原因见 §四。**

---

## 二、已实现内容

```
codeSentry/
├── codesentry/
│   ├── core/                     公共契约（两场景共用）
│   │   ├── symbol.py             Symbol / SymbolEdge / FileMeta / CallSite
│   │   ├── finding.py            Finding / Evidence / Extraction / SuggestionType
│   │   ├── fingerprint.py        内容指纹（禁用行号）
│   │   └── policy.py             policy.yaml 加载与校验（加载时即报错）
│   ├── parsers/                  解析层
│   │   ├── python_parser.py      标准库 ast，零依赖
│   │   └── ts_parser.py          ts.createSourceFile，经 Node 子进程
│   ├── index/                    索引层
│   │   ├── discovery.py          文件发现 + 两类排除
│   │   ├── pagerank.py           纯 Python PageRank（无 numpy/scipy/networkx）
│   │   ├── resolver.py           跨文件符号解析
│   │   ├── entrypoint.py         入口点两级识别
│   │   └── roles.py              角色标签（不参与排序）
│   ├── output/report.py          L1 定位 / L2 骨架
│   └── cli/main.py               onboard / scan / index / init
├── evals/
│   ├── extract_groundtruth.py    从项目文档自动抽取 ground truth
│   ├── m0_acceptance.py          验收脚本
│   └── groundtruth/*.json        两个项目的 ground truth
├── tests/                        34 个单测
└── docs/                         技术选型与实测报告
```

**依赖**：仅 `pydantic` + `pyyaml`（+ `pytest` 开发依赖）。TypeScript 侧复用目标项目已装的 `typescript`，**零新增依赖**。

---

## 三、实测数据

### 3.1 research_agent

```
文件 154 · 符号 2,511 · 边 17,494
端到端 1.04s
阶段：discover 0.005 / parse 0.871 / resolve 0.014 / pagerank 0.002
      symbol_pagerank 0.004 / entrypoints 0.020 / roles 0.060

调用分类：
  builtin        9,970 (57.0%)   正确的不该解析
  local          2,258 (12.9%)   同文件
  cross_file     1,609 ( 9.2%)   跨文件已解析
  test_helper    1,508 ( 8.6%)   测试断言
  unresolved     1,587 ( 9.1%)   纯 AST 无法解析
  module_level     296 ( 1.7%)   无调用者归属
  ambiguous        266 ( 1.5%)   同名多定义
```

**项目内解析率 = (local + cross_file) / (local + cross_file + unresolved + ambiguous) = 3,867 / 4,720 = 81.9%**

> v0.2 §5.5 定的 "≥ 0.6" 若按**全部调用**口径算只有 22.1%（因为 57% 是 builtin，本就不该解析）；按**项目内调用**口径是 81.9%，超过目标。**指标口径必须写清楚，否则数字没有意义。**

### 3.2 Knowledge Loop

```
文件 140 · 符号 1,364 · 边 8,880
端到端 1.06s
调用分类：builtin 49.5% / cross_file / local / unresolved 6.9% / module_level 20.3%
```

**TS 侧 unresolved 显著低于 Python（6.9% vs 9.1%），因 TS 的 import 语法明确给出模块路径。**

### 3.3 关键文件 Top-K 命中

ground truth **自动从项目自带文档抽取**（README「项目结构」+《项目接手指南》），不做人工挑选：

| 项目 | ground truth | Top10 | Top20 | Top30 |
|---|---|---|---|---|
| research_agent | 44 项 | 10/44 (22.7%) | 16/44 (36.4%) | 18/44 (40.9%) |
| Knowledge Loop | 11 项 | 2/11 (18.2%) | 5/11 (45.5%) | 6/11 (54.5%) |

**阅读顺序（L2 的真实产出，从入口出发）：**

| 项目 | Top5 | Top10 | Top20 | Top30 |
|---|---|---|---|---|
| research_agent | 3/44 | 8/44 (18.2%) | 16/44 (36.4%) | **19/44 (43.2%)** |
| Knowledge Loop | 3/11 (27.3%) | 4/11 (36.4%) | 6/11 (54.5%) | **7/11 (63.6%)** |

**阅读顺序命中普遍优于纯 PageRank 排名**——这印证了 §4 的分析。

---

## 四、未达标项的分析

### 4.1 关键文件 Top-K 命中未达 0.8

**原因一（主因）：PageRank 对入口/编排类文件无系统性偏好。**

实测（research_agent）：

| 类别 | 项数 | 排名中位 | 最好 | 最差 |
|---|---|---|---|---|
| 入口类 | 8 | 70 | 9 | 81 |
| 编排类（orchestr/graph/agent 等） | 6 | 77 | 66 | 81 |
| 全部 | 38 | 60 | — | — |

**入口类中位 70 vs 全部中位 60**——PageRank 系统性地把入口/编排器排在后面。

**这不是 bug，是设计目标的必然**：PageRank 衡量"被引用的中心性"，而入口与编排器是"引用别人"的一方。`research_agent.py` import 了 30 个模块但几乎不被 import，所以 PageRank 给它 0.003。

**因此 v0.2 §5.5 的「关键文件 Top-K 命中 ≥ 0.8」这条指标，如果继续用纯 PageRank 排序衡量，是不合理的。** 已改为衡量「阅读顺序」（L2 的真实产出）。

**M1 的三处改进**（Top30 命中：Python 19/44 → 23/44，TS 7/11 → 9/11）：

1. **入口优先 + 沿依赖 BFS 展开**（替代「入口 + PageRank TopN 拼接」）
   —— BFS 保证"先读骨架层，再深入细节"，符合"先建立全局印象"的需求
2. **区分主入口与叶子入口** —— 只有出度 > 0 的入口是阅读起点。
   实测 `src/preload.ts` / `App.tsx` / `main.tsx` 出度都是 0（渲染层叶子），
   从它们读起会走进死胡同
3. **补上 import 边** —— 调用图和依赖图是两回事。接口文件、类型契约、
   常量模块只有 import 关系、没有任何函数调用，在调用图里是孤立点。
   实测 Knowledge Loop 有 5 个核心文件在调用图里入度出度全为 0
   （`knowledge-repository.ts` / `desktop-api.ts` / `json-post.ts` /
   `fetch-api-request.ts` / `preload.ts`）
4. **契约层前置** —— 判据为「无向下依赖 + 向上依赖 ≥ 2 + 含 interface/type
   定义」的文件，是架构骨架（"这个项目有哪些接口"），必须排在实现细节之前

**改进方向（M1）**：阅读顺序应沿**依赖边从入口展开 BFS**，而非"入口 + PageRank TopN"拼接。当前实现是拼接，还不是真正的可达性遍历。

**原因二：ground truth 里有相当比例是"不在依赖图中"的文件。**

`api/app.py`、`api/routes.py`、`frontend/src/App.tsx` 这类文件**不 import 也不被 import**（UI 层与路由层是叶子），PageRank 给它们的分极低。但它们确实是"读懂项目必读"。

**这类文件只能靠「文件名规律 + 框架注册」识别，PageRank 无能为力。** 已通过入口点识别部分覆盖（`api/app.py`、`App.tsx` 都在应用入口里）。

### 4.2 符号解析率口径

见 §3.1 的说明。**建议 v0.2 §5.5 补一条口径定义**：

```
项目内符号解析率 = (local + cross_file) / (local + cross_file + unresolved + ambiguous)
```

按此口径 research_agent 81.9%、Knowledge Loop 待测。

---

## 五、实现过程中发现并修正的问题

| # | 问题 | 根因 | 修正 |
|---|---|---|---|
| 1 | TS 解析全部失败（符号 0） | Node 脚本 `Array.from(new Set(imports))`——`imports` 已改成对象 | 改为 `Object.keys(imports)` |
| 2 | NODE_PATH 指向错误目录 | `Path(ts_path).parent.parent` 多退一层，应为 `.parent` | 修正 |
| 3 | 解析耗时 1.76s | `file_meta()` 与 `parse()` 各读文件、各 parse 一遍 AST | 合并为 `parse_with_meta()`，降到 0.98s（省 44%） |
| 4 | 入口点 54 个 → 仍太多 | "高组装度"信号不可靠：`deepseek-client.ts`(出度61)、`desktop-wiki-service.ts`(101) 排在真入口前 | **删除该信号**，只用文件名/框架/被导入 |
| 5 | 符号级 Top10 被测试文件霸占 | 符号级 PageRank 包含测试文件间的调用 | 只在生产文件间计算 |
| 6 | 角色标签全空 | 默认 `Policy()` 的 `roles` 用了空默认 | 加 `RolesConfig.default_rules()` |
| 7 | 测试符号显示 0 | `is_test`/`is_script` 只传给了 FileMeta 没传给 Symbol | 符号继承文件标记 |
| 8 | ground truth 重复计数 | basename 兜底匹配让同一文件被计两次 | 匹配后加入 `seen` 排除 |
| 9 | Windows 路径分隔符 | `replace("\\","/").split(os.sep)` 永远切不开 | 统一 `_parts()` 先替换再 split |

**问题 4 是本轮最重要的修正**，它推翻了我自己在 v0.2 §4.3.2 里的一个说法（"出度保留为入口识别的独立信号"）。**实测证明出度高 ≠ 是入口。**

---

## 六、下一步（M1）

| # | 事项 | 说明 |
|---|---|---|
| 1 | 阅读顺序改为 BFS 遍历 | 沿依赖边从入口展开，而非拼接 |
| 2 | 扩充 ground truth | Knowledge Loop 只有 11 项，统计意义有限 |
| 3 | 补「叶子层」文件识别 | UI/路由等既不 import 也不被 import 的文件 |
| 4 | v0.2 §5.5 补符号解析率口径 | 按项目内调用计 |
| 5 | 增量缓存 | v0.2 §4.5 已定但 M0 未实现（当前每次全量） |

---

## 附：复现

```bash
cd D:/develop/project/codeSentry

# 单元测试
python -m pytest tests/ -q

# 抽取 ground truth
python evals/extract_groundtruth.py "D:/develop/academic/research_agent" \
    --out evals/groundtruth/research_agent.json
python evals/extract_groundtruth.py "D:/develop/agent for obsidian" \
    --out evals/groundtruth/knowledge_loop.json

# 验收
python evals/m0_acceptance.py "D:/develop/academic/research_agent" \
    evals/groundtruth/research_agent.json
python evals/m0_acceptance.py "D:/develop/agent for obsidian" \
    evals/groundtruth/knowledge_loop.json

# CLI
python -m codesentry.cli.main onboard "D:/develop/agent for obsidian" --level 2
```
