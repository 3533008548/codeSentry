# CodeSentry 项目长期约定

## 项目位置

**`D://develop//project//codeSentry`**（2026-10-21 由 D://admin//APPData//workbuddy//codeSentry 迁入）

## 项目定位

CodeSentry = 本地优先的代码审查 Agent。确定性 AST 分析 + LLM 语义裁决 + 发布门禁，输出可定位到行号的结论。

**两个场景（v0.2 定）**：
- **场景 A · 理解**（优先级最高）：帮用户读懂陌生项目。输出导航图 + 推荐阅读顺序
- **场景 B · 审查**：提交前的问题检出与门禁阻断

两场景共用 **M0 索引层**（Symbol 图 + 引用边 + PageRank 重要度 + 内容哈希增量缓存）。叙事是因果链：理解能力 → 图索引 → 审查误报率下降。

用途优先级：**提升能力 > 改进自建项目 > 简历素材**。真实数据与不可编造的指标优先于功能完整度。

无硬性时间截止。宁可做扎实，不做快速验证。

## 权威文档

- `interview/CodeSentry_项目方案.md` —— v1.0 方案草案（项目背景、设计动机、里程碑原案）
- `docs/CodeSentry_技术选型定稿_v0.2.md` —— **当前实施基准，与方案冲突时以此为准**
- `docs/CodeSentry_索引层实测报告_v1.0.md` —— research_agent（Python 侧）实测
- `docs/CodeSentry_跨项目验证报告_KnowledgeLoop.md` —— Knowledge Loop（TS 侧）实测
- `docs/CodeSentry_开工前置检查清单_v1.0.md` —— 开工前的 9 项前置核查与 4 个待处理问题
- `docs/CodeSentry_技术选型定稿_v0.1.md` —— 已被 v0.2 取代，未被推翻的决策仍有效
- `docs/CodeSentry_M0验收报告_v1.0.md` —— M0 实现与两项目验收数据

## 被审查对象的已知状态（2026-10-21 核查）

- `D:\develop\academic\research_agent` —— Python，85 提交，41,897 行生产代码
  - ⚠️ **无 LICENSE 文件**（方案 §7.2 声称 MIT，实际只有 Knowledge Loop 有）→ 发布前须补
  - ⚠️ **工作区不干净**（1 deleted + 2 untracked）→ M2 bug-reintroduction 前用 `git worktree` 隔离
  - ✅ README「项目结构」章节含 30 个文件级标注 → **Python 侧 ground truth 首选**
  - ✅ 12+ 个 fix 类提交可用（`ad36172` 静默失效类最佳）
  - ⚠️ `runtime/` 占全仓 Python 行数 80% 但非源码
- `D:\develop\agent for obsidian` —— TypeScript，23 提交，26,075 行
  - ✅ 有 LICENSE
  - ⚠️ ground truth 仅 9 个文件（《项目接手指南》§5），README 只有目录级描述 → 需扩充
  - ✅ 工作区干净

## 已定型的技术决策（v0.1，不可随意推翻）

1. **解析层**：各语言用各自最优工具（Python 标准库 `ast`；TS 先轻量抽取，M4 起引入 `ts-morph`）。**不用 tree-sitter**。跨语言能力做在规则层，不做在解析层。
2. **数据模型**：Finding 用 Pydantic 定义，一份模型同时满足 LLM structured output、Web 报告序列化、policy.yaml 校验。
3. **LLM 角色**：候选驱动为默认模式（确定性层定位、LLM 裁决是否成立）。`--explore` 自由扫描仅作演示，指标分开统计，**不得进阻断路径**。
4. **回验边界**：verifier 只能挡幻觉型误报（行号/符号不存在），挡不住判断型误报。精确率主要靠候选漏斗收敛，不靠回验。
5. **基线key**：内容指纹 `sha1(rule_id + normalized_symbol + normalized_snippet)`，**禁用行号**（否则插一行全部失效，门禁会被误报淹没而关掉）。
6. **修复建议三级分类**：`structural`（仅参考）/ `patch`（过门禁后可用）/ `advisory`（主力）。确定性层必须提供 `extraction` 字段给出机器可读依据（子结构计数等），而非只报行数。
7. **置信度门禁**：只有 deterministic + 回验通过才可阻断；LLM 结论与 explore 模式一律仅警告/展示。

## v0.2 新增决策

8. **检索不用向量**：静态索引 + 引用图，结果带 `file:line` 可验证证据。理由同决策 7。
9. **重要度用 PageRank**（文件为节点、符号引用为边）。增量场景用反向引用计数+层级深度做局部近似，显式 `refresh-index` 才跑全量。**trade-off 必须写进 README，不假装解决了。**
10. **L1/L2 全确定性，不调 LLM**；L3（关键路径）才引入 LLM。Phase A 先做 L1+L2。
11. **幻觉符号率 = 0 是硬门槛**：理解场景输出中的符号名/文件必须在代码中真实存在，复用 verifier。
12. **CLI 多子命令**：`scan` / `onboard` / `trace` / `propose`，现在只写前两个。底层数据模型（Symbol/Edge/Finding/Insight）两场景共用，现在就定。
13. **自进化只做两层**：知识层（M5）+ 规则层（M6），**不做代码层**。理由是实证的（见下）。

## 索引层 v0.2 实测修订（两个真实项目验证后，勿推翻）

14. **重要度用纯 PageRank**，不参与其他加权：
    - ⚠️ **出度不作为入口识别信号**（v0.2 修订五，M0 实测）：`deepseek-client.ts` 出度 61、`desktop-wiki-service.ts` 101 会被误判为入口并排在真入口前。**出度高只说明 import 得多，不说明是入口**。入口可靠判据只有：文件名规律 / 框架注册 / 被生产模块导入
    - ⚠️ **四信号模型（PR+出度+入度+角色）已撤回** —— 基于循环论证得出（用角色词表测角色识别，样本是主观挑的 9 个）。改用项目自带文档的**全量**标注清单重测：Python 侧纯 PR Top10 命中 **8/30** 优于四信号 5/30；TS 侧同口径亦纯 PR 最优
    - **出度** 保留为**入口识别的独立信号**（`src/main.ts` 出度 55 入度 0，纯 PR 排 74 但它是第一入口），不作排序加权
    - **角色信号** 保留 8 类规则，但降级为**输出分组标签**（告诉用户"这是入口/守卫/契约"），不参与排序
    - 详见 `docs/CodeSentry_技术选型定稿_v0.2.md` §4.3.2
15. **必须建两张图：调用图 + 依赖图**（v0.2 修订六）
    - 调用图（函数调用）覆盖实现型模块；依赖图（import）额外覆盖**接口/契约/常量模块**
    - 实测 Knowledge Loop 有 5 个核心文件在调用图里入度出度全为 0（只有 import 没有调用）
    - **import 边只用于阅读顺序与影响面，不进 PageRank**（保持"重要度 = 调用结构中心性"）
16. **L2 阅读顺序 = 入口 → 契约层 → 沿依赖 BFS 展开**，不是纯 PageRank 排序
    - 入口按**出度**排（组装得多才是起点）；**出度 0 的叶子入口不是阅读起点**
    - 契约层判据：无向下依赖 + 向上依赖 ≥2 + 含 interface/type 定义；**必须排在实现细节之前**
    - 实测 Top30 命中：Python 19/44 → 23/44，TS 7/11 → 9/11
17. **符号主键必须是限定名 `file::symbol`**：research_agent 重名率 18%，裸名做主键会让 PageRank 变成"给最常见的词打分"。
18. **排除规则分两类，不可混**：① 不解析（runtime/papers/node_modules/dist）② 不参与重要度排序（scripts/evals/tools/tests）。后者是源码但不是产品架构的一部分。
19. **TS 解析器用 TypeScript 编译器 API**（`ts.createSourceFile`），不是正则，也**不需要 ts-morph**（其价值是类型信息，M4 才用）。实测 68,618 行/秒，是 Python ast 的 3.1 倍。
20. **每次全量算 PageRank**，不做局部近似（实测 30,000 节点 169 ms；局部近似 Top50 重合度仅 11/50）。**不引入 numpy/scipy/networkx**（scipy 在 Windows 装直接超时）。
21. **性能有余量时质量优先**：L1+L2 端到端 <1s，比目标（L1<30s/L2<3min）有 30–180 倍余量。
22. **Windows 路径分隔符必须显式统一**：`f.replace("\\","/").split(os.sep)` 永远切不开（os.sep 是 `\`）。只在此平台复现，交付前必炸。
23. **dataclass 的 field() 不支持 description**（只有 Pydantic 支持）——踩了两次。

## ⚠️ 评测方法论红线（犯过一次，必记）

**用主观挑选的少数样本当 ground truth 前，必须先问：这个样本的选择是否与被测机制相关？**
- 相关 → 循环论证，指标虚高（本次教训：挑 9 个角色多样的文件去测角色识别）
- 不相关 → 有效

**正确做法：ground truth 用项目自带文档的**全量**清单**（README 结构表 / 接手指南全表），让工具去比，不由人挑。

## 自进化的三条硬护栏（v0.2，不可绕过）

1. **自进化产物不得进入自己的评分函数**：场景 A 的 Insight 只影响场景 A 输出，绝不影响场景 B 的门禁判定。
2. **任何自进化必须过留出集且零回归**：进化只在 train 集做，`evals/holdout/` 进化过程不可读，任何指标下降即回滚。
3. **进化只能改数据，不能改评分器**：禁止改 `gate_eval.py` 判定逻辑、`verifier.py` 回验逻辑、评测集、已入库基线。**规则提案必须是 PR 形态**（`rules/proposals/` → 人工 review → `rules/active/`）。

**代码层自进化不做的实证依据**：arXiv 2609.17817（Roesner & Kohno）显示投毒评测集可致永久污染（DGM/SICA/Hyperagents 中毒后 30/30，用干净基准继续进化仍是 30/30），LLM 评审委员会拦不住（judge 反对的是复杂度不是安全），Sonnet 4.5 也会沦陷——harness 决定成败，护栏必须写在架构里。

## 评测方法论（关键，勿简化）

- `evals/cases/` 必须是三个子集：`bugs/`（测recall）、`clean/`（测 precision）、`debt/`（测报告质量）。
- **没有负例集时 precision 数字无效**（什么都不报的检查器 precision=1.0）。
- fix 提交与架构债样本不可混列：前者代码前后变化有正例，后者代码从未变、不是 bug。
- M2 判定标准包含**跨项目误报率一致性** —— 阈值不是过拟合到单个项目。
- 场景 A 指标：入口点召回率 100%、**入口点精确率 ≥0.9**、幻觉符号率 0、关键文件 Top-K 命中 ≥0.8、L1<30s / L2<3min、项目内符号解析率 ≥0.6。
- **ground truth 来源：项目自带的文档**。README / 架构文档 / 《接手指南》天然含"核心文件是什么"的答案，无需人工标注、无需 git 历史构造。

## 里程碑原则

M1 判定标准是**真实误报率**，不是"检出已知样本"。已知答案的样本只能证明代码能跑。

M0 索引层必须先行（两场景共用地基）；M5/M6 置于最后（依赖前面所有层）。

## 流程约定

- 分析器必须可单测。
- 配置在加载时校验，不在运行时失败。
- 基线用 git 跟踪的 JSON，不用 SQLite（要能 diff / review / 回滚）。
- LLM 调用并发走 `asyncio` + `Semaphore`。
- 不为尚未验证的能力提前支付架构成本。**但薄 dispatch 层（CLI 子命令结构）不属于此列**——真正贵的是共享数据模型，那个必须现在定。
- 规则准入只认确定性指标，**LLM 不参与判定规则好坏**（提案者不得自评）。
