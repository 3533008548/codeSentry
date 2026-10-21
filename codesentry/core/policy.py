"""配置加载与校验。

流程约定：**配置在加载时校验，不在运行时失败**。
所以这里用 Pydantic 严格校验，任何非法配置在启动时就抛错。
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


# ---------- 排除规则 ----------

class ExcludeConfig(BaseModel):
    """排除规则。

    v0.2 修订：**两类排除，用途不同，不可混为一谈**。

      ① 不解析（not_parsed）           —— 不是源码，解析即浪费
      ② 不参与重要度排序（not_ranked） —— 是源码但不是产品架构的一部分

    实测：research_agent 的 runtime/ 占全仓 Python 行数 80% 但一行都不是
    源码（论文库、实验产物）；而 scripts/ evals/ 是源码，但它们的
    `__main__` 守卫会命中 entry 角色规则，把重要度排序搅乱。
    """

    not_parsed: list[str] = Field(
        default_factory=lambda: [
            "node_modules", "__pycache__", ".git", ".venv", "venv",
            "dist", "build", ".next", "site-packages", ".pytest_cache",
            "htmlcov", ".mypy_cache", ".ruff_cache",
            # 数据目录：论文库、实验产物、临时文件
            "runtime", "papers", "artifacts", "source_artifacts",
            "research_documents", "derived", "tmp",
        ],
        description="不解析的目录名（匹配任意层级）",
    )
    not_ranked: list[str] = Field(
        default_factory=lambda: [
            "scripts", "evals", "tools", "tests", "test",
            "benchmarks", "migrations", "docs",
        ],
        description="参与解析但不参与重要度排序的目录名",
    )
    extensions: list[str] = Field(
        default_factory=lambda: [".py", ".ts", ".tsx"],
        description="纳入索引的文件扩展名",
    )

    @field_validator("not_parsed", "not_ranked", "extensions")
    @classmethod
    def _norm(cls, v: list[str]) -> list[str]:
        return [x.strip().strip("/\\") for x in v if x.strip()]


# ---------- 角色规则 ----------

class RoleRule(BaseModel):
    """一条角色识别规则。

    v0.2 修订三：角色信号**不参与重要度排序**，只用于输出分组标签。
    但规则本身保留，并做成可配置，由 M5 知识层产出项目专属覆盖。
    """

    role: str
    weight: float = Field(default=0.5, ge=0.0, le=1.0)
    path_pattern: str | None = Field(
        default=None, description="匹配相对路径的正则"
    )
    name_pattern: str | None = Field(
        default=None, description="匹配文件名的正则"
    )
    content_pattern: str | None = Field(
        default=None, description="匹配文件内容的正则"
    )


class RolesConfig(BaseModel):
    """角色规则表。

    v0.2 修订三：角色信号**不参与重要度排序**，只用于输出分组标签。
    但规则本身保留，并做成可配置，由 M5 知识层产出项目专属覆盖。
    """

    default_weight: float = Field(default=0.2, ge=0.0, le=1.0)
    rules: list[RoleRule] = Field(default_factory=list)

    @field_validator("rules")
    @classmethod
    def _check(cls, v: list[RoleRule]) -> list[RoleRule]:
        for r in v:
            if not (r.path_pattern or r.name_pattern or r.content_pattern):
                raise ValueError(f"角色规则 {r.role} 至少需要一个判据")
        return v

    @classmethod
    def default_rules(cls) -> "RolesConfig":
        """内置的默认角色规则（8 类）。

        这些规则是**架构约定的通用形态**（授权中心叫 policy/engine、
        入口叫 main/app、契约层叫 api/types），跨生态迁移性较好。
        """
        return cls(rules=[
            RoleRule(
                role="entry", weight=1.0,
                name_pattern=r"^(main|index|app|server|cli|electron|worker|preload)$",
                content_pattern=(
                    r"createRoot\(|app\.whenReady|BrowserWindow\(|ipcMain\.|"
                    r"argparse\.ArgumentParser|FastAPI\(|Flask\("
                ),
            ),
            RoleRule(
                role="guard", weight=0.95,
                path_pattern=r"policy|guard|security|permission|auth|sandbox|safe",
            ),
            RoleRule(
                role="contract", weight=0.85,
                path_pattern=r"(^|/)(api|types|contract|schema|interface|shared)(/|\.)",
            ),
            RoleRule(
                role="orchestrator", weight=0.85,
                path_pattern=(
                    r"loop|orchestr|coordinat|agent|runner|workflow|"
                    r"pipeline|dispatch|router|graph"
                ),
            ),
            RoleRule(
                role="proposal", weight=0.70,
                path_pattern=r"proposal|preview|draft|action|intent",
            ),
            RoleRule(
                role="service", weight=0.60,
                path_pattern=r"service|client|provider|adapter|handler",
            ),
            RoleRule(
                role="store", weight=0.60,
                path_pattern=r"store|repository|persistence|database|index|snapshot",
            ),
            RoleRule(
                role="infra", weight=0.50,
                path_pattern=r"config|hash|log|util|helper|domain|base|common|paths",
            ),
        ])


# ---------- 索引配置 ----------

class IndexConfig(BaseModel):
    """索引层配置。"""

    exclude: ExcludeConfig = Field(default_factory=ExcludeConfig)
    roles: RolesConfig = Field(default_factory=RolesConfig.default_rules)
    pagerank_alpha: float = Field(default=0.85, gt=0.0, lt=1.0)
    pagerank_max_iter: int = Field(default=100, gt=0)
    pagerank_tol: float = Field(default=1e-6, gt=0.0)
    cache_enabled: bool = True

    @model_validator(mode="after")
    def _check(self) -> "IndexConfig":
        if self.pagerank_tol < 1e-9:
            raise ValueError("pagerank_tol 过小会导致不收敛")
        return self


# ---------- 门禁配置 ----------

class GateConfig(BaseModel):
    """门禁判定配置。"""

    block_severities: list[str] = Field(
        default_factory=lambda: ["critical", "high"],
        description="达到这些严重级别且可阻断的发现才阻断",
    )
    max_new_findings: int = Field(
        default=0, description="允许的新增问题数，超过则阻断"
    )
    min_confidence: float = Field(
        default=0.9, ge=0.0, le=1.0, description="阻断所需最低置信度"
    )


# ---------- 顶层配置 ----------

class Policy(BaseModel):
    """policy.yaml 的顶层结构。"""

    version: int = 1
    index: IndexConfig = Field(default_factory=IndexConfig)
    gate: GateConfig = Field(default_factory=GateConfig)
    llm: dict[str, Any] = Field(default_factory=dict)

    @property
    def blocking_severities(self) -> set[str]:
        return set(self.gate.block_severities)


DEFAULT_POLICY_PATH = Path("policy.yaml")


def default_policy_text() -> str:
    """生成默认 policy.yaml 内容（用于首次运行时写出）。"""
    return """\
# CodeSentry 策略配置
# 加载时校验，非法配置在启动时即报错（不延迟到运行时）

version: 1

index:
  exclude:
    # ① 不解析：不是源码
    not_parsed:
      - node_modules
      - __pycache__
      - .git
      - .venv
      - venv
      - dist
      - build
      - .next
      - site-packages
      - runtime          # 论文库 / 实验产物，实测占全仓行数 80%
      - papers
      - artifacts
      - source_artifacts
      - research_documents
      - derived
      - tmp
    # ② 参与解析但不参与重要度排序：是源码但不是产品架构的一部分
    not_ranked:
      - scripts
      - evals
      - tools
      - tests
      - benchmarks
      - migrations
    extensions:
      - .py
      - .ts
      - .tsx

  pagerank_alpha: 0.85
  pagerank_max_iter: 100
  pagerank_tol: 1.0e-6
  cache_enabled: true

  roles:
    # 角色信号不参与重要度排序，只用于输出时的分组标签
    default_weight: 0.2
    rules:
      - role: entry
        weight: 1.0
        name_pattern: "^(main|index|app|server|cli|electron|worker|preload)$"
        content_pattern: "createRoot\\\\(|app\\\\.whenReady|BrowserWindow\\\\(|ipcMain\\\\.|argparse\\\\.ArgumentParser|FastAPI\\\\("
      - role: guard
        weight: 0.95
        path_pattern: "policy|guard|security|permission|auth|sandbox|safe"
      - role: contract
        weight: 0.85
        path_pattern: "(^|/)(api|types|contract|schema|interface|shared)(/|\\\\.)"
      - role: orchestrator
        weight: 0.85
        path_pattern: "loop|orchestr|coordinat|agent|runner|workflow|pipeline|dispatch|router"
      - role: proposal
        weight: 0.70
        path_pattern: "proposal|preview|draft|action|intent"
      - role: service
        weight: 0.60
        path_pattern: "service|client|provider|adapter|handler"
      - role: store
        weight: 0.60
        path_pattern: "store|repository|persistence|database|index|snapshot"
      - role: infra
        weight: 0.50
        path_pattern: "config|hash|log|util|helper|domain|base|common|paths"

gate:
  block_severities:
    - critical
    - high
  max_new_findings: 0
  min_confidence: 0.9

llm:
  provider: ""
  model: ""
"""


def load_policy(path: str | os.PathLike[str] | None = None) -> Policy:
    """加载并校验 policy。

    找不到文件时返回默认策略（不报错），保证首次运行可用。
    文件存在但非法时抛错（配置错误在加载时暴露，不在运行时）。
    """
    if path is None:
        return Policy()

    p = Path(path)
    if not p.exists():
        return Policy()

    if yaml is None:  # pragma: no cover
        raise RuntimeError("需要 pyyaml 才能加载 policy.yaml")

    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if raw is None:
        return Policy()
    if not isinstance(raw, dict):
        raise ValueError(f"{p} 顶层必须是映射（mapping），实际是 {type(raw).__name__}")

    return Policy.model_validate(raw)
