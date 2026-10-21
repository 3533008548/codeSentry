"""角色标签。

v0.2 修订三：角色信号**不参与重要度排序**，只用于输出时的分组标签——
告诉用户"这是入口 / 这是授权中心 / 这是契约层"，帮助理解，而非决定顺序。

**为什么保留但降级**：实测发现角色权重经全局归一化后，同类文件会集体
霸榜（research_agent 的 api/ 下 7 个文件全部命中 contract，归一化后全部
满分，把 Top15 里 9 个位置吃掉），且角色信号在两项目上的排序命中都
劣于纯 PageRank。详见 docs/CodeSentry_技术选型定稿_v0.2.md §4.3.2。

词表做成可配置（policy.yaml 的 index.roles.rules），
由 M5 知识层产出项目专属覆盖。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from codesentry.core.policy import RolesConfig, RoleRule


@dataclass
class RoleLabel:
    """一个文件的角色标签。"""

    role: str
    weight: float
    matched_by: str = ""


class RoleTagger:
    """按配置的规则给文件打角色标签。"""

    def __init__(self, cfg: RolesConfig):
        self.cfg = cfg
        self._compiled: list[tuple[RoleRule, re.Pattern[str] | None,
                                   re.Pattern[str] | None,
                                   re.Pattern[str] | None]] = []
        for rule in cfg.rules:
            self._compiled.append((
                rule,
                re.compile(rule.path_pattern, re.IGNORECASE) if rule.path_pattern else None,
                re.compile(rule.name_pattern, re.IGNORECASE) if rule.name_pattern else None,
                re.compile(rule.content_pattern, re.IGNORECASE) if rule.content_pattern else None,
            ))

    def tag(self, rel_path: str, content: str = "") -> RoleLabel:
        """给一个文件打标签。

        多个规则命中时取权重最高者；同权重取先声明者。
        """
        name = rel_path.replace("\\", "/").split("/")[-1]
        stem = name.rsplit(".", 1)[0]
        best: RoleLabel | None = None
        best_rule: RoleRule | None = None

        for rule, p_re, n_re, c_re in self._compiled:
            matched = False
            matched_by = ""
            if p_re and p_re.search(rel_path):
                matched, matched_by = True, "路径"
            elif n_re and n_re.search(stem):
                matched, matched_by = True, "文件名"
            elif c_re and content and c_re.search(content):
                matched, matched_by = True, "内容"
            if matched:
                if best is None or rule.weight > best.weight:
                    best = RoleLabel(rule.role, rule.weight, matched_by)
                    best_rule = rule

        if best is None:
            return RoleLabel("-", self.cfg.default_weight, "")
        return best
