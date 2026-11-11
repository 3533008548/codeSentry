"""评测指标的纯函数；无标注或无预测时不伪造满分。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence


@dataclass(frozen=True)
class RankingMetrics:
    k: int
    recommended: int
    hits: int
    truth_count: int
    precision: float | None
    recall: float | None
    unlabelled: tuple[str, ...]


@dataclass(frozen=True)
class EntryMetrics:
    """文件级应用入口；没有独立标签时不从预测自造标准答案。"""

    predicted: int
    truth_count: int | None
    hits: int | None
    precision: float | None
    recall: float | None


def application_entry_predictions(entries: Sequence[object]) -> tuple[str, ...]:
    """Select the process/mount file union without promoting evidence hints.

    This only selects already classified predictions. It does not establish
    execution success, independent gold, or per-role precision/recall.
    """
    return tuple(sorted({
        entry.file for entry in entries
        if getattr(entry, "level", "script") != "script"
        and getattr(entry, "kind", "candidate") in {"process", "mount"}
        and getattr(entry, "confidence", "heuristic") in {"static", "declared"}
        and isinstance(getattr(entry, "file", None), str) and entry.file
    }))


def entrypoint_metrics(
    predicted: Sequence[str], truth: Sequence[str] | None,
    *, independently_annotated: bool = False,
) -> EntryMetrics:
    predictions = set(predicted)
    if truth is None or not independently_annotated:
        return EntryMetrics(len(predictions), None, None, None, None)
    labelled = set(truth)
    hits = len(predictions & labelled)
    return EntryMetrics(
        len(predictions), len(labelled), hits,
        hits / len(predictions) if predictions else None,
        hits / len(labelled) if labelled else None,
    )


def ranking_metrics(
    recommended: Sequence[str], truth: Sequence[str], k: int,
) -> RankingMetrics:
    """P@K 的分母是实际前 K 项数，Recall@K 的分母是唯一标注数。

    推荐不足 K 项时仍报告实际分母，是否足以验收由调用方单独判断。
    未命中文档标注的推荐并不自动等同于人工判定的错误。
    重复推荐占位置但同一标注只能命中一次，防止重复项抬高指标。
    """
    if k <= 0:
        raise ValueError("k 必须大于 0")
    labelled = set(truth)
    top = list(recommended[:k])
    hits = len(set(top) & labelled)
    return RankingMetrics(
        k=k, recommended=len(top), hits=hits, truth_count=len(labelled),
        precision=hits / len(top) if top and labelled else None,
        recall=hits / len(labelled) if labelled else None,
        unlabelled=tuple(f for f in top if f not in labelled),
    )


def precision(true_positives: int, false_positives: int) -> float | None:
    """审查 precision=TP/(TP+FP)；无告警为 N/A，不能视作通过。

    clean 集只能提供误报告警数，不能单独估计总体 precision；TP/FP
    须来自已裁决标注，不能把未标注输出直接当作 FP。
    """
    if true_positives < 0 or false_positives < 0:
        raise ValueError("TP 和 FP 不能为负数")
    count = true_positives + false_positives
    return true_positives / count if count else None


@dataclass(frozen=True)
class DirectoryCoverage:
    directory: str
    expected: int
    covered: int

    @property
    def complete(self) -> bool:
        return self.expected == self.covered


def directory_coverage(
    truth: Sequence[str], recommended: Sequence[str],
) -> list[DirectoryCoverage]:
    """由文件 GT 的直接父目录聚合，未推荐的目录仍计入分母。

    这不是独立的人工架构目录标注，不代表全项目架构覆盖率。
    """
    groups: dict[str, set[str]] = {}
    for path in set(truth):
        parent = path.rsplit("/", 1)[0] + "/" if "/" in path else "./"
        groups.setdefault(parent, set()).add(path)
    output = set(recommended)
    return [
        DirectoryCoverage(parent, len(files), len(files & output))
        for parent, files in sorted(groups.items())
    ]


@dataclass(frozen=True)
class ResolutionMetrics:
    resolved: int
    denominator: int
    heuristic: int
    rate: float | None


def resolution_summary(stats: Mapping[str, int]) -> ResolutionMetrics:
    """确定绑定率：local+cross_file / 确定绑定+未解+歧义+启发式。

    这里只汇总调用方给出的分类；builtin/external/test_helper 只有在绑定
    来源已获证实时才可从候选分母排除。heuristic 是猜测，不计成功。
    """
    resolved = stats.get("local", 0) + stats.get("cross_file", 0)
    heuristic = stats.get("heuristic", 0)
    denominator = resolved + sum(
        stats.get(kind, 0) for kind in ("unresolved", "ambiguous", "heuristic")
    )
    return ResolutionMetrics(
        resolved, denominator, heuristic,
        resolved / denominator if denominator else None,
    )
