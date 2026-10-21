"""Finding 与门禁边界的单测。

v0.1 决策 7：只有 deterministic + 回验通过才可阻断。
"""
from codesentry.core.finding import Finding, Severity, Source, SuggestionType


def _f(**kw) -> Finding:
    base = dict(
        file="a.py", line=10, rule_id="complexity.function_length",
        severity=Severity.HIGH, source=Source.DETERMINISTIC,
        reason="函数过长", verified=True, confidence=0.95,
    )
    base.update(kw)
    return Finding(**base)


def test_确定性且已回验可阻断():
    assert _f().can_block() is True


def test_llm结论不可阻断():
    assert _f(source=Source.LLM).can_block() is False


def test_explore不可阻断():
    assert _f(source=Source.EXPLORE).can_block() is False


def test_未回验不可阻断():
    assert _f(verified=False).can_block() is False


def test_置信度不足不可阻断():
    assert _f(confidence=0.85).can_block() is False


def test_边界置信度():
    assert _f(confidence=0.9).can_block() is True
    assert _f(confidence=0.89).can_block() is False


def test_修复建议三级分类():
    f = _f(suggestion_type=SuggestionType.STRUCTURAL)
    assert f.suggestion_type == SuggestionType.STRUCTURAL
    assert f.suggestion_type != SuggestionType.PATCH


def test_extraction_提供机器可读依据():
    from codesentry.core.finding import Extraction
    f = _f(extraction=Extraction(
        sub_symbols=["add_node", "add_conditional_edges"],
        sub_symbol_counts=[7, 2],
        function_lines=793,
    ))
    assert f.extraction is not None
    assert f.extraction.sub_symbol_counts == [7, 2]
    assert f.extraction.function_lines == 793
