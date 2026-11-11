"""The development ablation never relabels unknowns or shrinks recall truth."""
from evals.navigation_comparison import proxy_counts,load_tool_baseline


def test_proxy_metric_retains_missing_label_and_does_not_claim_quality_pass():
    order=[(f'file{index}.py','core',-1) for index in range(10)]
    measured=proxy_counts(order,['file0.py','not_in_allowed_scope.py'])
    assert measured['hits']==1 and measured['p10']==0.1
    assert measured['recall10_denominator']==2 and measured['recall10']==0.5
    assert measured['unlabelled_prefix']==9
    assert measured['unlabelled_is_not_false_positive']
    assert measured['formal_quality_passed'] is False


def test_short_prefix_is_not_a_perfect_p10():
    measured=proxy_counts([('only.py','core',0)],['only.py'])
    assert measured['p10'] is None
    assert measured['requested_k']==10 and measured['returned_prefix']==1


def test_baseline_is_hash_pinned_tool_history_not_an_import_of_target_code():
    detector,reader=load_tool_baseline()
    assert callable(detector.detect) and callable(reader.reading_order)
    assert detector.__file__.startswith('3df1782b23eecec50486f75b761e5814a516ba92:codesentry/')
    assert reader.__file__.endswith('codesentry/output/reading_order.py')
