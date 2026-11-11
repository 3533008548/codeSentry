"""Local detector/reader ablation on a frozen, permission-bound current graph.

The two baseline modules are hash-pinned CodeSentry history, never target code.
This is not a replay of the historical binary or a human-gold quality test.
Target source stays in this process; console output contains aggregate counts.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import time
import tokenize
import types

from codesentry.index.builder import build_index
from codesentry.index.cache import hash_content
from codesentry.output.reading_order import reading_order
from codesentry.output.report import render_l1, render_l2
from evals.m0_acceptance import load_contract, output_location_errors
from evals.navigation_development import _confirmed_access, validate_run_manifest

REPOSITORY = Path(__file__).resolve().parents[1]
BASELINE_COMMIT = '3df1782b23eecec50486f75b761e5814a516ba92'
BASELINE_FILES = {
    'codesentry/index/entrypoint.py': '63f2bdd58bf3a0b0a7cb26d1f7997b999cc18c0520bdee1fa38fed44ffbb9226',
    'codesentry/output/reading_order.py': 'd759c7cf5ebd3f9887fd0cdc38622dba5ead82e77e246ddbafec5baf5cfbe0da',
}


def implementation_hashes():
    """Hash the trusted analyzer, never the inspected repository's tool code."""
    paths = sorted(path for path in (REPOSITORY / 'codesentry').rglob('*')
                   if path.is_file() and path.suffix in {'.py', '.js'})
    paths.extend(REPOSITORY / name for name in (
        'evals/navigation_comparison.py', 'evals/navigation_development.py',
        'evals/m0_acceptance.py', 'evals/metrics.py'))
    return {path.relative_to(REPOSITORY).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths}


def load_tool_baseline():
    modules = []
    for index, (path, digest) in enumerate(BASELINE_FILES.items()):
        data = subprocess.check_output(['git','-C',str(REPOSITORY),'show',f'{BASELINE_COMMIT}:{path}'], timeout=10)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Pinned CodeSentry baseline hash mismatch')
        name = f'_codesentry_navigation_baseline_{index}'
        module = types.ModuleType(name)
        module.__file__ = f'{BASELINE_COMMIT}:{path}'
        sys.modules[name] = module
        exec(compile(data, module.__file__, 'exec'), module.__dict__)
        modules.append(module)
    return tuple(modules)


def proxy_counts(order, labels):
    """Retain the parent's positive labels and denominator, including absences."""
    files = [row[0] for row in order]
    prefix = files[:10]
    truth = set(labels)
    hits = len(set(prefix) & truth)
    return {'hits':hits,'requested_k':10,'returned_prefix':len(prefix),
            'p10':hits/10 if len(prefix)==10 else None,
            'recall10_hits':hits,'recall10_denominator':len(truth),
            'recall10':hits/len(truth) if truth else None,
            'unlabelled_prefix':len(prefix)-hits,
            'unlabelled_is_not_false_positive':True,'formal_quality_passed':False}


def compare(manifest_path: Path, workspace_data_dir: Path, *, output: Path) -> dict:
    started = time.perf_counter()
    implementation = implementation_hashes()
    precheck = validate_run_manifest(manifest_path, workspace_data_dir)
    if not precheck.get('valid'):
        raise ValueError('Frozen development inputs are no longer current')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    root = Path(manifest['root']).resolve()
    access, identity = _confirmed_access(root, workspace_data_dir)
    frozen = load_contract(Path(manifest['parent_contract_path']), manifest['project_id'],root,None,access=access)
    old_entries, old_reading = load_tool_baseline()
    build_started = time.perf_counter()
    result = build_index(root, frozen.policy, use_cache=False, access=access)
    build_seconds = time.perf_counter()-build_started
    # Trusted legacy detector needs source text. Read only the already allowed
    # indexed files, within the same source budget, and never serialize text.
    contents = {}
    remaining = 64*1024*1024
    source_hashes = {row['path']:row['sha256'] for row in manifest['inputs']['source_inventory']}
    for meta in result.files:
        if remaining <= 0:
            raise ValueError('Ablation source byte budget exceeded')
        raw = access.read_bytes(meta.path, limit=min(8*1024*1024,remaining))
        remaining -= len(raw)
        encoding=tokenize.detect_encoding(io.BytesIO(raw).readline)[0] if meta.path.endswith('.py') else 'utf-8-sig'
        text=raw.decode(encoding)
        if (hashlib.sha256(raw).hexdigest()!=source_hashes.get(meta.path)
                or meta.is_parsed and hash_content(text)!=meta.content_hash):
            raise ValueError('Ablation source differs from the parsed frozen graph')
        contents[meta.path] = text
    metadata = {meta.path:meta for meta in result.files}
    baseline_apps, baseline_scripts = old_entries.detect(metadata,contents,result.out_degree,result.in_degree,result.production_files)
    del contents
    baseline = replace(result,entrypoints=baseline_apps,script_entrypoints=baseline_scripts)
    before = old_reading.reading_order(baseline,max_depth=4,max_items=30)
    after = reading_order(result,max_depth=4,max_items=30)
    # Separate the contributions on the same graph, rather than attributing
    # all changes to either the parser or a single ordering heuristic.
    current_entries_old_reader = old_reading.reading_order(result,max_depth=4,max_items=30)
    locations = output_location_errors(root,result,[row[0] for row in after],access=access)
    labels = manifest['label_provenance']['ranking_eligible_canonical_labels']
    versions = {
        'legacy_detector_legacy_reader':proxy_counts(before,labels),
        'current_detector_legacy_reader':proxy_counts(current_entries_old_reader,labels),
        'current_detector_current_reader':proxy_counts(after,labels),
    }
    render_started=time.perf_counter()
    l1=render_l1(result)
    l1_seconds=build_seconds+time.perf_counter()-render_started
    l2=render_l2(result)
    l2_seconds=build_seconds+time.perf_counter()-render_started
    rendered={'l1_characters':len(l1),'l2_characters':len(l2),
              'build_and_l1_seconds':round(l1_seconds,4),'build_and_l2_seconds':round(l2_seconds,4)}
    del l1,l2
    postcheck=validate_run_manifest(manifest_path,workspace_data_dir)
    access.check_current()
    if not postcheck.get('valid') or _confirmed_access(root,workspace_data_dir)[1]!=identity:
        raise ValueError('Inputs or permissions changed; comparison discarded')
    if implementation_hashes() != implementation:
        raise ValueError('Analyzer implementation changed; comparison discarded')
    payload={
        'schema_version':1,'evaluation':'controlled development detector/reader ablation',
        'project_id':manifest['project_id'],'manifest_sha256':precheck['manifest_sha256'],
        'input_snapshot_sha256':precheck['input_snapshot_sha256'],
        'parent_contract_sha256':frozen.sha256,'legacy_compatibility':manifest['legacy_compatibility'],
        'baseline_tool_commit':BASELINE_COMMIT,'baseline_tool_sources_sha256':BASELINE_FILES,
        'analysis_implementation_sha256':implementation,
        'conditions':{'same_current_parser_and_graph':True,'historical_binary_replayed':False,
                      'target_code_executed':False,'target_dependencies_installed':False,
                      'target_tests_collected':False,'model_calls':False,'target_source_text_exported':False,
                      'cache_used':False,'manifest_valid_before_and_after':True},
        'counts':{'indexed':len(result.files),'parsed':sum(meta.is_parsed for meta in result.files),
                  'parse_failures':result.parse_failures,'source_complete':result.is_complete,
                  'entry_evidence_issues':len(result.entry_evidence_issues),'position_errors':len(locations),
                  'before_entry_candidates':len(baseline_apps),'current_entry_roles':dict(Counter(entry.kind for entry in result.entrypoints)),
                  'before_reading_items':len(before),'after_reading_items':len(after)},
        'proxy_label_metrics':versions,'performance':{'build_seconds':round(build_seconds,4),**rendered,
                                                      'stage_seconds':{key:round(value,4) for key,value in result.timings.items()},
                                                      'including_validation_seconds':round(time.perf_counter()-started,4)},
        'formal_acceptance':{'passed':False,'human_entry_gold':'not_adjudicated',
                             'label_source':'unchanged legacy document positives; unlabelled remains unknown',
                             'unmatched_labels_retained':len(manifest['label_provenance']['unmatched_labels']),
                             'ambiguous_labels_retained':len(manifest['label_provenance']['ambiguous_labels']),
                             'blockers':manifest['label_provenance']['formal_acceptance_blockers']},
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x',encoding='utf-8') as stream:
        json.dump(payload,stream,ensure_ascii=False,indent=2)
        stream.write('\n')
    return payload


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest',type=Path)
    parser.add_argument('--workspace-data-dir',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        report=compare(args.manifest,args.workspace_data_dir,output=args.output)
    except Exception as error:
        # Target filenames, snippets and exception text remain local. Failure
        # cannot become a quality pass or an excuse to widen file permissions.
        print(json.dumps({'status':'not_evaluable','error_type':type(error).__name__}))
        return 1
    print(json.dumps({key:report[key] for key in ['project_id','counts','proxy_label_metrics','performance','legacy_compatibility']},ensure_ascii=False))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
