"""Resolve operator-confirmed access before any target content is read."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from contextlib import ExitStack
import weakref

from codesentry.access import AccessDenied, AccessPolicy, validate_settings
from codesentry.access.registry import RegistryGuard


def default_workspace_data_dir() -> Path:
    base = os.environ.get('LOCALAPPDATA') or os.environ.get('XDG_DATA_HOME')
    return (Path(base) if base else Path.home() / '.local' / 'share') / 'codesentry' / 'workbench'


def _registry_metadata(root: Path, data_dir: Path) -> dict | None:
    """Reading metadata must not create a registry or silently confirm migration."""
    with RegistryGuard(root, data_dir) as guard:
        return guard.snapshot


def _registered_access(root: Path, data_dir: Path):
    try:
        guard = RegistryGuard(root, data_dir)
    except AccessDenied as error:
        # A rejected initial registry is an unavailable input, as before the
        # guard optimization. Later revocations keep their AccessDenied type.
        raise ValueError('工作空间访问范围不可用，请先在工作台确认范围或完成迁移') from error
    return guard.settings, guard


class ConfirmedAccessPolicy(AccessPolicy):
    """One CLI/evaluation policy owns the lifetime of its registry guard."""

    def __init__(self, root, settings, *, guards, cleanup, workspace_id=None, workspace_version=None):
        self.workspace_id = workspace_id
        self.workspace_version = workspace_version
        self._resource_finalizer = weakref.finalize(self, cleanup)
        # The callback retains guards, never this policy, so forgotten callers
        # do not form a reference cycle that would delay connection cleanup.
        def check_current():
            for guard in guards:
                guard()
        try:
            super().__init__(root, settings, confirmed=True, read_guard=check_current)
        except BaseException:
            self.close()
            raise

    def close(self):
        self._resource_finalizer()

    def __enter__(self):
        self.check_current()
        return self

    def __exit__(self, *_):
        self.close()


def resolve_access(args, root: Path) -> AccessPolicy:
    with ExitStack() as resources:
        access = _resolve_access(args, root, resources)
        stack = getattr(args, '_access_stack', None)
        if stack is not None:
            stack.callback(access.close)
        return access


def _resolve_access(args, root: Path, resources: ExitStack) -> ConfirmedAccessPolicy:
    data_dir = (Path(args.workspace_data_dir).expanduser().resolve()
                if args.workspace_data_dir else default_workspace_data_dir())
    registered, workspace_guard = _registered_access(root, data_dir)
    resources.callback(workspace_guard.close)
    guards = [workspace_guard]
    supplied = None
    if args.access_policy:
        source = Path(args.access_policy).expanduser().resolve(strict=True)
        if source.is_relative_to(root):
            raise ValueError('访问策略须由项目目录之外的可信文件提供，不能自动信任仓库配置')
        with source.open('rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('访问策略文件超过64KiB')
        expected_digest = hashlib.sha256(raw).digest()
        def check_supplied_policy():
            with source.open('rb') as stream:
                current = stream.read(65537)
            if hashlib.sha256(current).digest() != expected_digest:
                raise AccessDenied('可信访问策略文件已变化，本次操作停止')
        guards.append(check_supplied_policy)
        document = json.loads(raw.decode('utf-8-sig'))
        if not isinstance(document, dict):
            raise ValueError('访问策略须为JSON对象')
        if 'root' in document and (not isinstance(document['root'], str)
                                   or Path(document['root']).expanduser().resolve() != root):
            raise ValueError('访问策略中的项目目录与本次目标不匹配')
        supplied = validate_settings(document.get('settings', {k:v for k,v in document.items() if k != 'root'}))
    if registered is None and supplied is None and not args.confirm_access:
        raise ValueError('请先在工作台确认文件范围，或使用 --confirm-access 明确按默认忽略规则仅在本地分析；可用 --exclude 和 --local-only 进一步限制')
    settings = dict(registered or supplied or validate_settings({}))
    if registered is not None and supplied is not None:
        # A one-off CLI configuration may narrow an existing workspace, never
        # restore paths that its persisted permissions have excluded.
        settings['exclude'] = [*settings['exclude'], *supplied['exclude']]
        settings['local_only'] = [*settings['local_only'], *supplied['local_only']]
        settings['respect_gitignore'] = settings['respect_gitignore'] or supplied['respect_gitignore']
    settings['exclude'] = [*settings['exclude'], *args.exclude]
    settings['local_only'] = [*settings['local_only'], *args.local_only]
    return ConfirmedAccessPolicy(root, validate_settings(settings), guards=guards,
                                 cleanup=resources.pop_all().close, workspace_id=workspace_guard.workspace_id,
                                 workspace_version=workspace_guard.snapshot["version"] if registered is not None else None)
