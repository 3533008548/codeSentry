"""Remove only known CodeSentry-managed artifacts without reading old payloads."""
from pathlib import Path
import re

from codesentry.access.policy import AccessDenied, is_link


def clear_owned_artifacts(root: Path) -> list[str]:
    from codesentry.index.cache import default_cache_dir, default_index_dir
    removed = []
    locations = ((default_cache_dir(root), ('parse_cache.json', 'parse_cache.access.json')),
                 (default_index_dir(root), ('index.json', 'index.json.access.json')))
    for directory, names in locations:
        absolute = directory.absolute()
        if any(is_link(parent) for parent in (absolute, *absolute.parents)):
            raise AccessDenied('缓存目录已被重定向，权限保持收紧，等待清理')
        targets = [(absolute, names)]
        scopes = absolute / 'scopes'
        if is_link(scopes):
            raise AccessDenied('权限缓存目录被重定向，保持禁止读取')
        if scopes.exists():
            if not scopes.is_dir():
                raise AccessDenied('权限缓存目录类型异常，等待清理')
            try:
                for child in scopes.iterdir():
                    if is_link(child):
                        raise AccessDenied('权限缓存子目录被重定向，保持禁止读取')
                    if re.fullmatch(r'[0-9a-f]{64}', child.name) and child.is_dir():
                        targets.append((child, names))
            except OSError as error:
                raise AccessDenied('无法枚举权限缓存目录，保持禁止读取') from error
        for parent, owned_names in targets:
            for name in owned_names:
                path = parent / name
                if path.parent != parent:
                    raise AccessDenied('无效的应用缓存清理路径')
                try:
                    if is_link(path):
                        raise AccessDenied('受管缓存文件被重定向，保持禁止读取')
                    if path.exists():
                        path.unlink()
                        removed.append(str(path))
                except OSError as error:
                    raise AccessDenied('旧缓存清理未完成，权限保持收紧，等待重试') from error
    return removed
