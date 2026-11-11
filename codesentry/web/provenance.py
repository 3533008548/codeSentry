"""Process-pinned identity of trusted analyzer code, not target project data.

Restart the service after upgrading its code. A newly started worker with a
different identity cannot publish into an older supervisor's analysis history.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
from pathlib import Path
import sys


RESULT_SCHEMA = "web-analysis-v1"


@lru_cache(maxsize=1)
def analysis_provenance() -> str:
    """Hash once per process, including output code and the trusted JS parser.

    This detects version drift; it is not a signature or an authorization token.
    It never reads the project under analysis or its dependencies.
    """
    return _implementation_identity(Path(__file__).resolve().parents[1])


def _implementation_identity(package: Path) -> str:
    digest = hashlib.sha256()
    digest.update(f"{RESULT_SCHEMA}\0{sys.implementation.name}\0{sys.version}\0".encode())
    paths = sorted(path for path in package.rglob("*")
                   if path.is_file() and path.suffix in {".py", ".js"}
                   and "__pycache__" not in path.parts)
    for path in paths:
        name = path.relative_to(package).as_posix().encode()
        content = path.read_bytes()
        digest.update(name + b"\0" + str(len(content)).encode() + b"\0" + content)
    return f"{RESULT_SCHEMA}:{digest.hexdigest()}"
