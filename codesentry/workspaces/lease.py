"""One OS-owned lease per local registry; a crash releases it automatically."""
from __future__ import annotations

import os
from pathlib import Path


class DirectoryLease:
    def __init__(self, data_dir: Path):
        self.descriptor: int | None = None
        descriptor = os.open(data_dir / ".instance.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.set_inheritable(descriptor, False)
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            raise RuntimeError("这个数据目录已由另一个 CodeSentry 服务使用，请使用已打开的工作台") from error
        self.descriptor = descriptor

    def close(self) -> None:
        descriptor, self.descriptor = self.descriptor, None
        if descriptor is None:
            return
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        # Keep the lock file: unlinking it could allow two different inodes to
        # be locked concurrently. The OS lock, not file existence, is the lease.
