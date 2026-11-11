"""Bounded queue and cancellable trusted analysis subprocesses."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import sys
import threading
import time

from codesentry.environment import get_toolchain
from codesentry.access import AccessPolicy, clear_owned_artifacts
from codesentry.environment.toolchain import clean_process_environment, is_link
from codesentry.web.processes import stop_family, track_family
from codesentry.workspaces.files import checked_root
from codesentry.workspaces.lease import DirectoryLease
from codesentry.workspaces.store import ACCESS_ERROR, IMPLEMENTATION_ERROR, TERMINAL, WorkspaceStore, now

MAX_LOG_BYTES = 256 * 1024
ANALYSIS_TIMEOUT = 180


class PolicyConflict(ValueError):
    pass


class AnalysisManager:
    def __init__(self, store: WorkspaceStore, *, timeout: float = ANALYSIS_TIMEOUT, semantic_transport=None,
                 configured_api_key: str | None = None, configured_key_source: str | None = None):
        self.store = store
        self.timeout = timeout
        self.pending: queue.Queue[tuple[str, str] | None] = queue.Queue(maxsize=128)
        self.stopping = threading.Event()
        self.lock = threading.RLock()
        self.workspace_locks: dict[str, threading.RLock] = {}
        self.policy_cache: dict[str, tuple[int, AccessPolicy]] = {}
        self.change_lock = threading.RLock()
        self.cancellations: dict[tuple[str, str], threading.Event] = {}
        self.completed: dict[tuple[str, str], threading.Event] = {}
        self.active: set[tuple[str, str]] = set()
        self.processes: dict[tuple[str, str], subprocess.Popen] = {}
        self.semantic_reservations = {}
        self.thread = threading.Thread(target=self._loop, name="codesentry-analysis", daemon=True)
        self.lease = DirectoryLease(store.data_dir)
        self.closed = False
        try:
            from codesentry.review.approvals import BaselineStore
            from codesentry.semantic.service import SemanticService
            self.baselines = BaselineStore(store.data_dir)
            self.semantic = SemanticService(store.data_dir, transport=semantic_transport,
                configured_api_key=configured_api_key, configured_key_source=configured_key_source)
            from codesentry.conversation.service import ConversationService
            self.conversations = ConversationService(self)
            self.store.mark_interrupted()
            self.thread.start()
        except BaseException:
            self.lease.close()
            raise

    def _workspace_lock(self, workspace_id: str):
        with self.lock:
            return self.workspace_locks.setdefault(workspace_id, threading.RLock())

    def _current_policy(self, workspace: dict) -> AccessPolicy:
        access = workspace["access_policy"]
        cached = self.policy_cache.get(workspace["id"])
        if cached is None or cached[0] != access["version"] or cached[1].settings != access["settings"]:
            policy = AccessPolicy(checked_root(Path(workspace["path"])), access["settings"], confirmed=True)
            self.policy_cache[workspace["id"]] = (access["version"], policy)
        else:
            policy = cached[1]
            getattr(policy, "refresh_if_changed", policy.refresh)()
        return policy

    def _cleanup_workspace(self, workspace_id: str) -> None:
        # Only application-generated IDs from this registry may name cleanup
        # roots. Never recurse into a source directory, link or junction.
        if not re.fullmatch(r"[a-f0-9]{32}", workspace_id):
            raise ValueError("无法验证工作空间清理路径")
        workspace = self.store.get_workspace(workspace_id)
        self.conversations.invalidate(workspace_id)
        self.semantic.clear_workspace_content(workspace_id)
        self.baselines.invalidate_workspace(workspace_id)
        clear_owned_artifacts(Path(workspace["path"]))
        base = self.store.data_dir / "workspaces" / workspace_id / "analyses"
        for component in [base, *base.parents]:
            if component.is_relative_to(self.store.data_dir) and is_link(component):
                raise ValueError("应用数据目录被重定向，旧数据清理被阻止")
        if not base.exists():
            return
        if not base.resolve().is_relative_to(self.store.data_dir):
            raise ValueError("应用数据目录不在受管范围")
        with self.store.connection() as connection:
            identities = [row["id"] for row in connection.execute("SELECT id FROM analyses WHERE workspace_id=?", (workspace_id,))]
        self._cleanup_analysis_files(base, identities)

    def _cleanup_analysis_files(self, base, identities):
        for component in [base, *base.parents]:
            if component.is_relative_to(self.store.data_dir) and is_link(component):
                raise ValueError("应用数据目录被重定向，旧数据清理被阻止")
        if not base.exists():
            return
        if not base.resolve().is_relative_to(self.store.data_dir):
            raise ValueError("应用数据目录不在受管范围")
        for identity in identities:
            if not re.fullmatch(r"[a-f0-9]{32}", identity):
                raise ValueError("无法验证历史任务清理路径")
            root = base / identity
            if not root.exists():
                continue
            if is_link(root) or root.resolve() != root or not root.is_relative_to(base):
                raise ValueError("历史任务目录被重定向，清理被阻止")
            files, directories = [], []
            for current, children, names in os.walk(root, followlinks=False):
                directory = Path(current)
                if is_link(directory):
                    raise ValueError("历史任务包含重定向，清理被阻止")
                for child in children + names:
                    path = directory / child
                    if is_link(path) or not path.resolve().is_relative_to(root):
                        raise ValueError("历史任务包含重定向，清理被阻止")
                files.extend(directory / name for name in names)
                directories.append(directory)
            for path in files:
                path.unlink()
            for directory in reversed(directories):
                directory.rmdir()

    def _quiesce_workspace(self, workspace_id: str) -> None:
        with self.lock:
            identities = [identity for identity in self.cancellations if identity[0] == workspace_id]
            waits = [self.completed[identity] for identity in identities if identity in self.active]
            for identity in identities:
                self.cancellations[identity].set()
            processes = [process for identity, process in self.processes.items() if identity[0] == workspace_id]
        for process in processes:
            self._stop(process)
        deadline = time.monotonic() + 15
        for completed in waits:
            if not completed.wait(max(0, deadline - time.monotonic())):
                raise RuntimeError("旧分析尚未停止，访问保持关闭，请稍后重新保存范围")

    def confirm_policy(self, workspace_id: str, settings: dict, *, fingerprint: str | None = None,
                       expected_version: int | None = None, stale_ok: bool = False) -> dict:
        with self.change_lock:
            with self._workspace_lock(workspace_id):
                workspace = self.store.get_workspace(workspace_id)
                if expected_version is not None and workspace["access_policy"]["version"] != expected_version:
                    if stale_ok:
                        return workspace
                    raise PolicyConflict("访问范围已被其他窗口修改，请重新预览并确认")
                policy = AccessPolicy(checked_root(Path(workspace["path"])), settings, confirmed=True)
                if fingerprint is not None and fingerprint != policy.fingerprint:
                    raise ValueError("访问范围预览已改变，请重新预览并确认")
                access = workspace["access_policy"]
                if (access["confirmed"] and not access["cleanup_pending"]
                        and access["settings"] == policy.settings and access["fingerprint"] == policy.fingerprint):
                    return workspace
                self.store.begin_policy_change(workspace_id, policy)
            try:
                self.semantic.clear_workspace_content(workspace_id)
                self._quiesce_workspace(workspace_id)
                self._cleanup_workspace(workspace_id)
            except Exception as error:
                self.store.finish_policy_change(workspace_id, error=f"旧数据清理尚未完成: {str(error)[:300]}")
                return self.store.get_workspace(workspace_id)
            with self._workspace_lock(workspace_id):
                self.store.finish_policy_change(workspace_id)
                return self.store.get_workspace(workspace_id)

    def synchronize(self, workspace_id: str) -> dict:
        with self._workspace_lock(workspace_id):
            workspace = self.store.get_workspace(workspace_id)
            access = workspace["access_policy"]
            changed = False
            if access["confirmed"] and not access["cleanup_pending"]:
                policy = self._current_policy(workspace)
                changed = policy.fingerprint != access["fingerprint"]
            if not changed:
                return workspace
        # A simultaneous trusted settings save wins over this older observation
        # of Git files. Never restore old settings while syncing external rules.
        return self.confirm_policy(workspace_id, access["settings"], expected_version=access["version"], stale_ok=True)

    @contextmanager
    def authorized(self, workspace_id: str):
        self.synchronize(workspace_id)
        with self._workspace_lock(workspace_id):
            workspace = self.store.get_workspace(workspace_id)
            access = workspace["access_policy"]
            if not access["confirmed"]:
                raise PermissionError("请先确认这个工作空间的文件访问范围")
            if access["cleanup_pending"]:
                raise PermissionError("旧数据仍待清理，文件访问保持关闭，请重新保存范围后重试")
            policy = self._current_policy(workspace)
            if policy.fingerprint != access["fingerprint"]:
                raise PermissionError("文件访问规则刚发生变化，请刷新后重试")
            yield workspace, policy

    def _snapshot_current(self, workspace_id: str, snapshot: dict | None) -> bool:
        if not self.store.policy_matches(workspace_id, snapshot):
            return False
        workspace = self.store.get_workspace(workspace_id)
        policy = self._current_policy(workspace)
        return policy.fingerprint == snapshot["fingerprint"]

    def submit(self, workspace_id: str, *, kind: str = "navigation", max_function_lines: int | None = None,
               base_ref: str | None = None, comparison: str | None = None, target_ref: str | None = None) -> dict:
        if self.stopping.is_set():
            raise ValueError("服务正在关闭")
        if kind == "semantic_review":
            raise ValueError("请先预览并逐次确认模型发送内容")
        with self.authorized(workspace_id):
            job = self.store.create_analysis(workspace_id, kind=kind, max_function_lines=max_function_lines,
                                             base_ref=base_ref, comparison=comparison, target_ref=target_ref)
        return self._enqueue(workspace_id, job)

    def submit_semantic(self, workspace_id, reservation):
        if self.stopping.is_set():
            raise ValueError("服务正在关闭")
        with self.authorized(workspace_id) as (workspace, access):
            if reservation.workspace_id != workspace_id:
                raise PermissionError("模型任务不属于这个工作空间")
            self.semantic.validate_current(reservation, access, access_version=workspace["access_policy"]["version"])
            job = self.store.create_analysis(workspace_id, kind="semantic_review", semantic_config=reservation.to_config())
            with self.lock:
                self.semantic_reservations[(workspace_id, job["id"])] = reservation
            return self._enqueue(workspace_id, job)

    def _enqueue(self, workspace_id, job):
        identity = (workspace_id, job["id"])
        with self.lock:
            self.cancellations[identity] = threading.Event()
            self.completed[identity] = threading.Event()
        try:
            self.pending.put_nowait(identity)
        except queue.Full:
            self.store.update_analysis(*identity, status="failed", finished_at=now(), error="分析队列已满，请稍后重试")
            with self.lock:
                self.cancellations.pop(identity, None)
                self.semantic_reservations.pop(identity, None)
                completed = self.completed.pop(identity, None)
                if completed is not None:
                    completed.set()
            raise ValueError("分析队列已满，请稍后重试")
        return job

    def update_semantic_profile(self, workspace_id, changes, **options):
        # Serialize settings with source-scope changes, but release the workspace
        # lock while waiting so an in-flight response can observe revocation.
        with self.change_lock:
            with self.authorized(workspace_id):
                result = self.semantic.update_profile(workspace_id, changes, **options)
                self.conversations.revoke(workspace_id)
                with self.store.connection() as connection:
                    rows = connection.execute("SELECT id,config FROM analyses WHERE workspace_id=?", (workspace_id,)).fetchall()
                identities = [row["id"] for row in rows if json.loads(row["config"]).get("kind") == "semantic_review"]
                with self.lock:
                    waits = []
                    for analysis_id in identities:
                        identity = (workspace_id, analysis_id)
                        if identity in self.cancellations:
                            self.cancellations[identity].set()
                        if identity in self.active:
                            waits.append(self.completed[identity])
                        self.store.invalidate_analysis(*identity)
            deadline = time.monotonic() + 15
            for complete in waits:
                if not complete.wait(max(0, deadline - time.monotonic())):
                    self.semantic.update_profile(workspace_id, {"enabled": False}, expected_revision=result["revision"], clear_key=True)
                    raise ValueError("旧模型任务仍在关闭，模型访问已关闭，请稍后重新保存设置")
            base = self.store.data_dir / "workspaces" / workspace_id / "analyses"
            try:
                self._cleanup_analysis_files(base, identities)
            except Exception:
                self.semantic.update_profile(workspace_id, {"enabled": False}, expected_revision=result["revision"], clear_key=True)
                raise ValueError("旧模型数据清理未完成，模型访问已关闭，请重新保存设置") from None
            return result

    def cancel(self, workspace_id: str, analysis_id: str) -> dict:
        job = self.store.get_analysis(workspace_id, analysis_id)
        if job["status"] in TERMINAL:
            return job | {"logs": [], "result": None, "error": None}
        identity = (workspace_id, analysis_id)
        with self.lock:
            event = self.cancellations.get(identity)
            if event is None:
                raise ValueError("分析任务不属于本次服务，请刷新后重试")
            event.set()
            if job["status"] == "queued":
                self.store.update_analysis(*identity, status="cancelled", finished_at=now())
            process = self.processes.get(identity)
            completed = self.completed.get(identity)
        if process is not None:
            self._stop(process)
        if completed is not None and job["status"] == "running":
            completed.wait(3)
        # Cancel is a tightening action. It must not wait for a source-tree scan
        # or expose historical payloads before a separate authorized read.
        return self.store.get_analysis(*identity) | {"logs": [], "result": None, "error": None}

    @staticmethod
    def _stop(process: subprocess.Popen) -> None:
        stop_family(process)

    @staticmethod
    def _spawn(arguments, *, cwd, env, stdout):
        process = subprocess.Popen(arguments, cwd=cwd, env=env,
                                   stdin=subprocess.DEVNULL, stdout=stdout, stderr=subprocess.STDOUT,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                   start_new_session=os.name != "nt")
        try:
            track_family(process)
        except OSError:
            stop_family(process)
            raise
        return process

    def _loop(self) -> None:
        while True:
            identity = self.pending.get()
            try:
                if identity is None:
                    return
                if self.stopping.is_set():
                    if self.store.get_analysis(*identity)["status"] not in TERMINAL:
                        self.store.update_analysis(*identity, status="interrupted", finished_at=now(), error="服务关闭，任务未执行")
                    continue
                with self.lock:
                    self.active.add(identity)
                self._run(*identity)
            except Exception as error:
                if identity is not None:
                    semantic = identity in self.semantic_reservations
                    self.store.update_analysis(*identity, status="failed", finished_at=now(),
                                               error="模型审查未完成，请重新生成发送预览" if semantic else
                                               f"分析服务错误: {type(error).__name__}: {str(error)[:500]}")
            finally:
                if identity is not None:
                    with self.lock:
                        self.cancellations.pop(identity, None)
                        self.semantic_reservations.pop(identity, None)
                        self.active.discard(identity)
                        completed = self.completed.pop(identity, None)
                        if completed is not None:
                            completed.set()
                self.pending.task_done()

    def _run(self, workspace_id: str, analysis_id: str) -> None:
        identity = (workspace_id, analysis_id)
        event = self.cancellations[identity]
        with self.lock:
            if event.is_set() or self.store.get_analysis(*identity)["status"] != "queued":
                return
            self.store.update_analysis(*identity, status="running", started_at=now())
        workspace = self.store.get_workspace(workspace_id)
        root = checked_root(Path(workspace["path"]))
        destination = self.store.result_file(*identity)
        log_file = destination.with_name("worker.log")
        config = self.store.analysis_config(*identity)
        kind = config.get("kind", "navigation")
        snapshot = self.store.analysis_policy(*identity)
        if kind == "semantic_review":
            self._run_semantic(identity, event, root, destination, config, snapshot)
            return
        package_root = Path(__file__).resolve().parents[2]
        # -I intentionally ignores PYTHONIOENCODING/PYTHONUTF8. The supervisor
        # decodes this pipe as UTF-8, so configure both worker streams explicitly.
        bootstrap = ("import sys; sys.stdout.reconfigure(encoding='utf-8'); "
                     "sys.stderr.reconfigure(encoding='utf-8'); "
                     f"sys.path.insert(0, {str(package_root)!r}); "
                     "from codesentry.web.worker import main; raise SystemExit(main())")
        environment = clean_process_environment()
        environment.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
        # Even disabled cache constructors may ask for an OS home/cache path.
        # Point those fallbacks at this job, never copy the user's credential home.
        environment.update({"HOME": str(destination.parent), "USERPROFILE": str(destination.parent),
                            "LOCALAPPDATA": str(destination.parent / "cache"),
                            "XDG_CACHE_HOME": str(destination.parent / "cache")})
        if kind == "navigation":
            toolchain = get_toolchain(root)
            if toolchain.node:
                environment["CODESENTRY_NODE"] = toolchain.node
        elif kind == "change_scope":
            git_executable = shutil.which("git")
            if git_executable:
                environment["CODESENTRY_GIT"] = str(Path(git_executable).resolve())
        arguments = [sys.executable, "-I", "-c", bootstrap, str(root), str(destination), workspace_id,
                     analysis_id, json.dumps(config), json.dumps(snapshot), str(self.store.data_dir)]
        started = time.monotonic()
        self.store.append_log(*identity, "正在生成只报告审查预览；不执行目标代码，门禁未评估" if kind == "review_preview"
                              else "正在进行静态分析；目标代码与目标依赖不会执行")
        process = None
        outcome = None
        try:
            with log_file.open("wb") as output:
                with self._workspace_lock(workspace_id):
                    if event.is_set():
                        self.store.update_analysis(*identity,
                                                   status="interrupted" if self.stopping.is_set() else "cancelled",
                                                   finished_at=now())
                        return
                    if not self._snapshot_current(workspace_id, snapshot):
                        self.store.invalidate_analysis(*identity)
                        return
                    process = self._spawn(arguments, cwd=package_root, env=environment, stdout=output)
                with self.lock:
                    self.processes[identity] = process
                while process.poll() is None:
                    if self.stopping.is_set():
                        outcome = "interrupted"
                        self._stop(process)
                        break
                    if event.is_set():
                        outcome = "cancelled"
                        self._stop(process)
                        break
                    if time.monotonic() - started > self.timeout:
                        outcome = "failed"
                        self._stop(process)
                        self.store.append_log(*identity, "分析超时，进程已回收")
                        break
                    if log_file.stat().st_size > MAX_LOG_BYTES:
                        outcome = "failed"
                        self._stop(process)
                        self.store.append_log(*identity, "分析输出超过上限，进程已回收")
                        break
                    time.sleep(0.05)
            # Cancellation has no source payload to publish. Finish it before
            # any expensive scope refresh and do not read the old worker log.
            if self.stopping.is_set() or event.is_set():
                self.store.update_analysis(*identity,
                                           status="interrupted" if self.stopping.is_set() else "cancelled",
                                           finished_at=now(), elapsed_seconds=round(time.monotonic() - started, 3))
                return
            with self._workspace_lock(workspace_id):
                if not self._snapshot_current(workspace_id, snapshot):
                    self.store.invalidate_analysis(*identity)
                    return
                with log_file.open("rb") as output:
                    logs = output.read(MAX_LOG_BYTES).decode("utf-8", errors="replace")
                for line in logs.splitlines()[-24:]:
                    self.store.append_log(*identity, line)
            # close() can reap the process before the next poll enters the loop.
            # Preserve the requested outcome even in that shutdown race.
            if outcome is None:
                if self.stopping.is_set():
                    outcome = "interrupted"
                elif event.is_set():
                    outcome = "cancelled"
            status = outcome or ("succeeded" if process.returncode == 0 else "incomplete" if process.returncode == 1 else "failed")
            if status in {"succeeded", "incomplete"}:
                result = json.loads(destination.read_text(encoding="utf-8"))
                if (result.get("workspace_id") != workspace_id or result.get("analysis_id") != analysis_id
                        or result.get("policy_version") != snapshot["version"]
                        or result.get("policy_fingerprint") != snapshot["fingerprint"]):
                    raise ValueError("分析工作空间身份不匹配")
                if (snapshot.get("analysis_provenance") != self.store.analysis_provenance
                        or result.get("analysis_provenance") != self.store.analysis_provenance):
                    raise ValueError(IMPLEMENTATION_ERROR)
                if (result.get("kind", "navigation") != kind
                        or json.dumps(result.get("config"), sort_keys=True) != json.dumps(config, sort_keys=True)):
                    raise ValueError("分析任务类型或冻结配置不匹配")
                with self._workspace_lock(workspace_id):
                    if not self._snapshot_current(workspace_id, snapshot):
                        self.store.invalidate_analysis(*identity)
                        return
                    self.store.update_analysis(*identity, status=status, finished_at=now(),
                                               elapsed_seconds=round(time.monotonic() - started, 3),
                                               result_path=str(destination.relative_to(self.store.data_dir)))
            else:
                message = None if status == "cancelled" else "分析未完成，可查看任务记录后重试"
                self.store.update_analysis(*identity, status=status, finished_at=now(),
                                           elapsed_seconds=round(time.monotonic() - started, 3), error=message)
        finally:
            if process is not None:
                self._stop(process)
            with self.lock:
                self.processes.pop(identity, None)

    def _run_semantic(self, identity, event, root, destination, config, snapshot):
        from codesentry.web.worker import RegisteredAccessPolicy
        workspace_id, analysis_id = identity
        reservation = self.semantic_reservations[identity]
        started = time.monotonic()

        def guard():
            if event.is_set() or self.stopping.is_set():
                raise PermissionError("semantic_cancelled")
            if not self.store.policy_matches(workspace_id, snapshot):
                raise PermissionError("semantic_scope_changed")

        temporary = destination.with_suffix(".tmp")
        try:
            with RegisteredAccessPolicy(root, self.store.data_dir, workspace_id, snapshot) as access:
                report = self.semantic.execute(reservation, access, cancel_event=event, live_guard=guard)
                with self._workspace_lock(workspace_id):
                    if event.is_set() or self.stopping.is_set():
                        self.store.update_analysis(*identity, status="interrupted" if self.stopping.is_set() else "cancelled", finished_at=now())
                        return
                    if not self._snapshot_current(workspace_id, snapshot):
                        self.store.invalidate_analysis(*identity)
                        return
                    self.semantic.validate_current(reservation, access, access_version=snapshot["version"], allow_completed=True)
                    report.update(workspace_id=workspace_id, analysis_id=analysis_id, kind="semantic_review", config=config,
                                  policy_version=snapshot["version"], policy_fingerprint=snapshot["fingerprint"],
                                  analysis_provenance=self.store.analysis_provenance)
                    guard()
                    temporary.write_text(json.dumps(report, ensure_ascii=False, allow_nan=False), encoding="utf-8")
                    # cancel() sets its event under this same lock. Staging is
                    # outside it so cancellation can win before publication.
                    with self.lock:
                        if event.is_set() or self.stopping.is_set():
                            self.store.update_analysis(*identity,
                                status="interrupted" if self.stopping.is_set() else "cancelled", finished_at=now())
                            return
                        guard()
                        self.semantic.validate_current(reservation, access, access_version=snapshot["version"], allow_completed=True)
                        os.replace(temporary, destination)
                        self.store.update_analysis(*identity, status="succeeded" if report["review_status"] == "warnings" else "incomplete",
                            finished_at=now(), elapsed_seconds=round(time.monotonic() - started, 3),
                            result_path=str(destination.relative_to(self.store.data_dir)))
        finally:
            temporary.unlink(missing_ok=True)

    def close(self) -> None:
        if self.closed:
            return
        with self.lock:
            self.stopping.set()
            for event in self.cancellations.values():
                event.set()
            for process in self.processes.values():
                self._stop(process)
        self.conversations.close()
        self.semantic.close()
        # Drain queued tasks in order; the sentinel is inserted after them.
        self.pending.put(None, timeout=5)
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            # Do not let another instance take over while this manager still
            # owns a worker. Process exit will release the OS lease if needed.
            raise RuntimeError("分析进程仍在关闭，数据目录暂时保持占用")
        self.lease.close()
        self.closed = True
