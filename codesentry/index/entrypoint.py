"""入口点识别。

v0.2 修订：**分两级**。

| 级别 | 判据 | 输出 |
|---|---|---|
| 应用入口 | 文件名规律 + 框架注册 + 被生产模块导入 | L1 主入口，通常 1–3 个 |
| 脚本入口 | 有 __main__ 守卫，但在 scripts/ tests/ evals/ tools/ 下 | 折叠为「辅助脚本 N 个」 |

实测依据：第一版仅用 `__main__` 守卫作信号，research_agent 命中 54 个
（含 22 个 scripts、25 个 tests、多个非入口模块），召回率 100% 但精确率
仅约 11%。改为两级后收敛到 3 个应用入口。

**根因认识**：`if __name__ == "__main__"` 是**可执行脚本标记**，
不是**应用入口标记**。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from codesentry.core.symbol import FileMeta, Symbol

# 应用入口的文件名
APP_ENTRY_NAMES = re.compile(
    r"^(main|index|app|server|cli|wsgi|asgi|manage|run|__main__|"
    r"application|electron|worker|preload)$",
    re.IGNORECASE,
)
APP_FACTORY_NAMES = re.compile(
    r"^(main_app|app_factory|create_app|build_app|make_app|get_app|"
    r"setup_app)$"
)

# 框架注册特征
FRAMEWORK_MARKERS = (
    "FastAPI(",
    "Flask(",
    "APIRouter(",
    "argparse.ArgumentParser",
    "click.command",
    "typer.Typer",
    "uvicorn.run",
    "Celery(",
    "createRoot(",
    "ReactDOM.render",
    "app.whenReady",
    "BrowserWindow(",
    "ipcMain.",
    "new Worker(",
    "defineConfig(",
    "createServer(",
)

MAIN_GUARD = re.compile(
    r"__name__\s*==\s*[\"']__main__[\"']|"
    r"require\.main\s*===\s*module|"
    r"process\.argv\[2\]"
)

# 配置文件：即使命中框架标记也不是应用入口
CONFIG_NAMES = re.compile(
    r"^(vite|vitest|jest|webpack|rollup|esbuild|tsconfig|"
    r"babel|postcss|tailwind|eslint|prettier)\.", re.IGNORECASE
)


@dataclass
class EntryPoint:
    """一个入口点。"""

    file: str
    level: str          # app | script
    reason: str
    out_degree: int = 0
    in_degree: int = 0


def detect(
    metas: dict[str, FileMeta],
    contents: dict[str, str],
    out_degree: dict[str, int],
    in_degree: dict[str, int],
    production_files: set[str],
) -> tuple[list[EntryPoint], list[EntryPoint]]:
    """识别入口点。

    Returns:
        (应用入口列表, 脚本入口列表)
    """
    app_entries: list[EntryPoint] = []
    script_entries: list[EntryPoint] = []
    seen: set[str] = set()

    for rel, meta in sorted(metas.items()):
        if rel in seen:
            continue
        # 配置文件不是入口
        if CONFIG_NAMES.match(rel.replace("\\", "/").split("/")[-1]):
            continue
        content = contents.get(rel, "")
        stem = rel.replace("\\", "/").split("/")[-1].rsplit(".", 1)[0]

        name_hit = bool(APP_ENTRY_NAMES.match(stem) or APP_FACTORY_NAMES.match(stem))
        framework_hit = any(m in content for m in FRAMEWORK_MARKERS)
        main_hit = bool(MAIN_GUARD.search(content))

        reasons: list[str] = []
        if name_hit:
            reasons.append("文件名规律")
        if framework_hit:
            reasons.append("框架注册")
        if main_hit:
            reasons.append("__main__ 守卫")

        if not reasons:
            continue
        seen.add(rel)

        is_script = meta.is_script
        # 被生产模块导入 → 强入口信号
        imported = in_degree.get(rel, 0) > 0 and rel in production_files

        if name_hit or framework_hit:
            if is_script:
                script_entries.append(EntryPoint(
                    rel, "script", " + ".join(reasons),
                    out_degree.get(rel, 0), in_degree.get(rel, 0)))
            else:
                if imported and "框架注册" not in reasons:
                    reasons.append("被生产模块导入")
                app_entries.append(EntryPoint(
                    rel, "app", " + ".join(reasons),
                    out_degree.get(rel, 0), in_degree.get(rel, 0)))
        elif main_hit:
            script_entries.append(EntryPoint(
                rel, "script", " + ".join(reasons),
                out_degree.get(rel, 0), in_degree.get(rel, 0)))

    # 注意：**不使用「高出度」作为入口信号**。
    # 实测两项目都证明它不可靠：
    #   research_agent: llm_client.py(出度23)、daily_orchestrator.py(29)
    #   Knowledge Loop: deepseek-client.ts(61)、desktop-wiki-service.ts(101)
    # 出度高只说明「它 import 了很多东西」，不说明「它是入口」——
    # 依赖多的服务模块会排在真正的入口前面。
    # 入口的可靠判据是：文件名规律 / 框架注册 / 被生产模块导入。
    return app_entries, script_entries
