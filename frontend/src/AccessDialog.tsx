import { useEffect, useRef, useState } from "react";
import {
  FolderOpen,
  LoaderCircle,
  ShieldCheck,
  TriangleAlert,
  X,
} from "lucide-react";
import {
  ApiError,
  type AccessConfirmation,
  type AccessPreview,
  type AccessSettings,
  type Api,
  type Workspace,
} from "./api";
import { accessConfirmed, defaultAccessSettings, ruleLines, withModelDefault } from "./access";
import { aborted, errorMessage } from "./format";

function AccessEditor({
  client,
  path,
  settings,
  onChange,
  onProof,
  busy,
  resetKey,
}: {
  client: Api;
  path: string;
  settings: AccessSettings;
  onChange: (value: AccessSettings) => void;
  onProof: (value: AccessConfirmation | null) => void;
  busy: boolean;
  resetKey: number;
}) {
  const [preview, setPreview] = useState<AccessPreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ack, setAck] = useState(false);
  const [excludeText, setExcludeText] = useState(settings.exclude.join("\n"));
  const [localText, setLocalText] = useState(settings.local_only.join("\n"));
  const [modelText, setModelText] = useState(settings.model_scope.join("\n"));
  const signature = JSON.stringify([path.trim(), settings]);
  const current = useRef(signature);
  current.current = signature;
  const request = useRef<AbortController | null>(null);
  useEffect(() => {
    request.current?.abort();
    setPreview(null);
    setAck(false);
    setLoading(false);
    setError(null);
    onProof(null);
    return () => request.current?.abort();
  }, [signature, onProof, resetKey]);
  async function loadPreview() {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    const key = signature;
    setLoading(true);
    setError(null);
    setPreview(null);
    setAck(false);
    onProof(null);
    try {
      const value = await client.previewAccess(
        path.trim(),
        settings,
        controller.signal,
      );
      if (!controller.signal.aborted && current.current === key)
        setPreview(value);
    } catch (error) {
      if (
        !controller.signal.aborted &&
        !aborted(error) &&
        current.current === key
      )
        setError(errorMessage(error));
    } finally {
      if (!controller.signal.aborted && current.current === key)
        setLoading(false);
    }
  }
  function choose(
    path: string,
    isDir: boolean,
    mode: "exclude" | "local_only" | "model_scope",
  ) {
    const pattern = path + (isDir ? "/" : "");
    const rules = [...new Set([...settings[mode], pattern])];
    if (mode === "exclude") setExcludeText(rules.join("\n"));
    else if (mode === "local_only") setLocalText(rules.join("\n"));
    else setModelText(rules.join("\n"));
    onChange({ ...settings, [mode]: rules });
  }
  const modeLabel = {
    exclude: "完全排除",
    local_only: "仅限本地分析",
    model_eligible: "模型候选",
  };
  return (
    <section className="access-editor" aria-label="文件访问范围">
      <div className="access-section-title">
        <ShieldCheck size={16} />
        <h3>文件访问范围</h3>
      </div>
      <label className="access-checkbox">
        <input
          type="checkbox"
          checked={settings.respect_gitignore}
          disabled={busy}
          onChange={(event) =>
            onChange({ ...settings, respect_gitignore: event.target.checked })
          }
        />
        遵守 .gitignore
      </label>
      <p className="access-help">
        默认排除凭据、.env 和私钥。Git
        忽略规则同样约束已跟踪文件，但不能保证允许的源码不含秘密。
      </p>
      <label className="access-checkbox">
        <input type="checkbox" aria-label="普通文件默认允许模型取材"
          checked={settings.model_scope.includes("**") || settings.model_scope.includes("**/*")}
          disabled={busy} onChange={event => {
            const next = withModelDefault(settings, event.target.checked);
            setModelText(next.model_scope.join("\n"));
            onChange(next);
          }} />
        普通文件默认允许模型取材
      </label>
      <p className="access-help">明确设为“仅限本地”或“完全排除”的文件仍按原规则处理；.gitignore和敏感文件排除继续优先。关闭后仅使用下方候选名单。</p>
      <div className="access-rule-columns">
        <div>
          <label htmlFor="access-exclude">额外排除（完全不读取）</label>
          <textarea
            id="access-exclude"
            data-testid="exclude-input"
            value={excludeText}
            disabled={busy}
            placeholder={"private/\n**/secrets.*"}
            onChange={(event) => {
              setExcludeText(event.target.value);
              onChange({ ...settings, exclude: ruleLines(event.target.value) });
            }}
          />
        </div>
        <div>
          <label htmlFor="access-local-only">
            仅限本地分析（不进入任何模型）
          </label>
          <textarea
            id="access-local-only"
            data-testid="local-only-input"
            value={localText}
            disabled={busy}
            placeholder={"internal/\ncustomer-data.py"}
            onChange={(event) => {
              setLocalText(event.target.value);
              onChange({
                ...settings,
                local_only: ruleLines(event.target.value),
              });
            }}
          />
        </div>
        <div>
          <label htmlFor="access-model-scope">模型候选范围（支持通配符）</label>
          <textarea id="access-model-scope" data-testid="model-scope-input" value={modelText} disabled={busy}
            placeholder={"public/\nsrc/example.py"} onChange={(event) => {
              setModelText(event.target.value);
              onChange({ ...settings, model_scope: ruleLines(event.target.value) });
            }} />
        </div>
      </div>
      <p className="access-help">
        每行填写一个工作空间相对路径或匹配模式，可使用
        *、**、?。完全排除优先；仅限本地内容及其衍生结果禁止进入本地或云端模型。
        模型候选不会解除这两类限制，也不自动发送；调整后须重新预览并确认范围。
      </p>
      <div className="access-preview-toolbar">
        <button
          type="button"
          className="button secondary"
          data-testid="access-preview-button"
          disabled={busy || loading || !path.trim()}
          onClick={loadPreview}
        >
          {loading ? (
            <LoaderCircle size={14} className="spin" />
          ) : (
            <FolderOpen size={14} />
          )}
          预览访问范围
        </button>
        <span>仅枚举名称及读取获准的 .gitignore 控制文件，不预读源码。</span>
      </div>
      {error && (
        <div className="form-error" role="alert">
          <TriangleAlert size={15} />
          {error}
        </div>
      )}
      {preview && (
        <div className="access-preview" data-testid="access-preview">
          <div className="access-preview-summary">
            预览 {preview.entries.length} 项
            {preview.truncated ? "（部分条目未列出）" : ""} ·{" "}
            {preview.entries.filter((item) => item.mode === "exclude").length}{" "}
            项完全排除 ·{" "}
            {
              preview.entries.filter((item) => item.mode === "local_only")
                .length
            }{" "}
            项仅限本地
            {" "}· {preview.entries.filter((item) => item.mode === "model_eligible").length} 项模型候选
          </div>
          <ul>
            {preview.entries.map((entry, index) => (
              <li key={`${entry.path}:${index}`}>
                <div className="access-preview-entry">
                  <code title={entry.path}>
                    {entry.path}
                    {entry.is_dir ? "/" : ""}
                  </code>
                  <span className={`access-mode ${entry.mode}`}>
                    {modeLabel[entry.mode]}
                  </span>
                </div>
                <p>{entry.reason}</p>
                <div className="access-path-actions">
                  <button
                    type="button"
                    disabled={busy}
                    aria-label={`完全排除 ${entry.path}`}
                    onClick={() => choose(entry.path, entry.is_dir, "exclude")}
                  >
                    设为完全排除
                  </button>
                  <button type="button" disabled={busy} aria-label={`模型候选 ${entry.path}`}
                    onClick={() => choose(entry.path, entry.is_dir, "model_scope")}>
                    设为模型候选
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    aria-label={`仅限本地 ${entry.path}`}
                    onClick={() =>
                      choose(entry.path, entry.is_dir, "local_only")
                    }
                  >
                    设为仅限本地
                  </button>
                </div>
              </li>
            ))}
          </ul>
          {preview.access_policy.issues.length > 0 && (
            <div className="access-issues" role="status">
              {preview.access_policy.issues.map((issue, index) => (
                <p key={index}>{issue}</p>
              ))}
            </div>
          )}
          <label className="access-checkbox">
            <input
              type="checkbox"
              checked={ack}
              disabled={
                busy ||
                !preview.access_policy.fingerprint ||
                !Number.isSafeInteger(preview.expected_version) ||
                preview.expected_version < 0
              }
              onChange={(event) => {
                setAck(event.target.checked);
                onProof(
                  event.target.checked
                    ? {
                        confirmed: true,
                        settings: preview.access_policy.settings,
                        fingerprint: preview.access_policy.fingerprint,
                        expected_version: preview.expected_version,
                      }
                    : null,
                );
              }}
            />
            我已核对以上文件访问范围
          </label>
        </div>
      )}
      <p className="access-model-note">
        {settings.model_scope.includes("**") || settings.model_scope.includes("**/*")
          ? "普通文件默认可供模型取材，明确限制的文件除外。"
          : "未命中候选名单的文件仅限本地。"}
        候选范围与发送授权分别设置：项目对话确认一次项目授权后自动取材，片段审查仍逐次预览确认。
      </p>
    </section>
  );
}

export function AccessDialog({
  client,
  workspace,
  knownWorkspaces = [],
  settingsMode = false,
  onClose,
  onSaved,
  onPolicySaveStart,
  onPolicySaveFailed,
}: {
  client: Api;
  workspace?: Workspace;
  knownWorkspaces?: Workspace[];
  settingsMode?: boolean;
  onClose: () => void;
  onSaved: (workspace: Workspace) => void;
  onPolicySaveStart: (id: string) => void;
  onPolicySaveFailed: (id: string) => void;
}) {
  const [path, setPath] = useState(workspace?.path || "");
  const [name, setName] = useState(workspace?.name || "");
  const [settings, setSettings] = useState<AccessSettings>(
    () => workspace?.access_policy?.settings || defaultAccessSettings(),
  );
  const [proof, setProof] = useState<AccessConfirmation | null>(null);
  const [previewReset, setPreviewReset] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const changed =
    JSON.stringify(settings) !==
    JSON.stringify(
      workspace?.access_policy?.settings || defaultAccessSettings(),
    );
  const needsConfirmation =
    !workspace || !accessConfirmed(workspace) || changed;
  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) onClose();
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [busy, onClose]);
  function change(value: AccessSettings) {
    if (JSON.stringify(value) !== JSON.stringify(settings)) setProof(null);
    setSettings(value);
  }
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (busy || !path.trim() || (needsConfirmation && !proof)) return;
    setBusy(true);
    setError(null);
    let savingId: string | null = null;
    try {
      let value: Workspace;
      if (workspace) {
        if (needsConfirmation) {
          savingId = workspace.id;
          onPolicySaveStart(savingId);
        }
        value = await client.updateWorkspace(workspace.id, {
          ...(settingsMode ? { name: name.trim() } : {}),
          ...(needsConfirmation ? { access_policy: proof! } : {}),
        });
      } else {
        const normalize = (value: string) => {
          const clean = value.replaceAll("\\", "/").replace(/\/+$/, "");
          return /^[a-z]:/i.test(clean) ? clean.toLowerCase() : clean;
        };
        const known = knownWorkspaces.find(
          (item) => normalize(item.path) === normalize(path.trim()),
        );
        if (
          known &&
          (!accessConfirmed(known) ||
            JSON.stringify(known.access_policy?.settings) !==
              JSON.stringify(proof?.settings) ||
            known.access_policy?.fingerprint !== proof?.fingerprint)
        ) {
          savingId = known.id;
          onPolicySaveStart(savingId);
        }
        value = await client.createWorkspace(
          path.trim(),
          name.trim() || undefined,
          proof!,
        );
        if (
          !accessConfirmed(value) ||
          JSON.stringify(value.access_policy?.settings) !==
            JSON.stringify(proof?.settings) ||
          value.access_policy?.fingerprint !== proof?.fingerprint
        ) {
          savingId = value.id;
          onPolicySaveStart(savingId);
          value = await client.updateWorkspace(value.id, {
            access_policy: proof!,
          });
        }
      }
      if (!accessConfirmed(value))
        throw new Error(
          value.access_policy?.cleanup_pending
            ? "旧数据仍待清理，暂不开放文件读取。请重试或查看范围问题。"
            : "文件访问范围尚未确认，请重新预览并保存。",
        );
      onSaved(value);
    } catch (error) {
      if (savingId) onPolicySaveFailed(savingId);
      if (error instanceof ApiError && error.status === 409) {
        setProof(null);
        setPreviewReset((value) => value + 1);
        setError(
          "文件访问范围已变化，请重新预览并确认。 " + errorMessage(error),
        );
      } else setError(errorMessage(error));
      setBusy(false);
    }
  }
  const title = !workspace
    ? "打开项目，建立工作空间"
    : settingsMode
      ? "工作空间设置"
      : "确认文件访问范围";
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onClose();
      }}
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="access-dialog-title"
        className="workspace-dialog access-dialog"
      >
        <div className="dialog-heading">
          <span className="dialog-icon">
            <ShieldCheck size={22} />
          </span>
          <button
            className="icon-button"
            aria-label="关闭文件访问范围"
            disabled={busy}
            onClick={onClose}
          >
            <X size={17} />
          </button>
        </div>
        <h2 id="access-dialog-title">{title}</h2>
        <p>
          {workspace
            ? workspace.path
            : "关联本地代码目录；访问范围保存成功后才开放源码和分析。"}
        </p>
        {workspace && !accessConfirmed(workspace) && (
          <p className="access-migration-note">
            此工作空间需要确认访问范围。确认前不会恢复源码标签、读取内容或启动分析。
          </p>
        )}
        <form onSubmit={submit}>
          {!workspace && (
            <>
              <label htmlFor="workspace-path">
                项目目录
                <input
                  id="workspace-path"
                  data-testid="workspace-path-input"
                  name="path"
                  autoFocus
                  autoComplete="off"
                  required
                  placeholder="D:\projects\my-app 或 /home/me/projects/my-app"
                  disabled={busy}
                  value={path}
                  onChange={(event) => {
                    if (event.target.value.trim() !== path.trim())
                      setProof(null);
                    setPath(event.target.value);
                  }}
                />
              </label>
              <label htmlFor="workspace-name">
                工作空间名称 <span>可选</span>
                <input
                  id="workspace-name"
                  name="name"
                  autoComplete="off"
                  placeholder="默认使用目录名称"
                  value={name}
                  disabled={busy}
                  onChange={(event) => setName(event.target.value)}
                />
              </label>
            </>
          )}
          {settingsMode && (
            <>
              <label htmlFor="settings-name">
                名称
                <input
                  id="settings-name"
                  required
                  value={name}
                  disabled={busy}
                  onChange={(event) => setName(event.target.value)}
                />
              </label>
            </>
          )}
          <AccessEditor
            client={client}
            path={path}
            settings={settings}
            onChange={change}
            onProof={setProof}
            busy={busy}
            resetKey={previewReset}
          />
          {error && (
            <div className="form-error" role="alert">
              <TriangleAlert size={15} />
              {error}
            </div>
          )}
          {workspace && needsConfirmation && (
            <div className="dialog-note">
              <ShieldCheck size={14} />
              保存新范围会清理应用管理的旧对话和报告，源文件仍在原目录。
            </div>
          )}
          <div className="dialog-actions">
            <button
              type="button"
              className="button ghost"
              disabled={busy}
              onClick={onClose}
            >
              取消
            </button>
            <button
              type="submit"
              data-testid="access-confirm-button"
              className="button primary"
              disabled={
                busy ||
                !path.trim() ||
                (settingsMode && !name.trim()) ||
                (needsConfirmation && !proof)
              }
            >
              {busy ? (
                <LoaderCircle size={15} className="spin" />
              ) : (
                <ShieldCheck size={15} />
              )}
              {busy
                ? "正在保存…"
                : !workspace
                  ? "打开工作空间"
                  : settingsMode
                    ? "保存设置"
                    : "确认并保存范围"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
