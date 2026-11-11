import { useEffect, useRef, useState } from "react";
import { LoaderCircle, X } from "lucide-react";
import { ApiError, type Api, type DeepSeekModel, type SemanticProfile, type Workspace } from "./api";
import { ensureAccess } from "./access";
import { errorMessage } from "./format";

export function ModelSettingsDialog({ client, workspace, onClose, onSaved, onPermissionLost }: {
  client: Api; workspace: Workspace;
  onClose: () => void; onSaved: () => void; onPermissionLost: () => void;
}) {
  const [profile, setProfile] = useState<SemanticProfile | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [model, setModel] = useState<DeepSeekModel>("deepseek-flash");
  const [key, setKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  const mounted = useRef(false);
  const writing = useRef(false);

  function apply(value: SemanticProfile) {
    ensureAccess(value, workspace);
    if (value.workspace_id !== workspace.id) throw new ApiError("模型设置不属于当前工作空间", 403);
    setProfile(value); setEnabled(value.enabled); setModel(value.model); setKey("");
  }
  function failed(cause: unknown) {
    if (cause instanceof ApiError && cause.status === 403) onPermissionLost();
    else if (cause instanceof ApiError && cause.status === 409) {
      setProfile(null);
      setError("模型设置已在另一个窗口修改，请重新读取。");
    } else setError(errorMessage(cause));
  }

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    setProfile(null); setError(null); setSaved(false);
    if (!client.semanticProfile) setError("当前服务无法提供模型设置。");
    else {
      setLoading(true);
      client.semanticProfile(workspace.id, controller.signal).then(value => {
        if (!controller.signal.aborted) apply(value);
      }).catch(cause => {
        if (!controller.signal.aborted) failed(cause);
      }).finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    }
    return () => { mounted.current = false; controller.abort(); };
  }, [client, workspace.id, reload]);

  async function save(action: "save" | "clear" | "configured") {
    if (!profile || !client.updateSemanticProfile || writing.current) return;
    writing.current = true; setBusy(true); setSaved(false); setError(null);
    try {
      const value = await client.updateSemanticProfile(workspace.id, {
        expected_revision: profile.revision,
        settings: action === "save" ? { enabled, model } : { enabled: profile.enabled, model: profile.model },
        ...(action === "clear" ? { clear_key: true } : action === "configured" ? { use_configured_key: true } : key ? { api_key: key } : {}),
      });
      if (mounted.current) { apply(value); setSaved(true); onSaved(); }
    } catch (cause) {
      if (mounted.current) failed(cause);
    } finally {
      writing.current = false;
      if (mounted.current) { setKey(""); setBusy(false); }
    }
  }

  const disabled = busy || !profile || !client.updateSemanticProfile;
  const configured = profile?.key_source === "env_file" || profile?.key_source === "environment";
  const keyStatus = !profile?.key_configured ? "尚未配置密钥"
    : profile.key_source === "env_file" ? "已使用 CodeSentry .env 密钥"
    : profile.key_source === "environment" ? "已使用启动环境变量密钥" : "已使用本项目的临时密钥";
  return <div className="dialog-backdrop"><section className="dialog model-settings-dialog" role="dialog" aria-modal="true" aria-label="模型设置">
    <div className="dialog-header"><h2>模型设置</h2><button className="icon-button" aria-label="关闭模型设置" disabled={busy} onClick={onClose}><X size={18} /></button></div>
    {loading ? <p role="status"><LoaderCircle size={14} className="spin" />正在读取设置…</p> : <form onSubmit={event => { event.preventDefault(); void save("save"); }}>
      <label className="access-checkbox"><input type="checkbox" checked={enabled} disabled={disabled} onChange={event => { setEnabled(event.target.checked); setSaved(false); }} />启用 DeepSeek 对话</label>
      <label>DeepSeek 模型<select value={model} disabled={disabled} onChange={event => { setModel(event.target.value as DeepSeekModel); setSaved(false); }}>
        <option value="deepseek-flash">deepseek-flash</option><option value="deepseek-v4-pro">deepseek-v4-pro</option></select></label>
      <label>DeepSeek API key<input type="password" value={key} disabled={disabled} autoComplete="new-password" spellCheck={false}
        onChange={event => { setKey(event.target.value); setSaved(false); }} placeholder="留空使用当前密钥" /></label>
      {profile && <p className="subtle">{keyStatus}。此处填写的密钥仅在本项目当前服务会话中使用。</p>}
      {saved && <p className="saved-hint" role="status">模型设置已保存</p>}
      {error && <p className="chat-failure" role="alert">{error}</p>}
      <div className="dialog-actions">
        {profile?.key_configured && <button type="button" className="text-button danger" disabled={disabled} onClick={() => void save("clear")}>清除此工作空间密钥</button>}
        {profile?.configured_key_available && !configured && <button type="button" className="text-button" disabled={disabled} onClick={() => void save("configured")}>使用启动配置密钥</button>}
        {!profile && error && client.semanticProfile && <button type="button" className="text-button" onClick={() => setReload(value => value + 1)}>重新读取</button>}
        <button className="button primary" type="submit" disabled={disabled}>保存模型设置</button>
      </div>
    </form>}
  </section></div>;
}
