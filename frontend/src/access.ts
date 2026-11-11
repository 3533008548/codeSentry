import {
  ApiError,
  type AccessSettings,
  type PolicyIdentity,
  type Workspace,
} from "./api";

export const defaultAccessSettings = (): AccessSettings => ({
  respect_gitignore: true,
  exclude: [],
  local_only: [],
  model_scope: ["**"],
});
export function withModelDefault(settings: AccessSettings, enabled: boolean): AccessSettings {
  const explicit = settings.model_scope.filter(rule => rule !== "**" && rule !== "**/*");
  return { ...settings, model_scope: enabled ? [...explicit, "**"] : explicit };
}
export const accessConfirmed = (workspace?: Workspace): boolean =>
  !!workspace?.access_policy?.confirmed &&
  !workspace.access_policy.cleanup_pending &&
  Number.isSafeInteger(workspace.access_policy.version) &&
  workspace.access_policy.version > 0 &&
  typeof workspace.access_policy.fingerprint === "string" &&
  workspace.access_policy.fingerprint.length > 0;
export const accessKey = (workspace?: Workspace): string =>
  workspace
    ? `${workspace.id}:${workspace.access_policy?.version ?? 0}:${workspace.access_policy?.fingerprint ?? "unconfirmed"}:${workspace.access_policy?.confirmed ? 1 : 0}:${workspace.access_policy?.cleanup_pending ? 1 : 0}`
    : "";
export const matchesAccess = (
  value: PolicyIdentity,
  workspace?: Workspace,
): boolean =>
  accessConfirmed(workspace) &&
  value.policy_version === workspace!.access_policy!.version &&
  value.policy_fingerprint === workspace!.access_policy!.fingerprint;
export function ensureAccess<T extends PolicyIdentity>(
  value: T,
  workspace: Workspace,
): T {
  if (!matchesAccess(value, workspace))
    throw new ApiError("文件访问范围已变化，正在重新核对工作空间。", 403);
  return value;
}
export const ruleLines = (value: string): string[] =>
  value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
