export type JobStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "incomplete"
  | "failed"
  | "cancelled"
  | "interrupted"
  | "invalidated";
export type AnalysisKind = "navigation" | "review_preview" | "change_scope" | "gate_check" | "defect_preview" | "semantic_review";
export type StaticAnalysisKind = Exclude<AnalysisKind, "semantic_review">;
export interface ChangeScopeOptions {
  base_ref: string;
  comparison: "working_tree" | "staged" | "commit";
  target_ref?: string;
}
export interface AnalysisConfig {
  max_depth?: number;
  max_items?: number;
  kind?: AnalysisKind;
  max_function_lines?: number;
  base_ref?: string;
  comparison?: ChangeScopeOptions["comparison"];
  target_ref?: string;
  gate_policy_sha256?: string;
}
export interface Workspace {
  id: string;
  name: string;
  path: string;
  created_at: string;
  updated_at: string;
  config: { max_depth: number; max_items: number };
  last_analysis?: AnalysisJob | null;
  access_policy?: AccessPolicy;
}
export interface AccessSettings {
  respect_gitignore: boolean;
  exclude: string[];
  local_only: string[];
  model_scope: string[];
}
export interface AccessPolicy {
  confirmed: boolean;
  version: number;
  settings: AccessSettings;
  fingerprint: string | null;
  cleanup_pending: boolean;
  issues: string[];
  restricted: boolean;
}
export interface AccessConfirmation {
  confirmed: true;
  settings: AccessSettings;
  fingerprint?: string | null;
  expected_version?: number;
}
export interface PolicyIdentity {
  policy_version?: number;
  policy_fingerprint?: string | null;
}
export interface AccessPreview {
  expected_version: number;
  path: string;
  access_policy: AccessPolicy;
  entries: {
    path: string;
    is_dir: boolean;
    mode: "exclude" | "local_only" | "model_eligible";
    reason: string;
  }[];
  truncated: boolean;
}
export type WorkspacePatch = {
  name?: string;
  config?: Partial<Workspace["config"]>;
  access_policy?: AccessConfirmation;
};
export interface SourceFile {
  path: string;
  language: string;
  size: number;
  access_mode?: "local_only" | "model_eligible";
}
export interface FileContent extends PolicyIdentity {
  workspace_id: string;
  path: string;
  content: string;
  language: string;
  sha256: string;
  lines: number;
  access_mode?: "local_only" | "model_eligible";
  content_hash?: string;
  content_hash_algorithm?: string;
  snapshot_content_hash?: string | null;
  snapshot_content_hash_algorithm?: string | null;
  is_stale?: boolean | null;
}
export interface SymbolDetail {
  qname: string;
  name: string;
  kind: string;
  file: string;
  line: number;
  end_line?: number | null;
  signature?: string;
  parent?: string | null;
}
export interface FileDetail {
  path: string;
  content_hash: string;
  lines: number;
  language: string;
  is_parsed?: boolean;
  parse_error?: string | null;
}
export interface ReadingItem {
  file: string;
  label: string;
  depth: number;
}
export type EntryKind =
  "process" | "mount" | "bridge" | "assembly" | "candidate";
export type EntryConfidence = "declared" | "static" | "heuristic";
export interface EntryEvidence {
  file: string;
  line: number | null;
  type: string;
  kind?: string;
}
export interface EntryPoint {
  file: string;
  line?: number | null;
  reason: string;
  kind?: EntryKind;
  confidence?: EntryConfidence;
  evidence?: EntryEvidence[];
  out_degree?: number;
  in_degree?: number;
}
export interface EntryEvidenceIssue {
  file: string;
  line?: number | null;
  status: string;
  message: string;
}
export interface NavigationResult extends PolicyIdentity {
  kind?: "navigation";
  access_scope_limited?: boolean;
  source_permissions?: Record<string, string>;
  root: string;
  analysis_mode: string;
  dynamic_verification: string;
  is_complete: boolean;
  parse_failures: number;
  files: number;
  symbols: number;
  edges: number;
  parse_issues?: { file: string; status: string; message: string }[];
  reading_order?: ReadingItem[];
  file_details?: FileDetail[];
  symbol_details?: SymbolDetail[];
  environment?: Record<string, unknown>;
  environment_fingerprint?: string;
  input_fingerprint?: string;
  timings?: Record<string, number>;
  call_stats?: Record<string, number>;
  entrypoints?: EntryPoint[];
  startup_inputs?: Record<string, string>;
  entry_evidence_complete?: boolean;
  entry_evidence_issues?: EntryEvidenceIssue[];
  top_files?: { file: string; role: string; score: number; lines: number }[];
  config?: AnalysisConfig;
}
export interface ReviewFinding {
  file: string;
  classification: string;
  mode: string;
  can_block: boolean;
  baseline?: BaselineAnnotation;
  finding: {
    file: string;
    line: number;
    end_line?: number | null;
    symbol?: string | null;
    rule_id: string;
    rule_version?: string;
    severity?: string;
    source?: string;
    confidence?: number;
    verified?: boolean;
    reason: string;
    evidence?: string;
    facts?: Record<string, unknown>;
    identity_digest?: string;
    evidence_digest?: string;
    combined_digest?: string;
  };
}
export interface BaselineAnnotation {
  status: "approved" | "new" | "evidence_changed" | "ambiguous" | "revoked" | "context_changed" | "unsupported_fingerprint";
  record_id?: string;
  exemption_applied: false;
}
export interface BaselineIssue {
  id: string; file: string; line: number; end_line?: number | null;
  symbol?: string | null; reason: string; rule_id: string; rule_version?: string;
  status: "pending" | "approved" | "revoked";
  fingerprint?: { version: number; identity_digest: string; evidence_digest: string; combined_digest: string };
}
export interface BaselineProposal extends PolicyIdentity {
  workspace_id: string; id: string; revision: number; status: string; created_at: string;
  source_analysis_id?: string; issues: BaselineIssue[];
}
export interface BaselineRecord extends BaselineIssue {
  status: "approved" | "revoked";
  approved_at?: string; approval_reason?: string; actor?: string;
  revoked_at?: string; revocation_reason?: string;
}
export interface BaselineState extends PolicyIdentity {
  workspace_id: string; revision: number; proposals: BaselineProposal[];
  records: BaselineRecord[]; context?: Record<string, unknown>; audit?: unknown[];
  gate_status: "not_evaluated";
}
export interface ReviewPreviewResult extends PolicyIdentity {
  kind: "review_preview";
  review_status: "report_only" | "incomplete" | "not_applicable";
  gate_status: "not_evaluated";
  mode: "preview";
  policy?: { max_function_lines?: number; [key: string]: unknown };
  policy_sha256?: string;
  coverage: {
    discovered_python: number;
    analyzed_python: number;
    attempted_python: number;
    excluded_python: number;
    other_language_files_not_evaluated: number;
    permissions_limited: boolean;
    within_scope_complete: boolean;
    whole_repository_evaluated: false;
  };
  source_sha256: Record<string, string>;
  findings: ReviewFinding[];
  issues: { file: string; status: string; line?: number | null }[];
  summary: { policy_debt_findings: number; behavior_bug_findings: number; blocking_findings: number };
  config?: AnalysisConfig;
}
export interface ChangeScopeResult extends PolicyIdentity {
  kind: "change_scope";
  mode: "change_scope";
  gate_status: "not_evaluated";
  change_status: "report_only" | "incomplete" | "unavailable";
  comparison: ChangeScopeOptions["comparison"];
  base_sha: string | null;
  target_sha: string | null;
  changes: {
    old_path: string | null; new_path: string | null;
    status: "added" | "deleted" | "modified" | "type_changed";
    layer: "combined" | "staged" | "unstaged" | "commit";
    language: "python" | "configuration" | "unsupported";
    old_sha256?: string | null; new_sha256?: string | null;
  }[];
  impact: {
    before: { direct: string[]; dependents: string[]; edges: number };
    after: { direct: string[]; dependents: string[]; edges: number };
    direct: string[]; dependents: string[];
    configuration_changed: boolean;
    whole_repository_evaluated: false;
    call_analysis: "not_evaluated";
  };
  coverage: {
    allowed_paths: number; before_python: number; after_python: number;
    excluded_paths: number; unsupported_paths: number;
    permissions_limited: boolean; within_scope_complete: boolean;
    whole_repository_evaluated: false;
  };
  source_sha256: Record<string, string>;
  issues: { file: string; status: string; message?: string }[];
  summary: { changed_files: number; staged: number; unstaged: number; untracked: number; affected_files: number };
  config?: AnalysisConfig;
}
export interface GateResult extends PolicyIdentity {
  kind: "gate_check";
  mode: "gate";
  gate_status: "pass" | "block" | "incomplete" | "error";
  exit_code: number;
  language_scope: "permitted_python_files_only";
  policy_sha256: string;
  policy: GatePolicy;
  required_rules: GateRule[];
  coverage: {
    discovered_python: number; attempted_python: number; analyzed_python: number;
    excluded_python: number; other_language_files_not_evaluated: number;
    permissions_limited: boolean; within_scope_complete: boolean;
    whole_repository_evaluated: false; bytes_accounted_for_budget: number;
  };
  findings: (ReviewFinding & { blocking: boolean })[];
  issues: { file?: string; status?: string; code?: string; message?: string; rule_id?: string }[];
  summary: {
    total_findings: number; report_only_findings: number; blocking_findings: number;
    required_rules: number; completed_required_rules: number; admitted_required_rules: number;
  };
  baseline_summary: { mode: "annotation_only"; gate_exemptions_applied: number };
  source_sha256: Record<string, string>;
  config?: AnalysisConfig;
}
export interface GateRule {
  rule_id: string; rule_version: string; implementation_hash: string;
  classification: string; required: true; admission: "report_only" | "admitted";
  approved_for_blocking: boolean;
  admission_evidence: { status: "absent" | "present"; missing: string[] };
  config: Record<string, unknown>;
  checks_attempted?: number; checks_completed?: number; completed?: boolean;
  completion?: "complete" | "incomplete" | "not_applicable";
}
export interface GatePolicy {
  policy_id: string; policy_version: string; policy_sha256: string;
  required_rules: GateRule[]; admission_ready: boolean;
  limits: Record<string, unknown>; scope: "permitted_python_files_only"; exit_codes: Record<string, number>;
  blocking_policy?: { block_severities: string[]; max_new_findings: number; count_unit: "unique_issue_occurrences" };
}
export interface DefectPreviewResult extends PolicyIdentity {
  kind: "defect_preview";
  mode: "defect_preview";
  review_status: "report_only" | "incomplete" | "not_applicable";
  gate_status: "not_evaluated";
  language_scope: "permitted_python_files_only";
  policy: { rule_id: string; rule_version: string; classification: "behavior_bug_candidate"; mode: "report_only"; [key: string]: unknown };
  policy_sha256: string;
  rules: { rule_id: string; rule_version: string; classification: "behavior_bug_candidate"; approved_for_blocking: false }[];
  coverage: ReviewPreviewResult["coverage"];
  findings: (ReviewFinding & { classification: "behavior_bug_candidate"; confirmed_behavior_bug: false })[];
  summary: { candidate_findings: number; confirmed_behavior_bug_findings: number; blocking_findings: number };
  issues: ReviewPreviewResult["issues"];
  limitations: string[];
  source_sha256: Record<string, string>;
  config?: AnalysisConfig;
}
export type DeepSeekModel = "deepseek-flash" | "deepseek-v4-pro";
export interface SemanticLimits {
  max_requests: number; max_input_bytes: number; max_excerpt_lines: number;
  max_output_tokens: number; total_token_budget: number; timeout_seconds: number; preview_ttl_seconds: number;
}
export interface SemanticProfile extends PolicyIdentity {
  workspace_id: string; schema_version: number; revision: number; enabled: boolean;
  provider: "deepseek"; endpoint: string; model: DeepSeekModel; purpose: "selected_excerpt_review";
  key_configured: boolean; limits: SemanticLimits;
  key_source?: "workspace_session" | "environment" | "env_file" | "none";
  configured_key_available?: boolean;
  configured_key_source?: "environment" | "env_file" | "none";
  configured_key_enabled?: boolean;
  session_budget: { requests_reserved: number; tokens_reserved: number; tokens_reported: number; remaining_requests: number; remaining_tokens: number };
  cost_estimate_is_guarantee: false;
}
export interface SemanticProfileUpdate {
  expected_revision: number; settings: { enabled: boolean; model: DeepSeekModel };
  api_key?: string; clear_key?: true; use_configured_key?: true;
}
export interface SemanticPreview extends PolicyIdentity {
  preview_id: string; workspace_id: string; profile_revision: number;
  provider: "deepseek"; model: DeepSeekModel; purpose: "selected_excerpt_review";
  path: string; start_line: number; end_line: number; source_sha256: string;
  excerpt_sha256: string; excerpt_bytes: number;
  request: { messages: { role: string; content: string }[]; [key: string]: unknown };
  request_json: string; expected_request_sha256: string; expires_in_seconds: number;
  single_use: true; estimated_reserved_tokens: number; limits: SemanticLimits;
}
export interface SemanticReviewResult extends PolicyIdentity {
  kind: "semantic_review"; mode: "semantic_review";
  review_status: "warnings" | "incomplete" | "error" | "cancelled"; gate_status: "not_evaluated";
  provider: "deepseek"; model: DeepSeekModel; purpose: "selected_excerpt_review";
  profile_revision: number; path: string; start_line: number; end_line: number;
  source_sha256: Record<string, string>; request_sha256: string;
  warnings: { line: number; end_line: number; reason: string; evidence_quote: string; suggestion: string;
    source: "llm"; verified: false; can_block: false; evidence_checked: boolean; confirmed_behavior_bug: false }[];
  issues: { status: string }[];
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number } | null;
  summary: { warnings: number; confirmed_behavior_bug_findings: number; blocking_findings: number };
  config?: AnalysisConfig;
}
export type AnalysisResult = NavigationResult | ReviewPreviewResult | ChangeScopeResult | GateResult | DefectPreviewResult | SemanticReviewResult;
export interface AnalysisJob extends PolicyIdentity {
  kind?: AnalysisKind;
  id: string;
  workspace_id: string;
  status: JobStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  elapsed_seconds?: number | null;
  logs: string[];
  error: string | null;
  result?: AnalysisResult | null;
  config?: AnalysisConfig;
  result_state?: "not_ready" | "available" | "unavailable";
}
export interface Session {
  token: string;
  api_version?: string;
  capabilities?: { analysis: boolean; review: boolean; chat: boolean };
}
export interface ChatSettings extends PolicyIdentity {
  workspace_id: string; consent: boolean; revision: number; context: string;
  profile_revision: number; model: DeepSeekModel; key_configured: boolean; profile_enabled: boolean;
  budget: { remaining_requests: number; remaining_tokens: number; max_requests: number; total_token_budget: number };
}
export interface ConversationSummary extends PolicyIdentity {
  workspace_id: string; id: string; title: string; created_at: string;
}
export interface ChatSourceLocation { path: string; line: number; end_line: number; sha256: string }
export interface ChatCitation extends ChatSourceLocation { quote: string; quote_checked: true }
export interface InsightDraft {
  statement: string; kind: "observation" | "hypothesis"; scope: "project" | "topic"; track_environment: boolean;
}
export interface ProjectInsight {
  id: string; statement: string; kind: InsightDraft["kind"]; scope: InsightDraft["scope"];
  tracks_environment: boolean; status: "active" | "stale" | "retired";
  drift_reason: "source" | "environment" | "history" | null; created_at: string; last_checked_at: string;
  origin_conversation_id: string; origin_turn_id: string; citations: ChatSourceLocation[];
}
interface InsightResponse extends PolicyIdentity { workspace_id: string }
export interface CrapCoverage { covered: number; total: number; ratio: number }
export interface CrapToolOptions { coverage_path: string | null; reference: number }
export interface CrapDiscussionTarget { turn_id: string; file: string; line: number }
export interface CrapFunction {
  file: string; function: string; line: number; end_line: number; complexity: number;
  crap: number | null; at_or_above_reference: boolean | null; coverage_status: string;
  branch_coverage: CrapCoverage | null; statement_coverage: CrapCoverage | null;
  missing_branches: [number, number][]; missing_lines: number[]; suggestion: string;
}
export interface CrapReport {
  scan_status: "complete" | "incomplete";
  coverage_origin: "imported_unverified" | "not_provided";
  coverage_report_sha256: string | null;
  summary: { python_files: number; functions: number; scored: number; unscored: number; at_or_above_reference: number };
  branch_totals: { covered: number; total: number; functions: number };
  functions: CrapFunction[]; source_sha256: Record<string, string>;
  issues: { file: string; status: string }[]; issue_count: number;
}
export interface CrapToolTurn extends CrapToolOptions { name: "crap"; report?: CrapReport }
export interface ConversationTurn {
  id: string; question: string; status: "running" | "completed" | "failed" | "cancelled" | "interrupted";
  answer: string; error: string | null; created_at: string; feedback: string;
  citations: ChatCitation[]; followups: string[];
  sources: { path: string; start_line: number; end_line: number; sha256: string }[];
  coverage?: { eligible_files: number; selected_files: number; source_bytes: number; partial: boolean };
  tool?: CrapToolTurn;
  crap_target?: CrapDiscussionTarget;
}
export interface Conversation extends ConversationSummary { turns: ConversationTurn[] }
export interface Api {
  workspaces(signal?: AbortSignal): Promise<Workspace[]>;
  createWorkspace(
    path: string,
    name?: string,
    accessPolicy?: AccessConfirmation,
  ): Promise<Workspace>;
  previewAccess(
    path: string,
    settings: AccessSettings,
    signal?: AbortSignal,
  ): Promise<AccessPreview>;
  workspace(id: string, signal?: AbortSignal): Promise<Workspace>;
  updateWorkspace(id: string, patch: WorkspacePatch): Promise<Workspace>;
  files(
    id: string,
    signal?: AbortSignal,
  ): Promise<
    {
      workspace_id: string;
      files: SourceFile[];
      truncated: boolean;
    } & PolicyIdentity
  >;
  file(
    id: string,
    path: string,
    analysisId?: string,
    signal?: AbortSignal,
  ): Promise<FileContent>;
  jobs(id: string, signal?: AbortSignal): Promise<AnalysisJob[]>;
  job(id: string, job: string, signal?: AbortSignal): Promise<AnalysisJob>;
  analyze(id: string, kind?: StaticAnalysisKind, options?: ChangeScopeOptions): Promise<AnalysisJob>;
  cancel(id: string, job: string): Promise<AnalysisJob>;
  baseline?(id: string, analysisId?: string, signal?: AbortSignal): Promise<BaselineState>;
  createBaselineProposal?(id: string, analysisId: string): Promise<BaselineProposal>;
  approveBaseline?(id: string, proposalId: string, selectedIds: string[], reason: string, expectedRevision: number): Promise<BaselineState>;
  revokeBaseline?(id: string, recordId: string, reason: string, expectedRevision: number): Promise<BaselineState>;
  gatePolicy?(signal?: AbortSignal): Promise<GatePolicy>;
  semanticProfile?(id: string, signal?: AbortSignal): Promise<SemanticProfile>;
  updateSemanticProfile?(id: string, body: SemanticProfileUpdate): Promise<SemanticProfile>;
  previewSemantic?(id: string, path: string, startLine: number, endLine: number, expectedProfileRevision: number): Promise<SemanticPreview>;
  sendSemantic?(id: string, previewId: string, expectedRequestSha256: string, expectedProfileRevision: number): Promise<AnalysisJob>;
  chatSettings?(id: string, signal?: AbortSignal): Promise<ChatSettings>;
  saveChatSettings?(id: string, settings: { consent: boolean; context: string; expected_revision: number; expected_policy_version: number; expected_profile_revision: number }): Promise<ChatSettings>;
  conversations?(id: string, signal?: AbortSignal): Promise<ConversationSummary[]>;
  createConversation?(id: string): Promise<ConversationSummary>;
  conversation?(id: string, conversationId: string, signal?: AbortSignal): Promise<Conversation>;
  sendQuestion?(id: string, conversationId: string, question: string, settingsRevision: number, selectedPath?: string, crapTarget?: CrapDiscussionTarget): Promise<Conversation>;
  runCrapTool?(id: string, conversationId: string, options: CrapToolOptions, policyVersion: number): Promise<Conversation>;
  cancelConversation?(id: string, conversationId: string): Promise<Conversation>;
  deleteConversation?(id: string, conversationId: string): Promise<void>;
  conversationFeedback?(id: string, conversationId: string, turnId: string, text: string): Promise<Conversation>;
  insights?(id: string, conversationId?: string, signal?: AbortSignal): Promise<InsightResponse & { insights: ProjectInsight[] }>;
  saveInsight?(id: string, cid: string, tid: string, draft: InsightDraft, version: number): Promise<InsightResponse & { insight: ProjectInsight }>;
  changeInsight?(id: string, noteId: string, action: "retire" | "delete", version: number, cid?: string): Promise<InsightResponse>;
}
export class ApiError extends Error {
  constructor(
    message: string,
    public status = 0,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
export function ensureWorkspace<T extends { workspace_id: string }>(
  value: T,
  id: string,
): T {
  if (value.workspace_id !== id)
    throw new ApiError("工作空间数据不匹配，已忽略这次响应。");
  return value;
}
export function isConfigStale(
  workspace?: Workspace,
  job?: AnalysisJob | null,
): boolean {
  if (!workspace || !job || job.workspace_id !== workspace.id || analysisKind(job) !== "navigation") return false;
  const snapshot = job.config || job.result?.config;
  if (
    !snapshot ||
    !Number.isFinite(snapshot.max_depth) ||
    !Number.isFinite(snapshot.max_items)
  )
    return false;
  return (
    snapshot.max_depth !== workspace.config.max_depth ||
    snapshot.max_items !== workspace.config.max_items
  );
}
export function isStartupInputStale(
  file: FileContent,
  result?: AnalysisResult | null,
): boolean {
  const snapshot = isNavigationResult(result) ? result.startup_inputs?.[file.path] : undefined;
  return (
    typeof snapshot === "string" &&
    /^[a-f0-9]{64}$/i.test(snapshot) &&
    /^[a-f0-9]{64}$/i.test(file.sha256) &&
    snapshot.toLowerCase() !== file.sha256.toLowerCase()
  );
}
export function isFileStale(
  file: FileContent,
  result?: AnalysisResult | null,
): boolean {
  if (file.is_stale === true) return true;
  if (isReviewResult(result) || isChangeScopeResult(result) || isGateResult(result) || isDefectPreviewResult(result) || isSemanticReviewResult(result)) {
    const snapshot = result.source_sha256?.[file.path];
    return typeof snapshot === "string" && /^[a-f0-9]{64}$/i.test(snapshot)
      && /^[a-f0-9]{64}$/i.test(file.sha256) && snapshot.toLowerCase() !== file.sha256.toLowerCase();
  }
  if (isStartupInputStale(file, result)) return true;
  if (!file.content_hash || file.content_hash_algorithm !== "sha1-decoded-text")
    return false;
  const snapshot = (isNavigationResult(result) ? result.file_details : undefined)?.find(
    (item) => item.path === file.path,
  )?.content_hash;
  return !!snapshot && snapshot !== file.content_hash;
}
export const analysisKind = (job?: Pick<AnalysisJob, "kind"> | null): AnalysisKind =>
  job?.kind === "review_preview" || job?.kind === "change_scope" || job?.kind === "gate_check" || job?.kind === "defect_preview" || job?.kind === "semantic_review" ? job.kind : "navigation";
export const isReviewResult = (result?: AnalysisResult | null): result is ReviewPreviewResult =>
  !!result && result.kind === "review_preview";
export const isChangeScopeResult = (result?: AnalysisResult | null): result is ChangeScopeResult =>
  !!result && result.kind === "change_scope";
export const isGateResult = (result?: AnalysisResult | null): result is GateResult =>
  !!result && result.kind === "gate_check";
export const isDefectPreviewResult = (result?: AnalysisResult | null): result is DefectPreviewResult =>
  !!result && result.kind === "defect_preview";
export const isSemanticReviewResult = (result?: AnalysisResult | null): result is SemanticReviewResult =>
  !!result && result.kind === "semantic_review";
export const isNavigationResult = (result?: AnalysisResult | null): result is NavigationResult =>
  !!result && (result.kind === "navigation" || (result.kind === undefined
    && ("files" in result || "file_details" in result || "reading_order" in result)));
const segment = encodeURIComponent;
export class LocalApi implements Api {
  private token: string | null = null;
  private connecting: Promise<void> | null = null;
  constructor(private transport: typeof fetch = (...args) => fetch(...args)) {}
  private async session() {
    if (this.token) return;
    if (!this.connecting)
      this.connecting = this.transport("/api/session", {
        credentials: "same-origin",
        cache: "no-store",
      })
        .then(async (response) => {
          if (!response.ok)
            throw new ApiError(
              "无法连接本地服务，请确认 CodeSentry 已启动。",
              response.status,
            );
          const session: Session = await response.json();
          if (typeof session.token !== "string" || !session.token)
            throw new ApiError("本地会话无效，请刷新后重试。");
          this.token = session.token;
        })
        .finally(() => {
          this.connecting = null;
        });
    await this.connecting;
  }
  private async request<T>(
    path: string,
    options: RequestInit = {},
    retry = true,
  ): Promise<T> {
    await this.session();
    const headers = new Headers(options.headers);
    headers.set("X-CodeSentry-Token", this.token!);
    if (options.body) headers.set("Content-Type", "application/json");
    const response = await this.transport(path, {
      ...options,
      headers,
      credentials: "same-origin",
      cache: "no-store",
    });
    if (response.status === 401 && retry) {
      this.token = null;
      return this.request<T>(path, options, false);
    }
    if (!response.ok) {
      let message = `请求未完成（${response.status}），请重试。`;
      try {
        const body = await response.json();
        if (typeof body.detail === "string") message = body.detail;
      } catch {
        /* response might be plain text */
      }
      throw new ApiError(message, response.status);
    }
    return response.json() as Promise<T>;
  }
  async workspaces(signal?: AbortSignal) {
    return (
      await this.request<{ workspaces: Workspace[] }>("/api/workspaces", {
        signal,
      })
    ).workspaces;
  }
  createWorkspace(
    path: string,
    name?: string,
    accessPolicy?: AccessConfirmation,
  ) {
    return this.request<Workspace>("/api/workspaces", {
      method: "POST",
      body: JSON.stringify({
        path,
        ...(name ? { name } : {}),
        ...(accessPolicy ? { access_policy: accessPolicy } : {}),
      }),
    });
  }
  previewAccess(path: string, settings: AccessSettings, signal?: AbortSignal) {
    return this.request<AccessPreview>("/api/access/preview", {
      method: "POST",
      body: JSON.stringify({ path, settings }),
      signal,
    });
  }
  async workspace(id: string, signal?: AbortSignal) {
    const value = await this.request<Workspace>(
      `/api/workspaces/${segment(id)}`,
      { signal },
    );
    if (value.id !== id) throw new ApiError("工作空间数据不匹配。");
    return value;
  }
  async updateWorkspace(id: string, patch: WorkspacePatch) {
    const value = await this.request<Workspace>(
      `/api/workspaces/${segment(id)}`,
      { method: "PATCH", body: JSON.stringify(patch) },
    );
    if (value.id !== id) throw new ApiError("工作空间数据不匹配。");
    return value;
  }
  async files(id: string, signal?: AbortSignal) {
    return ensureWorkspace(
      await this.request<{
        workspace_id: string;
        files: SourceFile[];
        truncated: boolean;
        policy_version: number;
        policy_fingerprint: string;
      }>(`/api/workspaces/${segment(id)}/files`, { signal }),
      id,
    );
  }
  async file(
    id: string,
    path: string,
    analysisId?: string,
    signal?: AbortSignal,
  ) {
    const query = new URLSearchParams({ path });
    if (analysisId) query.set("analysis_id", analysisId);
    return ensureWorkspace(
      await this.request<FileContent>(
        `/api/workspaces/${segment(id)}/file?${query}`,
        { signal },
      ),
      id,
    );
  }
  async jobs(id: string, signal?: AbortSignal) {
    const response = ensureWorkspace(
      await this.request<{ workspace_id: string; analyses: AnalysisJob[] }>(
        `/api/workspaces/${segment(id)}/analyses`,
        { signal },
      ),
      id,
    );
    return response.analyses.map((item) => ensureWorkspace(item, id));
  }
  async job(id: string, job: string, signal?: AbortSignal) {
    const value = ensureWorkspace(
      await this.request<AnalysisJob>(
        `/api/workspaces/${segment(id)}/analyses/${segment(job)}`,
        { signal },
      ),
      id,
    );
    if (value.id !== job) throw new ApiError("分析任务数据不匹配，已忽略这次响应。");
    return value;
  }
  async analyze(id: string, kind: StaticAnalysisKind = "navigation", options?: ChangeScopeOptions) {
    return ensureWorkspace(
      await this.request<AnalysisJob>(
        `/api/workspaces/${segment(id)}/analyses`,
        { method: "POST", body: JSON.stringify({ mode: "static", kind, ...(kind === "change_scope" ? options : {}) }) },
      ),
      id,
    );
  }
  async cancel(id: string, job: string) {
    return ensureWorkspace(
      await this.request<AnalysisJob>(
        `/api/workspaces/${segment(id)}/analyses/${segment(job)}/cancel`,
        { method: "POST", body: "{}" },
      ),
      id,
    );
  }
  async baseline(id: string, analysisId?: string, signal?: AbortSignal) {
    const query = analysisId ? `?${new URLSearchParams({ analysis_id: analysisId })}` : "";
    return ensureWorkspace(await this.request<BaselineState>(`/api/workspaces/${segment(id)}/baseline${query}`, { signal }), id);
  }
  async createBaselineProposal(id: string, analysisId: string) {
    return ensureWorkspace(await this.request<BaselineProposal>(`/api/workspaces/${segment(id)}/baseline/proposals`, {
      method: "POST", body: JSON.stringify({ analysis_id: analysisId }),
    }, false), id);
  }
  async approveBaseline(id: string, proposalId: string, selectedIds: string[], reason: string, expectedRevision: number) {
    return ensureWorkspace(await this.request<BaselineState>(`/api/workspaces/${segment(id)}/baseline/proposals/${segment(proposalId)}/approve`, {
      method: "POST", body: JSON.stringify({ selected_ids: selectedIds, reason, expected_revision: expectedRevision }),
    }, false), id);
  }
  async revokeBaseline(id: string, recordId: string, reason: string, expectedRevision: number) {
    return ensureWorkspace(await this.request<BaselineState>(`/api/workspaces/${segment(id)}/baseline/records/${segment(recordId)}/revoke`, {
      method: "POST", body: JSON.stringify({ reason, expected_revision: expectedRevision }),
    }, false), id);
  }
  gatePolicy(signal?: AbortSignal) {
    return this.request<GatePolicy>("/api/gate-policy", { signal });
  }
  async semanticProfile(id: string, signal?: AbortSignal) {
    return ensureWorkspace(await this.request<SemanticProfile>(`/api/workspaces/${segment(id)}/semantic-profile`, { signal }), id);
  }
  async chatSettings(id: string, signal?: AbortSignal) {
    return ensureWorkspace(await this.request<ChatSettings>(`/api/workspaces/${segment(id)}/chat-settings`, { signal }), id);
  }
  async saveChatSettings(id: string, settings: { consent: boolean; context: string; expected_revision: number; expected_policy_version: number; expected_profile_revision: number }) {
    return ensureWorkspace(await this.request<ChatSettings>(`/api/workspaces/${segment(id)}/chat-settings`, { method: "PUT", body: JSON.stringify(settings) }), id);
  }
  async conversations(id: string, signal?: AbortSignal) {
    const value = ensureWorkspace(await this.request<{ workspace_id: string; conversations: ConversationSummary[] } & PolicyIdentity>(`/api/workspaces/${segment(id)}/conversations`, { signal }), id);
    value.conversations.forEach(item => ensureWorkspace(item, id));
    return value.conversations.map(item => ({ ...item, policy_version: value.policy_version, policy_fingerprint: value.policy_fingerprint }));
  }
  async createConversation(id: string) {
    return ensureWorkspace(await this.request<ConversationSummary>(`/api/workspaces/${segment(id)}/conversations`, { method: "POST", body: "{}" }), id);
  }
  async conversation(id: string, conversationId: string, signal?: AbortSignal) {
    const value = ensureWorkspace(await this.request<Conversation>(`/api/workspaces/${segment(id)}/conversations/${segment(conversationId)}`, { signal }), id);
    if (value.id !== conversationId) throw new ApiError("对话身份不匹配，已忽略响应");
    return value;
  }
  async sendQuestion(id: string, conversationId: string, question: string, settingsRevision: number, selectedPath?: string, crapTarget?: CrapDiscussionTarget) {
    return ensureWorkspace(await this.request<Conversation>(`/api/workspaces/${segment(id)}/conversations/${segment(conversationId)}/messages`, {
      method: "POST", body: JSON.stringify({ question, expected_settings_revision: settingsRevision,
        ...(selectedPath ? { selected_path: selectedPath } : {}), ...(crapTarget ? { crap_target: crapTarget } : {}) }) }, false), id);
  }
  async runCrapTool(id: string, conversationId: string, options: CrapToolOptions, policyVersion: number) {
    return ensureWorkspace(await this.request<Conversation>(`/api/workspaces/${segment(id)}/conversations/${segment(conversationId)}/tools/crap`, {
      method: "POST", body: JSON.stringify({ ...options, expected_policy_version: policyVersion }),
    }, false), id);
  }
  async cancelConversation(id: string, conversationId: string) {
    return ensureWorkspace(await this.request<Conversation>(`/api/workspaces/${segment(id)}/conversations/${segment(conversationId)}/cancel`, { method: "POST" }), id);
  }
  async deleteConversation(id: string, conversationId: string) {
    await this.request(`/api/workspaces/${segment(id)}/conversations/${segment(conversationId)}`, { method: "DELETE" });
  }
  async conversationFeedback(id: string, conversationId: string, turnId: string, text: string) {
    return ensureWorkspace(await this.request<Conversation>(`/api/workspaces/${segment(id)}/conversations/${segment(conversationId)}/turns/${segment(turnId)}/feedback`, { method: "PUT", body: JSON.stringify({ text }) }), id);
  }
  async insights(id: string, conversationId?: string, signal?: AbortSignal) {
    const query = conversationId ? `?conversation_id=${segment(conversationId)}` : "";
    return ensureWorkspace(await this.request<InsightResponse & { insights: ProjectInsight[] }>(`/api/workspaces/${segment(id)}/insights${query}`, { signal }), id);
  }
  async saveInsight(id: string, cid: string, tid: string, draft: InsightDraft, version: number) {
    return ensureWorkspace(await this.request<InsightResponse & { insight: ProjectInsight }>(
      `/api/workspaces/${segment(id)}/conversations/${segment(cid)}/turns/${segment(tid)}/insights`,
      { method: "POST", body: JSON.stringify({ ...draft, expected_policy_version: version }) }), id);
  }
  async changeInsight(id: string, noteId: string, action: "retire" | "delete", version: number, cid?: string) {
    return ensureWorkspace(await this.request<InsightResponse>(`/api/workspaces/${segment(id)}/insights/${segment(noteId)}`, {
      method: "PATCH", body: JSON.stringify({ cid, action, expected_policy_version: version }),
    }), id);
  }
  async updateSemanticProfile(id: string, body: SemanticProfileUpdate) {
    return ensureWorkspace(await this.request<SemanticProfile>(`/api/workspaces/${segment(id)}/semantic-profile`, {
      method: "PUT", body: JSON.stringify(body),
    }, false), id);
  }
  async previewSemantic(id: string, path: string, startLine: number, endLine: number, expectedProfileRevision: number) {
    return ensureWorkspace(await this.request<SemanticPreview>(`/api/workspaces/${segment(id)}/semantic-previews`, {
      method: "POST", body: JSON.stringify({ path, start_line: startLine, end_line: endLine, expected_profile_revision: expectedProfileRevision }),
    }, false), id);
  }
  async sendSemantic(id: string, previewId: string, expectedRequestSha256: string, expectedProfileRevision: number) {
    const value = ensureWorkspace(await this.request<AnalysisJob>(`/api/workspaces/${segment(id)}/semantic-previews/${segment(previewId)}/send`, {
      method: "POST", body: JSON.stringify({ confirmed: true, expected_request_sha256: expectedRequestSha256, expected_profile_revision: expectedProfileRevision }),
    }, false), id);
    if (analysisKind(value) !== "semantic_review") throw new ApiError("模型审查任务身份不匹配，已忽略这次响应。");
    return value;
  }
}
export const api = new LocalApi();
