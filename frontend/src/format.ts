import { analysisKind, type AnalysisJob } from "./api";
export const jobKindLabel = (job: AnalysisJob) => analysisKind(job) === "review_preview" ? "审查预览" : analysisKind(job) === "change_scope" ? "变更范围" : analysisKind(job) === "gate_check" ? "门禁检查" : analysisKind(job) === "defect_preview" ? "缺陷候选" : analysisKind(job) === "semantic_review" ? "模型审查" : "静态导航";
export const jobStatusLabel = (job: AnalysisJob) => analysisKind(job) === "gate_check" && job.status === "succeeded"
  ? "检查报告已生成" : analysisKind(job) !== "navigation" && job.status === "succeeded" ? "报告已生成" : statusLabel(job.status);
export const roleLabels: ReadonlyMap<string, string> = new Map([
  ["-", "模块"],
  ["entry", "入口线索"],
]);
export const activeStatus = (status?: string) =>
  status === "queued" || status === "running";
export function statusLabel(status?: string) {
  return (
    (
      {
        queued: "等待分析",
        running: "分析中",
        succeeded: "解析完成",
        incomplete: "部分完成",
        failed: "分析失败",
        cancelled: "已取消",
        interrupted: "已中断",
        invalidated: "结果已失效",
      } as Record<string, string>
    )[status || ""] || "尚未分析"
  );
}
export function formatTime(value?: string | null) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf())
    ? "—"
    : parsed.toLocaleString("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
}
export function duration(job?: AnalysisJob | null) {
  if (!job) return "—";
  if (typeof job.elapsed_seconds === "number")
    return job.elapsed_seconds < 60
      ? `${job.elapsed_seconds.toFixed(1)} 秒`
      : `${Math.floor(job.elapsed_seconds / 60)} 分 ${Math.round(job.elapsed_seconds % 60)} 秒`;
  return activeStatus(job.status) ? "正在处理" : "—";
}
export function shortPath(path: string) {
  return path.split(/[\\/]/).filter(Boolean).at(-1) || path;
}
export function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "操作未完成，请重试。";
}
export function aborted(error: unknown) {
  return (
    !!error &&
    typeof error === "object" &&
    "name" in error &&
    error.name === "AbortError"
  );
}
