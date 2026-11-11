import { useState } from "react";
import { FileCode2, X } from "lucide-react";
import type { ChatSourceLocation, CrapCoverage, CrapFunction, CrapToolOptions, CrapToolTurn } from "./api";

const coverageReasons: Record<string, string> = {
  coverage_not_provided: "未提供覆盖率报告",
  missing_function_coverage: "报告未包含这个函数",
  missing_start_line: "报告缺少函数起始行",
  location_mismatch: "报告与源码的函数位置不一致",
  invalid_region_lines: "报告中的覆盖行超出函数范围",
  invalid_coverage_counts: "覆盖率计数无法使用",
  no_measurable_coverage: "没有可测的覆盖项",
  ambiguous_function_name: "存在同名函数，无法唯一匹配",
};

const scanIssues: Record<string, string> = {
  syntax_error: "Python 语法无法解析",
  source_unavailable: "源码无法读取或分析",
  source_changed: "计算时源码发生变化",
  source_inventory_changed: "计算时文件清单发生变化",
  budget_exhausted: "达到本轮扫描上限",
  access_scope_limit: "达到文件枚举上限",
  access_scope_unreadable: "目录无法枚举",
  access_rules_blocked: "访问规则无法验证",
};

function percent(covered: number, total: number) {
  return `${(100 * covered / total).toFixed(1)}%`;
}

function coverageText(value: CrapCoverage | null) {
  return value ? `${percent(value.covered, value.total)}（${value.covered}/${value.total}）` : "N/A";
}

export function CrapReportView({ tool, onOpen, onDiscuss, canDiscuss, busy }: {
  tool: CrapToolTurn; onOpen: (location: ChatSourceLocation) => void;
  onDiscuss: (row: CrapFunction, location: ChatSourceLocation) => void;
  canDiscuss: (path: string) => boolean; busy: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const report = tool.report;
  if (!report) return null;
  const summary = report.summary;
  const branches = report.branch_totals;
  const visible = expanded ? report.functions : report.functions.slice(0, 10);

  return <section className="chat-answer crap-report" aria-label="CRAP 维护风险报告">
    <h2>CRAP 维护风险报告</h2>
    <div className="crap-report-summary">
      <span><strong>{summary.functions}</strong> 个函数 · {summary.python_files} 个 Python 文件</span>
      <span><strong>{summary.scored}</strong> 已评分 · {summary.unscored} 无分数</span>
      <span><strong>{summary.at_or_above_reference}</strong> 项达到参考线 {tool.reference}</span>
      <span><strong>{branches.total ? percent(branches.covered, branches.total) : "N/A"}</strong> 已测分支覆盖率
        {branches.total ? ` · ${branches.covered}/${branches.total}，涉及 ${branches.functions} 个函数` : ""}</span>
    </div>
    <p>{report.coverage_origin === "not_provided"
      ? "本次只计算圈复杂度。导入同一源码版本的覆盖率报告后可计算 CRAP。"
      : <>覆盖率来源 <code>{tool.coverage_path}</code>。使用分支覆盖率评分，无可用分支测量时使用语句覆盖率。</>}</p>
    {report.scan_status === "incomplete" && <details className="chat-evidence">
      <summary>扫描不完整 · {report.issue_count} 个问题</summary>
      {report.issues.map((issue, index) => <div key={index}>{issue.file} · {scanIssues[issue.status] || issue.status}</div>)}
    </details>}
    {visible.length ? <div className="crap-table-wrap"><table>
      <thead><tr><th scope="col">函数与源码</th><th scope="col">CRAP</th><th scope="col">圈复杂度</th>
        <th scope="col">分支覆盖率</th><th scope="col">语句覆盖率</th><th scope="col">修改建议</th></tr></thead>
      <tbody>{visible.map(row => {
        const location = { path: row.file, line: row.line, end_line: row.end_line, sha256: report.source_sha256[row.file] };
        const eligible = canDiscuss(row.file);
        return <tr key={`${row.file}:${row.line}`}>
        <td><button className="text-button crap-source" onClick={() => onOpen(location)}><FileCode2 size={13} /><span>{row.function}<small>{row.file}:{row.line}</small></span></button></td>
        <td className={row.at_or_above_reference ? "crap-over-reference" : undefined}>{row.crap?.toFixed(2) ?? "N/A"}
          {row.crap == null && <small>{coverageReasons[row.coverage_status] || "覆盖率不可用"}</small>}</td>
        <td>{row.complexity}</td><td>{coverageText(row.branch_coverage)}</td><td>{coverageText(row.statement_coverage)}</td>
        <td>{row.suggestion}
          {!!row.missing_branches.length && <small>未覆盖分支示例 {row.missing_branches.map(([from, to]) => `${from} → ${to > 0 ? to : "退出"}`).join("、")}</small>}
          {!!row.missing_lines.length && <small>未覆盖行示例 {row.missing_lines.join("、")}</small>}
          <button className="text-button crap-discuss" disabled={busy || !eligible} title={eligible ? row.function : "此文件不在模型候选范围内"}
            onClick={() => onDiscuss(row, location)}>讨论改法</button></td>
        </tr>;
      })}</tbody>
    </table></div> : <p>当前读取范围内没有可报告的 Python 函数。</p>}
    {report.functions.length > 10 && <button className="text-button" onClick={() => setExpanded(value => !value)}>
      {expanded ? "收起明细" : `展开 ${report.functions.length} 项明细`}</button>}
    {report.functions.length < summary.functions && <p className="subtle">对话保留排序靠前的 {report.functions.length} 项。完整明细可用 <code>codesentry crap --json</code> 查看。</p>}
    {report.coverage_report_sha256 && <details className="chat-evidence"><summary>核对输入与复测</summary>
      <p>报告摘要 <code>{report.coverage_report_sha256}</code></p>
      <p>改动后用相同测试范围重新收集覆盖率，再比较同一函数的分数、复杂度及未覆盖分支。</p>
    </details>}
  </section>;
}

export function CrapToolDialog({ initial, busy, error, onClose, onRun }: {
  initial: CrapToolOptions; busy: boolean; error: string | null;
  onClose: () => void; onRun: (options: CrapToolOptions) => void;
}) {
  const [path, setPath] = useState(initial.coverage_path ?? "");
  const [reference, setReference] = useState(String(initial.reference));
  const threshold = Number(reference);
  const valid = Number.isFinite(threshold) && threshold > 0;
  return <div className="dialog-backdrop"><section className="dialog crap-dialog" role="dialog" aria-modal="true" aria-label="CRAP 本地工具">
    <div className="dialog-header"><h2>CRAP 本地工具</h2><button className="icon-button" aria-label="关闭 CRAP 工具" onClick={onClose}><X size={18} /></button></div>
    <p>分析当前工作空间的 Python 函数，根据圈复杂度和测试覆盖率给出修改建议。报告保存在当前话题。</p>
    <form onSubmit={event => {
      event.preventDefault();
      if (valid && !busy) onRun({ coverage_path: path.trim() || null, reference: threshold });
    }}>
      <label>覆盖率报告路径（可选）<input value={path} onChange={event => setPath(event.target.value)} maxLength={4096}
        placeholder="coverage.json" /></label>
      <p>填写项目内相对路径。请使用同版本源码的 coverage.py JSON 报告。留空时可查看复杂度，分数和覆盖率显示 N/A。</p>
      <label>CRAP 参考线<input type="number" step="any" min="0" required value={reference} onChange={event => setReference(event.target.value)} /></label>
      {error && <p role="alert" className="chat-failure">{error}</p>}
      <div className="dialog-actions"><button type="button" className="button secondary" onClick={onClose}>取消</button>
        <button type="submit" className="button primary" disabled={!valid || busy}>生成报告</button></div>
    </form>
  </section></div>;
}
