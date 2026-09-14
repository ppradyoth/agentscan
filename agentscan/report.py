from __future__ import annotations
import json

from .model import Report, SEV_RANK

_COLOR = {
    "CRITICAL": "\033[41;97m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
    "LOW": "\033[94m", "INFO": "\033[90m",
}
_RESET = "\033[0m"


def _c(sev: str, text: str, use: bool) -> str:
    if not use:
        return text
    return f"{_COLOR.get(sev, '')}{text}{_RESET}"


def render_terminal(report: Report, color: bool = True) -> str:
    out: list[str] = []
    findings = report.sorted()
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    out.append("")
    out.append(f"agentscan — {report.files_scanned} config file(s) scanned, "
               f"{len(findings)} finding(s)")
    out.append("=" * 68)
    if not findings:
        out.append("No agent-security issues detected.")
        return "\n".join(out) + "\n"
    for f in findings:
        tag = _c(f.severity, f" {f.severity:<8}", color)
        flag = " [heuristic]" if f.heuristic else ""
        out.append(f"{tag} {f.rule_id}  {f.title}{flag}")
        out.append(f"          {f.file}:{f.line}")
        out.append(f"          evidence: {f.evidence}")
        out.append(f"          fix: {f.remediation}")
        out.append("")
    summary = "  ".join(
        _c(s, f"{s}:{counts[s]}", color)
        for s in sorted(counts, key=lambda x: -SEV_RANK[x])
    )
    out.append("-" * 68)
    out.append(f"Summary: {summary}")
    return "\n".join(out) + "\n"


def render_json(report: Report) -> str:
    return json.dumps(
        {
            "files_scanned": report.files_scanned,
            "finding_count": len(report.findings),
            "findings": [f.as_dict() for f in report.sorted()],
        },
        indent=2,
    )


def render_markdown(report: Report) -> str:
    findings = report.sorted()
    lines = ["# agentscan report", "",
             f"- Files scanned: **{report.files_scanned}**",
             f"- Findings: **{len(findings)}**", ""]
    if not findings:
        lines.append("No agent-security issues detected.")
        return "\n".join(lines) + "\n"
    lines += ["| Severity | Rule | Title | Location |",
              "|---|---|---|---|"]
    for f in findings:
        h = " _(heuristic)_" if f.heuristic else ""
        lines.append(f"| {f.severity} | {f.rule_id} | {f.title}{h} | `{f.file}:{f.line}` |")
    lines.append("")
    for f in findings:
        lines += [f"### {f.rule_id} — {f.title}",
                  f"- **Severity:** {f.severity}",
                  f"- **Location:** `{f.file}:{f.line}`",
                  f"- **Evidence:** `{f.evidence}`",
                  f"- **Fix:** {f.remediation}", ""]
    return "\n".join(lines) + "\n"
