from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    evidence: str
    remediation: str
    heuristic: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def sorted(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-SEV_RANK[f.severity], f.rule_id, f.file, f.line),
        )

    def max_rank(self) -> int:
        return max((SEV_RANK[f.severity] for f in self.findings), default=-1)
