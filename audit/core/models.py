from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass
class Finding:
    check_id: str          # e.g. "API2:2023"
    title: str
    severity: Severity
    status: Status
    detail: str
    recommendation: str
    evidence: Optional[str] = None


@dataclass
class AuditResult:
    target: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def score(self) -> int:
        """Simple security score out of 100."""
        penalties = {Severity.CRITICAL: 25, Severity.HIGH: 15, Severity.MEDIUM: 8, Severity.LOW: 3}
        total = sum(
            penalties.get(f.severity, 0)
            for f in self.findings
            if f.status == Status.FAIL
        )
        return max(0, 100 - total)

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if f.status == Status.FAIL]

    @property
    def passed(self) -> list[Finding]:
        return [f for f in self.findings if f.status == Status.PASS]
