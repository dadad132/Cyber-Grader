"""Data types shared by the checks, the grader and the report renderers."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum


class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"    # partly meets best practice: partial credit
    FAIL = "fail"
    SKIP = "skip"    # a prerequisite failed (e.g. no HTTPS): scored as zero
    INFO = "info"    # not applicable or informational: not scored
    ERROR = "error"  # could not be determined (timeout, SERVFAIL): not scored


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class NotApplicable(Exception):
    """Raised by a check when it doesn't apply to this domain (e.g. no website, no mail)."""


class NotTested(Exception):
    """Raised by a check when a prerequisite failed (e.g. HTTPS unreachable); scores zero."""


@dataclass
class Outcome:
    """What a check function returns; the grader turns it into a CheckResult."""

    status: Status
    severity: Severity = Severity.INFO
    summary: str = ""
    fix: str = ""
    evidence: str = ""
    score: float | None = None  # fraction of the check's points earned; None = all or nothing

    @classmethod
    def ok(cls, summary: str, evidence: str = "") -> Outcome:
        return cls(Status.PASS, Severity.INFO, summary, "", evidence)

    @classmethod
    def warn(cls, score: float, severity: Severity, summary: str, fix: str, evidence: str = "") -> Outcome:
        return cls(Status.WARN, severity, summary, fix, evidence, score)

    @classmethod
    def fail(cls, severity: Severity, summary: str, fix: str, evidence: str = "") -> Outcome:
        return cls(Status.FAIL, severity, summary, fix, evidence, 0.0)

    @classmethod
    def info(cls, summary: str, evidence: str = "") -> Outcome:
        return cls(Status.INFO, Severity.INFO, summary, "", evidence)

    @classmethod
    def skip(cls, summary: str) -> Outcome:
        return cls(Status.SKIP, Severity.INFO, summary, "", "", 0.0)

    @classmethod
    def error(cls, summary: str) -> Outcome:
        return cls(Status.ERROR, Severity.INFO, summary)


class Deductions:
    """Collects independent problems found by one check and folds them into a single Outcome."""

    def __init__(self) -> None:
        self.items: list[tuple[float, Severity, str, str]] = []

    def add(self, penalty: float, severity: Severity, problem: str, fix: str = "") -> None:
        self.items.append((penalty, severity, problem, fix))

    def outcome(self, ok_summary: str, evidence: str = "") -> Outcome:
        if not self.items:
            return Outcome.ok(ok_summary, evidence)
        score = max(0.0, 1.0 - sum(item[0] for item in self.items))
        severity = max((item[1] for item in self.items), key=lambda s: s.rank)
        summary = " ".join(item[2] for item in self.items)
        fix = " ".join(dict.fromkeys(item[3] for item in self.items if item[3]))
        if score <= 0:
            return Outcome.fail(severity, summary, fix, evidence)
        return Outcome.warn(round(score, 3), severity, summary, fix, evidence)


@dataclass
class CheckResult:
    id: str
    category: str
    title: str
    status: Status
    severity: Severity
    points: float
    max_points: float
    summary: str
    fix: str = ""
    evidence: str = ""

    @property
    def scored(self) -> bool:
        return self.max_points > 0 and self.status in (Status.PASS, Status.WARN, Status.FAIL, Status.SKIP)

    @property
    def is_finding(self) -> bool:
        return self.status in (Status.WARN, Status.FAIL) and self.severity is not Severity.INFO

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity"] = self.severity.value
        return data


@dataclass
class CategoryScore:
    name: str
    points: float
    max_points: float

    @property
    def percent(self) -> int | None:
        return round(100 * self.points / self.max_points) if self.max_points else None


@dataclass
class Report:
    domain: str
    display_domain: str
    scanned_at: datetime
    duration: float
    score: int
    grade: str
    grade_note: str
    coverage: float
    web_host: str | None
    homepage_url: str | None
    categories: list[CategoryScore]
    results: list[CheckResult]
    version: str

    @property
    def findings(self) -> list[CheckResult]:
        found = [r for r in self.results if r.is_finding]
        return sorted(found, key=lambda r: (-r.severity.rank, -(r.max_points - r.points)))

    @property
    def passed(self) -> list[CheckResult]:
        return [r for r in self.results if r.status is Status.PASS and r.max_points > 0]

    @property
    def skipped(self) -> list[CheckResult]:
        return [r for r in self.results if r.status is Status.SKIP]

    @property
    def errors(self) -> list[CheckResult]:
        return [r for r in self.results if r.status is Status.ERROR]

    @property
    def notes(self) -> list[CheckResult]:
        return [r for r in self.results if r.status is Status.INFO or (r.status is Status.PASS and r.max_points == 0)]

    @classmethod
    def from_dict(cls, data: dict) -> Report:
        """Rebuild a report saved with to_dict(), e.g. from a customer's scan history."""
        from .target import display_name

        results = [
            CheckResult(id=c["id"], category=c["category"], title=c["title"], status=Status(c["status"]),
                        severity=Severity(c["severity"]), points=c["points"], max_points=c["max_points"],
                        summary=c["summary"], fix=c.get("fix", ""), evidence=c.get("evidence", ""))
            for c in data["checks"]
        ]
        return cls(
            domain=data["domain"],
            display_domain=display_name(data["domain"]),
            scanned_at=datetime.fromisoformat(data["scanned_at"].replace("Z", "+00:00")),
            duration=data.get("duration_seconds", 0.0),
            score=data["score"],
            grade=data["grade"],
            grade_note=data.get("grade_note", ""),
            coverage=data.get("coverage", 1.0),
            web_host=data.get("web_host"),
            homepage_url=data.get("homepage_url"),
            categories=[CategoryScore(c["name"], c["points"], c["max_points"]) for c in data["categories"]],
            results=results,
            version=data.get("version", ""),
        )

    def to_dict(self) -> dict:
        timestamp = self.scanned_at.isoformat().replace("+00:00", "Z")
        return {
            "domain": self.domain,
            "scanned_at": timestamp,
            "duration_seconds": round(self.duration, 2),
            "score": self.score,
            "grade": self.grade,
            "grade_note": self.grade_note,
            "coverage": round(self.coverage, 3),
            "web_host": self.web_host,
            "homepage_url": self.homepage_url,
            "categories": [
                {"name": c.name, "percent": c.percent, "points": c.points, "max_points": c.max_points}
                for c in self.categories
            ],
            "checks": [r.to_dict() for r in self.results],
            # Fields kept from the v1 output format so existing consumers keep working.
            "timestamp": timestamp,
            "passed_checks": [r.summary for r in self.passed],
            "vulnerabilities_and_fixes": [
                {"category": r.category, "severity": r.severity.value.upper(), "issue": r.summary, "fix": r.fix}
                for r in self.findings
            ],
            "version": self.version,
        }
