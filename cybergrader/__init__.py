"""Passive cyber-hygiene grader: email spoofing protection, HTTPS/TLS, web security headers and DNS."""
from ._version import __version__
from .grader import grade_domain
from .models import CheckResult, Report, Severity, Status

__all__ = ["CyberHygieneGrader", "CheckResult", "Report", "Severity", "Status", "__version__", "grade_domain"]


class CyberHygieneGrader:
    """Backwards-compatible wrapper for the original single-class API."""

    def __init__(self, domain: str, **options) -> None:
        self.domain = domain
        self.options = options

    def run_full_grade(self) -> dict:
        return grade_domain(self.domain, **self.options).to_dict()
