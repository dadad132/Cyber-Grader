"""Check registry. Each check module registers its functions with @check when imported."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from ..models import Outcome

if TYPE_CHECKING:
    from ..context import ScanContext

EMAIL = "Email Security"
TLS = "HTTPS & TLS"
HEADERS = "Web Security Headers"
DOMAIN = "Domain & DNS"
CATEGORIES = (EMAIL, TLS, HEADERS, DOMAIN)


@dataclass(frozen=True)
class CheckSpec:
    id: str
    category: str
    title: str
    max_points: float
    func: Callable[[ScanContext], Outcome]


_REGISTRY: list[CheckSpec] = []


def check(check_id: str, category: str, title: str, max_points: float = 0.0):
    """Register a check. max_points=0 makes it informational (never scored)."""

    def register(func):
        _REGISTRY.append(CheckSpec(check_id, category, title, max_points, func))
        return func

    return register


def all_checks() -> list[CheckSpec]:
    from . import domain, mail, tls, web  # noqa: F401  (importing registers the checks)

    return sorted(_REGISTRY, key=lambda spec: CATEGORIES.index(spec.category))
