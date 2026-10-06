from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Issue:
    """A restore warning. Line numbers are 1-based."""

    line: int
    code: str
    message: str
    excerpt: str
