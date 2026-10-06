"""Put real values back into an edited stand-in configuration."""

from __future__ import annotations

import re

from app.engine.mapper import Mapper


def restore_text(text: str, mapper: Mapper) -> str:
    """Replace stand-ins with real values. ``<REMOVED>`` is left untouched."""
    if not mapper.by_placeholder:
        return text
    items = sorted(mapper.by_placeholder.items(), key=lambda item: len(item[0]), reverse=True)
    lookup: dict[str, str] = {}
    parts: list[str] = []
    for placeholder, (_type, real) in items:
        parts.append(
            r"(?<![A-Za-z0-9_-])" + re.escape(placeholder) + r"(?![A-Za-z0-9_-])"
        )
        lookup[placeholder] = real
    pattern = re.compile("|".join(parts))

    def repl(match: re.Match[str]) -> str:
        return lookup[match.group(0)]

    return pattern.sub(repl, text)
