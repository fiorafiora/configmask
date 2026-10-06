from __future__ import annotations

import re

_KEYWORD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 ._-]{2,63}$")
_DENY = frozenset(
    {
        "interface",
        "address",
        "network",
        "router",
        "switch",
        "vlan",
        "description",
        "password",
        "secret",
        "enable",
        "username",
        "hostname",
        "domain",
        "server",
        "default",
        "route",
        "prefix",
        "object",
        "crypto",
        "tunnel",
        "banner",
        "snmp",
        "line",
        "login",
        "standby",
        "neighbor",
        "access",
        "permit",
        "deny",
        "remark",
        "host",
        "any",
        "gigabitethernet",
        "fastethernet",
        "port-channel",
        "loopback",
    }
)


def parse_keywords(text: str) -> tuple[list[str], list[str]]:
    """Return (accepted, rejected). Matching is case-insensitive later."""
    accepted: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        folded = item.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        if not _KEYWORD_RE.fullmatch(item) or folded in _DENY or not any(ch.isalpha() for ch in item):
            rejected.append(item)
            continue
        accepted.append(item)
    return accepted, rejected
