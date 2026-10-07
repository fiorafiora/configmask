"""Session-defined address stand-ins.

A blank row keeps automatic allocation. A listed network or single address
is rewritten to the stand-in beside it.
"""

from __future__ import annotations

import re

from app.engine.iputil import (
    format_ipv4,
    is_contiguous_mask,
    is_exempt,
    parse_ipv4,
    prefix_len,
    prefix_to_mask,
)

_CIDR = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$")
_HOST = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})$")
_MASKED = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$")


def parse_subnet_rules(reals: list[str], stands: list[str]) -> tuple[list[tuple[str, str]], bool]:
    """Return (pairs, ok). A rejected row makes ok false and discards the batch."""
    if len(reals) != len(stands):
        return [], False
    accepted: list[tuple[str, str]] = []
    seen_real: set[object] = set()
    seen_hosts: set[int] = set()
    blocks: list[tuple[int, int]] = []
    for raw_real, raw_stand in zip(reals, stands):
        real_text = raw_real.strip()
        stand_text = raw_stand.strip()
        if not real_text and not stand_text:
            continue
        real = _target(real_text)
        stand = _target(stand_text)
        if real is None or stand is None or real[0] != stand[0]:
            return [], False
        if real[0] == "host":
            if real[1] == stand[1] or real[1] in seen_real or stand[1] in seen_hosts:
                return [], False
            seen_real.add(real[1])
            seen_hosts.add(stand[1])
            accepted.append((format_ipv4(real[1]), format_ipv4(stand[1])))
            continue
        if real[1][1] != stand[1][1] or real[1] == stand[1] or real[1] in seen_real or _overlaps(stand[1], blocks):
            return [], False
        seen_real.add(real[1])
        size = 1 << (32 - stand[1][1])
        blocks.append((stand[1][0], stand[1][0] + size))
        accepted.append(
            (f"{format_ipv4(real[1][0])}/{real[1][1]}", f"{format_ipv4(stand[1][0])}/{stand[1][1]}")
        )
    return accepted, True


def _target(text: str) -> tuple[str, int | tuple[int, int]] | None:
    if text.endswith("/32"):
        text = text[:-3]
    if _HOST.fullmatch(text):
        try:
            ip = parse_ipv4(text)
        except ValueError:
            return None
        if is_exempt(ip):
            return None
        return "host", ip
    network = _network(text)
    if network is None:
        return None
    return "net", network


def _network(text: str) -> tuple[int, int] | None:
    cidr = _CIDR.fullmatch(text)
    if cidr:
        try:
            ip = parse_ipv4(cidr.group(1))
        except ValueError:
            return None
        prefix = int(cidr.group(2))
    else:
        masked = _MASKED.fullmatch(text)
        if not masked:
            return None
        try:
            ip = parse_ipv4(masked.group(1))
            mask = parse_ipv4(masked.group(2))
        except ValueError:
            return None
        if not is_contiguous_mask(mask):
            return None
        prefix = prefix_len(mask)
    if not 8 <= prefix <= 30:
        return None
    network = ip & prefix_to_mask(prefix)
    if is_exempt(network):
        return None
    return network, prefix


def _overlaps(stand: tuple[int, int], blocks: list[tuple[int, int]]) -> bool:
    size = 1 << (32 - stand[1])
    start = stand[0]
    end = start + size
    return any(existing_start < end and start < existing_end for existing_start, existing_end in blocks)
