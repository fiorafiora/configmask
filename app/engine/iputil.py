"""IPv4 helpers. No sockets, no DNS, no outbound calls."""

from __future__ import annotations

import re

IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![A-Za-z0-9])"
)

# Encryption type numbers Cisco places beside a secret.
ENC_TYPES = frozenset({"0", "4", "5", "6", "7", "8", "9"})


def parse_ipv4(text: str) -> int:
    parts = text.split(".")
    if len(parts) != 4:
        raise ValueError(f"not an IPv4 address: {text}")
    value = 0
    for part in parts:
        if not part.isdigit():
            raise ValueError(f"not an IPv4 address: {text}")
        octet = int(part)
        if octet > 255:
            raise ValueError(f"not an IPv4 address: {text}")
        value = (value << 8) | octet
    return value


def format_ipv4(value: int) -> str:
    value &= 0xFFFFFFFF
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def prefix_to_mask(prefix: int) -> int:
    if prefix <= 0:
        return 0
    if prefix >= 32:
        return 0xFFFFFFFF
    return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF


def prefix_len(mask: int) -> int:
    return bin(mask & 0xFFFFFFFF).count("1")


def is_contiguous_mask(value: int) -> bool:
    """True when value is 1-bits followed by 0-bits (a subnet mask)."""
    inverted = (~value) & 0xFFFFFFFF
    return (inverted & (inverted + 1)) == 0


def is_contiguous_wildcard(value: int) -> bool:
    """True when value is 0-bits followed by 1-bits (a typical ACL wildcard)."""
    value &= 0xFFFFFFFF
    return (value & (value + 1)) == 0


def is_rfc1918(value: int) -> bool:
    if (value & 0xFF000000) == 0x0A000000:  # 10.0.0.0/8
        return True
    if (value & 0xFFF00000) == 0xAC100000:  # 172.16.0.0/12
        return True
    if (value & 0xFFFF0000) == 0xC0A80000:  # 192.168.0.0/16
        return True
    return False


def is_exempt(value: int) -> bool:
    """Addresses that must pass through unchanged.

    0.0.0.0/8 covers the all-zero address and wildcard masks that start with 0.
    255.0.0.0/8 covers 255.255.255.255 and subnet masks such as 255.255.255.0.
    """
    if (value & 0xFF000000) == 0:  # 0.0.0.0/8
        return True
    if (value & 0xFF000000) == 0xFF000000:  # 255.0.0.0/8
        return True
    if (value & 0xFF000000) == 0x7F000000:  # 127.0.0.0/8
        return True
    if (value & 0xFFFFFF00) == 0xE0000000:  # 224.0.0.0/24 well-known multicast
        return True
    return False
