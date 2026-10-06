"""Session mapping table.

One mapper is shared by every configuration in a session so a real address
or name always becomes the same stand-in, including across devices.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.engine.allocator import Allocator, MappingCollision
from app.engine.iputil import (
    format_ipv4,
    is_exempt,
    is_rfc1918,
    parse_ipv4,
    prefix_len,
    prefix_to_mask,
)

TOKEN_TYPES = frozenset(
    {
        "hostname",
        "username",
        "domain",
        "vlan",
        "acl",
        "routemap",
        "cryptomap",
        "object",
        "prefixlist",
        "keychain",
        "name",
    }
)

PREFIX = {
    "hostname": "HOST",
    "username": "USER",
    "description": "DESC",
    "banner": "BANNER",
    "vlan": "VLAN",
    "snmp_location": "LOC",
    "snmp_contact": "CONTACT",
    "remark": "REMARK",
    "acl": "ACL",
    "routemap": "RMAP",
    "cryptomap": "CMAP",
    "object": "OBJ",
    "prefixlist": "PFX",
    "keychain": "CHAIN",
    "keyword": "KEY",
    "name": "NAME",
    "chassis": "CHASSIS",
    "domain": "example",
}


@dataclass
class Entry:
    type: str
    real: str
    placeholder: str
    seq: int
    dirty: bool = False


@dataclass
class Mapper:
    keywords: list[str] = field(default_factory=list)
    entries: list[Entry] = field(default_factory=list)
    by_key: dict[tuple[str, str], str] = field(default_factory=dict)
    by_placeholder: dict[str, tuple[str, str]] = field(default_factory=dict)
    token_by_real: dict[str, str] = field(default_factory=dict)
    keyword_cf: dict[str, str] = field(default_factory=dict)
    subnets: dict[tuple[int, int], int] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    next_seq: int = 1
    allocator: Allocator = field(default_factory=Allocator)

    def load_entry(self, type_: str, real: str, placeholder: str, seq: int) -> None:
        self._bind(type_, real, placeholder, seq=seq, dirty=False)

    def new_entries(self) -> list[Entry]:
        return sorted((entry for entry in self.entries if entry.dirty), key=lambda e: e.seq)

    def all_entries(self) -> list[Entry]:
        return sorted(self.entries, key=lambda entry: entry.seq)

    def placeholders(self) -> set[str]:
        return set(self.by_placeholder)

    def reals_of(self, type_: str) -> set[str]:
        return {real for (typ, real) in self.by_key if typ == type_}

    def placeholders_of(self, type_: str) -> set[str]:
        return {placeholder for (typ, _), placeholder in self.by_key.items() if typ == type_}

    def map_value(self, type_: str, real: str) -> str:
        if real == "":
            return real
        key = (type_, real)
        if key in self.by_key:
            return self.by_key[key]
        if type_ in TOKEN_TYPES and real in self.token_by_real:
            return self.token_by_real[real]
        placeholder = self._mint(type_)
        self._bind(type_, real, placeholder, dirty=True)
        return placeholder

    def map_keyword(self, matched: str) -> str:
        folded = matched.casefold()
        existing = self.keyword_cf.get(folded)
        if existing:
            return existing
        placeholder = self._mint("keyword")
        self._bind("keyword", matched, placeholder, dirty=True)
        return placeholder

    def ensure_subnet(self, network: int, prefix: int) -> int:
        mask = prefix_to_mask(prefix)
        network &= mask
        found = self.subnets.get((network, prefix))
        if found is not None:
            return found
        pool = "private" if is_rfc1918(network) else "public"
        fake = self.allocator.allocate(prefix, pool, avoid=network)
        real_s = f"{format_ipv4(network)}/{prefix}"
        fake_s = f"{format_ipv4(fake)}/{prefix}"
        self._bind("subnet", real_s, fake_s, dirty=True)
        return fake

    def map_ip(self, ip_text: str) -> str:
        ip = parse_ipv4(ip_text)
        if is_exempt(ip):
            return ip_text
        match = self._longest(ip)
        if match is None:
            network = ip & 0xFFFFFF00
            fake_net = self.ensure_subnet(network, 24)
            prefix = 24
        else:
            _network, prefix, fake_net = match
        host_mask = (1 << (32 - prefix)) - 1 if prefix < 32 else 0
        if fake_net & host_mask:
            raise MappingCollision("stand-in network is not aligned to its prefix")
        fake_ip = fake_net | (ip & host_mask)
        fake_text = format_ipv4(fake_ip)
        key = ("ipv4", ip_text)
        if key in self.by_key:
            return self.by_key[key]
        self._bind("ipv4", ip_text, fake_text, dirty=True)
        return fake_text

    def _longest(self, ip: int) -> tuple[int, int, int] | None:
        best: tuple[int, int, int] | None = None
        for (network, prefix), fake in self.subnets.items():
            if prefix <= 0:
                continue
            mask = prefix_to_mask(prefix)
            if ip & mask == network and (best is None or prefix > best[1]):
                best = (network, prefix, fake)
        return best

    def _mint(self, type_: str) -> str:
        number = self.counters.get(type_, 0) + 1
        self.counters[type_] = number
        if type_ == "domain":
            return f"example-{number:03d}.local"
        prefix = PREFIX[type_]
        return f"{prefix}-{number:03d}"

    def _bind(
        self,
        type_: str,
        real: str,
        placeholder: str,
        *,
        seq: int | None = None,
        dirty: bool = True,
    ) -> str:
        key = (type_, real)
        if key in self.by_key:
            return self.by_key[key]
        previous = self.by_placeholder.get(placeholder)
        if previous is not None and previous != key:
            raise MappingCollision(f"Placeholder {placeholder} is already in use")
        if seq is None:
            seq = self.next_seq
            self.next_seq += 1
        else:
            self.next_seq = max(self.next_seq, seq + 1)
        self.entries.append(Entry(type_, real, placeholder, seq, dirty))
        self.by_key[key] = placeholder
        self.by_placeholder[placeholder] = key
        self._observe_counter(type_, placeholder)
        if type_ in TOKEN_TYPES:
            self.token_by_real.setdefault(real, placeholder)
        if type_ == "keyword":
            self.keyword_cf.setdefault(real.casefold(), placeholder)
        if type_ == "subnet":
            self._index_subnet(real, placeholder)
        return placeholder

    def _index_subnet(self, real: str, placeholder: str) -> None:
        real_ip, real_prefix = real.split("/")
        fake_ip, fake_prefix = placeholder.split("/")
        prefix = int(real_prefix)
        if int(fake_prefix) != prefix:
            raise MappingCollision("stand-in prefix length does not match the real network")
        network = parse_ipv4(real_ip) & prefix_to_mask(prefix)
        fake = parse_ipv4(fake_ip)
        if prefix_len(prefix_to_mask(prefix)) != prefix:
            raise MappingCollision("invalid subnet prefix")
        self.subnets[(network, prefix)] = fake
        self.allocator.reserve(fake, prefix)

    def _observe_counter(self, type_: str, placeholder: str) -> None:
        if type_ == "domain":
            match = re.fullmatch(r"example-(\d+)\.local", placeholder)
        else:
            prefix = PREFIX.get(type_)
            if not prefix:
                return
            match = re.fullmatch(rf"{re.escape(prefix)}-(\d+)", placeholder)
        if match:
            self.counters[type_] = max(self.counters.get(type_, 0), int(match.group(1)))
