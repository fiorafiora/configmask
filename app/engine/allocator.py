"""Stand-in IPv4 pools.

RFC 1918 networks are rewritten into 10.0.0.0/8.
Other unicast networks are rewritten into 198.18.0.0/15 (RFC 2544
benchmarking space) and, if that fills up, 100.64.0.0/10 (RFC 6598).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.engine.iputil import format_ipv4


class PoolExhausted(Exception):
    def __init__(self, pool: str, prefix: int):
        self.pool = pool
        self.prefix = prefix
        super().__init__(
            f"No room left in the {pool} stand-in pool for a /{prefix} network."
        )


class MappingCollision(Exception):
    pass


@dataclass(frozen=True)
class _Pool:
    name: str
    base: int
    size: int


def _align_up(value: int, block: int) -> int:
    if block <= 1:
        return value
    return (value + block - 1) & ~(block - 1)


class Allocator:
    def __init__(self) -> None:
        self.pools = {
            "private": _Pool("private", 0x0A000000, 1 << 24),  # 10.0.0.0/8
            "public": _Pool("public", 0xC6120000, 1 << 17),  # 198.18.0.0/15
            "public2": _Pool("public2", 0x64400000, 1 << 22),  # 100.64.0.0/10
        }
        self.used: list[tuple[int, int]] = []

    def reserve(self, start: int, prefix: int) -> None:
        block = 1 << (32 - prefix)
        end = start + block
        for existing_start, existing_end in self.used:
            if existing_start == start and existing_end == end:
                return
            if existing_start < end and start < existing_end:
                raise MappingCollision(
                    "Stand-in network "
                    f"{format_ipv4(start)}/{prefix} overlaps an existing allocation"
                )
        self.used.append((start, end))
        self.used.sort()

    def allocate(self, prefix: int, pool_name: str) -> int:
        if prefix < 8 or prefix > 30:
            raise PoolExhausted(pool_name, prefix)
        names = ("public", "public2") if pool_name == "public" else (pool_name,)
        last: PoolExhausted | None = None
        for name in names:
            try:
                return self._allocate_in(prefix, self.pools[name])
            except PoolExhausted as exc:
                last = exc
        assert last is not None
        raise last

    def _allocate_in(self, prefix: int, pool: _Pool) -> int:
        block = 1 << (32 - prefix)
        if block > pool.size:
            raise PoolExhausted(pool.name, prefix)
        limit = pool.base + pool.size
        cursor = _align_up(pool.base, block)
        while cursor + block <= limit:
            conflict_end: int | None = None
            for start, end in self.used:
                if cursor + block <= start:
                    break
                if cursor < end and start < cursor + block:
                    conflict_end = end
                    break
            if conflict_end is None:
                self.used.append((cursor, cursor + block))
                self.used.sort()
                return cursor
            cursor = _align_up(conflict_end, block)
        raise PoolExhausted(pool.name, prefix)
