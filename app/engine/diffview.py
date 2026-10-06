"""Line diff between an original configuration and a restored one."""

from __future__ import annotations

import difflib
from dataclasses import dataclass


@dataclass(frozen=True)
class DiffRow:
    kind: str  # same, del, add, change
    left_no: int | None
    left: str
    right_no: int | None
    right: str


def build_diff(original: str, restored: str) -> list[DiffRow]:
    left_lines = original.splitlines()
    right_lines = restored.splitlines()
    matcher = difflib.SequenceMatcher(a=left_lines, b=right_lines, autojunk=False)
    rows: list[DiffRow] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset, line in enumerate(left_lines[i1:i2]):
                rows.append(
                    DiffRow("same", i1 + offset + 1, line, j1 + offset + 1, right_lines[j1 + offset])
                )
        elif tag == "delete":
            for offset, line in enumerate(left_lines[i1:i2]):
                rows.append(DiffRow("del", i1 + offset + 1, line, None, ""))
        elif tag == "insert":
            for offset, line in enumerate(right_lines[j1:j2]):
                rows.append(DiffRow("add", None, "", j1 + offset + 1, line))
        else:
            left = left_lines[i1:i2]
            right = right_lines[j1:j2]
            width = max(len(left), len(right))
            for offset in range(width):
                rows.append(
                    DiffRow(
                        "change",
                        i1 + offset + 1 if offset < len(left) else None,
                        left[offset] if offset < len(left) else "",
                        j1 + offset + 1 if offset < len(right) else None,
                        right[offset] if offset < len(right) else "",
                    )
                )
    return rows


def diff_stats(rows: list[DiffRow]) -> dict[str, int]:
    return {
        "same": sum(1 for row in rows if row.kind == "same"),
        "changed": sum(1 for row in rows if row.kind == "change"),
        "added": sum(1 for row in rows if row.kind == "add"),
        "removed": sum(1 for row in rows if row.kind == "del"),
    }
