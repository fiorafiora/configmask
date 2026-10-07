"""Orchestration. Logs metadata only — never configuration text."""

from __future__ import annotations

import logging
import re

import app.engine  # noqa: F401  (registers vendor modules)
from app.crypto import Vault
from app.db import (
    add_config,
    add_restore,
    get_session_row,
    load_keywords,
    load_mapper,
    load_subnet_settings,
    save_mapper_entries,
    seed_session_subnets,
)
from app.engine.allocator import PoolExhausted
from app.engine.mapper import Mapper
from app.engine.diffview import build_diff, diff_stats
from app.engine.registry import UnknownVendor, get_vendor
from app.engine.restore import restore_text
from app.settings import Settings

log = logging.getLogger("configmask")

TYPE_LABELS = {
    "ipv4": "IPv4",
    "subnet": "Subnet",
    "hostname": "Hostname",
    "domain": "Domain",
    "description": "Description",
    "banner": "Banner",
    "vlan": "VLAN name",
    "snmp_location": "SNMP location",
    "snmp_contact": "SNMP contact",
    "remark": "Remark",
    "acl": "ACL name",
    "routemap": "Route map",
    "cryptomap": "Crypto map",
    "object": "Object group",
    "prefixlist": "Prefix list",
    "keychain": "Key chain",
    "keyword": "Keyword",
    "name": "Name",
    "chassis": "Chassis ID",
    "username": "Username",
}

_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


class ConfigError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def type_label(type_name: str) -> str:
    return TYPE_LABELS.get(type_name, type_name)


def safe_filename(name: str) -> str:
    base = (name or "config.cfg").replace("\\", "/").split("/")[-1]
    cleaned = _FILENAME.sub("_", base).strip("._")[:80]
    return cleaned or "config.cfg"


def safe_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9 _.-]+", "", value or "").strip()
    return cleaned[:60]


def decode_config(data: bytes, limit: int) -> str:
    if len(data) > limit:
        raise ConfigError("too_large")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def sanitize_upload(
    settings: Settings,
    vault: Vault,
    session_id: int,
    text: str,
    *,
    filename: str,
    label: str,
) -> int:
    row = get_session_row(settings.db_path, session_id)
    if row is None:
        raise ConfigError("missing")
    try:
        vendor = get_vendor(row["vendor"])
    except UnknownVendor as exc:
        raise ConfigError("missing") from exc
    keywords = load_keywords(vault, row)
    mapper = Mapper(keywords=keywords)
    keep_ips, rules = load_subnet_settings(vault, row)
    mapper.keep_ips = keep_ips
    for real, stand_in in rules:
        if "/" in real:
            mapper.note_subnet(real, stand_in)
        else:
            mapper.note_host(real, stand_in)
    if mapper.keep_ips:
        mapper.activate_listed_subnets()
    else:
        seed_session_subnets(settings.db_path, vault, session_id, mapper)
    try:
        sanitized = vendor.sanitize(text, mapper)
    except PoolExhausted as exc:
        log.info(
            "sanitize failed session=%s job=%s reason=pool prefix=%s",
            session_id,
            row["job_code"],
            exc.prefix,
        )
        raise ConfigError("pool") from exc
    config_id = add_config(
        settings.db_path,
        vault,
        session_id,
        label=label,
        filename=safe_filename(filename),
        original=text,
        sanitized=sanitized,
    )
    added = save_mapper_entries(settings.db_path, vault, session_id, mapper, config_id)
    log.info(
        "sanitize session=%s job=%s bytes=%s lines=%s new_mappings=%s removed=%s config=%s",
        session_id,
        row["job_code"],
        len(text.encode("utf-8")),
        text.count("\n") + (0 if text.endswith("\n") or text == "" else 1),
        added,
        sanitized.count("<REMOVED>"),
        config_id,
    )
    return config_id


def build_restore(
    settings: Settings,
    vault: Vault,
    session_id: int,
    edited: str,
    compare_config_id: int | None,
) -> int:
    row = get_session_row(settings.db_path, session_id)
    if row is None:
        raise ConfigError("missing")
    keywords = load_keywords(vault, row)
    if compare_config_id is None:
        mapper = Mapper(keywords=keywords)
    else:
        mapper = load_mapper(settings.db_path, vault, session_id, keywords, compare_config_id)
    restored = restore_text(edited, mapper)
    restore_id = add_restore(
        settings.db_path,
        vault,
        session_id,
        compare_config_id=compare_config_id,
        edited=edited,
        restored=restored,
    )
    log.info(
        "restore session=%s job=%s bytes=%s lines=%s restore=%s",
        session_id,
        row["job_code"],
        len(edited.encode("utf-8")),
        edited.count("\n") + 1,
        restore_id,
    )
    return restore_id


def review_restore(edited: str, restored: str, original: str | None, vendor_id: str, mapper):
    vendor = get_vendor(vendor_id)
    issues = vendor.find_issues(edited, mapper)
    rows = build_diff(original, restored) if original is not None else []
    stats = diff_stats(rows) if original is not None else None
    summary: dict[str, int] = {}
    for issue in issues:
        summary[issue.code] = summary.get(issue.code, 0) + 1
    return issues, summary, rows, stats
