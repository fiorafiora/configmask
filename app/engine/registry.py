"""Vendor module registry.

ConfigMask ships with Cisco IOS / IOS-XE. FortiOS and Sangfor can be added
without changing the mapper, the database, or the restore step:

1. Add ``app/engine/vendors/<vendor>.py`` with a class that exposes
   ``id``, ``label``, ``sanitize(text, mapper) -> str``, and
   ``find_issues(text, mapper) -> list[Issue]``.
2. Register an instance from ``app/engine/vendors/__init__.py``.
3. New sessions store that vendor id. Existing sessions keep the id they
   were created with.
"""

from __future__ import annotations

from typing import Protocol

from app.engine.issues import Issue
from app.engine.mapper import Mapper


class Vendor(Protocol):
    id: str
    label: str

    def sanitize(self, text: str, mapper: Mapper) -> str: ...

    def find_issues(self, text: str, mapper: Mapper) -> list[Issue]: ...


class UnknownVendor(KeyError):
    def __init__(self, vendor_id: str):
        self.vendor_id = vendor_id
        super().__init__(vendor_id)


_REGISTRY: dict[str, Vendor] = {}


def register(vendor: Vendor) -> None:
    _REGISTRY[vendor.id] = vendor


def unregister(vendor_id: str) -> None:
    _REGISTRY.pop(vendor_id, None)


def get_vendor(vendor_id: str) -> Vendor:
    try:
        return _REGISTRY[vendor_id]
    except KeyError as exc:
        raise UnknownVendor(vendor_id) from exc


def available_vendors() -> list[Vendor]:
    return list(_REGISTRY.values())
