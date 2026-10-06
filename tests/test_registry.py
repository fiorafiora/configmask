"""Vendor modules register without the mapper knowing about IOS."""

import app.engine  # noqa: F401  (registers cisco_ios)
from app.engine.issues import Issue
from app.engine.mapper import Mapper
from app.engine.registry import available_vendors, get_vendor, register, unregister


class _FortiStub:
    id = "fortios"
    label = "FortiOS"

    def sanitize(self, text: str, mapper: Mapper) -> str:
        return text

    def find_issues(self, text: str, mapper: Mapper) -> list[Issue]:
        return []


def test_cisco_is_registered_and_another_vendor_can_be_added():
    vendors = {vendor.id: vendor.label for vendor in available_vendors()}
    assert vendors["cisco_ios"] == "Cisco IOS / IOS-XE"
    register(_FortiStub())
    try:
        assert get_vendor("fortios").label == "FortiOS"
        assert get_vendor("fortios").sanitize("set hostname edge\n", Mapper()) == "set hostname edge\n"
    finally:
        unregister("fortios")
    vendors = {vendor.id for vendor in available_vendors()}
    assert "fortios" not in vendors
    assert "cisco_ios" in vendors
