"""Built-in vendor rule modules.

To add FortiOS or Sangfor later, create a sibling module, implement
``sanitize`` and ``find_issues``, and register the class here. The session
record stores the vendor id; mapper and restore stay shared.
"""

from app.engine.vendors.cisco_ios import CiscoIOSVendor
from app.engine.registry import register

register(CiscoIOSVendor())
