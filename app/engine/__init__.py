"""De-identification engine.

Importing this package registers the built-in vendor modules. The mapper,
restore step, and database are vendor-neutral. Vendor modules only decide
which spans of a configuration are secrets, addresses, or client identifiers.
"""

from app.engine.vendors import cisco_ios as _cisco_ios  # noqa: F401
