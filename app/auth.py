"""Single-admin gate. The password hash lives in memory; the env value is not logged."""

from __future__ import annotations

import time
from threading import Lock


class LoginGuard:
    def __init__(self, limit: int = 8, lock_seconds: int = 60):
        self.limit = limit
        self.lock_seconds = lock_seconds
        self._fails = 0
        self._locked_until = 0.0
        self._lock = Lock()

    def allowed(self) -> bool:
        with self._lock:
            return time.monotonic() >= self._locked_until

    def record_failure(self) -> None:
        with self._lock:
            self._fails += 1
            if self._fails >= self.limit:
                self._locked_until = time.monotonic() + self.lock_seconds
                self._fails = 0

    def record_success(self) -> None:
        with self._lock:
            self._fails = 0
            self._locked_until = 0.0
