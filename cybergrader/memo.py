"""Thread-safe compute-once cache shared by checks that run in parallel."""
from __future__ import annotations

import threading
from typing import Any, Callable


class _Entry:
    __slots__ = ("lock", "done", "value", "error")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.done = False
        self.value: Any = None
        self.error: BaseException | None = None


class Memo:
    """Computes each key once; concurrent callers for the same key wait for the first.

    Exceptions are cached too, so every caller sees the same failure without retrying.
    A compute function must not ask for its own key.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[Any, _Entry] = {}

    def get(self, key: Any, compute: Callable[[], Any]) -> Any:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = _Entry()
        with entry.lock:
            if not entry.done:
                try:
                    entry.value = compute()
                except Exception as exc:
                    entry.error = exc
                entry.done = True
        if entry.error is not None:
            raise entry.error
        return entry.value

    def seed(self, key: Any, value: Any) -> None:
        entry = _Entry()
        entry.value, entry.done = value, True
        with self._lock:
            self._entries[key] = entry

    def peek(self, key: Any, default: Any = None) -> Any:
        """The computed value if it finished without error, else default. Never computes."""
        entry = self._entries.get(key)
        if entry is None or not entry.done or entry.error is not None:
            return default
        return entry.value
