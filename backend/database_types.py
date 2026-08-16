from __future__ import annotations

from typing import Any

from sqlalchemy import String
from sqlalchemy.types import TypeDecorator


UINT64_MAX = 2**64 - 1
UINT64_STORAGE_WIDTH = 20


class UInt64Decimal(TypeDecorator[int]):
    """Store a UINT64 as fixed-width decimal text without precision loss."""

    impl = String(UINT64_STORAGE_WIDTH)
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> str | None:
        if value is None:
            return None
        if type(value) is not int or not 0 <= value <= UINT64_MAX:
            raise ValueError("UINT64 database value is outside its bound")
        return f"{value:0{UINT64_STORAGE_WIDTH}d}"

    def process_result_value(self, value: Any, dialect: Any) -> int | None:
        if value is None:
            return None
        if not isinstance(value, str) or len(value) != UINT64_STORAGE_WIDTH:
            raise ValueError("stored UINT64 database value is not canonical")
        if not value.isascii() or not value.isdigit():
            raise ValueError("stored UINT64 database value is not decimal")
        number = int(value)
        if not 0 <= number <= UINT64_MAX:
            raise ValueError("stored UINT64 database value is outside its bound")
        if value != f"{number:0{UINT64_STORAGE_WIDTH}d}":
            raise ValueError("stored UINT64 database value is not canonical")
        return number


__all__ = ["UINT64_MAX", "UINT64_STORAGE_WIDTH", "UInt64Decimal"]
