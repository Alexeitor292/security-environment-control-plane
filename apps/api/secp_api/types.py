"""Custom SQLAlchemy column types.

``EnumType`` stores a Python ``str``-``Enum`` as a portable VARCHAR but returns the
enum instance on load, so ``Mapped[SomeEnum]`` annotations are accurate and
``.value`` access is always safe across SQLite and PostgreSQL.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from sqlalchemy import String
from sqlalchemy.types import TypeDecorator


class EnumType(TypeDecorator):
    impl = String
    cache_ok = True

    def __init__(self, enum_cls: type[Enum], length: int = 40, **kw: Any) -> None:
        self.enum_cls = enum_cls
        super().__init__(length=length, **kw)

    def process_bind_param(self, value: Any, dialect: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, self.enum_cls):
            return value.value
        return str(value)

    def process_result_value(self, value: Any, dialect: Any) -> Enum | None:
        if value is None:
            return None
        return self.enum_cls(value)
