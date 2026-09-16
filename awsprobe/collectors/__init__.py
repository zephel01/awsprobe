"""コレクタ群。import すると REGISTRY に自動登録される。"""
from __future__ import annotations

from .base import REGISTRY, Collector, register, jsonable, tag_name  # noqa: F401

# 各コレクタを import して REGISTRY に登録する。順序が収集順になる。
from . import network      # noqa: E402,F401
from . import compute      # noqa: E402,F401
from . import database     # noqa: E402,F401
from . import storage      # noqa: E402,F401
from . import edge         # noqa: E402,F401
from . import serverless   # noqa: E402,F401
from . import logging_     # noqa: E402,F401
from . import security     # noqa: E402,F401

#: 既定の収集順。依存関係は無いが、軽いものから流す。
DEFAULT_ORDER = (
    "network", "compute", "database", "storage",
    "edge", "serverless", "logging", "security",
)

__all__ = ["REGISTRY", "Collector", "register", "jsonable", "tag_name", "DEFAULT_ORDER"]
