"""Cấu trúc dữ liệu cho bản ghi cuckoo hash."""
from __future__ import annotations

from dataclasses import dataclass

from core.types.ip_types import IPKey


@dataclass
class ReputationEntry:
    ip: IPKey
    first_seen: int
    last_seen: int
