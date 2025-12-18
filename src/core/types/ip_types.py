"""Tiện ích khóa IP (chỉ IPv4).

Core yêu cầu lưu khóa IP đã hash (không dùng chuỗi gốc). Module này cung cấp
hàm chuẩn hóa địa chỉ IPv4 thành khóa số nguyên.
"""
from __future__ import annotations

import hashlib
import ipaddress
from typing import NewType

# Alias kiểu để diễn đạt ý nghĩa; lưu dưới dạng int Python (hỗ trợ tới 128-bit).
IPKey = NewType("IPKey", int)


def _hash_bytes(data: bytes) -> int:
    """Trả về băm 128-bit cho bytes đầu vào bằng SHA-256."""
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest[:16], byteorder="big", signed=False)


def ip_to_key(ip: str) -> IPKey:
    """Chuyển IPv4 dạng chuỗi thành IPKey bằng cách băm dạng packed."""
    addr = ipaddress.ip_address(ip)
    if addr.version != 4:
        raise ValueError("Chỉ hỗ trợ IPv4")
    packed = addr.packed
    hashed = _hash_bytes(packed)
    return IPKey(hashed)


def normalize_key(value: int | IPKey) -> IPKey:
    """Đảm bảo giá trị được ép kiểu IPKey."""
    return IPKey(int(value))

