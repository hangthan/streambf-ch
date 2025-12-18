"""Triển khai Bloom filter cho kiểm tra IP sạch cực nhanh."""
from __future__ import annotations

import hashlib
import math
import threading
from typing import Iterable

from core.types.ip_types import IPKey, normalize_key


class BloomFilter:
    def __init__(self, m_bits: int, k_hash: int) -> None:
        """Khởi tạo Bloom Filter với m bit và k hàm băm, dùng lock để thread-safe."""
        if m_bits <= 0:
            raise ValueError("m_bits must be positive")
        if k_hash <= 0:
            raise ValueError("k_hash must be positive")
        self._m = m_bits
        self._k = k_hash
        self._bits = bytearray((m_bits + 7) // 8)
        self._inserted = 0
        self._lock = threading.RLock()

    def insert(self, ip: IPKey) -> None:
        """Thêm một khóa IP vào Bloom filter (đặt k bit tương ứng)."""
        key = normalize_key(ip)
        positions = self._positions(key)
        with self._lock:
            for pos in positions:
                self._set_bit(pos)
            self._inserted += 1

    def insert_many(self, keys: Iterable[IPKey]) -> None:
        """Thêm nhiều khóa IP tuần tự vào Bloom filter."""
        for key in keys:
            self.insert(key)

    def might_contain(self, ip: IPKey) -> bool:
        """Kiểm tra nhanh khả năng tồn tại: trả false chắc chắn sạch, true có thể (có FPR)."""
        key = normalize_key(ip)
        positions = self._positions(key)
        with self._lock:
            return all(self._get_bit(pos) for pos in positions)

    def estimate_fpr(self) -> float:
        """Ước lượng xác suất dương tính giả dựa trên công thức Bloom chuẩn."""
        with self._lock:
            m = float(self._m)
            k = float(self._k)
            n = float(self._inserted)
        if m == 0:
            return 1.0
        exponent = -k * n / m
        return (1.0 - math.exp(exponent)) ** k

    def get_inserted_count(self) -> int:
        """Trả về số phần tử đã chèn (đếm logic, không khử trùng lặp)."""
        with self._lock:
            return self._inserted

    def m_bits(self) -> int:
        """Lấy tổng số bit của Bloom filter."""
        with self._lock:
            return self._m

    def k_hash(self) -> int:
        """Lấy số hàm băm đang dùng."""
        with self._lock:
            return self._k

    # Hàm nội bộ
    def _positions(self, key: IPKey) -> list[int]:
        """Sinh k vị trí bit bằng double hashing (SHA-256) trên khóa IP chuẩn hóa."""
        key_bytes = int(key).to_bytes(16, byteorder="big", signed=False)
        h1 = int.from_bytes(hashlib.sha256(b"bf1" + key_bytes).digest(), "big")
        h2 = int.from_bytes(hashlib.sha256(b"bf2" + key_bytes).digest(), "big")
        positions = []
        for i in range(self._k):
            combined = (h1 + i * h2) % self._m
            positions.append(int(combined))
        return positions

    def _set_bit(self, pos: int) -> None:
        """Đặt bit ở vị trí pos trong mảng bit."""
        byte_index = pos // 8
        bit_index = pos % 8
        self._bits[byte_index] |= 1 << bit_index

    def _get_bit(self, pos: int) -> bool:
        """Đọc bit ở vị trí pos trong mảng bit."""
        byte_index = pos // 8
        bit_index = pos % 8
        return (self._bits[byte_index] & (1 << bit_index)) != 0
