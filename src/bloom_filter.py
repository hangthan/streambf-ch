# -*- coding: utf-8 -*-
"""
Bloom Filter core module.
"""

import math


class BloomFilter:
    def __init__(self, capacity: int, k_hashes: int = 7):
        """Khởi tạo Bloom Filter."""
        self.capacity = capacity
        self.k = k_hashes

        p_target = 0.03  # FPR mục tiêu
        m_real = -(capacity * math.log(p_target)) / (math.log(2) ** 2)
        self.size = math.ceil(m_real)
        self.bit_array = bytearray(math.ceil(self.size / 8))

    def _hashes(self, item: str):
        """Sinh k giá trị hash trong [0, m)."""
        results = []
        for i in range(self.k):
            h = hash(f"{item}_{i}") % self.size
            results.append(h)
        return results

    def add(self, item: str) -> None:
        """Thêm item vào Bloom Filter."""
        for pos in self._hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            self.bit_array[byte_index] |= (1 << bit_index)

    def might_contain(self, item: str) -> bool:
        """Kiểm tra item có thể tồn tại."""
        for pos in self._hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            if not (self.bit_array[byte_index] & (1 << bit_index)):
                return False
        return True

    def estimate_fpr(self, n_items: int) -> float:
        """Tính FPR lý thuyết."""
        m, k, n = self.size, self.k, n_items
        return (1 - math.exp(-k * n / m)) ** k
