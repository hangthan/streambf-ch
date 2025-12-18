"""Tiện ích tham số Bloom filter."""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class BloomParams:
    m_bits: int
    k_hash: int

    @staticmethod
    def for_capacity(expected_items: int, target_fpr: float) -> "BloomParams":
        """Tính m (bit) và k (số hash) tối ưu cho sức chứa và FPR mong muốn."""
        if expected_items <= 0:
            raise ValueError("expected_items must be positive")
        if not (0 < target_fpr < 1):
            raise ValueError("target_fpr must be in (0,1)")

        m = -expected_items * math.log(target_fpr) / (math.log(2) ** 2)
        m_bits = max(8, int(math.ceil(m)))
        k = max(1, int(round((m_bits / expected_items) * math.log(2))))
        return BloomParams(m_bits=m_bits, k_hash=k)
