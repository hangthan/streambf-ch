# core/bloom_filter.py (Phiên bản cải thiện cho StreamBF-CH)
import math
import mmh3
import os
import secrets
from bitarray import bitarray
from typing import Iterable, Set


class BloomFilter:
    """
    Bloom Filter cải tiến cho StreamBF-CH:
    - Salted hashing để tăng randomness và giảm correlation
    - Derive k hashes từ 2 hash calls (nhanh hơn)
    - Hỗ trợ adaptive resize (rebuild khi FPR cao)
    - Theo dõi items để resize chính xác (không mất dữ liệu)
    - Estimate FPR thực tế tốt hơn
    """
    def __init__(
        self,
        expected_items: int,
        false_positive_rate: float = 0.05,
        salt: bytes | None = None
    ):
        if expected_items <= 0 or not (0 < false_positive_rate < 1):
            raise ValueError("expected_items > 0 và fpr trong (0,1)")

        self.fpr_target = false_positive_rate
        self.expected_items = expected_items
        self.salt = salt or secrets.token_bytes(16)  # Random salt mỗi instance

        # Công thức chuẩn
        self.size = self._optimal_size(expected_items, false_positive_rate)
        self.hash_count = self._optimal_hash_count(self.size, expected_items)

        self.bit_array = bitarray(self.size)
        self.bit_array.setall(0)

        self.inserted_count = 0
        self.items: Set[str] = set()  # Lưu items thật để resize (malicious ít → OK)

        print(
            f"[BloomFilter Init] salt={self.salt[:4].hex()}..., "
            f"m={self.size:,} bits (~{self.size//8//1024:.1f} KB), "
            f"k={self.hash_count} hashes, expected_n={expected_items:,}, "
            f"target_fpr={false_positive_rate:.2%}"
        )

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        return max(1, int(-(n * math.log(p)) / (math.log(2) ** 2)))

    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        return max(1, int((m / n) * math.log(2)))

    def _hashes(self, item: str) -> list[int]:
        """Derive k hashes từ 2 hash128 calls (nhanh & uniform)"""
        seed = self.salt + item.encode("utf-8")
        h1 = mmh3.hash128(seed, seed=0)
        h2 = mmh3.hash128(seed, seed=42)  # Seed khác để independent
        hashes = []
        for i in range(self.hash_count):
            # Kirsch-Mitzenmacher mitigation: g_i = h1 + i*h2
            h = (h1 + i * h2) % self.size
            hashes.append(int(h))
        return hashes

    def add(self, item: str):
        """Thêm item (lưu cả item thật để resize sau)"""
        for idx in self._hashes(item):
            self.bit_array[idx] = True
        self.inserted_count += 1
        self.items.add(item)

    def check(self, item: str) -> bool:
        for idx in self._hashes(item):
            if not self.bit_array[idx]:
                return False
        return True

    def __contains__(self, item: str) -> bool:
        return self.check(item)

    def __len__(self) -> int:
        return self.inserted_count

    def estimate_fpr(self) -> float:
        """Estimate FPR dựa trên saturation thực tế"""
        if self.inserted_count == 0:
            return 0.0
        filled_ratio = self.bit_array.count(1) / self.size # dùng xấp xỉ (số bit 1/m)
        return filled_ratio ** self.hash_count

    def resize(self, growth_factor: float = 2.0):
        """
        Adaptive resize: Tăng size để giảm FPR
        Re-add tất cả items từ self.items (chỉ malicious → nhanh)
        """
        new_expected = int(self.expected_items * growth_factor)
        new_fpr = self.fpr_target  # Giữ target FPR

        print(f"[BloomFilter] Adaptive resize: {self.expected_items:,} → {new_expected:,} items")

        new_bf = BloomFilter(expected_items=new_expected, false_positive_rate=new_fpr, salt=self.salt)

        for item in self.items:
            new_bf.add(item)

        # Copy thuộc tính sang
        self.size = new_bf.size
        self.hash_count = new_bf.hash_count
        self.bit_array = new_bf.bit_array
        self.expected_items = new_bf.expected_items
        self.inserted_count = new_bf.inserted_count
        # items giữ nguyên (đã re-add)

    def union(self, other: "BloomFilter") -> "BloomFilter":
        """Union 2 Bloom Filters (OR bit_array)"""
        if self.size != other.size or self.hash_count != other.hash_count:
            raise ValueError("Bloom filters phải cùng size & hash_count để union")
        new_bf = BloomFilter(self.expected_items + other.expected_items, self.fpr_target)
        new_bf.bit_array = self.bit_array | other.bit_array
        new_bf.inserted_count = self.inserted_count + other.inserted_count
        return new_bf

    def __repr__(self) -> str:
        current_fpr = self.estimate_fpr()
        return (
            f"BloomFilter(m={self.size:,} bits, k={self.hash_count}, "
            f"inserted={self.inserted_count:,}, "
            f"current_fpr≈{current_fpr:.4%}, target_fpr={self.fpr_target:.2%})"
        )