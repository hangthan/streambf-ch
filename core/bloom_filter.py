import math
import mmh3
from bitarray import bitarray

class BloomFilter:
    """
    Bloom Filter từ scratch cho dự án StreamBF-CH
    Hỗ trợ: add, check, estimate_fpr
    Tự động tính m và k theo công thức chuẩn
    """
    def __init__(self, expected_items: int, false_positive_rate: float = 0.05):
        if expected_items <= 0 or false_positive_rate <= 0 or false_positive_rate >= 1:
            raise ValueError("expected_items phải > 0 và fpr phải trong (0,1)")

        self.fpr_target = false_positive_rate
        self.expected_items = expected_items

        # Công thức chuẩn
        self.size = self._optimal_size(expected_items, false_positive_rate)
        self.hash_count = self._optimal_hash_count(self.size, expected_items)

        self.bit_array = bitarray(self.size)
        self.bit_array.setall(0)

        self.inserted_count = 0

        print(f"[BloomFilter Init] m={self.size:,} bits (~{self.size//8/1024:.1f} KB), "
              f"k={self.hash_count} hashes, expected_n={expected_items:,}, target_fpr={false_positive_rate:.2%}")

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        return max(1, int(-(n * math.log(p)) / (math.log(2) ** 2)))

    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        return max(1, int((m / n) * math.log(2)))

    def add(self, item: str):
        for seed in range(self.hash_count):
            index = mmh3.hash(item, seed) % self.size
            self.bit_array[index] = True
        self.inserted_count += 1

    def check(self, item: str) -> bool:
        for seed in range(self.hash_count):
            index = mmh3.hash(item, seed) % self.size
            if not self.bit_array[index]:
                return False
        return True

    def estimate_fpr(self) -> float:
        if self.inserted_count == 0:
            return 0.0
        return (1 - math.exp(-self.hash_count * self.inserted_count / self.size)) ** self.hash_count

    def __len__(self):
        return self.inserted_count

    def __repr__(self):
        current_fpr = self.estimate_fpr()
        return (f"BloomFilter(m={self.size:,} bits, k={self.hash_count}, "
                f"inserted={self.inserted_count:,}, current_fpr≈{current_fpr:.4%})")
