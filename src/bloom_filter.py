import math

class BloomFilter:
    def __init__(self, capacity: int, k_hashes: int = 7):
        """
        Initialize Bloom Filter.
        capacity: số lượng phần tử tối đa mong muốn
        k_hashes: số hàm băm (default=7)
        """
        p = 0.05  # False Positive Rate mong muốn
        self.k = k_hashes
        self.size = int(-(capacity * math.log(p)) / (math.log(2) ** 2))
        self.bit_array = bytearray(math.ceil(self.size / 8))

    def _hashes(self, item: str):
        """
        Sinh ra k giá trị hash cho item.
        Dùng hash() kết hợp chỉ số i để tránh trùng.
        """
        results = []
        for i in range(self.k):
            h = hash(f"{item}_{i}") % self.size
            results.append(h)
        return results

    def add(self, item: str):
        """Thêm item vào Bloom Filter bằng cách set các bit tương ứng."""
        for position in self._hashes(item):
            byte_index = position // 8
            bit_index = position % 8
            self.bit_array[byte_index] |= (1 << bit_index)

    def might_contain(self, item: str) -> bool:
        """Kiểm tra xem item có thể đã tồn tại (membership test)."""
        for position in self._hashes(item):
            byte_index = position // 8
            bit_index = position % 8
            if not (self.bit_array[byte_index] & (1 << bit_index)):
                return False
        return True

    def estimate_fpr(self, n_items: int) -> float:
        """Tính FPR lý thuyết dựa vào công thức: (1 - e^(-k * n / m))^k"""
        m = self.size
        k = self.k
        n = n_items
        return (1 - math.exp(-k * n / m)) ** k
