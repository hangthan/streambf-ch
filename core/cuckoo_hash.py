import hashlib

class CuckooHashTable:
    """
    Cuckoo Hash Table cho StreamBF-CH – ĐÃ SỬA BUG growth_factor
    growth_factor luôn là int, cast an toàn khi resize
    """
    def __init__(self, initial_capacity: int = 1024, load_limit: float = 0.9, growth_factor: int = 2):
        if initial_capacity < 1:
            initial_capacity = 1024
        if growth_factor < 2:
            growth_factor = 2  # Phải >=2

        self.capacity = initial_capacity
        self.load_limit = load_limit
        self.growth_factor = growth_factor  # Luôn là int

        self.table1 = [None] * self.capacity
        self.table2 = [None] * self.capacity
        self.size = 0

    def _hash1(self, key: str) -> int:
        return int(hashlib.md5(key.encode()).hexdigest(), 16) % self.capacity

    def _hash2(self, key: str) -> int:
        return int(hashlib.sha1(key.encode()).hexdigest(), 16) % self.capacity

    def _need_resize(self) -> bool:
        return self.size / (2 * self.capacity) > self.load_limit

    def resize(self):
        old_capacity = self.capacity
        old_table1 = self.table1[:]
        old_table2 = self.table2[:]

        # Cast int an toàn, nhân với growth_factor (int)
        self.capacity = int(self.capacity * self.growth_factor)
        self.table1 = [None] * self.capacity
        self.table2 = [None] * self.capacity
        self.size = 0

        print(f"[Cuckoo] Resizing: {old_capacity:,} → {self.capacity:,} (previous load={self.load_factor():.2%})")

        # Re-insert tất cả items cũ
        for table in [old_table1, old_table2]:
            for entry in table:
                if entry is not None:
                    key, value = entry
                    self.insert(key, value)  # Gọi insert để xử lý collision

    def insert(self, key: str, value: any = True) -> bool:
        if self._need_resize():
            self.resize()

        # Thử table1
        pos = self._hash1(key)
        if self.table1[pos] is None:
            self.table1[pos] = (key, value)
            self.size += 1
            return True

        # Thử table2
        pos = self._hash2(key)
        if self.table2[pos] is None:
            self.table2[pos] = (key, value)
            self.size += 1
            return True

        # Eviction chain
        current_key = key
        current_value = value
        for _ in range(500):  # Giới hạn cycles
            # Kick từ table1
            pos = self._hash1(current_key)
            if self.table1[pos] is not None:
                current_key, current_value = self.table1[pos]
                self.table1[pos] = (key, value)
            else:
                self.table1[pos] = (key, value)
                self.size += 1
                return True

            # Kick từ table2
            pos = self._hash2(current_key)
            if self.table2[pos] is not None:
                current_key, current_value = self.table2[pos]
                self.table2[pos] = (key, value)
            else:
                self.table2[pos] = (key, value)
                self.size += 1
                return True

        # Nếu loop quá lâu → resize và thử lại
        self.resize()
        return self.insert(key, value)

    def lookup(self, key: str) -> any:
        pos = self._hash1(key)
        if self.table1[pos] and self.table1[pos][0] == key:
            return self.table1[pos][1]

        pos = self._hash2(key)
        if self.table2[pos] and self.table2[pos][0] == key:
            return self.table2[pos][1]

        return None

    def load_factor(self) -> float:
        return self.size / (2 * self.capacity) if self.capacity > 0 else 0

    def __repr__(self):
        return f"CuckooHashTable(capacity={self.capacity:,}, size={self.size:,}, load={self.load_factor():.2%})"
