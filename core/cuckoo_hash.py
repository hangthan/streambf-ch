import hashlib
from typing import List, Tuple, Any, Optional

class CuckooHashTable:
    """
    Cuckoo Hash Table cải tiến cho StreamBF-CH (gần với Cuckoo Filter gốc)
    - Fingerprint storage (16 bits) → memory thấp, load factor cao ~95%
    - Non-recursive resize → không MemoryError
    - Dễ tích hợp với Bloom Filter trong hybrid
    """
    def __init__(
        self,
        initial_capacity: int = 1024,
        load_limit: float = 0.95,
        growth_factor: int = 2,
        fingerprint_bits: int = 16
    ):
        self.capacity = max(1024, initial_capacity)
        self.load_limit = load_limit
        self.growth_factor = int(growth_factor)
        self.fingerprint_bits = fingerprint_bits
        self.fingerprint_mask = (1 << fingerprint_bits) - 1

        self.table1: List[Optional[Tuple[int, Any]]] = [None] * self.capacity
        self.table2: List[Optional[Tuple[int, Any]]] = [None] * self.capacity
        self.size = 0

    def _fingerprint(self, key: str) -> int:
        """Tính fingerprint ngắn từ key (SHA256 → 16 bits)"""
        hash_bytes = hashlib.sha256(key.encode()).digest()
        fp = int.from_bytes(hash_bytes[:2], 'little')  # 16 bits đầu
        return fp & self.fingerprint_mask

    def _hash1(self, key: str) -> int:
        return int(hashlib.md5(key.encode()).hexdigest(), 16) % self.capacity

    def _hash2(self, fingerprint: int, pos1: int) -> int:
        """Tính vị trí thay thế từ fingerprint XOR với pos1 (theo paper Cuckoo Filter)"""
        return (pos1 ^ fingerprint) % self.capacity

    def load_factor(self) -> float:
        return self.size / (2 * self.capacity)

    def _need_resize(self) -> bool:
        return self.load_factor() > self.load_limit

    def resize(self):
        old_capacity = self.capacity
        old_items = []

        # Thu thập tất cả (fingerprint, value) từ 2 table cũ
        for table in [self.table1, self.table2]:
            for entry in table:
                if entry is not None:
                    old_items.append(entry)

        # Tăng capacity và tạo table mới
        self.capacity = int(self.capacity * self.growth_factor)
        self.table1 = [None] * self.capacity
        self.table2 = [None] * self.capacity
        self.size = 0

        print(f"[Cuckoo] Resizing: {old_capacity:,} → {self.capacity:,} (prev load {self.load_factor():.2%})")

        # Re-insert non-recursive
        for fp, value in old_items:
            self._insert_fingerprint(fp, value)

    def _insert_fingerprint(self, fingerprint: int, value):
        """Insert chỉ dùng fingerprint – không gọi resize (dùng cho rehash)"""
        pos = fingerprint % self.capacity  # Vị trí đầu tiên

        # Thử chèn vào table1
        if self.table1[pos] is None:
            self.table1[pos] = (fingerprint, value)
            self.size += 1
            return True

        # Thử table2
        alt_pos = self._hash2(fingerprint, pos)
        if self.table2[alt_pos] is None:
            self.table2[alt_pos] = (fingerprint, value)
            self.size += 1
            return True

        # Cuckoo eviction ngắn (giới hạn 50 lần để an toàn khi rehash)
        current_pos = alt_pos if self.table2[alt_pos] is not None else pos
        current_fp = fingerprint
        current_value = value

        for _ in range(50):
            # Kick từ table hiện tại
            if current_pos < self.capacity and self.table1[current_pos] is not None:
                current_fp, current_value = self.table1[current_pos]
                self.table1[current_pos] = (fingerprint, value)
            elif self.table2[current_pos] is not None:
                current_fp, current_value = self.table2[current_pos]
                self.table2[current_pos] = (fingerprint, value)
            else:
                # Tìm slot trống
                if current_pos < self.capacity:
                    self.table1[current_pos] = (fingerprint, value)
                else:
                    self.table2[current_pos] = (fingerprint, value)
                self.size += 1
                return True

            # Tính vị trí mới cho victim
            current_pos = self._hash2(current_fp, current_pos % self.capacity)

        # Nếu vẫn không được (rất hiếm sau resize) → bỏ qua
        return False

    def insert(self, key: str, value: any = True) -> bool:
        if self._need_resize():
            self.resize()

        fingerprint = self._fingerprint(key)
        pos1 = fingerprint % self.capacity
        pos2 = self._hash2(fingerprint, pos1)

        # Thử chèn trực tiếp
        if self.table1[pos1] is None:
            self.table1[pos1] = (fingerprint, value)
            self.size += 1
            return True
        if self.table2[pos2] is None:
            self.table2[pos2] = (fingerprint, value)
            self.size += 1
            return True

        # Cuckoo eviction (giới hạn 200 lần)
        current_fp = fingerprint
        current_value = value
        current_pos = pos1

        for _ in range(200):
            # Kick victim
            if self.table1[current_pos] is not None:
                current_fp, current_value = self.table1[current_pos]
                self.table1[current_pos] = (fingerprint, value)
            elif self.table2[current_pos] is not None:
                current_fp, current_value = self.table2[current_pos]
                self.table2[current_pos] = (fingerprint, value)
            else:
                # Slot trống
                if current_pos < self.capacity:
                    self.table1[current_pos] = (fingerprint, value)
                else:
                    self.table2[current_pos] = (fingerprint, value)
                self.size += 1
                return True

            # Tính vị trí mới cho victim
            current_pos = self._hash2(current_fp, current_pos % self.capacity)

        # Nếu quá lâu → resize và thử lại
        self.resize()
        return self.insert(key, value)

    def lookup(self, key: str) -> any:
        fingerprint = self._fingerprint(key)
        pos1 = fingerprint % self.capacity
        pos2 = self._hash2(fingerprint, pos1)

        if self.table1[pos1] and self.table1[pos1][0] == fingerprint: # type: ignore
            return self.table1[pos1][1] # type: ignore
        if self.table2[pos2] and self.table2[pos2][0] == fingerprint: # type: ignore
            return self.table2[pos2][1] # type: ignore

        return None

    def __repr__(self):
        return f"CuckooHashTable(cap={self.capacity:,}, size={self.size:,}, load={self.load_factor():.2%})"