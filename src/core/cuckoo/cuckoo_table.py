"""Bảng băm cuckoo lưu chính xác danh tiếng IP."""
from __future__ import annotations

import hashlib
import threading
from typing import Iterator, Optional

from core.cuckoo.cuckoo_entry import ReputationEntry
from core.types.ip_types import IPKey, normalize_key


class CuckooHashTable:
    def __init__(self, capacity: int = 2048, max_kicks: int = 500) -> None:
        """Khởi tạo bảng băm cuckoo với dung lượng gần lũy thừa 2 và giới hạn số lần đẩy."""
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = self._next_power_of_two(capacity)
        self._max_kicks = max_kicks
        self._table: list[Optional[ReputationEntry]] = [None] * self._capacity
        self._size = 0
        self._rehash_count = 0
        self._lock = threading.RLock()

    def insert(self, ip: IPKey, entry: ReputationEntry) -> bool:
        """Chèn hoặc cập nhật entry; dùng chiến lược cuckoo, rehash khi cần."""
        key = normalize_key(ip)
        with self._lock:
            if self.load_factor() >= 0.9:
                self._rehash(self._capacity * 2)

            if self._place_if_present(key, entry):
                return True

            new_entry = entry
            for kick in range(self._max_kicks):
                pos1 = self._hash1(key)
                pos2 = self._hash2(key)
                if self._try_place(pos1, new_entry) or self._try_place(pos2, new_entry):
                    return True

                # Hoán đổi với một trong hai vị trí ứng viên
                pos = pos1 if (kick % 2 == 0) else pos2
                self._table[pos], new_entry = new_entry, self._table[pos]  # type: ignore[misc]
                key = new_entry.ip  # type: ignore[assignment]

            # Nếu chèn thất bại sau max_kicks, rehash rồi thử lại một lần
            self._rehash(self._capacity * 2)
            return self.insert(key, new_entry)

    def contains(self, ip: IPKey) -> bool:
        """Kiểm tra sự tồn tại của IP."""
        return self.get(ip) is not None

    def get(self, ip: IPKey) -> Optional[ReputationEntry]:
        """Truy xuất entry của IP ở một trong hai vị trí hash, nếu có."""
        key = normalize_key(ip)
        with self._lock:
            pos1 = self._hash1(key)
            entry = self._table[pos1]
            if entry is not None and entry.ip == key:
                return entry
            pos2 = self._hash2(key)
            entry = self._table[pos2]
            if entry is not None and entry.ip == key:
                return entry
            return None

    def remove(self, ip: IPKey) -> bool:
        """Xóa entry nếu tồn tại ở bất kỳ vị trí hash nào."""
        key = normalize_key(ip)
        with self._lock:
            pos1 = self._hash1(key)
            if self._table[pos1] is not None and self._table[pos1].ip == key:
                self._table[pos1] = None
                self._size -= 1
                return True
            pos2 = self._hash2(key)
            if self._table[pos2] is not None and self._table[pos2].ip == key:
                self._table[pos2] = None
                self._size -= 1
                return True
            return False

    def __iter__(self) -> Iterator[ReputationEntry]:
        """Trả về snapshot iterator các entry để tránh xung đột khi lock."""
        with self._lock:
            snapshot = [e for e in self._table if e is not None]
        return iter(snapshot)

    def load_factor(self) -> float:
        """Tính hệ số tải hiện tại (size/capacity)."""
        with self._lock:
            return self._size / float(self._capacity)

    def __len__(self) -> int:
        """Số entry hiện có."""
        with self._lock:
            return self._size

    def rehash_count(self) -> int:
        """Số lần đã thực hiện rehash."""
        with self._lock:
            return self._rehash_count

    def capacity(self) -> int:
        """Dung lượng hiện tại của bảng (số slot)."""
        with self._lock:
            return self._capacity

    def maybe_rehash(self, load_limit: float = 0.9, growth_factor: int = 2) -> tuple[bool, int, int, float]:
        """Nếu load_factor vượt ngưỡng thì rehash và trả về (đã_rehash, old_cap, new_cap, load_factor_trước)."""
        with self._lock:
            load_factor = self._size / float(self._capacity) if self._capacity else 0.0
            if load_limit <= 0:
                return False, self._capacity, self._capacity, load_factor
            if load_factor < load_limit:
                return False, self._capacity, self._capacity, load_factor

            old_cap = self._capacity
            new_cap = max(1, int(old_cap * growth_factor))
            self._rehash(new_cap)
            return True, old_cap, self._capacity, load_factor

    # Hàm nội bộ
    def _try_place(self, pos: int, entry: ReputationEntry) -> bool:
        """Thử đặt entry vào vị trí; ghi đè nếu trùng khóa, trả True khi đặt được."""
        current = self._table[pos]
        if current is None:
            self._table[pos] = entry
            self._size += 1
            return True
        if current.ip == entry.ip:
            self._table[pos] = entry
            return True
        return False

    def _place_if_present(self, key: IPKey, entry: ReputationEntry) -> bool:
        """Nếu key đã tồn tại ở pos1/pos2 thì ghi đè entry mới và trả True."""
        pos1 = self._hash1(key)
        if self._table[pos1] is not None and self._table[pos1].ip == key:
            self._table[pos1] = entry
            return True
        pos2 = self._hash2(key)
        if self._table[pos2] is not None and self._table[pos2].ip == key:
            self._table[pos2] = entry
            return True
        return False

    def _rehash(self, new_capacity: int) -> None:
        """Mở rộng bảng (lũy thừa 2), chèn lại toàn bộ entry và tăng bộ đếm rehash."""
        new_capacity = self._next_power_of_two(new_capacity)
        old_entries = [e for e in self._table if e is not None]
        self._rehash_count += 1
        self._capacity = new_capacity
        self._table = [None] * self._capacity
        self._size = 0
        for entry in old_entries:
            self.insert(entry.ip, entry)

    def _hash1(self, key: IPKey) -> int:
        """Hàm băm thứ nhất dùng SHA-256 với seed riêng, trả về chỉ số slot."""
        key_bytes = int(key).to_bytes(16, byteorder="big", signed=False)
        digest = hashlib.sha256(b"cuckoo1" + key_bytes).digest()
        return int.from_bytes(digest[:8], "big") % self._capacity

    def _hash2(self, key: IPKey) -> int:
        """Hàm băm thứ hai độc lập, dùng phần khác của SHA-256 để tạo chỉ số slot."""
        key_bytes = int(key).to_bytes(16, byteorder="big", signed=False)
        digest = hashlib.sha256(b"cuckoo2" + key_bytes).digest()
        return int.from_bytes(digest[8:16], "big") % self._capacity

    @staticmethod
    def _next_power_of_two(n: int) -> int:
        """Lấy lũy thừa 2 gần nhất >= n (bit-twiddling)."""
        n -= 1
        n |= n >> 1
        n |= n >> 2
        n |= n >> 4
        n |= n >> 8
        n |= n >> 16
        n |= n >> 32
        return n + 1
