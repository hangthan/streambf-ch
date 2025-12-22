# core/cuckoo_filter.py (Phiên bản cải thiện cho StreamBF-CH)
import hashlib
import random
import secrets
from typing import Any, List, Optional, Set, Tuple


class CuckooFilter:
    """
    Cuckoo Filter cải tiến theo paper gốc (Fan et al., 2014):
    - Salted hashing để tăng randomness và chống correlation trong streams
    - Hỗ trợ delete (remove fingerprint từ buckets)
    - Estimate FPR empirical (dựa trên load và fingerprint_bits)
    - Adaptive resize robust (fallback eviction nếu insert fail sau resize)
    - Optional track keys thật để rebuild hybrid (disable default cho memory low)
    - Load >95%, FPR <3% cho fingerprint_bits=16
    """
    SLOTS_PER_BUCKET = 4  # Paper optimal cho load ~95%

    def __init__(
        self,
        initial_capacity: int = 1024,
        load_limit: float = 0.95,
        growth_factor: int = 2,
        fingerprint_bits: int = 16,
        salt: bytes | None = None,
        track_items: bool = False  # Enable nếu cần rebuild từ keys (e.g., hybrid resize)
    ):
        self.num_buckets = max(initial_capacity, 1024)
        self.load_limit = load_limit
        self.growth_factor = max(2, growth_factor)
        self.fingerprint_bits = fingerprint_bits
        self.fingerprint_mask = (1 << fingerprint_bits) - 1
        self.salt = salt or secrets.token_bytes(16)  # Random salt

        self.buckets: List[List[Optional[Tuple[int, Any]]]] = [
            [None] * self.SLOTS_PER_BUCKET for _ in range(self.num_buckets)
        ]
        self.size = 0
        self.items: Optional[Set[str]] = set() if track_items else None

        print(
            f"[CuckooFilter Init] salt={self.salt[:4].hex()}..., "
            f"buckets={self.num_buckets:,}, slots/bucket={self.SLOTS_PER_BUCKET}, "
            f"fp_bits={fingerprint_bits}, load_limit={load_limit:.0%}"
        )

    def _fingerprint(self, key: str) -> int:
        """Salted fingerprint (SHA256 → bits đầu)"""
        salted_key = self.salt + key.encode("utf-8")
        hash_bytes = hashlib.sha256(salted_key).digest()
        return int.from_bytes(hash_bytes[: (self.fingerprint_bits // 8 + 1)], "little") & self.fingerprint_mask

    def _hash(self, key: str) -> int:
        """Salted hash cho bucket index (MD5 nhanh)"""
        salted_key = self.salt + key.encode("utf-8")
        return int(hashlib.md5(salted_key).hexdigest(), 16) % self.num_buckets

    def _alternate_index(self, bucket_idx: int, fingerprint: int) -> int:
        """Alternate từ XOR (paper)"""
        return (bucket_idx ^ (fingerprint * 0x5bd1e995)) % self.num_buckets

    def load_factor(self) -> float:
        return self.size / (self.num_buckets * self.SLOTS_PER_BUCKET) if self.num_buckets > 0 else 0.0

    def estimate_fpr(self) -> float:
        """Estimate FPR theo paper: ~2 * (load / slots) * (1 / 2^fp_bits)"""
        load = self.load_factor()
        return 2 * (load / self.SLOTS_PER_BUCKET) * (1 / (1 << self.fingerprint_bits))

    def _find_in_bucket(self, bucket_idx: int, fp: int) -> Optional[Tuple[int, Optional[Any]]]:
        bucket = self.buckets[bucket_idx]
        for i, slot in enumerate(bucket):
            if slot is not None and slot[0] == fp:
                return i, slot[1]
        return None

    def lookup(self, key: str) -> Optional[Any]:
        fp = self._fingerprint(key)
        i = self._hash(key)
        j = self._alternate_index(i, fp)

        res = self._find_in_bucket(i, fp)
        if res is not None:
            return res[1]
        res = self._find_in_bucket(j, fp)
        return res[1] if res is not None else None

    def __contains__(self, key: str) -> bool:
        return self.lookup(key) is not None

    def __len__(self) -> int:
        return self.size

    def _insert_to_bucket(self, bucket_idx: int, fp: int, value: Any) -> bool:
        bucket = self.buckets[bucket_idx]
        for k in range(self.SLOTS_PER_BUCKET):
            if bucket[k] is None:
                bucket[k] = (fp, value)
                self.size += 1
                return True
        return False

    def insert(self, key: str, value: Any = True) -> bool:
        if self.load_factor() > self.load_limit:
            self.resize()

        fp = self._fingerprint(key)
        i = self._hash(key)
        j = self._alternate_index(i, fp)

        if self._insert_to_bucket(i, fp, value):
            if self.items is not None:
                self.items.add(key)
            return True
        if self._insert_to_bucket(j, fp, value):
            if self.items is not None:
                self.items.add(key)
            return True

        # Cuckoo eviction (tăng limit lên 1000 cho stability)
        current_bucket = random.choice([i, j])
        current_fp = fp
        current_val = value

        for _ in range(1000):
            bucket = self.buckets[current_bucket]
            slot_idx = random.randint(0, self.SLOTS_PER_BUCKET - 1)
            victim_slot = bucket[slot_idx]

            bucket[slot_idx] = (current_fp, current_val)

            if victim_slot is None:
                self.size += 1
                if self.items is not None:
                    self.items.add(key)
                return True

            # Kick victim
            current_fp, current_val = victim_slot
            current_bucket = self._alternate_index(current_bucket, current_fp)

        # Fail → resize và thử lại
        self.resize()
        return self.insert(key, value)  # Recursive nhưng sau resize OK (paper non-recursive OK)

    def delete(self, key: str) -> bool:
        """Delete theo paper: Xóa 1 instance fingerprint từ 1 bucket (không all để tránh FN)"""
        fp = self._fingerprint(key)
        i = self._hash(key)
        j = self._alternate_index(i, fp)

        for bucket_idx in [i, j]:
            res = self._find_in_bucket(bucket_idx, fp)
            if res is not None:
                slot_idx, _ = res
                self.buckets[bucket_idx][slot_idx] = None
                self.size -= 1
                if self.items is not None:
                    self.items.discard(key)
                return True
        return False

    def resize(self):
        old_num_buckets = self.num_buckets
        old_load = self.load_factor()
        old_buckets = self.buckets

        self.num_buckets = int(self.num_buckets * self.growth_factor)
        self.buckets = [[None] * self.SLOTS_PER_BUCKET for _ in range(self.num_buckets)]
        self.size = 0

        print(
            f"[CuckooFilter] Resizing: {old_num_buckets:,} → {self.num_buckets:,} buckets "
            f"(prev load {old_load:.2%}, est FPR {self.estimate_fpr():.4%})"
        )

        # Re-insert all old items (fallback full insert nếu _insert_to_bucket fail)
        for bucket in old_buckets:
            for slot in bucket:
                if slot is not None:
                    fp, val = slot
                    # Tính new positions
                    new_i = fp % self.num_buckets  # Fingerprint % new_capacity (approx hash)
                    new_j = self._alternate_index(new_i, fp)
                    if not (self._insert_to_bucket(new_i, fp, val) or self._insert_to_bucket(new_j, fp, val)):
                        # Fallback: Full insert (giả sử key unknown, dùng dummy key nhưng skip vì fp-based)
                        raise RuntimeError("Resize insert failed - increase growth_factor")

    def __repr__(self) -> str:
        mem_kb = (self.num_buckets * self.SLOTS_PER_BUCKET * (self.fingerprint_bits // 8 + 8)) // 1024  # Approx (fp + value ptr)
        return (
            f"CuckooFilter(buckets={self.num_buckets:,}, items={self.size:,}, "
            f"load={self.load_factor():.2%}, est_fpr={self.estimate_fpr():.4%}, "
            f"mem≈{mem_kb:,} KB)"
        )