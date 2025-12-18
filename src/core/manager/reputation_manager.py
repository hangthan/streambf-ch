"""Trình quản lý danh tiếng điều phối Bloom + Cuckoo (không dùng điểm)."""
from __future__ import annotations

import time
import math
from enum import Enum, auto
from typing import Optional

from core.bloom.bloom_filter import BloomFilter
from core.cuckoo.cuckoo_entry import ReputationEntry
from core.cuckoo.cuckoo_table import CuckooHashTable
from core.metrics.metrics import Metrics
from core.types.ip_types import IPKey, normalize_key


class CheckResult(Enum):
    CLEAN = auto()
    MALICIOUS = auto()
    BLOOM_FALSE_POSITIVE = auto()


class ReputationManager:
    def __init__(
        self,
        bloom: BloomFilter,
        cuckoo: CuckooHashTable,
        fpr_limit: float = 0.05,
        cuckoo_load_limit: float = 0.9,
        cuckoo_growth_factor: int = 2,
        metrics: Optional[Metrics] = None,
    ) -> None:
        """Khởi tạo bộ phối hợp Bloom + Cuckoo với ngưỡng FPR."""
        self.bloom = bloom
        self.cuckoo = cuckoo
        self.fpr_limit = fpr_limit
        self.cuckoo_load_limit = cuckoo_load_limit
        self.cuckoo_growth_factor = cuckoo_growth_factor
        self.cuckoo_rescale_no = 1
        self.bloom_rescale_no = 1
        self.metrics = metrics or Metrics()
        self.bloom_rebuilds = 0
        self.bloom_rebuild_events: list[str] = []

    def report_malicious_ip(self, ip: IPKey, timestamp: int) -> None:
        """Ghi nhận IP xấu, lưu vào Bloom + Cuckoo và cập nhật last_seen."""
        key = normalize_key(ip)
        entry = self.cuckoo.get(key)
        if entry:
            entry.last_seen = max(entry.last_seen, timestamp)
            return

        new_entry = ReputationEntry(ip=key, first_seen=timestamp, last_seen=timestamp)
        if self.cuckoo.insert(key, new_entry):
            self.bloom.insert(key)
            self.metrics.record_insertion()

    def fast_check(self, ip: IPKey) -> CheckResult:
        """Tra cứu nhanh trạng thái IP qua Bloom rồi xác nhận bằng Cuckoo, có thu thập metrics."""
        start = time.perf_counter_ns()
        key = normalize_key(ip)

        in_bloom = self.bloom.might_contain(key)
        self.metrics.record_bloom_check(in_bloom)
        if not in_bloom:
            self.metrics.record_lookup_latency(self._micros_since(start))
            return CheckResult.CLEAN

        entry = self.cuckoo.get(key)
        hit = entry is not None
        self.metrics.record_cuckoo_hit(hit)
        self.metrics.record_lookup_latency(self._micros_since(start))

        if hit:
            return CheckResult.MALICIOUS
        return CheckResult.BLOOM_FALSE_POSITIVE

    def maintenance(self, now: int) -> None:
        """Tái tạo Bloom khi FPR vượt ngưỡng."""
        self.maybe_rescale()

    def maybe_rescale(self) -> None:
        """Kiểm tra và rescale Cuckoo/Bloom theo ngưỡng đã cấu hình, có log sự kiện."""
        did_rehash, old_cap, new_cap, load_factor = self.cuckoo.maybe_rehash(
            load_limit=self.cuckoo_load_limit, growth_factor=self.cuckoo_growth_factor
        )
        if did_rehash:
            print(
                f"[Cuckoo Rescale #{self.cuckoo_rescale_no}] Mở rộng bảng Cuckoo (load_factor={load_factor:.3f} > {self.cuckoo_load_limit}). "
                f"old_capacity={old_cap} new_capacity={new_cap} size={len(self.cuckoo)}"
            )
            self.cuckoo_rescale_no += 1

        if self.bloom.estimate_fpr() > self.fpr_limit:
            prev_m = self.bloom.m_bits()
            prev_k = self.bloom.k_hash()
            new_m, new_k, est_fpr = self._rebuild_bloom(reason="fpr_exceeded")
            print(
                f"[Bloom Rescale #{self.bloom_rescale_no}] Mở rộng Bloom vì FPR vượt ngưỡng. "
                f"size={max(1, len(self.cuckoo))} prev_m={prev_m} prev_k={prev_k} "
                f"new_m={new_m} new_k={new_k} est_fpr={est_fpr:.4f} limit={self.fpr_limit}"
            )
            self.bloom_rescale_no += 1

    # Hàm nội bộ
    def _rebuild_bloom(self, reason: str) -> tuple[int, int, float]:
        """Tái tạo Bloom Filter với kích thước mới để kiểm soát FPR, lưu sự kiện phục vụ debug."""
        active = max(1, len(self.cuckoo))

        # Chiến lược tăng dần nhưng đảm bảo đủ m cho FPR mục tiêu:
        # - yêu cầu tối thiểu: m_req = -n ln(p) / (ln2)^2
        # - new_m = max(current_m * 2, m_req)
        current_m = self.bloom.m_bits()
        ln2_sq = math.log(2) ** 2
        m_req = int(math.ceil(-active * math.log(self.fpr_limit) / ln2_sq)) if self.fpr_limit < 1 else current_m
        new_m = max(current_m * 2, m_req, current_m + 1)
        new_k = max(1, int(round((new_m / active) * math.log(2))))

        new_bloom = BloomFilter(new_m, new_k)
        keys = (entry.ip for entry in self.cuckoo)
        new_bloom.insert_many(keys)
        self.bloom = new_bloom
        self.bloom_rebuilds += 1
        # Ước lượng FPR mới theo công thức lý thuyết: (1 - e^{-k n / m})^k
        est = (1.0 - math.exp(-(new_k * active) / float(new_m))) ** new_k if new_m > 0 else 1.0
        event = (
            f"reason={reason}, time={int(time.time())}, active={active}, "
            f"m_bits={new_m}, k_hash={new_k}, fpr_limit={self.fpr_limit}, prev_m_bits={current_m}, "
            f"m_req={m_req}, est_fpr_new={est:.6f}"
        )
        self.bloom_rebuild_events.append(event)
        return new_m, new_k, est

    @staticmethod
    def _micros_since(start_ns: int) -> int:
        """Tính thời gian đã trôi qua (micro giây) từ thời điểm start_ns."""
        end = time.perf_counter_ns()
        return int((end - start_ns) / 1000)
