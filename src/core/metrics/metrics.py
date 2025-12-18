"""Bộ đếm metrics gọn cho quan sát hệ thống."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Metrics:
    bloom_checks: int = 0
    bloom_misses: int = 0
    bloom_hits: int = 0
    cuckoo_hits: int = 0
    cuckoo_misses: int = 0
    evictions: int = 0
    insertions: int = 0
    lookup_latency_total_us: int = 0
    lookup_count: int = 0

    def record_bloom_check(self, hit: bool) -> None:
        self.bloom_checks += 1
        if hit:
            self.bloom_hits += 1
        else:
            self.bloom_misses += 1

    def record_cuckoo_hit(self, hit: bool) -> None:
        if hit:
            self.cuckoo_hits += 1
        else:
            self.cuckoo_misses += 1

    def record_eviction(self) -> None:
        self.evictions += 1

    def record_insertion(self) -> None:
        self.insertions += 1

    def record_lookup_latency(self, micros: int) -> None:
        self.lookup_latency_total_us += micros
        self.lookup_count += 1

    def average_lookup_latency_us(self) -> float:
        if self.lookup_count == 0:
            return 0.0
        return self.lookup_latency_total_us / float(self.lookup_count)
