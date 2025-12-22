from core.bloom_filter import BloomFilter
from core.cuckoo_hash import CuckooHashTable
import time

class ReputationManager:
    def __init__(
        self,
        expected_items: int = 1000,
        fpr_limit: float = 0.05,
        cuckoo_load_limit: float = 0.9,
        growth_factor: int = 2
    ):
        self.fpr_limit = fpr_limit
        self.cuckoo_load_limit = cuckoo_load_limit
        self.growth_factor = growth_factor

        self.bloom = BloomFilter(expected_items=expected_items, false_positive_rate=fpr_limit)
        self.cuckoo = CuckooHashTable(
            initial_capacity=max(1024, int(expected_items * 2)),
            load_limit=cuckoo_load_limit,
            growth_factor=growth_factor
        )

        self.stats = {
            "bloom_positive": 0,
            "bloom_false_positive": 0,
            "cuckoo_hit": 0,
            "total_queries": 0,
            "resize_count": 0
        }

        print(f"[ReputationManager Init] Expected={expected_items:,}, FPR_limit={fpr_limit:.1%}, Cuckoo_load_limit={cuckoo_load_limit:.0%}")

    def insert_malicious(self, ip: str):
        self.bloom.add(ip)
        self.cuckoo.insert(ip, {"ip": ip, "type": "malicious", "first_seen": time.time()})

    def fast_check(self, ip: str) -> str:
        self.stats["total_queries"] += 1
        if not self.bloom.check(ip):
            return "CLEAN"
        self.stats["bloom_positive"] += 1
        if self.cuckoo.lookup(ip) is not None:
            self.stats["cuckoo_hit"] += 1
            return "MALICIOUS"
        else:
            self.stats["bloom_false_positive"] += 1
            return "FP"

    def maybe_adaptive_resize(self):
        current_fpr = self.bloom.estimate_fpr()
        current_load = self.cuckoo.load_factor()

        if current_fpr <= self.fpr_limit and current_load <= self.cuckoo_load_limit:
            return

        print(f"\n[Adaptive Trigger #{self.stats['resize_count']+1}] FPR={current_fpr:.2%} > {self.fpr_limit:.0%} "
              f"or Load={current_load:.2%} > {self.cuckoo_load_limit:.0%} → Resizing...")

        self.stats["resize_count"] += 1

        old_capacity = self.cuckoo.capacity
        self.cuckoo.resize()
        print(f"[Cuckoo] Resized: {old_capacity:,} → {self.cuckoo.capacity:,}")

        new_expected = int(self.bloom.expected_items * self.growth_factor * 1.5)
        new_bloom = BloomFilter(expected_items=new_expected, false_positive_rate=self.fpr_limit)

        for key, _ in self.cuckoo._get_all_items():
            new_bloom.add(key)

        self.bloom = new_bloom
        print(f"[Bloom] Resized: m={self.bloom.size:,} bits (~{self.bloom.size//8//1024:.1f} KB)")

    # ← METHOD BỊ THIẾU – BÂY GIỜ ĐÃ CÓ
    def _get_stats(self):
        return self.stats.copy()

    def print_stats(self):
        s = self.stats
        total = s["total_queries"]
        if total == 0:
            print("Chưa có query nào.")
            return
        print("\n=== Hybrid Stats ===")
        print(f"Tổng queries: {total:,}")
        print(f"Bloom positive rate: {s['bloom_positive']/total:.2%}")
        print(f"Cuckoo detected attacks: {s['cuckoo_hit']:,}")
        print(f"Bloom false positives (bị Cuckoo loại): {s['bloom_false_positive']:,}")
        hybrid_fpr = s["bloom_false_positive"] / total
        print(f"→ Hybrid FPR thực tế: {hybrid_fpr:.4%}")
        print(f"Bloom estimated FPR: {self.bloom.estimate_fpr():.4%}")
        print(f"Cuckoo load: {self.cuckoo.load_factor():.2%}")
        print(f"Tổng số lần adaptive resize: {s['resize_count']}")

    def _get_all_items(self):
        items = []
        for table in [self.cuckoo.table1, self.cuckoo.table2]:
            for entry in table:
                if entry:
                    items.append(entry)
        return items
