# core/reputation_manager.py (Phiên bản cải thiện cho StreamBF-CH)
import time
from typing import Any, Dict

import psutil  # Để đo memory real

from core.bloom_filter import BloomFilter  # Cải thiện: salted, resize, items
from core.cuckoo_filter import CuckooFilter  # Cải thiện: salted, delete, estimate_fpr, track_items


class ReputationManager:
    """
    Hybrid StreamBF-CH cải tiến: Bloom (pre-filter) + Cuckoo (exact lookup)
    - Shared salt giữa Bloom và Cuckoo để consistent hashing
    - Hỗ trợ delete_malicious (Cuckoo delete, Bloom skip → FP có thể tăng nhẹ)
    - Adaptive resize auto-trigger (mỗi 1000 ops check)
    - Rebuild Bloom từ cuckoo.items (enable track_items=True cho Cuckoo)
    - Stats nâng cao: hybrid_estimate_fpr, throughput, memory real (psutil)
    - Phù hợp CIC-DDoS2019: Insert Source IP nếu Label=attack, check stream theo Timestamp
    - FPR hybrid <5%, load >95%, hỗ trợ high-velocity (10^5 qps)
    """
    CHECK_INTERVAL = 1000  # Check adaptive mỗi N ops

    def __init__(
        self,
        expected_items: int = 100_000,
        fpr_limit: float = 0.05,
        cuckoo_load_limit: float = 0.95,
        growth_factor: int = 2,
        fingerprint_bits: int = 16,  # Từ paper, cho FPR low
    ):
        self.fpr_limit = fpr_limit
        self.cuckoo_load_limit = cuckoo_load_limit
        self.growth_factor = growth_factor

        # Shared salt cho consistent
        shared_salt = secrets.token_bytes(16)

        # Bloom: Pre-filter nhanh
        self.bloom = BloomFilter(
            expected_items=expected_items * 10,
            false_positive_rate=fpr_limit,
            salt=shared_salt,
        )

        # Cuckoo: Exact storage, track_items=True để rebuild Bloom
        self.cuckoo = CuckooFilter(
            initial_capacity=max(1024, expected_items // 10),
            load_limit=cuckoo_load_limit,
            growth_factor=growth_factor,
            fingerprint_bits=fingerprint_bits,
            salt=shared_salt,
            track_items=True,  # Enable để lấy items rebuild Bloom
        )

        # Stats chi tiết
        self.stats: Dict[str, Any] = {
            "total_queries": 0,
            "bloom_positive": 0,
            "bloom_false_positive": 0,
            "cuckoo_hit": 0,
            "resize_count": 0,
            "delete_count": 0,
            "op_count": 0,  # Để trigger adaptive
            "total_time": 0.0,  # Để tính throughput
            "memory_kb": 0,  # Update real-time
        }

        print(
            f"[ReputationManager] Init: expected={expected_items:,}, "
            f"Bloom FPR target={fpr_limit:.1%}, Cuckoo load limit={cuckoo_load_limit:.0%}, "
            f"fp_bits={fingerprint_bits}, shared_salt={shared_salt[:4].hex()}..."
        )

    # Thêm IP độc hại vào cả Bloom và Cuckoo.   
    def insert_malicious(self, ip: str, metadata: Dict[str, Any] = None):
        """Chèn IP malicious (với metadata như timestamp, type từ CIC-DDoS)"""
        value = metadata or {"ip": ip, "type": "malicious", "first_seen": time.time()}
        self.bloom.add(ip)
        self.cuckoo.insert(ip, value)
        self.stats["op_count"] += 1
        self._auto_adaptive_check()

    def delete_malicious(self, ip: str) -> bool:
        """Xóa IP (Cuckoo delete, Bloom skip → FP có thể tăng)"""
        deleted = self.cuckoo.delete(ip)
        if deleted:
            self.stats["delete_count"] += 1
            self.stats["op_count"] += 1
            self._auto_adaptive_check()
        return deleted

    def fast_check(self, ip: str) -> str:
        start = time.time()
        self.stats["total_queries"] += 1 #Đo thời gian bắt đầu → dùng để tính total_time cho throughput (queries/s).

        # Nếu Bloom không chứa → chắc chắn benign (no false negative).
        if not self.bloom.check(ip):
            self.stats["total_time"] += time.time() - start
            self.stats["op_count"] += 1
            self._auto_adaptive_check()
            return "CLEAN"
        
        # tăng counter positive rate (dùng để tính Bloom positive rate
        self.stats["bloom_positive"] += 1

        # Nếu Cuckoo tìm thấy → xác nhận thật sự malicious.
        if self.cuckoo.lookup(ip) is not None:
            self.stats["cuckoo_hit"] += 1
            self.stats["total_time"] += time.time() - start
            self.stats["op_count"] += 1
            self._auto_adaptive_check()
            return "MALICIOUS"
        else: # Nếu Cuckoo không tìm thấy → đây là false positive từ Bloom
            self.stats["bloom_false_positive"] += 1
            self.stats["total_time"] += time.time() - start
            self.stats["op_count"] += 1
            self._auto_adaptive_check()
            return "FP"

    def _auto_adaptive_check(self):
        """Auto trigger resize mỗi CHECK_INTERVAL ops"""
        if self.stats["op_count"] % self.CHECK_INTERVAL == 0:
            self.maybe_adaptive_resize()

    def maybe_adaptive_resize(self) -> bool:
        """Adaptive resize nếu FPR/load cao (rebuild Bloom từ cuckoo.items)"""
        current_fpr = self.bloom.estimate_fpr()
        current_load = self.cuckoo.load_factor()
        cuckoo_fpr = self.cuckoo.estimate_fpr()

        if current_fpr <= self.fpr_limit and current_load <= self.cuckoo_load_limit and cuckoo_fpr <= self.fpr_limit / 10:
            return False

        print(
            f"\n[Adaptive Resize #{self.stats['resize_count']+1}] "
            f"Bloom FPR={current_fpr:.2%} > {self.fpr_limit:.0%} "
            f"or Cuckoo load={current_load:.2%} > {self.cuckoo_load_limit:.0%} "
            f"or Cuckoo FPR={cuckoo_fpr:.4%}"
        )

        self.stats["resize_count"] += 1

        # Resize Cuckoo trước
        # Vì Cuckoo lưu dữ liệu thật (track_items=True), cần mở rộng trước để chứa hết khi rebuild Bloom
        self.cuckoo.resize()

        # Rebuild Bloom từ cuckoo.items (vì track_items=True)
        # Paper CoNEXT'14 (Cuckoo Filter): Gợi ý growth factor ≥2 cho resize
        # Nếu chỉ tăng nhẹ (ví dụ x2 thuần túy), FPR mới chỉ giảm nhẹ → sớm vượt ngưỡng lần nữa → trigger resize liên tục
        new_expected = int(self.bloom.expected_items * self.growth_factor * 1.5)
        new_bloom = BloomFilter(expected_items=new_expected, false_positive_rate=self.fpr_limit, salt=self.bloom.salt)

        if self.cuckoo.items is not None:
            for ip in self.cuckoo.items:
                new_bloom.add(ip)
        else:
            raise RuntimeError("Cuckoo track_items=False, không thể rebuild Bloom")

        self.bloom = new_bloom
        print(f"[Bloom] Resized to expected={new_expected:,} items (~{new_bloom.size//8//1024:.1f} KB)")
        return True

    def _get_stats(self) -> Dict[str, Any]:
        """Trả về stats copy, thêm hybrid_fpr, throughput, memory real"""
        s = self.stats.copy()
        total = s["total_queries"]
        if total > 0:
            s["hybrid_fpr"] = s["bloom_false_positive"] / total
            s["bloom_positive_rate"] = s["bloom_positive"] / total
            s["recall"] = s["cuckoo_hit"] / max(1, s["cuckoo_hit"] + (total - s["bloom_positive"]))  # Recall approx
            s["throughput_qps"] = total / max(1e-6, s["total_time"])  # Queries/sec
        s["bloom_estimated_fpr"] = self.bloom.estimate_fpr()
        s["cuckoo_estimated_fpr"] = self.cuckoo.estimate_fpr()
        s["hybrid_estimated_fpr"] = s["bloom_estimated_fpr"] * (1 - s.get("recall", 1)) + s["cuckoo_estimated_fpr"]
        s["cuckoo_load"] = self.cuckoo.load_factor()
        s["memory_kb"] = psutil.Process().memory_info().rss / 1024  # Real RSS
        return s

    def print_stats(self):
        """In stats đẹp, phù hợp báo cáo (FPR, throughput, memory)"""
        s = self._get_stats()
        total = s["total_queries"]
        if total == 0:
            print("Chưa có query.")
            return

        print("\n=== Hybrid StreamBF-CH Stats ===")
        print(f"Tổng queries: {total:,}")
        print(f"Bloom positive rate: {s['bloom_positive_rate']:.2%}")
        print(f"Cuckoo detected malicious: {s['cuckoo_hit']:,}")
        print(f"Bloom false positives: {s['bloom_false_positive']:,}")
        print(f"→ Hybrid FPR thực tế: {s['hybrid_fpr']:.4%}")
        print(f"Hybrid estimated FPR: {s['hybrid_estimated_fpr']:.4%}")
        print(f"Recall approx: {s.get('recall', 0):.2%}")
        print(f"Throughput: {s['throughput_qps']:,.0f} queries/s")
        print(f"Cuckoo load factor: {s['cuckoo_load']:.2%}")
        print(f"Tổng adaptive resize: {s['resize_count']}")
        print(f"Tổng deletes: {s['delete_count']}")
        print(f"Memory usage: ~{s['memory_kb']:,} KB")