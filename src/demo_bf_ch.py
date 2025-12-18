"""CLI demo: adaptive Bloom Filter + Cuckoo Hash.

- Bước 1: nạp blacklist nền (synth_malicious_base_100.csv + synth_malicious_rescale_29900.csv) với rescale Bloom/Cuckoo.
- Bước 2: chạy log traffic CSV (vd: synth_traffic_5m.csv) qua fast_check, in thống kê FPR/FP.
- Menu console cho phép chọn dataset và xem tiến trình.
"""

from __future__ import annotations

import csv
import os
import time
from typing import Dict, Iterable, List, Optional

try:
    import psutil
except Exception:  # psutil không bắt buộc
    psutil = None

from core.bloom.bloom_filter import BloomFilter
from core.bloom.bloom_params import BloomParams
from core.cuckoo.cuckoo_entry import ReputationEntry
from core.cuckoo.cuckoo_table import CuckooHashTable
from core.manager.reputation_manager import CheckResult, ReputationManager
from core.types.ip_types import IPKey, ip_to_key


# Đường dẫn dữ liệu synthetic mới tạo
BASE_BLACKLIST_CSV = "ddos_data/synth_malicious_base_100.csv"
INCREMENTAL_BLACKLIST_CSV = "ddos_data/synth_malicious_rescale_29900.csv"
SYNTH_TRAFFIC_CSV = "ddos_data/synth_traffic_5m.csv"

# Ngưỡng điều chỉnh
FPR_LIMIT = 0.01  # 5%
CUCKOO_LOAD_LIMIT = 0.9
CUCKOO_GROWTH_FACTOR = 2


def _current_memory_bytes() -> Optional[int]:
    """Lấy RSS của tiến trình (bytes). Ưu tiên psutil, fallback tracemalloc."""

    if psutil is not None:
        try:
            return psutil.Process(os.getpid()).memory_info().rss
        except Exception:
            pass
    try:
        import tracemalloc

        if not tracemalloc.is_tracing():
            tracemalloc.start()
        current, _ = tracemalloc.get_traced_memory()
        return current
    except Exception:
        return None


def load_ip_keys(csv_path: str, column: str = "Src IP") -> List[IPKey]:
    """Đọc cột IP từ CSV và trả về danh sách IPKey (đã khử trùng lặp, giữ thứ tự)."""

    keys: list[IPKey] = []
    seen: set[IPKey] = set()
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip_raw = (row.get(column) or "").strip()
            if not ip_raw:
                continue
            try:
                key = ip_to_key(ip_raw)
            except Exception:
                continue
            if key in seen:
                continue
            seen.add(key)
            keys.append(key)
    return keys


def init_structures(base_keys: Iterable[IPKey]) -> tuple[BloomFilter, CuckooHashTable]:
    """Khởi tạo Bloom và Cuckoo từ danh sách IP nền tảng."""

    base_keys_list = list(base_keys)
    bloom_params = BloomParams.for_capacity(max(1, len(base_keys_list)), FPR_LIMIT * 0.5)
    bloom = BloomFilter(bloom_params.m_bits, bloom_params.k_hash)
    cuckoo = CuckooHashTable(capacity=max(2048, len(base_keys_list) * 2))

    now = int(time.time())
    for key in base_keys_list:
        entry = ReputationEntry(ip=key, first_seen=now, last_seen=now)
        cuckoo.insert(key, entry)
        bloom.insert(key)

    print(
        "[Init] Khởi tạo từ blacklist nền: entries={} bloom_m_bits={} bloom_k_hash={} fpr_est={:.4f} "
        "cuckoo_capacity={} load_factor={:.3f}".format(
            len(base_keys_list), bloom.m_bits(), bloom.k_hash(), bloom.estimate_fpr(), cuckoo.capacity(), cuckoo.load_factor()
        )
    )
    return bloom, cuckoo


def build_manager_with_rescale() -> ReputationManager:
    """Nạp blacklist nền, rescale Bloom/Cuckoo trong quá trình chèn, trả về manager."""

    base_keys = load_ip_keys(BASE_BLACKLIST_CSV)
    blacklist_keys = load_ip_keys(INCREMENTAL_BLACKLIST_CSV)

    base_set = set(base_keys)
    incremental_keys = [k for k in blacklist_keys if k not in base_set]

    print(
        f"[Load] Đọc blacklist: base={len(base_keys)} incremental_mới={len(incremental_keys)} tổng_kỳ_vọng={len(base_keys) + len(incremental_keys)}"
    )

    bloom, cuckoo = init_structures(base_keys)
    now = int(time.time())
    for idx, key in enumerate(incremental_keys, start=1):
        entry = ReputationEntry(ip=key, first_seen=now + idx, last_seen=now + idx)
        cuckoo.insert(key, entry)
        bloom.insert(key)

        if idx % 5000 == 0 or idx == len(incremental_keys):
            current_fpr = bloom.estimate_fpr()
            print(
                f"[Tiến độ nạp blacklist] thêm={idx}/{len(incremental_keys)} fpr_est={current_fpr:.4f} "
                f"cuckoo_load={cuckoo.load_factor():.3f} bloom_m={bloom.m_bits()}"
            )

    manager = ReputationManager(
        bloom=bloom,
        cuckoo=cuckoo,
        fpr_limit=FPR_LIMIT,
        cuckoo_load_limit=CUCKOO_LOAD_LIMIT,
        cuckoo_growth_factor=CUCKOO_GROWTH_FACTOR,
    )

    # Sau khi nạp incremental, để chắc chắn FPR/load nằm trong ngưỡng
    manager.maybe_rescale()
    return manager


def _label_is_attack(label_raw: str) -> bool:
    label = (label_raw or "").strip().lower()
    return "ddos" in label or "attack" in label or "malicious" in label


def run_traffic_dataset(
    manager: ReputationManager,
    csv_path: str,
    ip_column: str = "Src IP",
    label_column: str = "Label",
    verbose: bool = False,
    max_rows: Optional[int] = None,
) -> Dict[str, int | float]:
    """Stream log CSV qua fast_check, trả về thống kê."""

    stats: Dict[str, int | float] = {
        "total_requests": 0,
        "attack_gt": 0,
        "clean_gt": 0,
        "bloom_negative": 0,
        "bloom_positive": 0,
        "cuckoo_hit": 0,
        "bloom_false_positive": 0,
    }

    start_time = time.time()
    start_mem = _current_memory_bytes()

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            ip_raw = (row.get(ip_column) or "").strip()
            label_raw = row.get(label_column) or ""
            if not ip_raw:
                continue

            try:
                key = ip_to_key(ip_raw)
            except Exception:
                if verbose:
                    print(f"[Dòng {idx}] Bỏ qua IP không hợp lệ: ip='{ip_raw}' label='{label_raw}'")
                continue

            stats["total_requests"] += 1
            if _label_is_attack(label_raw):
                stats["attack_gt"] += 1
            else:
                stats["clean_gt"] += 1

            # Adaptive rescale trong lúc chạy lưu lượng
            manager.maybe_rescale()

            result = manager.fast_check(key)
            if result is CheckResult.CLEAN:
                stats["bloom_negative"] += 1
                verdict = "CLEAN"
            elif result is CheckResult.MALICIOUS:
                stats["bloom_positive"] += 1
                stats["cuckoo_hit"] += 1
                verdict = "ATTACK"
            else:
                stats["bloom_positive"] += 1
                stats["bloom_false_positive"] += 1
                verdict = "BLOOM_FP"

            if verbose:
                print(f"[Dòng {idx}] ip={ip_raw} nhãn='{label_raw}' -> phán đoán={verdict}")

            if max_rows is not None and stats["total_requests"] >= max_rows:
                break

            if idx % 50000 == 0:
                elapsed = max(1e-9, time.time() - start_time)
                throughput = stats["total_requests"] / elapsed
                fpr_obs = stats["bloom_false_positive"] / max(1, stats["clean_gt"])
                mem_now = _current_memory_bytes()
                mem_txt = f"{mem_now:,}" if mem_now is not None else "n/a"
                print(
                    f"[Replay tiến độ] đã_xử_lý={idx} bloom_neg={stats['bloom_negative']} "
                    f"bloom_pos={stats['bloom_positive']} fp={stats['bloom_false_positive']} "
                    f"throughput={throughput:,.0f} req/s fpr_thực={fpr_obs:.4%} mem={mem_txt} bytes"
                )

    stats["duration_sec"] = time.time() - start_time
    stats["start_mem_bytes"] = start_mem
    stats["end_mem_bytes"] = _current_memory_bytes()
    return stats


def print_stats(stats: Dict[str, int | float]) -> None:
    total = stats.get("total_requests", 0)
    bloom_pos = stats.get("bloom_positive", 0)
    bloom_neg = stats.get("bloom_negative", 0)
    cuckoo_hit = stats.get("cuckoo_hit", 0)
    bloom_fp = stats.get("bloom_false_positive", 0)
    attack_gt = stats.get("attack_gt", 0)
    clean_gt = stats.get("clean_gt", 0)
    duration = stats.get("duration_sec") or 0.0
    end_mem = stats.get("end_mem_bytes")
    start_mem = stats.get("start_mem_bytes")

    print("\n=== Tóm tắt kết quả ===")
    print(f"Tổng số request: {total}")
    print(f"Attack (theo nhãn): {attack_gt}")
    print(f"Clean (theo nhãn): {clean_gt}")
    print("")
    print(f"Bloom âm (không khớp): {bloom_neg}")
    print(f"Bloom dương: {bloom_pos}")
    print(f" ├─ Cuckoo khớp (true positive): {cuckoo_hit}")
    print(f" └─ Bloom false positive: {bloom_fp}")

    if duration > 0 and total > 0:
        throughput = total / duration
        print(f"Thời gian chạy: {duration:.1f}s (~{throughput:,.0f} req/s)")
    if end_mem is not None:
        mem_delta = end_mem - start_mem if start_mem is not None else None
        delta_txt = f" (Δ={mem_delta:+,} bytes)" if mem_delta is not None else ""
        print(f"Memory tiến trình (kết thúc): {end_mem:,} bytes{delta_txt}")

    print("Các tỉ lệ chính:")
    if clean_gt > 0:
        fpr_real = bloom_fp / clean_gt
        print(f"- FPR thực tế ≈ {bloom_fp}/{clean_gt} ≈ {fpr_real:.2%}")
    if total > 0:
        bloom_pos_rate = bloom_pos / total
        print(f"- Tỉ lệ Bloom positive trên toàn lưu lượng ≈ {bloom_pos}/{total} ≈ {bloom_pos_rate:.2%}")
    if bloom_pos > 0:
        fp_share = bloom_fp / bloom_pos
        print(f"- Tỉ lệ dương giả trong Bloom positive ≈ {bloom_fp}/{bloom_pos} ≈ {fp_share:.2%}")
    if attack_gt > 0:
        recall = cuckoo_hit / attack_gt
        print(f"- Recall tấn công (cuckoo_hit/attack_gt): {cuckoo_hit}/{attack_gt} ≈ {recall:.2%}")


def choose_dataset() -> tuple[str, str]:
    options = {
        "1": ("Traffic synthetic 5 phút", SYNTH_TRAFFIC_CSV, "Src IP"),
        "2": ("Tự nhập đường dẫn", None, None),
    }

    print("\nChọn dataset để replay (log traffic):")
    for key, (title, path, _) in options.items():
        suffix = f" ({path})" if path else ""
        print(f" {key}. {title}{suffix}")

    choice = input("Chọn dataset [1]: ").strip() or "1"
    selected = options.get(choice)
    if selected is None:
        print("Lựa chọn không hợp lệ, dùng mặc định 1.")
        selected = options["1"]

    title, path, ip_col = selected
    if path is None:
        custom = input("Nhập đường dẫn CSV: ").strip()
        ip_col = input("Nhập tên cột IP [Src IP]: ").strip() or "Src IP"
        return custom, ip_col
    return path, ip_col or "Src IP"


def main() -> None:
    print("=== Demo Adaptive Bloom + Cuckoo (log tiếng Việt) ===")
    manager: Optional[ReputationManager] = None

    while True:
        print("\nMenu:")
        print(" 1. Nạp blacklist (base + incremental) với rescale")
        print(" 2. Chọn dataset traffic và chạy fast_check")
        print(" 3. Thoát")
        choice = input("Chọn [1/2/3]: ").strip()

        if choice == "1" or choice == "":
            manager = build_manager_with_rescale()
        elif choice == "2":
            if manager is None:
                print("Hãy nạp blacklist trước (chọn 1).")
                continue
            dataset_path, ip_col = choose_dataset()
            verbose = input("In log từng dòng? [y/N]: ").strip().lower() == "y"
            stats = run_traffic_dataset(manager, dataset_path, ip_column=ip_col, verbose=verbose)
            print_stats(stats)
        elif choice == "3":
            print("Thoát.")
            break
        else:
            print("Lựa chọn không hợp lệ.")


if __name__ == "__main__":
    main()

