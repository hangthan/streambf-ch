# benchmark/run_benchmark.py (Phiên bản refactor hoàn chỉnh cho StreamBF-CH)
"""
Benchmark script refactor cho dự án StreamBF-CH (Hybrid Bloom + Cuckoo Filter)

Cải tiến chính:
- Modular: Separate functions cho load data, generate test set, benchmark each method
- Real memory measurement dùng psutil (RSS trước/sau)
- Multiple runs với avg ± std cho FPR, throughput, memory
- Support cả CSV và Parquet (CIC-DDoS2019 thường Parquet)
- Tự động detect column names (Source IP / Src IP, Label)
- Plot nâng cao: Error bars cho std, 3 metrics (FPR, Throughput, Memory)
- In bảng kết quả đẹp (tabulate)
- Adaptive resize tự động trigger trong benchmark
- Phù hợp sơ đồ triển khai và kế hoạch (so sánh Bloom thuần vs Hybrid trên CIC-DDoS2019)
"""

import os
import time
import random
import psutil
import numpy as np
import matplotlib.pyplot as plt
from glob import glob
from typing import List, Set, Tuple

import pandas as pd  # Để load Parquet/CSV hiệu quả

from core.bloom_filter import BloomFilter
from core.reputation_manager import ReputationManager


def generate_random_ip() -> str:
    """Generate random IPv4 không trùng attack_ips"""
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))


def load_attack_ips(
    file_paths: List[str],
    sample_size: int = 50_000,
    ip_column: str = "Source IP",
    label_column: str = "Label"
) -> Set[str]:
    """
    Load attack IPs từ nhiều file (CSV hoặc Parquet)
    - Chỉ lấy rows có Label != 'BENIGN'
    - Dedup IPs
    - Limit sample_size per file nếu cần
    """
    attack_ips: Set[str] = set()
    process = psutil.Process()

    print(f"Loading attack IPs từ {len(file_paths)} files (target ~{sample_size:,} unique)...")
    print(f"  IP column: '{ip_column}', Label column: '{label_column}'")
    print(f"  Memory trước load: {process.memory_info().rss / 1024 / 1024:.1f} MB")

    for path in file_paths:
        print(f"  Processing {os.path.basename(path)}...")
        if path.endswith(".parquet"):
            df = pd.read_parquet(path, columns=[ip_column, label_column])
        else:
            df = pd.read_csv(path, usecols=[ip_column, label_column], low_memory=False)

        # Auto-detect column nếu không match
        if ip_column not in df.columns:
            possible = [c for c in df.columns if "IP" in c or "ip" in c]
            if possible:
                ip_column = possible[0]
                print(f"    Auto-detect IP column: {ip_column}")
        if label_column not in df.columns:
            possible = [c for c in df.columns if "Label" in c or "label" in c]
            if possible:
                label_column = possible[0]
                print(f"    Auto-detect Label column: {label_column}")

        # Filter attack
        attack_df = df[df[label_column] != "BENIGN"]
        ips = attack_df[ip_column].astype(str).unique().tolist()

        for ip in ips:
            if ip != "nan" and ip not in attack_ips:
                attack_ips.add(ip)
                if len(attack_ips) >= sample_size:
                    print(f"  Đạt {sample_size:,} unique attack IPs.")
                    print(f"  Memory sau load: {process.memory_info().rss / 1024 / 1024:.1f} MB")
                    return attack_ips

    print(f"  Tổng unique attack IPs: {len(attack_ips):,}")
    return attack_ips


def prepare_test_set(attack_ips: Set[str], total_queries: int = 500_000) -> List[str]:
    """Prepare test set: ~10% malicious, 90% clean (tỷ lệ DDoS thực tế)"""
    num_malicious = int(total_queries * 0.1)
    num_clean = total_queries - num_malicious

    malicious_list = list(attack_ips) * (num_malicious // len(attack_ips) + 1)
    malicious_test = random.sample(malicious_list, num_malicious)

    clean_test = []
    while len(clean_test) < num_clean:
        ip = generate_random_ip()
        if ip not in attack_ips:
            clean_test.append(ip)

    test_ips = malicious_test + clean_test
    random.shuffle(test_ips)
    print(f"Prepared test set: {total_queries:,} queries ({len(malicious_test):,} malicious, {len(clean_test):,} clean)")
    return test_ips


def benchmark_bloom_only(attack_ips: Set[str], test_ips: List[str]) -> dict:
    """Benchmark Bloom Filter thuần"""
    print("\n=== Running Bloom Filter Thuần ===")
    bf = BloomFilter(expected_items=len(attack_ips) * 10, false_positive_rate=0.05)

    start_insert = time.time()
    for ip in attack_ips:
        bf.add(ip)
    insert_duration = time.time() - start_insert

    start_query = time.time()
    false_positives = sum(1 for ip in test_ips if bf.check(ip) and ip not in attack_ips)
    query_duration = time.time() - start_query

    throughput = len(test_ips) / query_duration
    fpr = false_positives / len(test_ips)
    memory_kb = psutil.Process().memory_info().rss / 1024

    return {
        "fpr": fpr,
        "throughput_qps": throughput,
        "insert_time_s": insert_duration,
        "query_time_s": query_duration,
        "memory_kb": memory_kb,
    }


def benchmark_hybrid(attack_ips: Set[str], test_ips: List[str]) -> dict:
    """Benchmark StreamBF-CH Hybrid"""
    print("\n=== Running StreamBF-CH (Hybrid) ===")
    manager = ReputationManager(expected_items=len(attack_ips) * 10)

    start_insert = time.time()
    for ip in attack_ips:
        manager.insert_malicious(ip)
    insert_duration = time.time() - start_insert

    start_query = time.time()
    for ip in test_ips:
        manager.fast_check(ip)
    query_duration = time.time() - start_query

    stats = manager._get_stats()
    throughput = stats["throughput_qps"]
    fpr = stats["hybrid_fpr"]
    memory_kb = stats["memory_kb"]

    return {
        "fpr": fpr,
        "throughput_qps": throughput,
        "insert_time_s": insert_duration,
        "query_time_s": query_duration,
        "memory_kb": memory_kb,
        "resize_count": stats["resize_count"],
    }


def run_full_benchmark(
    data_paths: List[str],
    sample_size: int = 50_000,
    total_queries: int = 500_000,
    num_runs: int = 3
) -> dict:
    """Chạy benchmark full với multiple runs"""
    results = {"Bloom Only": [], "StreamBF-CH (Hybrid)": []}

    for run in range(1, num_runs + 1):
        print(f"\n{'='*20} RUN {run}/{num_runs} {'='*20}")

        attack_ips = load_attack_ips(data_paths, sample_size=sample_size)
        test_ips = prepare_test_set(attack_ips, total_queries=total_queries)

        bloom_res = benchmark_bloom_only(set(attack_ips), test_ips)
        results["Bloom Only"].append(bloom_res)

        hybrid_res = benchmark_hybrid(set(attack_ips), test_ips)
        results["StreamBF-CH (Hybrid)"].append(hybrid_res)

        manager = None  # Clear memory
        print(f"Run {run} hoàn thành.\n")

    # Tính avg ± std
    summary = {}
    for name, runs in results.items():
        fprs = [r["fpr"] for r in runs]
        throughputs = [r["throughput_qps"] for r in runs]
        memories = [r["memory_kb"] for r in runs]

        summary[name] = {
            "fpr_mean": np.mean(fprs),
            "fpr_std": np.std(fprs),
            "throughput_mean": np.mean(throughputs),
            "throughput_std": np.std(throughputs),
            "memory_mean": np.mean(memories),
            "memory_std": np.std(memories),
        }

    print_results(summary)
    plot_results(summary)
    return summary


def print_results(summary: dict):
    """In bảng kết quả đẹp"""
    from tabulate import tabulate

    table = []
    for name, s in summary.items():
        table.append([
            name,
            f"{s['fpr_mean']:.4%} ± {s['fpr_std']:.4%}",
            f"{s['throughput_mean']:,.0f} ± {s['throughput_std']:,.0f} qps",
            f"{s['memory_mean']:,.0f} ± {s['memory_std']:,.0f} KB"
        ])

    print("\n=== KẾT QUẢ BENCHMARK (Avg ± Std over 3 runs) ===")
    print(tabulate(table, headers=["Method", "Hybrid FPR", "Throughput", "Memory"], tablefmt="github"))


def plot_results(summary: dict):
    """Vẽ biểu đồ 3 metrics với error bars"""
    names = list(summary.keys())
    fpr_means = [summary[n]["fpr_mean"] * 100 for n in names]
    fpr_stds = [summary[n]["fpr_std"] * 100 for n in names]
    throughput_means = [summary[n]["throughput_mean"] / 1000 for n in names]
    throughput_stds = [summary[n]["throughput_std"] / 1000 for n in names]
    memory_means = [summary[n]["memory_mean"] for n in names]
    memory_stds = [summary[n]["memory_std"] for n in names]

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))

    # FPR
    ax1.bar(names, fpr_means, yerr=fpr_stds, capsize=5, color=['orange', 'green'], alpha=0.8)
    ax1.set_ylabel("False Positive Rate (%)")
    ax1.set_title("False Positive Rate")

    # Throughput
    ax2.bar(names, throughput_means, yerr=throughput_stds, capsize=5, color=['orange', 'green'], alpha=0.8)
    ax2.set_ylabel("Throughput (K queries/s)")
    ax2.set_title("Throughput")

    # Memory
    ax3.bar(names, memory_means, yerr=memory_stds, capsize=5, color=['orange', 'green'], alpha=0.8)
    ax3.set_ylabel("Memory (KB)")
    ax3.set_title("Memory Usage")

    plt.suptitle("StreamBF-CH vs Bloom Filter Thuần\nTrên CIC-DDoS2019 Dataset")
    plt.tight_layout()

    os.makedirs("plots", exist_ok=True)
    plot_path = "plots/benchmark_full_comparison.png"
    plt.savefig(plot_path, dpi=200)
    plt.close()
    print(f"\nBiểu đồ đã lưu tại: {plot_path}")


if __name__ == "__main__":
    # Ví dụ chạy: Thay bằng path thực tế (CSV hoặc Parquet từ CIC-DDoS2019)
    data_files = glob("data/*.csv") + glob("data/*.parquet")
    if not data_files:
        print("Không tìm thấy file data. Đặt file CIC-DDoS2019 vào folder 'data/'")
    else:
        run_full_benchmark(
            data_paths=data_files[:4],  # Lấy 4 file đầu để nhanh
            sample_size=50_000,
            total_queries=500_000,
            num_runs=3
        )