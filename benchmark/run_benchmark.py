import time
import psutil
import matplotlib.pyplot as plt
from core.bloom_filter import BloomFilter
from core.reputation_manager import ReputationManager
from data.load_cicddos import load_cicddos_data
import os
import random

def generate_random_ip():
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))

def run_benchmark(csv_files, sample_size=50000):
    print("=== STREAMBF-CH BENCHMARK ===\n")
    
    # Load data
    _, attack_ips, _, _ = load_cicddos_data(csv_files, max_rows_per_file=sample_size)
    
    # Tạo non-members giả (nhiều hơn để thấy rõ FPR)
    non_member_ips = []
    while len(non_member_ips) < sample_size * 2:
        ip = generate_random_ip()
        if ip not in attack_ips:
            non_member_ips.append(ip)
    non_member_ips = non_member_ips[:sample_size * 2]
    
    test_ips = attack_ips * 10 + non_member_ips  # 10% malicious, 90% clean
    random.shuffle(test_ips)
    
    results = {}
    
    # 1. Bloom Filter thuần
    print("Running Bloom Filter thuần...")
    bf = BloomFilter(expected_items=len(attack_ips) * 10, false_positive_rate=0.05)
    for ip in attack_ips:
        bf.add(ip)
    
    start = time.time()
    fp_bloom = sum(1 for ip in test_ips if bf.check(ip) and ip not in attack_ips)
    duration_bloom = time.time() - start
    throughput_bloom = len(test_ips) / duration_bloom
    
    results['Bloom Only'] = {
        'fpr': fp_bloom / len(test_ips),
        'throughput': throughput_bloom,
        'memory_kb': bf.size // 8
    }
    
    # 2. Hybrid StreamBF-CH
    print("Running Hybrid StreamBF-CH...")
    manager = ReputationManager(expected_items=len(attack_ips) * 10)
    for ip in attack_ips:
        manager.insert_malicious(ip)
    
    start = time.time()
    for ip in test_ips:
        manager.fast_check(ip)
    duration_hybrid = time.time() - start
    throughput_hybrid = len(test_ips) / duration_hybrid
    
    stats = manager._get_stats()
    hybrid_fp = stats['bloom_false_positive']
    
    results['StreamBF-CH (Hybrid)'] = {
        'fpr': hybrid_fp / len(test_ips),
        'throughput': throughput_hybrid,
        'memory_kb': (bf.size // 8) + (manager.cuckoo.capacity * 16 // 1024)  # ước lượng
    }
    
    # In kết quả
    print("\n=== KẾT QUẢ BENCHMARK ===")
    for name, r in results.items():
        print(f"{name}:")
        print(f"   FPR: {r['fpr']:.4%}")
        print(f"   Throughput: {r['throughput']:,.0f} queries/s")
        print(f"   Memory: ~{r['memory_kb']:,} KB")
        print()
    
    # Vẽ biểu đồ
    plot_results(results)
    
    return results

def plot_results(results):
    import matplotlib.pyplot as plt
    names = list(results.keys())
    fpr = [results[n]['fpr'] * 100 for n in names]
    throughput = [results[n]['throughput'] / 1000 for n in names]  # K queries/s
    
    fig, ax1 = plt.subplots(figsize=(10, 6))
    
    ax1.bar(names, fpr, color=['orange', 'green'], alpha=0.7)
    ax1.set_ylabel('False Positive Rate (%)', color='black')
    ax1.tick_params(axis='y', labelcolor='black')
    
    ax2 = ax1.twinx()
    ax2.plot(names, throughput, 'b*-', linewidth=3, markersize=10)
    ax2.set_ylabel('Throughput (K queries/s)', color='blue')
    ax2.tick_params(axis='y', labelcolor='blue')
    
    plt.title('StreamBF-CH vs Bloom Filter Thuần\nFPR và Throughput trên CIC-DDoS2019')
    plt.grid(True, axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig('/content/drive/MyDrive/streambf-ch/plots/benchmark_comparison.png', dpi=200)
    plt.show()
    
    print("Biểu đồ đã lưu tại: plots/benchmark_comparison.png")
