"""
Test script for Bloom Filter core module.
------------------------------------------
Mục tiêu:
- Thêm 100 phần tử ngẫu nhiên vào Bloom Filter.
- Đo tỷ lệ False Positive Rate (FPR).
- Đảm bảo FPR thực nghiệm < 5%.

Cấu trúc:
1️⃣ Import BloomFilter class từ src/
2️⃣ Sinh dữ liệu test ngẫu nhiên
3️⃣ Đo FPR thực nghiệm & FPR lý thuyết
4️⃣ In kết quả ra console
"""

from src.bloom_filter import BloomFilter
import random
import string


def random_str(n=6):
    """Sinh chuỗi ngẫu nhiên gồm n ký tự thường."""
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def test_bloom_filter():
    """Kiểm thử chính cho Bloom Filter."""

    # Tạo Bloom Filter cho 100 phần tử
    bf = BloomFilter(capacity=100, k_hashes=7)

    # Sinh dữ liệu thật
    dataset = [random_str() for _ in range(100)]
    for item in dataset:
        bf.add(item)

    # Sinh dữ liệu kiểm thử (các item chưa có trong filter)
    test_data = [random_str() for _ in range(100)]
    false_positive = 0

    for item in test_data:
        if bf.might_contain(item) and item not in dataset:
            false_positive += 1

    # Tính FPR thực nghiệm
    empirical_fpr = false_positive / len(test_data)
    theoretical_fpr = bf.estimate_fpr(len(dataset))

    # In kết quả
    print("=" * 60)
    print("🌿 BLOOM FILTER TEST SUMMARY 🌿")
    print("- Items inserted:", len(dataset))
    print("- Hash functions (k):", bf.k)
    print("- Bit array size (m):", bf.size)
    print(f"- Empirical FPR: {empirical_fpr:.2%}")
    print(f"- Theoretical FPR: {theoretical_fpr:.2%}")
    print("=" * 60)

    # Kiểm tra điều kiện đạt yêu cầu
    assert empirical_fpr < 0.05, "❌ FPR quá cao (>5%)!"
    print("✅ Test passed: FPR < 5%")


# Nếu chạy trực tiếp file này
if __name__ == "__main__":
    test_bloom_filter()
