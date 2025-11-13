# -*- coding: utf-8 -*-
"""
Test script cho Bloom Filter core module.
"""

import sys
import os
import random
import string

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.bloom_filter import BloomFilter


def random_str(n: int = 6) -> str:
    """Sinh chuỗi ngẫu nhiên a–z."""
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def test_bloom_filter():
    """Kiểm thử Bloom Filter."""
    capacity = 100
    bf = BloomFilter(capacity=capacity, k_hashes=7)

    dataset = [random_str() for _ in range(capacity)]
    for item in dataset:
        bf.add(item)

    test_data = [random_str() for _ in range(capacity)]
    false_positive = sum(
        bf.might_contain(item) and item not in dataset for item in test_data
    )

    empirical_fpr = false_positive / len(test_data)
    theoretical_fpr = bf.estimate_fpr(len(dataset))

    print("=" * 60)
    print("🌿 BLOOM FILTER TEST SUMMARY 🌿")
    print(f"- Items inserted (n): {len(dataset)}")
    print(f"- Hash functions (k): {bf.k}")
    print(f"- Bit array size (m): {bf.size}")
    print(f"- Empirical FPR    : {empirical_fpr:.2%}")
    print(f"- Theoretical FPR  : {theoretical_fpr:.2%}")
    print("=" * 60)

    assert empirical_fpr < 0.05, "❌ FPR quá cao (>5%)!"
    print("✅ Test passed: Empirical FPR < 5%.")


if __name__ == "__main__":
    test_bloom_filter()
