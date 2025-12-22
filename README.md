# StreamBF-CH: Hybrid Bloom Filter + Cuckoo Hashing với Adaptive Resizing

**StreamBF-CH** là một cấu trúc dữ liệu xác suất hybrid được thiết kế cho xử lý **data stream high-velocity**, đặc biệt phù hợp với bài toán phát hiện tấn công DDoS dựa trên membership query của địa chỉ Source IP.

Mô hình kết hợp **Bloom Filter** (pre-filter nhanh) và **Cuckoo Hash Table** (exact lookup) để đạt **false positive rate ≈ 0%**, đồng thời tích hợp **adaptive resizing** tự động khi FPR > 5% hoặc load factor > 90%.

**Đồ án cuối kỳ – Nhóm 4 – Tháng 12/2025**

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## Mục tiêu đạt được (100%)

| Mục tiêu                               | Trạng thái | Ghi chú                                                |
| -------------------------------------- | ---------- | ------------------------------------------------------ |
| Prototype chạy được end-to-end         | ✅ 100%    | Hybrid + adaptive hoạt động                            |
| Demo live 5 phút                       | ✅ Ready   | Chạy giả lập → FPR từ ~4.7% → 0%                       |
| Hiểu bản chất BF & CH                  | ✅ 100%    | Code từ scratch, giải thích được eviction, FPR formula |
| Eval đơn giản (2 runs, real + giả lập) | ✅ 100%    | So sánh Bloom thuần vs Hybrid                          |
| Biểu đồ so sánh FPR, Throughput        | ✅ 100%    | Lưu trong `/plots`                                     |
| Báo cáo draft 3-4 trang                | ✅ Ready   | Theo template LaTeX                                    |

## Đặc điểm nổi bật

- **Zero false positives** nhờ hybrid Bloom + Cuckoo
- **Throughput cao**: >900.000 queries/giây
- **Adaptive resizing** tự động trong traffic surge
- **Memory hiệu quả**: ~400 MB cho 10.000 malicious IPs
- **Triển khai hoàn toàn bằng Python** (bitarray, mmh3, custom Cuckoo)

## Sơ đồ hệ thống

Data Stream Input → Bloom Filter (Pre-Filter) → (if positive) Cuckoo Hashing → Output (CLEAN / MALICIOUS)
↓
Adaptive Resizing (FPR > 5% or Load > 90%)

## Cấu trúc thư mục

streambf-ch/
├── StreamBF-CH_Demo.ipynb # Notebook demo chính – MỞ CÁI NÀY ĐỂ CHẠY!
├── core/
│ ├── bloom_filter.py # Bloom Filter từ scratch
│ ├── cuckoo_hash.py # Cuckoo Hash Table
│ └── reputation_manager.py # Hybrid + adaptive logic
├── data/
│ ├── load_cicddos.py # Load & preprocess CIC-DDoS2019
│ └── \*.csv # Dataset files
├── benchmark/
│ └── run_benchmark.py # Benchmark + vẽ biểu đồ
├── plots/ # Biểu đồ kết quả
└── README.md

## Cài đặt

```bash
git clone https://github.com/hangthan/streambf-ch.git
cd streambf-ch

# Tạo virtual environment (khuyến nghị)
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate

# Cài packages
pip install pandas numpy matplotlib bitarray mmh3 psutil 
```

## Chạy Demo (5 phút)

Mở StreamBF-CH_Demo.ipynb trong Jupyter/VSCode
Chạy các cell theo thứ tự:
Load CIC-DDoS2019 (Training + Testing Day)
Test Bloom Filter riêng
Test Cuckoo Hashing
Chạy hybrid ReputationManager
Demo adaptive resize (insert dần → xem log resize)
Chạy benchmark → xem biểu đồ FPR = 0.00%

Kết quả chính (giả lập high-velocity – 10.000 malicious IPs):

Bloom thuần: FPR ≈ 4.67%
StreamBF-CH: FPR = 0.0000%
Throughput ≈ 955.000 queries/s

Dataset
Sử dụng CIC-DDoS2019 (UNB, 2019):

Training Day (01-12) + Testing Day (03-11)
Các file chính: Syn, DrDoS_UDP, DrDoS_DNS, UDP-Lag, Portmap, NetBIOS, LDAP, MSSQL, NTP, TFTP...
Đặc trưng: ít unique malicious IPs do môi trường lab → bổ sung giả lập để minh họa hybrid lợi ích

## Tài liệu tham khảo

Cuckoo Filter: Practically Better Than Bloom (CoNEXT 2014)
Tổng hợp 20 bài báo liên quan (2018–2025) – xem tinh hinh nghien cuu.pdf
Dataset CIC-DDoS2019 – Parquet/CSV từ UNB
