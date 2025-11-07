# streambf-ch
# StreamBF-CH: Hybrid Probabilistic Hashing for High-Velocity Data Streams

**Đề tài 1** – Môn Cấu trúc Dữ liệu & Thuật toán Nâng cao  
**Nhóm 4 người** – Đạt 8-9 điểm  

## Mục tiêu
- [x] Code BF & CH từ đầu  
- [x] Hybrid + Adaptive resize  
- [x] Eval trên CAIDA + Twitter  
- [x] Demo live + Báo draft 3-4 trang  

## Thành viên
- **TV1 (Lead)**: @hangthan205 – Review + Writing  
- **TV2**: Bloom Filter + Data  
- **TV3**: Cuckoo Hashing + Adaptive  
- **TV4**: Integration + Metrics + Visuals  

## Cách chạy
```bash
pip install -r requirements.txt
python src/benchmark.py
```
## Cấu trúc thư mục
streambf-ch/
│
├── src/                  # Code chính
│   ├── bloom_filter.py   # TV2
│   ├── cuckoo_hash.py    # TV3
│   ├── streambf_ch.py    # TV4 (hybrid + adaptive)
│   └── benchmark.py      # TV4 (metrics)
│
├── data/                 # Dữ liệu
│   ├── caida_sample.csv  # TV2 parse
│   └── twitter_sample.csv
│
├── tests/                # Test
│   ├── test_bf.py
│   ├── test_ch.py
│   └── test_hybrid.py
│
├── notebooks/            # Colab
│   └── demo.ipynb        # TV4 demo
│
├── docs/                 # Báo cáo
│   └── report_draft.md
│
├── README.md
└── requirements.txt
