# Adaptive Bloom + Cuckoo Reputation Demo

## Tổng quan

- Hệ thống minh họa pipeline phát hiện IP độc hại dạng streaming, kết hợp Bloom Filter (lọc nhanh khả năng âm tính) và Cuckoo Hash Table (lưu chính xác các IP đã biết xấu).
- Dữ liệu vào là log traffic CSV; blacklist nền được nạp từ hai tập CSV synthetic. Khi lưu lượng chạy, Bloom và Cuckoo có thể tự mở rộng để giữ FPR nằm dưới ngưỡng cấu hình.
- Mục tiêu: kiểm tra nhanh, tỷ lệ dương giả thấp, và có thể tái tạo Bloom khi cần để duy trì FPR.

## Thành phần chính

- `core/bloom/bloom_filter.py`: Cài đặt Bloom Filter (double hashing, thread-safe bằng RLock, ước lượng FPR).
- `core/bloom/bloom_params.py`: Tính toán m (bit) và k (hash) tối ưu theo sức chứa và FPR mục tiêu.
- `core/cuckoo/cuckoo_table.py`: Bảng băm Cuckoo (2 hàm băm, hoán vị khi va chạm, rehash khi load factor cao).
- `core/cuckoo/cuckoo_entry.py`: Bản ghi danh tiếng IP (`ip`, `first_seen`, `last_seen`).
- `core/manager/reputation_manager.py`: Điều phối Bloom + Cuckoo, fast_check, tái tạo Bloom khi FPR vượt ngưỡng.
- `core/metrics/metrics.py`: Thu thập số lần tra Bloom/Cuckoo, latency lookup, eviction/insert.
- `core/types/ip_types.py`: Chuẩn hóa IPv4 thành khóa băm 128-bit.
- `demo_bf_ch.py`: CLI demo (menu) để nạp blacklist, chạy replay traffic, in thống kê.
- `ddos_data/`: CSV synthetic (blacklist base, incremental, traffic 5 phút).

## Sơ đồ workflow (chi tiết hơn)

```
[Nạp blacklist]
  base CSV + incremental CSV
    -> ip_to_key
    -> insert vào Cuckoo (đúng) và Bloom (xấp xỉ)
    -> nếu load_factor(Cuckoo) > 0.9: rehash x2
    -> nếu est_fpr(Bloom) > FPR_LIMIT: rebuild Bloom (tính m,k mới)

[Replay traffic CSV]
  dòng log -> ip_to_key
    -> Bloom.might_contain?
      -> No  -> trả CLEAN (bỏ qua)
      -> Yes -> Cuckoo.get
           -> Hit  -> MALICIOUS
           -> Miss -> BLOOM_FALSE_POSITIVE
    -> định kỳ hoặc khi ước lượng FPR vượt ngưỡng: rebuild Bloom
    -> nếu load_factor(Cuckoo) vượt ngưỡng: rehash x2

[Thống kê]
  - bloom_positive/negative, cuckoo_hit, bloom_false_positive
  - throughput, fpr_real, recall
```

## Khởi tạo & rescale

- Nạp blacklist nền vào Cuckoo và Bloom với tham số tính từ `BloomParams` (FPR mục tiêu \*0.5).
- Trong quá trình nạp incremental và khi replay traffic:
  - Nếu load factor Cuckoo > 0.9: `_rehash` tăng dung lượng (nhân 2).
  - Nếu FPR ước lượng của Bloom > FPR_LIMIT: tái tạo Bloom với kích thước mới (nhân đôi hoặc đủ để đạt FPR).

## Chạy nhanh

```bash
python demo_bf_ch.py
```

Menu:

1. Nạp blacklist (base + incremental) kèm rescale động.
2. Chọn dataset traffic (mặc định `ddos_data/synth_traffic_5m.csv`) và chạy `fast_check` (có tùy chọn verbose).
3. Thoát.

## Tham số mặc định

- FPR_LIMIT: 0.01
- Cuckoo load limit: 0.9, growth factor: 2

## Cấu trúc thư mục

```
core/
  bloom/        Bloom Filter + tính tham số
  cuckoo/       Cuckoo hash table + entry
  manager/      Điều phối fast_check, rebuild Bloom
  metrics/      Bộ đếm metrics
  types/        Chuẩn hóa IP
ddos_data/      CSV synthetic (blacklist, traffic)
demo_bf_ch.py   CLI demo
```
