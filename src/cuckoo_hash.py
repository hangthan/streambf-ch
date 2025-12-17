import numpy as np

# --- Cấu hình ---
# Số lượng khóa DUY NHẤT bạn muốn chèn vào Cuckoo/Bloom Filter
N_ITEMS_TO_INSERT = 10000 
# Số lượng truy vấn (queries) bạn muốn kiểm tra (Ví dụ: 2 lần số lượng chèn)
N_QUERIES = 20000 
# Tỷ lệ lấy mẫu từ file lớn (ví dụ: 5% tổng số dòng)
SAMPLE_FRACTION = 0.05 

# --- Định nghĩa các cột CẦN THIẾT (Sử dụng tên chính xác) ---
KEY_COLS = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol']

print(f"Bắt đầu đọc mẫu {SAMPLE_FRACTION*100}% dữ liệu và tạo khóa...")

# 1. Đọc mẫu dữ liệu
try:
    df_sample = pd.read_csv(
        CSV_FILE_PATH,
        usecols=KEY_COLS, # Chỉ đọc các cột cần thiết để tiết kiệm bộ nhớ
        # Lấy mẫu ngẫu nhiên 5% số dòng
        skiprows=lambda i: i > 0 and np.random.rand() > SAMPLE_FRACTION 
    )
    print(f"Đã đọc {len(df_sample)} dòng mẫu.")

except Exception as e:
    print(f"Lỗi đọc mẫu dữ liệu: {e}")
    # Xử lý ngoại lệ nếu cần

# 2. Tạo Khóa Duy nhất (5-tuple Key)
df_sample.dropna(inplace=True) # Xóa các hàng có giá trị NaN để đảm bảo khóa hợp lệ

df_sample['Flow_Key'] = (
    df_sample['Src IP'].astype(str) + '|' +
    df_sample['Src Port'].astype(str) + '|' +
    df_sample['Dst IP'].astype(str) + '|' +
    df_sample['Dst Port'].astype(str) + '|' +
    df_sample['Protocol'].astype(str)
)

# Lấy tất cả các khóa duy nhất
all_unique_keys = df_sample['Flow_Key'].unique()

if len(all_unique_keys) < N_ITEMS_TO_INSERT:
    raise ValueError(f"Không đủ khóa duy nhất ({len(all_unique_keys)}) để tạo {N_ITEMS_TO_INSERT} items. Cần tăng SAMPLE_FRACTION.")

# 3. Chia Tập hợp
# a) INSERT_SET (Tập hợp các khóa để chèn)
INSERT_SET = all_unique_keys[:N_ITEMS_TO_INSERT]

# b) QUERY_SET (Tập hợp các khóa để kiểm tra)
# Chúng ta tạo 50% True Positives (có) và 50% True Negatives (không)
N_HALF_QUERY = N_QUERIES // 2

# Phần 1: True Positives (Chọn ngẫu nhiên từ INSERT_SET)
query_tp = np.random.choice(INSERT_SET, size=N_HALF_QUERY, replace=True)

# Phần 2: True Negatives (Chọn ngẫu nhiên từ phần còn lại của dữ liệu)
remaining_keys = all_unique_keys[N_ITEMS_TO_INSERT:]
query_tn = np.random.choice(remaining_keys, size=N_HALF_QUERY, replace=True)

QUERY_SET = np.concatenate([query_tp, query_tn])
np.random.shuffle(QUERY_SET) # Xáo trộn

print("\n=== Kết quả Xử lý Dữ liệu ===")
print(f"Tổng số Khóa Duy nhất có thể dùng: {len(all_unique_keys)}")
print(f"Kích thước INSERT_SET (để ADD): {len(INSERT_SET)} khóa")
print(f"Kích thước QUERY_SET (để LOOKUP): {len(QUERY_SET)} khóa")

# 4. Dọn dẹp (Xóa file CSV tạm thời)
# Nếu bạn muốn tiết kiệm dung lượng Colab VM, bạn có thể xóa file CSV đã giải nén
# import shutil
# shutil.rmtree(UNZIP_DIR) 
# print(f"Đã xóa thư mục tạm thời: {UNZIP_DIR}")


import time
import math
import random
import sys

# Tăng giới hạn đệ quy (Cần thiết cho quá trình gọi lại insert() sau resize)
sys.setrecursionlimit(2000) 

# Giới hạn số lần đẩy ra (eviction) tối đa để phát hiện chu kỳ
MAX_LOOP = 50 

# =======================================================
#               LỚP CUCKOOHASH HOÀN CHỈNH
# =======================================================

class CuckooHash:
    
    def __init__(self, initial_capacity=100):
        if initial_capacity % 2 != 0:
            initial_capacity += 1 
            
        self.capacity = initial_capacity
        self.count = 0 
        self.table1 = [None] * self.capacity
        self.table2 = [None] * self.capacity
        self.seed1 = random.randint(1, 100000)
        self.seed2 = random.randint(1, 100000)

    def _h1(self, key):
        return (hash(key) + self.seed1) % self.capacity

    def _h2(self, key):
        return (hash(key[::-1]) + self.seed2) % self.capacity 

    def lookup(self, key):
        pos1 = self._h1(key)
        if self.table1[pos1] is not None and self.table1[pos1][0] == key:
            return self.table1[pos1][1] 
        
        pos2 = self._h2(key)
        if self.table2[pos2] is not None and self.table2[pos2][0] == key:
            return self.table2[pos2][1] 
            
        return None 

    def insert(self, key, value):
        
        if self.lookup(key) is not None:
            return True

        current_key = key
        current_value = value
        
        for _ in range(MAX_LOOP):
            
            # Eviction T1
            pos1 = self._h1(current_key)
            if self.table1[pos1] is None:
                self.table1[pos1] = (current_key, current_value)
                self.count += 1
                return True
            
            old_key, old_value = self.table1[pos1]
            self.table1[pos1] = (current_key, current_value)
            current_key, current_value = old_key, old_value

            # Eviction T2
            pos2 = self._h2(current_key)
            if self.table2[pos2] is None:
                self.table2[pos2] = (current_key, current_value)
                self.count += 1
                return True

            old_key, old_value = self.table2[pos2]
            self.table2[pos2] = (current_key, current_value)
            current_key, current_value = old_key, old_value
            
        # Phát hiện Chu kỳ
        print(f"!!! Cảnh báo: Phát hiện Chu kỳ sau {MAX_LOOP} lần đẩy ra. Kích hoạt Adaptive Resize.")
        self._adaptive_resize()
        return self.insert(current_key, current_value)

    def _adaptive_resize(self):
        print(f"Bắt đầu Resize. Kích thước hiện tại: {self.capacity * 2} ô.")
        
        old_items = []
        for table in [self.table1, self.table2]:
            for item in table:
                if item is not None:
                    old_items.append(item)
                    
        new_capacity = self.capacity * 2
        self.capacity = new_capacity
        
        self.table1 = [None] * self.capacity
        self.table2 = [None] * self.capacity
        self.count = 0 
        
        self.seed1 = random.randint(100001, 200000)
        self.seed2 = random.randint(200001, 300000)

        print(f"  > Đang Tái băm {len(old_items)} khóa vào cấu trúc mới ({self.capacity * 2} ô)...")
        for key, value in old_items:
            self.insert(key, value)
            
        print(f"Resize và Tái băm hoàn tất. Kích thước mới: {self.capacity * 2} ô.")
