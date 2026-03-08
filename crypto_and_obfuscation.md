# 加密實作與混淆手法 — 技術分析

> 本文是 [EAC Kernel Driver 靜態分析](README.md) 系列的一部分。

EAC 在讓這個 driver 難以分析這件事上下了很大的功夫。沒有 import table，字串被打亂，函式指標被加密，加密例程是用大量 SIMD 手寫的，每個反編譯器都會頭痛。這份文件記錄把這些東西一一拆解後找到的東西。

---

## 目錄
1. [P-256 橢圓曲線加密實作](#1-p-256-橢圓曲線加密實作)
2. [NTT / Montgomery 模運算](#2-ntt--montgomery-模運算)
3. [Zstd 壓縮引擎](#3-zstd-壓縮引擎)
4. [Hash 演算法套件](#4-hash-演算法套件)
5. [加密函式指標分派機制](#5-加密函式指標分派機制)
6. [字串混淆](#6-字串混淆)
7. [SIMD 演算法混淆](#7-simd-演算法混淆)
8. [Driver 卸載 Canary](#8-driver-卸載-canary)

---

## 1. P-256 橢圓曲線加密實作

EAC 在 kernel driver 中直接實作了一套完整的 **P-256 (secp256r1 / NIST P-256)** 橢圓曲線加密。這是 TLS 1.3、ECDSA 和現代程式碼簽名使用的同一條曲線。實作分三層：

### 第一層：Field 運算 — 9-Limb 30-Bit Radix 多項式乘法

**`sub_FFFFF807C1E21280`** — 在 P-256 質數域上使用 **9-limb、30-bit radix** 表示法的 256-bit 多項式乘法：

```c
// P-256 field element = 9 × 30-bit limbs 存在 uint32[] 中
// 這樣可以避免部分積的 64-bit 溢位

// 乘法計算 GF(p) 上的 a × b，其中 p = 2^256 - 2^224 + 2^192 + 2^96 - 1
// 使用類 Karatsuba 的教科書乘法：
v29[0] = v4 * v3;                              // limb[0] × limb[0]
v29[1] = v4 * v5 + v3 * v6;                   // 交叉項
v29[2] = v4 * v28 + v5 * v6 + v3 * v7;        // 以此類推...
// ... 共 17 個輸出 limb ...

// 帶 30-bit 遮罩的進位傳播：
for (i = 0; i < 17; i++) {
    v22 = v29[i] + carry;
    result = v22 & 0x3FFFFFFF;   // 保留低 30 bits
    carry  = v22 >> 30;           // 傳播高位 bits
    output[i] = result;
}
output[17] = carry;
```

### 第二層：純量乘法 — Constant-Time Double-and-Add

**`sub_FFFFF807C1E226E0`** — **Mont-ladder / constant-time double-and-add** 點純量乘法。對純量中的每對 bits 進行迭代，使用**無分支 XOR 遮罩**在兩個候選點之間做條件選擇：

```c
// Constant-time 條件交換 — 沒有時序洩漏：
*((_BYTE *)v49 + v27) ^= (uint8_t)-((v25 ^ 2) - 1 < 0) 
                        & (*((_BYTE *)v52 + v27) ^ *((_BYTE *)v49 + v27));
// 如果條件為真：元素被交換（XOR 兩次 = 原始值）
// 如果條件為假：元素不變（XOR 0 = 原始值）
// 兩條路徑花費完全相同的時間 — 時序側通道被封鎖
```

每輪處理 **2 bits**（Möller 的 2-bit NAF window），執行 `floor(256/2) = 128` 次迭代。

### 第三層：模化簡 — Montgomery/Barrett 化簡

**`sub_FFFFF807C1E1AF00`** — field 乘法後的大整數模化簡：

```c
// 62-bit 模常數設置：
v64 = (a5 * (*(_QWORD *)a6 * a5 + 2LL)) & 0x3FFFFFFFFFFFFFFFLL;

// Montgomery 乘法內層迴圈：
v55 = 4 * *(_QWORD *)v17 * v64;           // Montgomery 因子
v56 = v55 * (uint128_t)*v54;              // 128-bit 乘法
v57 = v52 + v56 + (uint64_t)(v55 * *v54); // 累加
v52 = 4LL * *((uint64_t*)&v57 + 1);      // 提取高字（進位）
```

用途：
1. **簽名驗證** — 驗證 EAC 自身的程式碼沒有被篡改
2. **遙測簽名** — 對遙測封包做加密簽名，讓 EAC 伺服器能驗證真實性
3. **Challenge-response** — 回應來自 EAC 伺服器的加密挑戰

### EAC 簽名的內容

每個遙測封包都用嵌入在 driver 中的 P-256 私鑰做 **ECDSA 簽名**。伺服器用對應的公鑰驗證。這意味著：
- 無法偽造遙測封包 — 私鑰不在你手上
- 無法重放舊封包 — 時間戳是簽名資料的一部分
- 對封包內容的任何修改都會讓簽名失效

---

## 2. NTT / Montgomery 模運算

在 Montgomery 化簡的基礎上，EAC 還使用了 **Number Theoretic Transform (NTT)**，這是快速傅立葉變換的模運算版本，出現在 `sub_FFFFF807C1E1AF00` 的實作中。

NTT 用於多項式乘法，應用場景包括：
- **基於格的運算**（可能是後量子抗性的金鑰交換）
- **零知識證明原語**（在不揭露資料的情況下證明知道某資料）
- **高速 RSA** 運算

關鍵觀察：常數 `& 0x3FFFFFFFFFFFFFFFLL` 遮罩到 **62-bit 質數域**，這是 NTT 實作的特徵（質數必須 `< 2^62` 才能讓變換不溢位）。

---

## 3. Zstd 壓縮引擎

EAC 在 kernel driver 中直接編譯了一套**完整的 Zstandard (Zstd) 壓縮函式庫**，用來在加密和傳輸之前壓縮所有遙測資料。實作分三個效能層級：

### SSE2 Huffman 編碼器（`sub_FFFFF807C1E11EE0`，大小 0x579）
- 使用 SSE2 128-bit XMM 暫存器同時處理兩個串流
- 在 AVX2 不可用或處理較小資料塊時使用

### AVX2 Huffman 編碼器（`sub_FFFFF807C1E12460`，大小 0x54D）
- 使用 256-bit YMM 暫存器
- 每次迭代處理兩個獨立的 bitstream

### AVX2 4-Stream Huffman（`sub_FFFFF807C1E13100`，大小 0x577）
- 最高效能層 — 最多處理 **6 個平行串流**
- 使用 `vpinsrb`、`vmovdqu`、`vpaddq`
- 主迴圈每次迭代處理 **15 bytes**
- 同時解碼正向和反向串流（雙向）

### 頻率表建構器（`sub_FFFFF807C1E11C00`，大小 0x2D1）
- 建立用於 Huffman tree 建構的 byte 頻率直方圖
- 也用作**熵估計器** — 高熵區域表示加密/壓縮的內容被修補進了合法 process

### 為什麼要在 Kernel 空間做 Zstd？

在 kernel 空間使用壓縮器意味著 EAC 可以：
1. 在把大型遙測封包傳遞到 user-mode 之前先壓縮
2. 壓縮後的資料看起來像隨機 bytes — 從網路封包更難逆向工程
3. 不依賴可能被 hook 或替換的 user-space 壓縮函式庫

---

## 4. Hash 演算法套件

`sub_FFFFF807C1E3A4C0` 是 EAC 的 **hash 演算法初始化函式**，支援完整的 SHA 家族加上 MD5：

```c
// 選擇器 1：SHA-1（20-byte 輸出，64-byte block）
IVs: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

// 選擇器 2：MD5（16-byte 輸出，64-byte block）
IVs: 1732584193, -271733879, -1732584194, 271733878

// 選擇器 4：SHA-224（28-byte 輸出，64-byte block）
IVs: 0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
     0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4

// 選擇器 5：SHA-256（32-byte 輸出，64-byte block）
IVs: 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
     0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19

// 選擇器 6：SHA-384 → sub_FFFFF807C1E3BCCC
// 選擇器 7：SHA-512 → sub_FFFFF807C1E3BB98
```

### 各 Hash 的用途

| Hash | 用途 |
|---|---|
| **SHA-256** | 模組檔案完整性（比對已載入的 .sys/.dll 與已知良好的 hash）|
| **SHA-1** | 舊版遊戲檔案驗證 |
| **SHA-512** | 遙測封包認證標籤 |
| **MD5** | 對 process 記憶體快照做快速唯一性檢查 |
| **SHA-384** | 憑證鏈驗證中間 hash |

---

## 5. 加密函式指標分派機制

在 [IOCTL 與 Driver 追蹤](ioctl_and_driver_tracking.md#3-加密函式分派) 中已有深入說明，這裡補充加密相關的額外混淆層：

### Key Table 佈局

加密指標表位於 `0xFFFFF807C2068E78` 及附近偏移：

```
0xFFFFF807C2068E78  → slot 0：加密的 PsGetCurrentProcess 等效函式
0xFFFFF807C2068E88  → slot 1：加密的封包序列化器
0xFFFFF807C2068EC8  → slot 2：加密的 PsGetProcessSessionId
0xFFFFF807C2068EE8  → slot 3：加密的 KeQuerySystemTime
... 更多 slot 以 +0x10 遞增 ...
```

每個 slot 是**一個 QWORD**，包含 XOR 加密的 kernel 函式位址。解密金鑰在 driver 載入時從硬體特定資料計算得出，讓加密值在每台機器上都是唯一的。

---

## 6. 字串混淆

EAC 在 binary 中**不存放任何明文字串**。globals 段包含命名為 `a41`、`a42`、... `a7e` 的 byte 陣列 — 這些是混淆字串表的索引。

在執行時，字串透過專用的反混淆函式按需解碼。編碼方式是**帶有位置相關金鑰的滾動 XOR 加密**。因為金鑰取決於位置，無法只用一個值 XOR 整個緩衝區 — 必須逆向反混淆函式。

這意味著：
- 在 binary 中搜尋 `"NtReadVirtualMemory"` 這樣的字串什麼都找不到
- `strings` 分析、IDA 字串視窗全都顯示亂碼
- 實際的 API 名稱只在**執行期間出現在 RAM 中**

---

## 7. SIMD 演算法混淆

EAC 的 Huffman 和 hashing 例程是用大量 intrinsic 的 C 或直接用組合語言手寫的，刻意增加複雜度來混淆反編譯器：

```c
// 來自 sub_FFFFF807C1E13100（AVX2 Huffman）— 反編譯器輸出：
__int128 v4;   // xmm1
__int128 v5;   // xmm0
// ... 40+ 個 xmm/ymm 變數 ...

// Hex-Rays 產生「不正確」的輸出，因為：
// 1. AVX2 指令以 Hex-Rays 無法完全建模的方式操作子暫存器
// 2. 程式碼刻意混合 SIMD 和純量路徑來混淆型別推斷
// 3. 手動 SSE2/AVX2 組合語言序列無法乾淨地映射到 C 抽象
```

反編譯輸出在語法上看起來有效，但**語義上令人困惑** — 即使是有經驗的逆向工程師也需要時間手動追蹤資料流。

---

## 8. Driver 卸載 Canary

`sub_FFFFF807C1E50D40` 是 **driver 清理 / 卸載處理器**，包含一個值得注意的 canary 檢查：

```c
// 在釋放主要 EAC 分配之前，驗證 canary：
result = 0xBC44A31CA74B4AAFuLL;
if ( *(_QWORD *)qword_FFFFF807C206A828 == 0xBC44A31CA74B4AAFuLL 
     && qword_FFFFF807C206A828 ) {
    sub_FFFFF807C1F201E0(qword_FFFFF807C206A828);  // 正常清理
    result = sub_FFFFF807C1F16DE0(v1);             // 釋放記憶體
}
qword_FFFFF807C206A828 = 0;
```

magic 值 `0xBC44A31CA74B4AAF` 在建立時被寫入 **EAC 主要 pool 分配的開頭**。在釋放之前：
1. 檢查指標是否非 null
2. 檢查前 8 bytes 是否符合 magic 值
3. 如果 canary 消失了（被覆寫），EAC **跳過釋放**（防止 double-free 或 use-after-free 崩潰）

這表明 EAC 遇到過或預期到 heap 損壞攻擊，並對清理路徑做了加固。

---

*← [IOCTL 與 Driver 追蹤](ioctl_and_driver_tracking.md) | [遙測 →](telemetry.md)*
