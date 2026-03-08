# EAC 偵測機制 — 技術分析

> 本文是 [EAC Kernel Driver 靜態分析](README.md) 系列的一部分。

---

## 目錄
1. [EPROCESS 直接存取](#1-eprocess-直接存取)
2. [VAD Tree 掃描 — 找出注入的記憶體](#2-vad-tree-掃描)
3. [Handle Table 遍歷](#3-handle-table-遍歷)
4. [Thread 建立監控](#4-thread-建立監控)
5. [Kernel 模組列舉](#5-kernel-模組列舉)
6. [Kernel 完整性驗證 — SSDT 與 Inline Hook](#6-kernel-完整性驗證)
7. [時序分析與反 VM](#7-時序分析與反-vm)
8. [Hash 驗證實作](#8-hash-驗證實作)
9. [可疑行為指標彙整](#9-可疑行為指標彙整)

---

## 1. EPROCESS 直接存取

EAC kernel driver 跑在 Ring-0，可以直接讀取每個 process 的 `EPROCESS` block，完全不需要經過任何 Windows API。這和依賴 user-mode API 的反作弊不同 — 那些 API 可以被 hook，但直接讀取 kernel 結構偏移就沒有這個問題。

### 從反編譯結果看到的 EPROCESS 偏移

從 `sub_FFFFF807C1E1DD80`（遙測組裝器）的反編譯輸出：

```c
// EPROCESS+56  = UniqueProcessId / Token 比對
result = ((__int64 (*)(void))((0x936ACF702E4281A9uLL * v3) ^ 0xFA85638DCFA646E7uLL))();
if ( result == *(_UNKNOWN ***)(a1 + 56) )   // token/PID 比對檢查

// EPROCESS+64  = InheritedFromUniqueProcessId (父 PID)
v56 = *(_DWORD *)(a1 + 64);

// EPROCESS+96  = ImageFileName (15 字元 process 名稱)
v57 = sub_FFFFF807C1E8D840(*(_QWORD *)(a1 + 96));   // 對 image 名稱做 hash

// EPROCESS+240 = Peb / VadRoot 指標
// 打包成 8-byte 值放入遙測
((void (...))(...))(0, v54, v24, 11, a1 + 240, 8);

// EPROCESS+376 = ObjectTable (handle table) 或 token chain
v26 = *(_QWORD *)(a1 + 376);
sub_FFFFF807C1EBF800(v26, 60, 1);   // 鎖定 + 驗證偏移處的結構

// EPROCESS+556 = 保護旗標 / PS_PROTECTION
if ( (_DWORD)result || *(_DWORD *)(a1 + 556) )
```

### 每個 Process 提取的欄位

| 欄位 | EPROCESS 偏移 | 用途 |
|---|---|---|
| **Process token / PID** | `+56` | 驗證 process 身份 |
| **父 PID** | `+64` | 重建 process 樹，找出注入來源 |
| **Image 檔名 hash** | `+96` | 比對已知作弊工具名稱 |
| **Uptime / session** | Kernel API 呼叫 | 偵測剛建立的 VM |
| **VAD root / PEB** | `+240` | 虛擬記憶體映射的起始點 |
| **Handle table 指標** | `+376` | 列舉開啟的 handle |
| **保護旗標** | `+556` | 偵測偽造的 Protected Process Light |

### 觸發標記的條件

EAC 把每個 process 和預期基準線比對。不符合的情況 — 例如 process 宣稱自己是系統 process 但父 process 是 user-mode 的，或在不應該有 `SeDebugPrivilege` 的情況下啟用了它 — 都會被標記並包含在遙測報告中。

---

## 2. VAD Tree 掃描

**Virtual Address Descriptor (VAD)** tree 是 Windows kernel 內部描述 process 每個映射記憶體區域的資料結構。EAC 遍歷這個 tree 來找：

### 掃描目標

**a) 手動映射的 PE Header（反射式注入）**
- 合法的 DLL 永遠有帶關聯 `FILE_OBJECT` 的 file-backed VAD 節點
- 手動映射的程式碼（反射式 DLL 注入、shellcode loader）建立的是**沒有關聯檔案的私有已提交記憶體**
- EAC 尋找 `VAD_NODE.u.VadFlags.PrivateMemory = 1` 同時具有可執行保護且沒有 file backing 的情況

**b) RWX 記憶體（Read-Write-Execute）**
- 合法的程式碼頁面要麼是 `PAGE_EXECUTE_READ`（程式碼），要麼是 `PAGE_READWRITE`（資料）
- 需要在執行時修補程式碼或做 JIT 的作弊需要 `PAGE_EXECUTE_READWRITE`
- 遊戲 process 中任何 RWX 區域都是紅旗

**c) 可疑的區域大小**
- 不屬於任何模組 header 的微小可執行區域（< 4KB）
- 位於不符合標準模組邊界的異常位址的區域

### VAD 遍歷實作

```c
// 來自 sub_FFFFF807C1E1DD80：
v26 = *(_QWORD *)(a1 + 376);     // 取得 handle table / 結構鏈
if ( v26 ) {
    sub_FFFFF807C1EBF800(v26, 60, 1);   // 安全讀取，大小 60 bytes
    v27 = *(_QWORD *)(a1 + 376);
    v28 = 0;
    v49 = 0;
    if ( v27 ) {
        for ( i = 0; ; ++i ) {          // 最多迭代 8 個項目
            if ( i >= 8 ) break;
            // XOR 解碼每個節點偏移 +28 處的 8 bytes
            *((_BYTE *)&v49 + i) = *(_BYTE *)(v27 + 4 * i + 28) ^ 0x90;
            v28 = v49;
        }
    }
    if ( v28 ) {
        sub_FFFFF807C1EBF800(v28, 64, 1);   // 驗證下一個結構（64 bytes）
        v30 = v28[5];   // 子結構指標（52 bytes — 可能是 MMVAD_SHORT）
        v31 = v28[6];   // 模組路徑指標（最多 461 bytes）
        v32 = (_BYTE *)v28[7];   // 二進位指紋（41 bytes）
```

EAC 讀取 **60、64、52、461 和 41 bytes** 偏移處的鏈結結構 — 對應 Windows kernel 中 MMVAD 節點的內部大小、模組路徑 UNICODE_STRING 緩衝區，以及模組二進位 ID。

---

## 3. Handle Table 遍歷

外部作弊從外部讀取遊戲記憶體時，必須以至少 `PROCESS_VM_READ` 的權限對遊戲 process 開啟一個 **handle**。EAC 的偵測方式：

1. **遍歷全域 handle table** — `ObpKernelHandleTable` 以及從 `EPROCESS.ObjectTable` 存取的每個 process handle table
2. **確認持有者身份** — 對任何指向遊戲 process 的 handle，EAC 記錄**開啟者的 PID、process 名稱和請求的存取遮罩**
3. **標記可疑的存取遮罩** — 來自非系統 process 的 `PROCESS_VM_READ (0x0010)`、`PROCESS_VM_WRITE (0x0020)`、`PROCESS_ALL_ACCESS (0x1FFFFF)` 都是自動紅旗

```
觸發 EAC 標記的存取遮罩：
  0x0010  PROCESS_VM_READ         — 外部記憶體讀取器
  0x0020  PROCESS_VM_WRITE        — 外部記憶體寫入器
  0x0008  PROCESS_VM_OPERATION    — VirtualProtectEx 呼叫者
  0x0400  PROCESS_QUERY_INFORMATION — 資訊蒐集
  0x1FFFFF PROCESS_ALL_ACCESS     — 幾乎肯定是作弊/除錯器
```

---

## 4. Thread 建立監控

EAC 透過 `PsSetCreateThreadNotifyRoutine` 註冊 thread 通知 callback，系統上任何地方建立或銷毀 thread 時都會觸發。這讓 EAC 能夠：

- 偵測**遠端 thread 注入** — 從外部 process 使用 `CreateRemoteThread` 或 `NtCreateThreadEx` 在遊戲 process 內啟動 thread
- 記錄遊戲中每個新 thread 的**建立來源** — 如果建立者不是遊戲本身或已知系統元件，就是可疑的
- 偵測 **Thread Hijacking** — 攻擊者暫停合法遊戲 thread 並將 `RIP` 暫存器重定向到 shellcode
- 監控 **thread 起始位址** — 從不對應任何已載入模組程式碼段的位址啟動的 thread 會被標記

---

## 5. Kernel 模組列舉

EAC 透過 `PsLoadedModuleList` 雙向鏈結串列列舉每個已載入的 kernel driver，對每個 driver 執行以下檢查：

### 各項檢查說明

| 檢查項目 | 偵測目標 |
|---|---|
| **數位簽名** | 未簽名或自簽名的 driver（作弊 driver 繞過 DSE）|
| **磁碟路徑** | 從暫存資料夾、RAM disk 或異常路徑載入的 driver |
| **模組名稱 hash** | 與內建黑名單比對 |
| **基址範圍** | 載入在可疑位址的 driver |
| **Image 大小 vs. section 數量** | 手動映射的 kernel 程式碼 |
| **Dispatch routine 指標** | 指向 driver 自身 image 之外（被 hook）|

### DKOM 反制

進階作弊會**把自己的 driver 從 `PsLoadedModuleList` 中移除**。EAC 的反制方式：

1. 獨立掃描**所有 kernel 記憶體頁面**尋找 PE header（`MZ` / `PE` magic bytes），不依賴模組列表
2. 把找到的 PE image 集合與 `PsLoadedModuleList` 比對 — 不在列表中的 PE image 就是隱藏的 driver
3. 檢查 **MmSystemRange** 模組追蹤結構是否有異常

---

## 6. Kernel 完整性驗證

EAC 驗證關鍵 kernel 函式沒有被 hook 或修補。

### SSDT Hook 偵測

**System Service Descriptor Table (SSDT)** 把系統呼叫號碼映射到 kernel 函式位址。Rootkit 和 kernel-mode 作弊 hook 這個表來攔截 `NtReadVirtualMemory` 等呼叫。EAC 的做法：

1. 從 `KeServiceDescriptorTable` 讀取原始 SSDT 項目
2. 驗證每個項目指向 `ntoskrnl.exe` 的合法程式碼段
3. 指向 `ntoskrnl.exe` 已知範圍之外的項目就是 hook

### Inline Hook 偵測

EAC 使用 SIMD hash 例程對關鍵 kernel 函式的前 N bytes 計算 checksum：

```c
// sub_FFFFF807C1E11C00 — Huffman/熵頻率表建構器
// 對 kernel 程式碼 bytes 執行，建立頻率直方圖
// 如果直方圖偏離預期模式，代表程式碼被修補了

// AVX2 變體（sub_FFFFF807C1E13100）每次迭代處理 15 bytes：
// vpinsrb, vmovdqu, vpaddq — 全部是 256-bit AVX2 SIMD
// 同時處理正向和反向串流以提高速度
```

### Dispatch Table Hook 偵測

對每個已載入的 driver，EAC 檢查 `DRIVER_OBJECT` 中的 `MajorFunction[IRP_MJ_*]` 指標是否**指向該 driver 自身的記憶體範圍內**。跳到另一個 driver 程式碼的指標就是 dispatch routine 上的 hook。

---

## 7. 時序分析與反 VM

### KUSER_SHARED_DATA 時序

```c
// 來自 sub_FFFFF807C1E1DD80：
v48 = MEMORY[0xFFFFF78000000014];   // KUSER_SHARED_DATA.TickCountLow
```

`0xFFFFF78000000014` 是 `KUSER_SHARED_DATA.TickCountLow` — Windows kernel 每約 15ms 更新一次的單調遞增計數器。EAC 用它來：

1. **為每條遙測記錄加上時間戳**
2. **偵測時間操控** — 如果作弊或 VM 暫停了時間，tick count 會落後於實際牆鐘時間
3. 與加密的 kernel 時間 API 呼叫**交叉比對**（`0xE462A05B3E35A30F * v9 ^ 0x7D67C96867B51F90LL` — 幾乎可以確定是 `KeQuerySystemTime` 或 `KeQueryInterruptTime`）

### VM 偵測訊號

| 訊號 | EAC 的讀取方式 |
|---|---|
| CPUID hypervisor bit | 透過加密的 CPUID 分派 |
| 系統 uptime 接近零 | `KUSER_SHARED_DATA.TickCountLow` 值很小 |
| 可疑的磁碟型號 | 透過 IOCTL 向磁碟 driver 查詢 |
| 不一致的硬體 ID | 跨來源比對 |
| 缺少 ACPI 表 | 韌體表掃描 |

---

## 8. Hash 驗證實作

`sub_FFFFF807C1E3A4C0` 是 EAC 的 **hash 演算法選擇器**，根據選擇器值初始化對應的 hash context：

```c
switch (selector - 1):
  case 0:  // SHA-1（輸出大小 = 20 bytes）
    init: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

  case 1:  // MD5（輸出大小 = 16 bytes）
    init: 1732584193, -271733879, -1732584194, 271733878

  case 2:  // SHA-1 變體（輸出大小 = 20 bytes）
    init: 相同的 SHA-1 常數 + 清零的額外狀態

  case 3:  // SHA-224（輸出大小 = 28 bytes）
    init: 0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939...

  case 4:  // SHA-256（輸出大小 = 32 bytes）
    init: 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A...
    
  case 5:  // SHA-384（輸出大小 = 48 bytes）
    sub_FFFFF807C1E3BCCC(context)

  case 6:  // SHA-512（輸出大小 = 64 bytes）
    sub_FFFFF807C1E3BB98(context)
```

用於 hash 的對象：
- **磁碟上的已載入模組** — 與已知良好的 hash 比對
- **記憶體中的程式碼段** — 偵測執行時修補
- **遙測封包內容** — 在用 ECC 簽名之前

---

## 9. 可疑行為指標彙整

| 指標 | 類別 | 風險等級 |
|---|---|---|
| 遊戲 process 中的 RWX 記憶體區域 | 記憶體 | 嚴重 |
| 記憶體中沒有 file backing 的 PE header | 記憶體 | 嚴重 |
| 從外部 process 在遊戲 process 中建立 thread | 注入 | 嚴重 |
| SSDT 項目指向 ntoskrnl.exe 之外 | Kernel hook | 嚴重 |
| 載入了未簽名的 kernel driver | Driver | 嚴重 |
| Driver 從 PsLoadedModuleList 中被移除（DKOM）| Driver | 嚴重 |
| Kernel driver dispatch routine 指向其 image 之外 | Hook | 嚴重 |
| 可疑 process 以 PROCESS_VM_READ 開啟遊戲 | Handle | 高 |
| 非開發者情境下啟用了 SeDebugPrivilege | 權限 | 高 |
| KUSER_SHARED_DATA tick count 不一致 | 時序 | 高 |
| 多個來源的硬體 ID 不一致 | HWID | 高 |
| 不應有 PPL 保護的 process 卻有 | 偽造 | 高 |
| Driver 從暫存/異常路徑載入 | Driver | 中 |
| Process 名稱符合已知作弊工具 | Process | 中 |
| CPUID 中設置了 hypervisor bit | VM | 中 |
| 在 kernel 函式中偵測到 inline hook | Kernel hook | 嚴重 |

---

*← [回到 README](README.md) | [IOCTL 與 Driver 追蹤 →](ioctl_and_driver_tracking.md)*
