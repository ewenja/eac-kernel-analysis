# IOCTL 通訊與 Driver 追蹤 — 技術分析

> 本文是 [EAC Kernel Driver 靜態分析](README.md) 系列的一部分。

---

## 目錄
1. [Device Object 與 IOCTL 架構](#1-device-object-與-ioctl-架構)
2. [Ring3 到 Ring0 的資料流](#2-ring3-到-ring0-的資料流)
3. [加密函式分派 — EAC 如何隱藏 API 呼叫](#3-加密函式分派)
4. [Kernel Driver 列舉與黑名單](#4-kernel-driver-列舉與黑名單)
5. [Dispatch Table Hook 偵測](#5-dispatch-table-hook-偵測)
6. [Filter Driver 與裝置 Stack 偵測](#6-filter-driver-與裝置-stack-偵測)
7. [Storage Driver IOCTL 攔截（HWID 收集）](#7-storage-driver-ioctl-攔截)

---

## 1. Device Object 與 IOCTL 架構

EAC kernel driver 載入時，`DriverEntry` 呼叫 `IoCreateDevice` 建立一個**具名 device object**。這個裝置是 Ring-3 EAC 服務和 Ring-0 kernel driver 之間的通訊通道。

```
User Mode                        Kernel Mode
──────────────────               ──────────────────────────────────
EasyAntiCheat.exe
  │
  │  CreateFile(L"\\\\.\\EasyAntiCheat")
  ▼
  [裝置的 HANDLE]
  │
  │  DeviceIoControl(handle, IOCTL_CODE, inBuf, inSize, outBuf, outSize)
  ▼
  [Windows I/O Manager]
  │
  │  建立 IRP（I/O Request Packet）
  │  路由到 EAC driver 的 MajorFunction[IRP_MJ_DEVICE_CONTROL]
  ▼
  [EAC Kernel Driver dispatch handler]
    → 讀取 IoStackLocation->Parameters.DeviceIoControl.IoControlCode
    → 分派到對應的子處理器
    → 填充輸出緩衝區
    → 完成 IRP
```

裝置名稱在 binary 中被混淆（以編碼的 byte 序列儲存，而非明文 UTF-16 字串），無法透過字串搜尋輕易找到。

---

## 2. Ring3 到 Ring0 的資料流

EAC 使用 **METHOD_BUFFERED** IOCTL 傳輸：
- 輸入資料從 user-mode 緩衝區複製到 kernel pool 分配
- 輸出資料寫入 kernel pool 分配，然後複製回 user-mode
- 這防止 user-mode 直接把指標傳入 kernel 空間

### IOCTL 控制碼結構

Windows IOCTL 碼是 32-bit 值，編碼如下：
```
Bits 31-16：DeviceType
Bits 15-14：Access（00=任意，01=讀，10=寫，11=讀+寫）
Bits 13-2：Function code（0x000–0x7FF = Microsoft，0x800–0xFFF = 廠商）
Bits 1-0：Transfer method（00=buffered，01=in direct，10=out direct，11=neither）
```

EAC 在**廠商範圍（0x800+）**使用自訂 function code。IOCTL dispatch handler 對從 IRP stack location 提取的 function code 執行一個大型 `switch()`。

### 已知的 IOCTL 類別（重建）

| 類別 | 方向 | 用途 |
|---|---|---|
| `INIT / HANDSHAKE` | Ring3 → Ring0 | 初始認證、session 金鑰交換 |
| `SCAN_REQUEST` | Ring3 → Ring0 | User mode 要求 driver 執行特定掃描 |
| `SCAN_RESULT` | Ring0 → Ring3 | Driver 回傳二進位掃描結果資料 |
| `MODULE_LIST` | Ring0 → Ring3 | Driver 回傳已載入 kernel 模組列表 |
| `TELEMETRY_COLLECT` | Ring3 → Ring0 | 觸發遙測封包組裝 |
| `TELEMETRY_FETCH` | Ring0 → Ring3 | 回傳壓縮+加密的遙測 blob |
| `HEARTBEAT` | Ring3 → Ring0 | 定期保活 / 反除錯檢查 |
| `GAME_PID_SET` | Ring3 → Ring0 | 告訴 driver 哪個 PID 是受保護的遊戲 |

---

## 3. 加密函式分派

這是 EAC 最聰明的防禦之一。**每一個 Windows kernel API 呼叫**都透過執行時解密層進行，而不是靜態 import table。這就是為什麼 EAC **沒有 import table** — 它自己解析所有東西。

### 分派機制

```c
// sub_FFFFF807C1ED4320 — 加密指標解析器
// 接受一個指向加密函式指標 slot 的指標
// 回傳解密後的原始函式位址

// 在 sub_FFFFF807C1E1DD80 中的使用範例：
v3 = sub_FFFFF807C1ED4320(&unk_FFFFF807C2068E78);
result = ((__int64 (*)(void))((0x936ACF702E4281A9uLL * v3) ^ 0xFA85638DCFA646E7uLL))();
//        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//        用常數 A 乘以加密值，XOR 常數 B，把結果當函式指標呼叫
```

### 解密流程

1. **儲存**：函式指標以**加密形式**儲存在資料表（`0xFFFFF807C2068E78` 及附近 slot）中。原始 bytes 不是有效的位址。

2. **解析**：`sub_FFFFF807C1ED4320` 讀取加密的 slot 並做初步轉換（可能是 XOR session 金鑰或基址）。

3. **解密**：結果再透過 `(CONSTANT_A * value) XOR CONSTANT_B` 轉換，每個 API 都有自己唯一的一對 64-bit 常數：

| 常數 A | 常數 B | 可能解析的函式 |
|---|---|---|
| `0x936ACF702E4281A9` | `0xFA85638DCFA646E7` | `PsGetCurrentProcess` 或等效函式 |
| `0xF3EC14C2131FEE4F` | `0xBE0DAFCD89B39CD1` | `PsGetProcessSessionId` |
| `0xE462A05B3E35A30F` | `0x7D67C96867B51F90` | `KeQuerySystemTime` / `KeQueryInterruptTime` |
| `0xE615DAFE9811D559` | `0x00A559FABE750D69` | 通用序列化器 / 封包寫入器 |

4. **呼叫**：解密後的值立即被轉型為函式指標並呼叫 — 明文位址在變數中停留的時間不夠長，難以輕易 dump。

### 為什麼這很難繞過

- 無法透過讀取 import table 找到「EAC 呼叫了哪些函式」— 根本沒有 import table
- 無法透過典型的 IAT hooking 來 hook EAC 的內部呼叫
- 每個 API 呼叫都有唯一的常數對 — 必須逐一解決
- 這些常數很可能**每次 EAC 重新建置時都會重新生成**

---

## 4. Kernel Driver 列舉與黑名單

EAC 不只檢查當前執行的 driver — 它維護一個看起來是**編譯進 binary 的黑名單**，儲存在 binary 資料段中。globals `aBin`（`0xFFFFF807C1FFEE10`）和 `aBin_0`（`0xFFFFF807C1FFEDF0`）包含編碼的二進位資料，作為特徵碼資料庫使用。

### 列舉流程

```
1. 遍歷 PsLoadedModuleList（LDR_DATA_TABLE_ENTRY 的雙向鏈結串列）
   對每個項目：
   ├── 讀取：BaseDllName（模組名稱）
   ├── 讀取：FullDllName（完整路徑）
   ├── 讀取：DllBase（載入位址）
   ├── 讀取：SizeOfImage（總映射大小）
   ├── 讀取：EntryPoint（DriverEntry 位址）
   └── Hash 名稱 → 與內部黑名單比對

2. 對每個 driver：
   ├── 驗證 Authenticode 數位簽名
   ├── 檢查 SizeOfImage 是否符合 PE header 值
   ├── 驗證 section header 是否完整
   └── 檢查 MajorFunction[] 指標是否在範圍內
```

### DKOM 反制措施

進階作弊 driver 會把自己從 `PsLoadedModuleList` 中移除以隱身。EAC 用第二次掃描來反制：

```
第二次掃描（DKOM 抵抗）：
1. 迭代 MmSystemRange 頁面尋找 MZ/PE header
2. 任何在頁面對齊位址找到但不在 PsLoadedModuleList 中的 PE image 就是隱藏的 driver
3. 這些隱藏的 driver 是最可疑的 — 立即標記
```

### 黑名單 Driver 類別

| 類別 | 範例 | 偵測方式 |
|---|---|---|
| **Kernel 記憶體讀取器** | mhyprotect、PhyMem、memdriver | 模組名稱 hash |
| **HWID spoofer** | 各種私人 spoofer | 特徵碼模式 |
| **除錯/分析工具** | WinDbg kernel stubs、kdnet | 模組名稱 |
| **Hypervisor** | VMware SVGA、VirtualBox additions | 模組路徑 |
| **作弊框架** | 各種遊戲作弊 driver | Byte 特徵碼 |
| **有漏洞的已簽名 driver** | 舊版 Dell BIOSConnect、Ene.sys 等 | Hash 比對 |

---

## 5. Dispatch Table Hook 偵測

每個 Windows kernel driver 都暴露一個 `DRIVER_OBJECT` 結構，包含 **28 個 major function 指標**的陣列。EAC 檢查這些是否被 hook：

```c
// 對每個已載入的 driver：
PDRIVER_OBJECT pDrv = ...;
for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
    PVOID handler = pDrv->MajorFunction[i];
    
    // 檢查：這個 handler 是否指向 driver 自身 image 內？
    if (handler < pDrv->DriverStart || 
        handler >= (PVOID)((ULONG_PTR)pDrv->DriverStart + pDrv->DriverSize)) {
        // 偵測到 HOOK — handler 指向 driver 之外！
        flag_as_suspicious();
    }
}
```

### 這能抓到什麼

- **Storage driver hook**：作弊 hook `disk.sys` 或 `storport.sys` 的 MajorFunction 來攔截 IDENTIFY DEVICE 命令並偽造序號
- **NDIS hook**：MAC 位址 spoofer hook NDIS miniport dispatch 來回傳假的 MAC
- **合法的呼叫路由**：有時 filter 合法地擴展 stack — EAC 知道預期的 stack 佈局並標記異常

---

## 6. Filter Driver 與裝置 Stack 偵測

Windows I/O 系統使用**分層裝置 stack** — 多個 driver 可以在彼此上下附加。例如：

```
[遊戲 Process] → [NTFS] → [Volume Manager] → [Disk Class Driver] → [HDD 韌體]
                                               ↑
                     [Spoofer filter 附加在這裡 — 攔截 IOCTL_STORAGE_QUERY]
```

EAC 呼叫 `IoGetAttachedDeviceReference` 和 `IoGetLowerDeviceObject` 來遍歷裝置 stack 並檢查：
- Storage stack 中的 driver 數量（意外的額外層 = 可疑）
- 每層的裝置類型是否符合預期類型
- 每層的 driver 名稱是否可識別

---

## 7. Storage Driver IOCTL 攔截

為了在不經過容易被 hook 的 user-mode API 的情況下收集硬體 ID，EAC 從 kernel mode **直接向 storage driver 發送 IOCTL 請求**：

```c
// EAC 在內部建立並發送這些 IOCTL：

// 1. 取得磁碟序號：
IOCTL_STORAGE_QUERY_PROPERTY
  → StorageDeviceProperty → SerialNumberId

// 2. 取得磁碟韌體資訊：
IOCTL_ATA_PASS_THROUGH
  → ATA IDENTIFY DEVICE 命令
  → 回傳 512 bytes，包含序號、型號、韌體版本

// 3. 取得 volume GUID：
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
  → 與 registry volume GUID 交叉比對

// 4. 取得網路介面卡 MAC：
IOCTL_NDIS_QUERY_GLOBAL_STATS
  → OID_802_3_PERMANENT_ADDRESS（永久的，無法透過軟體偽造）
```

透過**直接到 driver stack** 而不是透過 WMI 或 registry，EAC 繞過了大多數只攔截高層查詢路徑的 HWID 偽造軟體。

---

*← [回到 README](README.md) | [加密與混淆 →](crypto_and_obfuscation.md)*
