# HWID 收集與 Spoofer 偵測 — 技術分析

> 本文是 [EAC Kernel Driver 靜態分析](README.md) 系列的一部分。

硬體封禁是 EAC 對連環作弊者的長期解決方案。整個系統依賴可靠地識別實體機器 — 不是帳號，不是 OS 安裝，是實際的硬體。這份文件拆解 EAC 讀取的每個硬體 ID 來源、它如何交叉比對不一致性，以及它如何在 spoofer driver 攔截查詢之前就抓到它們。

---

## 目錄
1. [Spoofer 的運作原理](#1-spoofer-的運作原理)
2. [EAC 讀取的六個 HWID 來源](#2-eac-讀取的六個-hwid-來源)
3. [跨來源比對邏輯](#3-跨來源比對邏輯)
4. [偵測 Spoofer Driver 本身](#4-偵測-spoofer-driver-本身)
5. [Storage Driver Hook 偵測](#5-storage-driver-hook-偵測)
6. [NDIS MAC 位址偽造偵測](#6-ndis-mac-位址偽造偵測)
7. [GPU Spoofer 偵測](#7-gpu-spoofer-偵測)
8. [SMBIOS 韌體 Spoofer 偵測](#8-smbios-韌體-spoofer-偵測)
9. [時序異常偵測](#9-時序異常偵測)
10. [VM 與新機器偵測](#10-vm-與新機器偵測)
11. [硬體封禁流程](#11-硬體封禁流程)

---

## 1. Spoofer 的運作原理

**硬體 spoofer** 是一個 kernel-mode 工具，攔截硬體身份查詢並回傳假值，讓被硬體封禁的玩家透過讓自己看起來像在不同機器上來逃避封禁。

```
正常流程：
遊戲 → EAC usermode → IOCTL 到 EAC kernel → IOCTL 到 disk.sys → 真實序號 "ABC123"

有 spoofer 時：
遊戲 → EAC usermode → IOCTL 到 EAC kernel → IOCTL 到 [spoofer hook] → 假序號 "XYZ999"
```

Spoofer 在 stack 的某個地方攔截查詢並替換假值。EAC 的反制方式：
1. 從**多個獨立來源**讀取
2. **直接從 kernel** 發送查詢（更難攔截）
3. **驗證**查詢路徑中每個 driver 的完整性
4. 把 spoofer driver **本身**偵測為未簽名/可疑的 kernel driver

---

## 2. EAC 讀取的六個 HWID 來源

EAC 同時從**至少 6 個獨立的 kernel-mode 路徑**讀取硬體識別碼。Spoofer 通常只修補其中 1-2 個，讓透過跨來源比對偵測變得很容易。

### 來源 1：ATA 磁碟序號（直接 IOCTL）

```c
// EAC 直接向 \\Device\\Harddisk0\\DR0 發送 IOCTL_ATA_PASS_THROUGH：
ATA_PASS_THROUGH_EX ataPT = {0};
ataPT.AtaFlags = ATA_FLAGS_DATA_IN;
ataPT.DataTransferLength = 512;
ataPT.CurrentTaskFile[6] = 0xEC;  // ATA IDENTIFY DEVICE 命令

// 回應：512-byte IDENTIFY DEVICE 結構
// 序號在 bytes [20..39]（20 個 ASCII 字元）
// 型號在 bytes [54..93]
// 韌體版本在 bytes [46..53]
```

這繞過了 `WMI`、`IOCTL_STORAGE_QUERY_PROPERTY` 和 registry 路徑 — 這是一個**原始 ATA 命令**，很少有 spoofer 攔截它。

### 來源 2：Storage Query Property（高層次）

```c
// 也發送 IOCTL_STORAGE_QUERY_PROPERTY 作為比對來源
// 如果 ATA 序號 ≠ StorageQueryProperty 序號 → 偵測到 spoofer
STORAGE_PROPERTY_QUERY spq = {StorageDeviceProperty, PropertyStandardQuery};
DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &spq, ...);
// 回傳帶有 SerialNumber 的 STORAGE_DEVICE_DESCRIPTOR
```

### 來源 3：Volume GUID（Registry 交叉比對）

```c
// 從 HKLM\SYSTEM\MountedDevices 讀取
// 包含映射到實體磁碟識別碼的二進位 volume 特徵碼
// 與 IOCTL 結果交叉比對
// 如果值不符 → spoofer 只修補了一條路徑
```

### 來源 4：永久 MAC 位址（NDIS 直接）

```c
// 透過 OID_802_3_PERMANENT_ADDRESS 查詢 NDIS
// 這是硬體燒錄的 MAC，不是軟體可設定的「當前 MAC」
// 大多數 MAC spoofer 只改變當前 MAC（OID_802_3_CURRENT_ADDRESS）
// EAC 特別請求 PERMANENT 來取得不可變的硬體值
```

### 來源 5：GPU PnP 實例 ID

```c
// 查詢 Plug and Play manager 取得所有顯示介面卡
// 每個 GPU 都有唯一的裝置實例 ID，例如：
// PCI\VEN_10DE&DEV_2204&SUBSYS_40963842&REV_A1\4&1a2b3c4d&0&0018
//                         ^^^^ GPU 型號 ^^^^  ^^^^ 板卡序號 ^^^^
// 這個 ID 來自 PCI BARCAP，沒有真正的 kernel driver 很難偽造
```

### 來源 6：SMBIOS 韌體資料

```c
// 呼叫 NtQuerySystemInformation(SystemFirmwareTableInformation)
// 帶 provider 'RSMB' 取得原始 SMBIOS 表
// 提取：
//   Type 1（系統資訊）：UUID、序號、製造商
//   Type 2（主機板資訊）：板卡序號、資產標籤
//   Type 4（CPU 資訊）：處理器 ID
// 這些值來自 BIOS 晶片 — 不重新燒錄 BIOS 極難偽造
```

---

## 3. 跨來源比對邏輯

EAC 把所有收集到的 HWID 來源組合成一個**複合指紋**：

```
composite_id = hash(
    ata_serial,
    storage_query_serial,
    volume_guid,
    permanent_mac_1,
    permanent_mac_2,    // EAC 檢查所有網路介面卡
    gpu_instance_id,
    smbios_system_uuid,
    smbios_board_serial
)
```

複合值然後：
1. **與伺服器對這個帳號的記錄比對** — 封禁查找
2. **檢查內部一致性** — 如果 ATA 的磁碟序號與 storage query 不同，那就是 spoofer
3. **檢查已知的假值模式** — 全零序號、重複值、可疑的短字串

來源之間的任何不一致本身就是**偽造活動的強烈訊號**，即使個別的假值看起來合理。

---

## 4. 偵測 Spoofer Driver 本身

EAC 抓 spoofer 最可靠的方式不是檢查 ID — 而是在 **kernel 中找到 spoofer driver**。

### 為什麼 Spoofer 需要 Driver

要攔截對磁碟/NDIS driver 的 kernel-mode IOCTL 呼叫，spoofer **必須**載入自己的 kernel driver。在現代 Windows（有 Driver Signature Enforcement）中，這需要：
- **洩漏/被盜的 WHQL 憑證**（Microsoft 明確撤銷這些）
- **BYOVD 攻擊** — 利用合法簽名但有漏洞的 driver 來載入未簽名程式碼
- **測試簽名模式** — 在 UEFI 變數中留下 `BcdBootMgr.TestSigningEnabled` 旗標

EAC 三個都檢查：

```c
// 1. DSE 狀態檢查 — 是否啟用了測試簽名？
// 檢查 BCD store 或 ntoskrnl 的 g_CiOptions global
// 任何不是 0x6（CI_ENFORCEMENT）的值 = 可疑

// 2. 列舉所有已載入的 driver 並驗證簽名
// 任何沒有有效 Authenticode 鏈的 driver = 立即標記

// 3. BYOVD 有漏洞 driver 偵測
// EAC 維護已知有漏洞的已簽名 driver 列表
// （ene.sys、dbutil_2_3.sys 等）— 載入任何這些都會被標記
```

---

## 5. Storage Driver Hook 偵測

最常見的 spoofer 技術是 hook `disk.sys` 或 `storport.sys` 來攔截序號查詢。EAC 透過檢查每個 storage driver 的 **dispatch table** 來偵測：

```c
// 對 storage device stack 中的每個 driver：
PDRIVER_OBJECT pDisk = get_driver_object(L"\\Driver\\Disk");

for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
    PVOID handler = pDisk->MajorFunction[i];
    
    // 這個 handler 是否在 disk.sys 的程式碼段內？
    if (!is_in_module_range(handler, pDisk->DriverStart, pDisk->DriverSize)) {
        // Handler 指向 disk.sys 之外 — 它被 hook 了！
        report_hook(pDisk, i, handler);
    }
}

// 也檢查 DEVICE_OBJECT.DeviceExtension 是否有 filter driver 特徵碼
// 遍歷 IoGetAttachedDevice() 鏈尋找意外的層
```

---

## 6. NDIS MAC 位址偽造偵測

MAC 位址 spoofer 通常 hook NDIS OID 請求處理。EAC 的偵測方式：

```c
// 遍歷 NDIS miniport 列表（透過 NDIS 內部 globals）
// 對每個 miniport：
//   1. 比對 OID_802_3_PERMANENT_ADDRESS 與 OID_802_3_CURRENT_ADDRESS
//      如果它們的差異超過預期：
//      → 可能是 MAC spoofer
//
//   2. 檢查 MiniportCharacteristics.OidRequestHandler
//      是否指向 miniport driver 自身的 image 內？
//      → 如果不是，它被 hook 了
//
//   3. 檢查 NDIS_MINIPORT_BLOCK 的 handler table 是否未被修改
```

關鍵洞察：回傳假 `PERMANENT_ADDRESS`（只是修改過的 `CURRENT_ADDRESS`）的 spoofer 會製造 EAC 可以偵測到的邏輯不一致。

---

## 7. GPU Spoofer 偵測

GPU spoofer 通常在 DXGI / 顯示 driver 層面運作。EAC 的偵測方式：

```c
// 1. PnP 裝置列舉（kernel-mode）
// 對所有顯示介面卡呼叫 IoGetDeviceProperty()
// 取得 DEVPKEY_Device_InstanceId — 硬編碼在 PCI config space 中

// 2. 檢查 DxgKrnl driver dispatch table
// dxgkrnl.sys 處理 WDDM 呼叫 — spoofer 有時 hook 它的 IOCTL handler
// dxgkrnl.sys 中的任何 hook = 立即標記

// 3. DXGI adapter LUID 交叉比對
// driver 載入時分配的 adapter LUID 被追蹤
// 如果 user-mode DXGI 回報的 adapter 與 kernel-mode PnP 不同 → 不一致
```

---

## 8. SMBIOS 韌體 Spoofer 偵測

SMBIOS spoofer 在 EAC 讀取之前修改韌體表，通常透過 hook `NtQuerySystemInformation` 來做到。但 EAC 從 **kernel mode** 使用直接 syscall 或內部 API 呼叫這個 — 繞過任何 user-mode hook。

要抓 kernel-mode SMBIOS hook，EAC：
1. 透過加密分派使用 `NtQuerySystemInformation(SystemFirmwareTableInformation)` 讀取韌體表
2. **同時**透過 `MmMapIoSpace` 或類似方式從實體記憶體讀取原始 ACPI/SMBIOS 資料
3. 比對兩次讀取 — 如果它們不同，表在傳輸過程中被修改了

EAC 特別驗證的 SMBIOS 欄位：
- **System UUID（Type 1，偏移 8）**：16-byte RFC 4122 UUID — 必須唯一且非零
- **Board Serial（Type 2，偏移 4）**：ASCII 字串 — 與已知假值比對（"To be filled by O.E.M."、"None"、空字串）
- **Chassis Asset Tag（Type 3，偏移 8）**：spoofer 常常忽略這個

---

## 9. 時序異常偵測

一些 spoofer **非同步**攔截查詢（例如在 APC 或 DPC 層面 hook）。這引入了可測量的時序延遲。EAC 的偵測方式：

```c
// 對硬體查詢計時：
t0 = KUSER_SHARED_DATA.TickCountLow;
result = query_disk_serial();
t1 = KUSER_SHARED_DATA.TickCountLow;
latency = t1 - t0;

// ATA IDENTIFY 的預期延遲：1-10ms（在裝置上）
// 透過 hook/攔截：通常增加 50-500ms 延遲
// 極快（< 0.1ms）：值可能被 spoofer 從靜態表快取
// 三種情況都被標記
```

---

## 10. VM 與新機器偵測

EAC 使用多個訊號來偵測新建立的虛擬機器設置：

| 訊號 | 可疑值 | 偵測方式 |
|---|---|---|
| **系統 uptime** | < 60 秒 | `KUSER_SHARED_DATA.TickCountLow` |
| **CPUID hypervisor bit** | 已設置（CPUID 後 ECX 的 bit 31）| 直接 CPUID 指令 |
| **Hypervisor 廠商字串** | VMware、VirtualBox、QEMU 等 | CPUID leaf 0x40000000 |
| **SMBIOS 製造商** | VMware、VBOX、QEMU、Microsoft Corporation（HyperV）| SMBIOS Type 1 |
| **磁碟型號字串** | VBOX HARDDISK、VMware、QEMU HARDDISK | ATA IDENTIFY 回應 |
| **MAC OUI 前綴** | 00:0C:29（VMware）、08:00:27（VirtualBox）| NDIS 查詢 |
| **PCI 裝置 ID** | VMware SVGA II（0x0405）、VirtualBox GA（0xBEEF）| PnP 列舉 |
| **時序抖動** | RDTSC 與牆鐘的高變異數 | TSC 校準檢查 |

任何 2 個以上這些訊號的組合都會觸發加強審查。

---

## 11. 硬體封禁流程

當 EAC 決定發出**硬體封禁**時：

1. 複合 HWID hash 在簽名的遙測中傳送到 EAC 伺服器
2. 伺服器把這個 hash 與被封禁的帳號關聯儲存
3. 下次用任何帳號啟動遊戲時，EAC 重新收集所有 HWID 並重新計算複合 hash
4. Hash 在伺服器端與封禁列表比對
5. **符合 = 無論使用哪個帳號都套用封禁**

### 什麼讓硬體封禁難以繞過

EAC 的複合 hash 包含**極難同時偽造的來源**：
- ATA 序號（硬體晶片 — 需要實體修改才能更改）
- SMBIOS UUID（BIOS 晶片 — 需要重新燒錄）
- GPU PCI 實例（PCIe config space — 軟體無法存取）
- 永久 MAC（硬體熔絲 — 沒有韌體修改無法更改）

對有決心的 spoofer 開發者來說，更改一兩個是可行的，但在不觸發跨來源不一致偵測的情況下**同時**更改所有來源極其困難。

---

*← [遙測](telemetry.md) | [函式對照表 →](function_map.md)*
