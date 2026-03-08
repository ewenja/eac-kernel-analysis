# 外部作弊偵測 — 技術分析

> 本文是 [EAC Kernel Driver 靜態分析](README.md) 系列的一部分。

外部作弊和注入是不同的問題。遊戲裡沒有 DLL，沒有 thread 可以偵測，遊戲記憶體中也沒有分配 — 只是機器上另一個獨立的 process，用 `ReadProcessMemory` 或 kernel driver 從外部靜靜地讀取遊戲記憶體。大多數 ESP 和 aimbot 軟體實際上就是這樣運作的。以下是 EAC 如何應對。

---

## 目錄
1. [外部作弊的運作方式](#1-外部作弊的運作方式)
2. [Handle 偵測 — 主要偵測向量](#2-handle-偵測)
3. [低層 Handle Table 遍歷](#3-低層-handle-table-遍歷)
4. [跨 Process 記憶體存取模式偵測](#4-跨-process-記憶體存取模式偵測)
5. [Thread 與 Process 來源分析](#5-thread-與-process-來源分析)
6. [視窗與 UI Overlay 偵測](#6-視窗與-ui-overlay-偵測)
7. [已知外部作弊 Driver 特徵碼](#7-已知外部作弊-driver-特徵碼)
8. [外部偵測的已知缺口](#8-外部偵測的已知缺口)

---

## 1. 外部作弊的運作方式

外部作弊作為完全獨立的 process 執行，與遊戲分開。它不是把程式碼注入遊戲，而是從外部讀取遊戲記憶體，計算有用的資料（敵人位置、血量等），然後輸出（overlay、輸入注入等）。

```
遊戲 Process（Fortnite.exe、PUBG.exe 等）
     │  ← 外部作弊對這個 process 開啟 HANDLE
     ↑
外部作弊 Process（cheat.exe）
│
├── ReadProcessMemory(hGame, EntityListAddr, ...) → 讀取所有玩家資料
├── 用 DirectX 或 GDI 在遊戲視窗上繪製 overlay
└── 可選：透過 SendInput/WriteProcessMemory 發送輸入
```

因為沒有任何東西被注入遊戲 process，傳統的注入掃描器找不到外部作弊。EAC 對它們使用完全不同的偵測路徑。

---

## 2. Handle 偵測

抓外部作弊最可靠的方式是找到每個持有**對遊戲 process 開啟的記憶體存取 handle** 的 process。

### EAC 如何列舉 Handle

EAC **不**使用像 `NtQuerySystemInformation(SystemHandleInformation)` 這樣的 user-mode API — 那些可以被 hook。它直接從 kernel 記憶體遍歷 kernel handle table：

```c
// 對系統上的每個 process P：
//   對 P 持有的每個 handle H：
//     如果 H.ObjectType == PROCESS（type index 約 7）
//     且 H.Object == targetGameProcess  ← 指向遊戲的 EPROCESS
//     那麼：檢查 H.GrantedAccess

const DWORD SUSPICIOUS_ACCESS = 
    PROCESS_VM_READ        |  // 0x0010 — 可以讀取遊戲記憶體
    PROCESS_VM_WRITE       |  // 0x0020 — 可以寫入遊戲記憶體
    PROCESS_VM_OPERATION   |  // 0x0008 — 可以操作記憶體
    PROCESS_QUERY_INFORMATION; // 0x0400 — 可以查詢資訊

if ((grantedAccess & SUSPICIOUS_ACCESS) && ownerProcess != gameProcess)
    flag_external_cheat(ownerProcess);
```

### 觸發標記的存取遮罩

| 存取遮罩 | 十六進位 | 觸發等級 |
|---|---|---|
| `PROCESS_VM_READ` | `0x0010` | 立即標記 |
| `PROCESS_VM_WRITE` | `0x0020` | 立即標記 |
| `PROCESS_VM_OPERATION` | `0x0008` | 立即標記 |
| `PROCESS_ALL_ACCESS` | `0x1FFFFF` | 立即標記 |
| `PROCESS_QUERY_INFORMATION` | `0x0400` | 標記 + 觀察名單 |
| `PROCESS_QUERY_LIMITED_INFORMATION` | `0x1000` | 標記 + 觀察名單 |
| 僅 `SYNCHRONIZE` | `0x100000` | 不標記 |

### 合法的例外

EAC 維護一個合法開啟遊戲 handle 的 process 白名單：
- Windows Error Reporting（`WerFault.exe`）
- 防毒軟體（Intel/McAfee、Defender 等）— 透過可執行檔路徑 hash 比對
- NVIDIA overlay 系統（`nvcontainer.exe`、`nvoverlaycontainer.exe`）
- Steam overlay（`GameOverlayRenderer64.dll` 父 process）

任何不在白名單上的 process 對遊戲持有 `PROCESS_VM_READ` = 外部作弊。

---

## 3. 低層 Handle Table 遍歷

EAC 在內部直接存取 kernel 的 handle table 結構 — 和 `NtQuerySystemInformation(SystemHandleInformation)` 讀取的是同一個結構，但不經過 exported API。

### Handle Table 結構

```c
// Windows kernel handle table（簡化）：
// HANDLE_TABLE (_EPROCESS.ObjectTable)：
//   TableCode → 指向 ExHandleTable
//   HandleCount
//   QuotaProcess → 父 process
//   UniqueProcessId

// 每個 handle 項目（HANDLE_TABLE_ENTRY）：
//   ObjectPointerBits：59-bit 編碼的 OBJECT_HEADER 指標
//   GrantedAccessBits：25-bit 存取遮罩
//   Attributes：3-bit 旗標（繼承、防止關閉、稽核）

// 解碼 handle 項目：
OBJECT_HEADER* header = (OBJECT_HEADER*)(entry.ObjectPointerBits << 4);
PVOID object = (PVOID)((ULONG_PTR)header + sizeof(OBJECT_HEADER));
DWORD access = entry.GrantedAccessBits << 2;  // 移位回完整遮罩
```

EAC 透過以下方式遍歷這個表：
1. 讀取 `_EPROCESS.ObjectTable` 取得 process handle table
2. 根據 `TableCode & 3` 遍歷三層表樹（`L1 → L2 → L3`）
3. 對每個項目，解碼物件指標並與目標遊戲 EPROCESS 比對

這是**純 kernel-mode 操作** — 沒有等效的 user-mode 方式可以在不被 hook 的情況下做到這件事。

---

## 4. 跨 Process 記憶體存取模式偵測

除了檢查誰開啟了 handle，EAC 還透過 kernel callback 監控**使用模式**：

### PsSetCreateProcessNotifyRoutine

EAC 註冊了一個 process 建立 callback。當任何新 process 啟動時：
1. 檢查 process 名稱/hash 是否在黑名單中
2. 檢查 process 的**父 process** — 如果它是由已知的作弊啟動器生成的，標記它
3. 檢查 process 的**數位簽名** — 在特定路徑下的未簽名可執行檔 = 可疑
4. 如果 process 隨後開啟遊戲 handle，開始監控

### WindowStation 和 Desktop 隔離繞過偵測

外部作弊必須與遊戲共享同一個 desktop session 才能使用 overlay。EAC 檢查：
- 是否有意外的視窗在與遊戲視窗完全相同的 Z-order 位置？
- 是否有任何頂層視窗有 `WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED`（經典 ESP overlay）？
- 是否有任何視窗有 `WS_EX_TOOLWINDOW` 來從 Alt+Tab 中隱藏？

從 user-mode：EAC 服務呼叫 `EnumWindows` + `GetWindowLongPtr` 並透過 IOCTL 向 kernel driver 回報可疑的 overlay。

---

## 5. Thread 與 Process 來源分析

### 父 Process 偽造偵測

一些作弊偽造它們的父 process ID，讓自己看起來像是由合法 process 啟動的。EAC 透過交叉比對來偵測：

1. `EPROCESS.InheritedFromUniqueProcessId`（宣稱的父 PID）
2. 宣稱的父 process 的 `PsGetProcessCreationTime`
3. 實際的 Windows job 分配和 token 繼承

如果一個 process 宣稱 `explorer.exe` 是父 process，但沒有從那個 process 繼承的 token，或者宣稱的父 process 在那個 PID 上已不存在 → **偵測到父 PID 偽造**。

### 已簽名 vs. 未簽名可執行檔檢查

對每個開啟遊戲 handle 的 process：

```c
// 檢查 1：磁碟上的 .exe 是否已簽名？
// → VerifyImageSignature() 等效（Authenticode 檢查）

// 檢查 2：磁碟上的 hash 是否與記憶體中的 hash 相同？
// → 偵測 EXE 是否在啟動前被修補以避開簽名檢查

// 檢查 3：image 是否來自可疑路徑？
// → %TEMP%、%APPDATA%、C:\Users\*\Downloads = 立即可疑
// → System32、Program Files = 白名單

// 檢查 4：process 是否有合法的 Windows manifest？
// → 作弊載入器通常跳過嵌入適當的 manifest
```

---

## 6. 視窗與 UI Overlay 偵測

外部作弊通常在遊戲上方顯示 ESP overlay。這些 overlay 必須：
- 與遊戲在同一個 desktop 上
- 在 Z-order 中位於遊戲上方（或透明 + 置頂）

EAC 的 user-mode 元件透過 GDI 列舉偵測：

```c
// 表示 overlay 的擴展視窗樣式：
#define OVERLAY_STYLE (WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED)

// 也檢查 DWM composition 濫用：
// 一些 overlay 使用螢幕外的 DWM surface 來繞過 EnumWindows
// EAC 對所有視窗檢查 DwmGetWindowAttribute(DWMWA_EXTENDED_FRAME_BOUNDS)
// 並找出位置恰好在遊戲矩形上方的視窗
```

### 基於 DirectX/GDI Hook 的 Overlay

一些 overlay hook 遊戲 process 內的 `IDXGISwapChain::Present`，直接使用遊戲的 GPU context 渲染。這讓它們對視窗列舉不可見 — 但這種技術需要 DLL 注入，所以屬於**內部作弊**偵測的範疇。

---

## 7. 已知外部作弊 Driver 特徵碼

許多外部作弊使用 kernel driver 來執行記憶體讀取（繞過 handle 偵測）。EAC 透過 `aBin` / `aBin_0` 的黑名單直接用 driver 特徵碼標記這些：

| Driver 類型 | 如何繞過 Handle 偵測 | EAC 如何偵測 |
|---|---|---|
| **Physical memory mapper** | 開啟 `\\Device\\PhysicalMemory`，直接讀取實體 RAM | 模組名稱 hash；binary 中的模式 |
| **MmCopyMemory wrapper** | 透過有漏洞的 driver 直接呼叫 kernel 的 `MmCopyMemory` | 記憶體 driver 上的 dispatch hook |
| **CR3 mapper** | 讀取目標 process 的 CR3，直接映射頁面 | CPUID/MSR 存取模式 |
| **NtReadVirtualMemory patcher** | 修補 SSDT 以繞過存取檢查 | SSDT hash 檢查 |

---

## 8. 外部偵測的已知缺口

### 缺口 1：Kernel 對 Kernel 記憶體讀取（不需要 Handle）

有權限的 kernel driver 可以用遊戲的 `EPROCESS` 作為 context 呼叫 `MmCopyMemory`，完全繞過 handle table。由於沒有開啟 handle，EAC 的 handle 掃描器永遠看不到它。**需要的緩解措施：對讀取器 driver 本身進行實體記憶體掃描。**

### 缺口 2：透過 DMA 讀取實體記憶體

DMA（Direct Memory Access）攻擊使用第二個 PCIe 裝置透過 PCIe 讀取遊戲機器的 RAM。受害機器上沒有 driver 執行 → EAC 的 driver 掃描什麼都找不到。基於 DMA 的作弊在 driver 層面對 EAC 來說是無法偵測的（伺服器端行為分析可能會抓到它們）。

### 缺口 3：在 EAC 啟動前預先開啟 Handle

如果作弊在 **EAC 初始化之前**對遊戲開啟 handle，然後在 EAC 列舉 handle 之前關閉它，EAC 永遠看不到那個 handle。

### 缺口 4：僅使用 PROCESS_QUERY_LIMITED_INFORMATION

一些作弊只使用 `PROCESS_QUERY_LIMITED_INFORMATION`（不授予記憶體存取）透過 `NtQueryInformationProcess` 找到遊戲的基址，然後用 kernel driver 進行實際讀取。EAC 可能不會標記 user-mode handle，因為存取遮罩看起來無害。

### 缺口 5：Process 名稱冒充

一些外部作弊把可執行檔重命名為符合白名單的 process 名稱（`nvcontainer.exe`、`NVDisplay.Container.exe`）。除非 EAC 也檢查檔案路徑和簽名（而不只是 image 名稱字串），否則 `%TEMP%\NVDisplay.Container.exe` 中的作弊可能會通過初始的名稱過濾。

---

*← [回到 README](README.md) | [內部作弊與注入器 →](internal_cheats_and_injectors.md)*
