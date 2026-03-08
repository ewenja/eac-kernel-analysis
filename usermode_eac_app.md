# 使用者模式 EAC 應用程式（Ring 3）— 技術分析

> 本文是 [EAC Kernel Driver 分析](README.md) 系列的一部分。

多數人把注意力全放在 kernel driver 上，卻忽略了 user-mode EAC 服務同樣在做實質工作。本文分析 `EasyAntiCheat.exe` / `EasyAntiCheat_EOS.exe` — 它的實際功能、與 driver 的通訊方式、後端認證流程，以及最脆弱的環節在哪裡。

---

## 目錄
1. [雙層架構概覽](#1-雙層架構概覽)
2. [EAC 服務啟動流程](#2-eac-服務啟動流程)
3. [Ring3 → Ring0 通訊通道](#3-ring3--ring0-通訊通道)
4. [User-Mode 反除錯機制](#4-user-mode-反除錯機制)
5. [Authenticode / 憑證驗證（X.509 DER 解析器）](#5-authenticode--憑證驗證)
6. [遊戲檔案完整性驗證](#6-遊戲檔案完整性驗證)
7. [後端認證協定](#7-後端認證協定)
8. [EAC.exe 回報的資料 vs. Driver 回報的資料](#8-eacexe-回報的資料-vs-driver-回報的資料)
9. [Ring3 環境檢查項目](#9-ring3-環境檢查項目)
10. [User-Mode 元件的已知缺口](#10-user-mode-元件的已知缺口)

---

## 1. 雙層架構概覽

```
┌─────────────────────────────────────────────────────────┐
│                    USER-MODE（Ring 3）                   │
│                                                         │
│  Game.exe ←────────────── Game SDK ──────────────────→ │
│     │                    (EAC SDK)                      │
│     │                        │                          │
│  EasyAntiCheat.exe       EAC Game Library               │
│   （服務 process）        （GameModule.dll）              │
│       │                        │                        │
│       └──────────┬─────────────┘                        │
│                  │  DeviceIoControl                      │
└──────────────────┼──────────────────────────────────────┘
                   │ IOCTL（Ring3→Ring0 邊界）
┌──────────────────┼──────────────────────────────────────┐
│                  │      KERNEL-MODE（Ring 0）            │
│              EasyAntiCheat.sys                           │
│         （Kernel driver — 主要分析引擎）                  │
└─────────────────────────────────────────────────────────┘
```

**Kernel driver** 是最終決策者 — 所有安全關鍵判斷都在那裡執行。**User-mode 服務**的職責是：
1. 遊戲和 driver 之間的中繼
2. 收集 user-mode 可觀察的資料（視窗、process、overlay）
3. 把遙測傳送到 EAC 伺服器的網路客戶端
4. Kernel driver 本身的啟動器/驗證器

### 兩個 EAC 可執行檔說明

| 名稱 | 職責 | 出現時機 |
|---|---|---|
| `EasyAntiCheat.exe` | 舊版 EAC 服務 | 較舊的 EAC 遊戲（EOS 之前）|
| `EasyAntiCheat_EOS.exe` | Epic Online Services 整合 | 現代 EAC（2021 年後）|
| `EasyAntiCheat_Launcher.exe` | 遊戲啟動器包裝器 | 一些遊戲 |

---

## 2. EAC 服務啟動流程

受保護的遊戲啟動時，依序發生以下事件：

```
1. Game.exe 啟動
2. 遊戲程式碼載入 GameModule.dll（整合到遊戲的 EAC SDK）
3. SDK 呼叫 CreateProcess(EasyAntiCheat.exe) 作為子 process
4. EasyAntiCheat.exe 啟動並執行：

   a. [防篡改檢查] 驗證自身的 EXE 簽名和 hash
   b. [Driver 載入] 呼叫 NtLoadDriver 載入 EasyAntiCheat.sys
      → Driver 路徑必須在 System32\drivers\ 或遊戲資料夾中
   c. [Driver 開啟] CreateFile(L"\\\\.\\EasyAntiCheat") → 取得 HANDLE
   d. [握手 IOCTL] IOCTL_EAC_HANDSHAKE 帶：
      → Game ID（EAC 後端的每遊戲唯一識別碼）
      → 遊戲可執行檔路徑 hash
      → Windows 版本號
      → EAC 版本
   e. [遊戲 PID IOCTL] 通知 driver 哪個 PID 是受保護的遊戲
   f. [啟動 heartbeat 迴圈] 每約 5 秒：發送 IOCTL_EAC_HEARTBEAT
```

---

## 3. Ring3 → Ring0 通訊通道

User-mode 應用程式透過 `\\.\EasyAntiCheat` device object 使用 `DeviceIoControl` 與 kernel driver 通訊。所有資料在此跨越 Ring3/Ring0 邊界。

### 緩衝區格式說明

EAC 使用 **METHOD_BUFFERED**，這表示：
- 輸入緩衝區在 handler 執行前從 user space 複製到 kernel pool
- 輸出緩衝區由 kernel 填充，然後在之後複製回 user space

這表示：
- 沒有 user-mode 指標直接傳遞到 kernel（防止指標解引用攻擊）
- EAC 在 IOCTL handler 內部對所有輸入資料大小做自己的驗證

### Heartbeat 機制

```c
// 每 5 秒 user-mode process 呼叫：
DWORD heartbeatCode = GetCurrentProcessId() ^ some_crypto_constant;
DeviceIoControl(hDriver, IOCTL_EAC_HEARTBEAT, 
                &heartbeatCode, sizeof(DWORD),
                &response, sizeof(DWORD), &bytesret, NULL);
                
// Kernel driver 驗證：
// 1. 呼叫 process 的 PID 是否符合已註冊的 EAC 服務 PID
// 2. 加密值是否正確解密
// 如果 heartbeat 連續失敗 3 次 → driver 終止遊戲
```

如果 user-mode process 被殺死、暫停，或 heartbeat 被延遲，driver 就會偵測到。這是 EAC 對**process 暫停攻擊**的防禦機制，攻擊者試圖「凍結」EAC 來阻止掃描。

---

## 4. User-Mode 反除錯機制

User-mode 服務獨立於 kernel driver，自行執行一套反除錯檢查：

### 除錯器偵測方法

```c
// 方法 1：IsDebuggerPresent / NtQueryInformationProcess
IsDebuggerPresent();
NtQueryInformationProcess(hSelf, ProcessDebugPort, &port, ...);
// port != 0 → 除錯器已附加

// 方法 2：NtGlobalFlag 檢查
// 當 process 由除錯器建立時，NtGlobalFlag 有 heap 除錯旗標
DWORD ntgf = *(DWORD*)(TEB + 0x100);  // PEB 中的 NtGlobalFlag
if (ntgf & 0x70)  // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    // 設置了除錯器 heap 旗標 → 除錯器存在

// 方法 3：HEAP 結構中的 heap 旗標
DWORD heapFlags = *(DWORD*)(GetProcessHeap() + 0x70);
// 正常：0x00000002（HEAP_GROWABLE）
// 除錯：0x50000062（額外的除錯旗標）

// 方法 4：時序檢查（EAC 在 Ring3 使用 KeQueryInterruptTime）
ULONGLONG t0, t1;
t0 = __rdtsc();
NtDelayExecution(FALSE, -1);
t1 = __rdtsc();
// 如果（t1-t0）>> 預期的單次睡眠週期 → 單步除錯器
```

### 反修補自我完整性檢查

```c
// EAC 驗證自身的程式碼頁面沒有被修補：
// 1. 在啟動時對 EasyAntiCheat.exe 的 .text section 做 hash
// 2. 加密儲存預期的 hash
// 3. 定期重新 hash 並比對
// 如果被修補 → 自我崩潰 / 向 driver 回報
```

---

## 5. Authenticode / 憑證驗證

binary 中找到的最大函式之一 — `sub_FFFFF807C1EAD280`（大小 **0x264A bytes** = 約 9.8KB）— 是直接實作在 driver 內的**完整 X.509/DER 憑證解析與驗證引擎**（不呼叫 CryptoAPI）。

這個函式：
1. 解析 DER 編碼的 X.509 憑證資料
2. 驗證 `Magic` 值 `23117`（`0x5A4D` = 'MZ' — PE header 檢查）
3. 檢查 `IMAGE_NT_SIGNATURE`（`17744` = `0x4550` = 'PE\0\0'）
4. 驗證 PE optional header magic：
   - `267` = `0x10B` = PE32（32-bit）
   - `523` = `0x20B` = PE32+（64-bit）
5. 遍歷 PE section table 尋找憑證資料目錄（`IMAGE_DIRECTORY_ENTRY_SECURITY = 4`）
6. 解析每個 WIN_CERTIFICATE 項目（檢查 `wRevision=0x0200`、`wCertificateType=0x0002` 用於 PKCS#7 / Authenticode）
7. ASN.1 / DER 解碼 PKCS#7 SignedData blob
8. 驗證憑證鏈：
   - 提取簽名者憑證
   - 提取發行者憑證
   - 根據演算法 OID 使用 P-256 ECC 或 RSA 驗證簽名
   - 檢查有效期
   - 驗證到 Microsoft Root CA 的信任鏈

### 為什麼驗證邏輯放在 Driver 裡

透過在 **kernel driver 中**實作 Authenticode 驗證（而非從 user-mode 呼叫 `WinVerifyTrust`），EAC 確保：
- 作弊無法 hook `WinVerifyTrust` 來偽造簽名驗證
- 驗證在 Ring0 發生，沒有 user-mode 攔截點
- 所有憑證解析常數和邏輯都在加密/混淆的 driver 程式碼中

---

## 6. 遊戲檔案完整性驗證

在允許遊戲執行之前，EAC 對遊戲可執行檔和關鍵 DLL 執行檔案完整性檢查：

```c
// EAC 從 EAC 後端伺服器維護這個遊戲版本的 hash manifest。
// 在遊戲啟動時：
// 1. 下載/快取這個遊戲版本的 hash manifest
// 2. 對 manifest 中的每個檔案：
//    a. 透過路徑開啟檔案
//    b. 對它做 hash（透過 sub_FFFFF807C1E3A568 的 SHA-256）
//    c. 與 manifest hash 比對
// 3. 如果任何 hash 不符 → 偵測到修補的遊戲檔案

// 通常檢查的檔案包括：
// - GameName.exe（主要可執行檔）
// - Shipping DLL（UnrealEngine DLL 等）
// - 影響遊戲玩法的設定檔（伺服器/客戶端設定）
// - Shader 快取（偵測預先計算的 aimbot shader）
```

Manifest 本身以 EAC 的 P-256 私鑰簽名 — 因此無法偽造讓修改過的檔案看起來是乾淨的。

---

## 7. 後端認證協定

User-mode 應用程式連接到 EAC 後端伺服器（`https://*.easyanticheat.net`）以執行：
1. **認證**遊戲 session（遊戲特定的金鑰交換）
2. **上傳遙測**（來自 kernel driver 的壓縮+簽名封包）
3. **下載更新**到黑名單、白名單和 hash manifest
4. **接收**來自後端的封禁決定

### 認證流程圖

```
客戶端                          EAC 伺服器
  │                                 │
  │─── TLS 1.3 + ECDHE ────────────→│
  │←── 伺服器憑證 ──────────────────┤
  │    （由 in-driver 憑證解析器驗證）
  │                                 │
  │─── EAC_HELLO {                  │
  │      game_id,                   │
  │      client_version,            │
  │      session_nonce（隨機 32B）  │
  │    } ───────────────────────────→│
  │                                 │
  │←── SERVER_CHALLENGE {           │
  │      server_nonce,              │
  │      challenge_token            │
  │    } ───────────────────────────┤
  │                                 │
  │─── CLIENT_RESPONSE {            │
  │      P256 ECDSA 簽名，覆蓋      │
  │      (session_nonce || server_nonce || hwid_composite)
  │    } ───────────────────────────→│
  │                                 │
  │←── SESSION_OK {                 │
  │      session_key,               │
  │      allowed_flags              │
  │    } ───────────────────────────┤
```

`CLIENT_RESPONSE` 中的 **P-256 ECDSA 簽名**由 kernel driver（`sub_FFFFF807C1E226E0`）計算 — user-mode 應用程式只是透過 IOCTL 傳遞原始資料並取回簽名結果。私鑰永遠不離開 kernel。

---

## 8. EAC.exe 回報的資料 vs. Driver 回報的資料

| 資料項目 | 回報來源 | 方式 |
|---|---|---|
| 視窗列舉（overlay）| User-mode EAC.exe | EnumWindows → IOCTL 到 driver → 遙測 |
| Ring3 可見的 process 列表 | User-mode EAC.exe | `NtQuerySystemInformation` → IOCTL |
| 已載入模組列表（user-mode）| User-mode EAC.exe | `EnumProcessModules` → IOCTL |
| 硬體 ID | Kernel driver | 直接 IOCTL 到 storage/NDIS；來自韌體的 OEM 字串 |
| Kernel driver 列表 | Kernel driver | PsLoadedModuleList 遍歷 |
| Handle table 分析 | Kernel driver | 直接 kernel 結構存取 |
| EPROCESS 掃描 | Kernel driver | 直接 kernel 結構存取 |
| VAD tree 分析 | Kernel driver | 直接 kernel 結構存取 |
| 遙測的加密簽名 | Kernel driver | 透過加密分派的 P-256 ECDSA |

---

## 9. Ring3 環境檢查項目

User-mode 應用程式在 driver 之外另行執行一套環境檢查：

| 檢查 | 方式 | 偵測目標 |
|---|---|---|
| **Desktop window manager** | `DwmIsCompositionEnabled()` | 繞過 DWM 的 overlay |
| **螢幕擷取 API 狀態** | `IDXGIOutputDuplication::AcquireNextFrame` | Desktop duplication overlay |
| **剪貼簿監控** | 監控剪貼簿是否有作弊選單模式 | 作弊選單複製貼上設置 |
| **輸入裝置列舉** | `DirectInput8Create` 裝置列表 | 未知的巨集滑鼠、按鍵注入器 |
| **執行中的 process 名稱** | `EnumProcesses` + `GetModuleBaseName` | 已知的作弊載入器名稱 |
| **啟動 registry 項目** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | 持久性作弊載入器 |
| **服務列表** | `EnumServicesStatus` | 作弊框架服務 |
| **網路介面卡** | `GetAdaptersInfo` | VPN/tunnel 偵測（封禁逃避）|
| **時區 / 地區** | `GetTimeZoneInformation` | 地區不符偵測 |

---

## 10. User-Mode 元件的已知缺口

### 缺口 1：Ring3 反除錯可輕易繞過

User-mode 元件執行的每個反除錯檢查都可以被繞過。`IsDebuggerPresent` 可以被修補 — 只需把 `0` 寫入 `PEB.BeingDebugged`。NtGlobalFlag 可以被清除。RDTSC 時序可以透過 hypervisor 攔截。這讓 Ring3 反除錯層主要只是增加摩擦，而非真正的屏障。

### 缺口 2：IOCTL 冒充 / 中繼

知道確切 IOCTL 碼和封包格式的攻擊者可以自行撰寫「假 EAC user-mode 服務」，向 driver 發送精心製作的無害遙測。Driver 認證挑戰有助於防止這個，但如果 session 金鑰交換可以被重放或挑戰 token 可以被預測，就能提交假遙測。

### 缺口 3：網路層遙測攔截

即使遙測是 ECDSA 簽名的（無法偽造），EAC.exe 和 EAC 伺服器之間的中間人可以**丟棄或延遲**遙測封包。如果伺服器不標記突然停止發送遙測的 session，斷電攻擊可能有效 — 但 EAC 很可能把連線中斷視為可疑行為。

### 缺口 4：Process 暫停時序

EAC 的 heartbeat 機制意味著你不能無限期暫停 EAC process。但 hypervisor 可以在一個 heartbeat 和下一個之間暫停 EAC 的執行、讀取記憶體，然後在下一個 heartbeat 到期前的 5 秒視窗內恢復 EAC。這是「VMCS 操控」技術的運作方式。

### 缺口 5：憑證驗證結果快取

如果 EAC 快取 Authenticode 驗證的結果（避免重複驗證相同的模組路徑），它可能在初始時接受合法的模組路徑，然後在磁碟上的檔案被替換後不再重新驗證。如果作弊在初始快取命中後替換合法的 DLL，這個時序視窗可能被利用。

---

*← [內部作弊與注入器](internal_cheats_and_injectors.md) | [漏洞主列表 →](vulnerabilities_and_gaps.md)*
