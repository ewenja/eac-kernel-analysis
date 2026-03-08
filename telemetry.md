# 遙測封包逐欄位分析

> 本文是 [EAC Kernel Driver 靜態分析](README.md) 系列的一部分。

這可能是整個分析中最有實際參考價值的部分。EAC 不只是偵測作弊就停下來 — 它靜靜地組裝一個關於你機器上每個 process 的詳細二進位封包，壓縮它，簽名它，然後傳回 Epic 的伺服器。以下是那個封包裡逐欄位的確切內容。

---

## 目錄
1. [遙測管線概覽](#1-遙測管線概覽)
2. [組裝器函式分析](#2-組裝器函式分析)
3. [封包結構重建](#3-封包結構重建)
4. [Process 層級資料](#4-process-層級資料)
5. [模組層級資料](#5-模組層級資料)
6. [系統層級資料](#6-系統層級資料)
7. [XOR 混淆層](#7-xor-混淆層)
8. [壓縮與加密管線](#8-壓縮與加密管線)
9. [回報頻率](#9-回報頻率)

---

## 1. 遙測管線概覽

```
EPROCESS 結構（kernel）
         │
         ▼
sub_FFFFF807C1E1DD80       ← 遙測組裝器
  讀取：PID、父 PID、image 名稱、token、VAD、handle、模組列表
         │
         ▼
原始二進位封包（184+ bytes）
  部分欄位用 0x90 XOR 做基本混淆
         │
         ▼
sub_FFFFF807C1E11C00       ← Zstd 頻率建構器
sub_FFFFF807C1E13100       ← Zstd AVX2 壓縮器
  通常縮小 60-80%
         │
         ▼
sub_FFFFF807C1E1AF00       ← NTT 加密
sub_FFFFF807C1E226E0       ← P-256 ECDSA 簽名
  附加 ECDSA 簽名
         │
         ▼
User-mode EAC 中繼（IOCTL）
         │
         ▼
HTTPS POST 到 EAC 伺服器
  Content-Type: application/octet-stream
  Body：壓縮 + 簽名的二進位 blob
```

---

## 2. 組裝器函式分析

**`sub_FFFFF807C1E1DD80`** — 位址 `0xFFFFF807C1E1DD80`，大小 `0x844` bytes（早期程式碼段中最大的單一函式）。

這個函式接受**一個參數** — 指向 `EPROCESS` 結構的指標 — 並建構關於那個 process 的二進位遙測封包。對每個被監控的 process 呼叫一次。

### 執行流程

```c
// 步驟 1：驗證輸入的 EPROCESS
if ( !a1 ) return;  // null 檢查

// 步驟 2：解密並呼叫 PsGetCurrentProcess，比對 token
v3 = sub_FFFFF807C1ED4320(&unk_FFFFF807C2068E78);   // 取得加密指標
result = ((fn_t)((0x936ACF702E4281A9 * v3) ^ 0xFA85638DCFA646E7))();
if ( result != *(EPROCESS**)(a1 + 56) ) return;  // token 不符 — 跳過

// 步驟 3：收集保護旗標和 session ID
v4 = decrypt_and_call(0xF3EC14C2131FEE4F, 0xBE0DAFCD89B39CD1, EPROCESS_ptr);
v58 = (int)v4;  // session ID
if ( !v4 && !*(DWORD*)(a1 + 556) ) return;  // 跳過未保護的 process

// 步驟 4：初始化 184-byte 封包緩衝區
sub_FFFFF807C1E1E5C4(&unk_FFFFF807C20087C0, v54);  // 初始化/清零封包

// 步驟 5：從 KUSER_SHARED_DATA 收集時間戳
v48 = MEMORY[0xFFFFF78000000014];   // TickCountLow

// 步驟 6：透過加密 API 呼叫取得系統時間
v59 = decrypt_and_call(0xE462A05B3E35A30F, 0x7D67C96867B51F90, EPROCESS_ptr);

// 步驟 7：透過序列化函式收集所有欄位
write_field(key=0x20087C0, buf=v54, src=EPROCESS+556, len=4);  // 保護旗標
write_field(key=0x2008790, buf=v54, src=EPROCESS,     len=4);  // 基礎 process 結構
write_field(key=0x2008758, buf=v54, src=EPROCESS,     len=4);  // 另一個 EPROCESS 欄位
write_field(key=0x2008730, buf=v54, src=&v56,         len=4);  // PID 衍生值
write_field(key=0x20086F8, buf=v54, src=&v59,         len=8);  // 系統時間
write_field(key=0x20086C0, buf=v54, src=&v48,         len=8);  // tick count
write_field(key=0x2008688, buf=v54, src=&v58,         len=4);  // session ID
write_field(key=0x2008658, buf=v54, src=&v57,         len=4);  // image 名稱 hash
write_field(key=0x2008628, buf=v54, src=EPROCESS+240, len=8);  // VAD/PEB 指標

// 步驟 8：遍歷根植於 EPROCESS+376 的模組鏈結串列
// ... 詳細說明在第 5 節
```

---

## 3. 封包結構重建

二進位遙測封包（`v54`，stack 上 184 bytes）的估計佈局：

```
偏移    大小  類型      欄位                           來源
──────  ────  ────────  ─────────────────────────────  ──────────────────────
0x00    4     DWORD     封包版本 / 類型標籤             硬編碼
0x04    4     DWORD     Process 保護旗標               EPROCESS+556
0x08    4     DWORD     原始 EPROCESS 欄位 [base+0]    EPROCESS+0
0x0C    4     DWORD     原始 EPROCESS 欄位 [base+4]    EPROCESS+4
0x10    4     DWORD     繼承 PID / process 旗標        EPROCESS+64 衍生
0x14    4     DWORD     Image 名稱 hash（CRC/自訂）    EPROCESS+96 hashed
0x18    8     QWORD     系統時間（100ns 單位）          KeQuerySystemTime
0x20    8     QWORD     Tick count（低位）             KUSER_SHARED_DATA+0x14
0x28    4     DWORD     Session ID                     PsGetProcessSessionId
0x2C    4     DWORD     [填充 / 待確認欄位]             -
0x30    8     QWORD     VAD root / PEB 指標            EPROCESS+240
0x38    4     DWORD     列表中的模組數量               模組遍歷結果
0x3C    4     DWORD     模組基址 #1 低位               模組列表項目[0]
0x40    4     DWORD     模組基址 #1 高位               模組列表項目[0]
0x48    4     DWORD     模組基址 #2 低位               模組列表項目[1]
0x50    4     DWORD     模組基址 #2 高位               模組列表項目[1]
0x58    4     DWORD     模組基址 #3 低位               模組列表項目[2]
0x60    4     DWORD     模組基址 #3 高位               模組列表項目[2]
0x68    4     DWORD     模組基址 #4 低位               模組列表項目[3]
0x70    4     DWORD     模組基址 #4 高位               模組列表項目[3]
0x78    461   BYTES     模組完整路徑（UTF-16/8）        v31（461-byte 緩衝區）
0x...   41    BYTES     模組二進位指紋                 v32（41-byte 緩衝區）
... （此前的剩餘欄位用 0x90 XOR）...
0xB6    2     [結尾]    封包結尾 / checksum nibble      -
```

原始封包總計：**最少 184 bytes**（一些欄位是可變長度，動態附加）。

---

## 4. Process 層級資料

對系統上**每個被監控的 process**，EAC 收集：

| 資料點 | 收集方式 | 原因 |
|---|---|---|
| **Process ID (PID)** | EPROCESS+UniqueProcessId | 身份識別 |
| **父 PID** | EPROCESS+InheritedFromUniqueProcessId | 父鏈分析 |
| **Image 名稱** | EPROCESS+ImageFileName（15 字元）| 與黑名單比對 |
| **Image 名稱 hash** | `sub_FFFFF807C1E8D840(EPROCESS[96])` | 快速比對 |
| **Process session ID** | 加密的 `PsGetProcessSessionId` | 多使用者 / RDP 偵測 |
| **保護旗標** | EPROCESS+556（PS_PROTECTION）| 偽造 PPL 偵測 |
| **系統時間** | 加密的 `KeQuerySystemTime` | 報告的時間戳 |
| **Tick count** | `KUSER_SHARED_DATA.TickCountLow` | 交叉比對時序 |
| **VAD root 指標** | EPROCESS+240 | 記憶體掃描的起始點 |
| **Process 旗標** | EPROCESS+556 dword | Kernel 設置的旗標 |

---

## 5. 模組層級資料

收集 process 層級資料後，EAC 遍歷根植於 `EPROCESS+376` 的模組鏈結串列：

```c
// 遍歷鏈結結構：
v26 = *(QWORD*)(a1 + 376);    // 列表頭
if (v26) {
    safe_read(v26, 60);        // 鎖定第一個節點（60-byte 結構）
    for (i = 0; i < 8; i++) {
        // XOR 解碼節點內偏移+28 處的 8 bytes：
        decoded_byte = *(BYTE*)(v27 + 4*i + 28) ^ 0x90;
    }
    next_node = decoded_ptr;
    
    if (next_node) {
        safe_read(next_node, 64);    // 鎖定下一個節點（64-byte 結構）
        
        v30 = next_node[5];          // +40 處的子結構：52-byte block
        v31 = next_node[6];          // 路徑緩衝區：461 bytes
        v32 = next_node[7];          // 指紋：41 bytes
        
        if (v30 && valid_structure(v30, 52)) {
            // 從 v30 收集最多 4 個基址：
            if (count >= 1) base1 = *(QWORD*)(v30 + 20);
            if (count >= 2) base2 = *(QWORD*)(v30 + 28);
            if (count >= 3) base3 = *(QWORD*)(v30 + 36);
            if (count >= 4) base4 = *(QWORD*)(v30 + 44);
        }
        
        if (v31 && *(BYTE*)(v31 + 4)) {
            write_field(type=3, dst=v54, src=v31, len=461);
        }
        
        if (v32 && *v32) {
            write_field(type=3, dst=v54, src=v32, len=41);
        }
    }
}
```

### 每個模組收集的欄位

| 欄位 | 大小 | 說明 |
|---|---|---|
| **模組基址**（×4）| 各 8 bytes | 模組在記憶體中映射的位置 |
| **模組完整路徑** | 最多 461 bytes | DLL/driver 的完整檔案系統路徑 |
| **模組二進位指紋** | 41 bytes | 從 PE binary 計算的自訂 hash/ID |

**41-byte 二進位指紋**值得注意 — 這不是標準的 hash 長度。很可能是自訂的多重 hash：例如前 16 bytes = 前 64KB 的 MD5，接下來 20 bytes = entry point 區域的 SHA-1，最後 5 bytes = 自訂 metadata。

---

## 6. 系統層級資料

除了每個 process 的資料，EAC 還收集全機器範圍的資訊：

| 資料 | 來源 | 備註 |
|---|---|---|
| **磁碟序號** | IOCTL_ATA_PASS_THROUGH 到 disk.sys | 多個磁碟，全部檢查 |
| **Volume GUID** | Registry + IOCTL_VOLUME_GET_... | 與磁碟交叉比對 |
| **網路 MAC 位址** | NDIS OID_802_3_PERMANENT_ADDRESS | 硬體燒錄的 MAC |
| **GPU 裝置實例** | PnP manager 裝置列舉 | 裝置樹中 GPU 的 GUID |
| **SMBIOS / BIOS 資料** | 透過 NtQuerySystemInformation 的韌體表 | 主機板序號、BIOS 版本 |
| **CPU 資訊** | CPUID 指令 | 功能、hypervisor bit |
| **Windows 版本** | KUSER_SHARED_DATA.NtBuildNumber | OS 版本識別 |
| **系統 uptime** | KUSER_SHARED_DATA.TickCountLow | 新鮮 VM 偵測 |

---

## 7. XOR 混淆層

在封包交給壓縮器之前，一些欄位會被 XOR 混淆：

```c
// 來自模組遍歷段：
*((_BYTE *)&v49 + i) = *(_BYTE *)(v27 + 4 * i + 28) ^ 0x90;
//                                                       ^^^^
//                                                       0x90 XOR 金鑰
```

金鑰 `0x90` 逐 byte 應用到特定欄位（特別是鏈結串列節點資料）。這不是強加密 — 這是一個**防篡改措施**：如果有人修補 EAC driver 跳過 XOR 並發送明文，伺服器會注意到遙測解碼不正確並標記那個 session。

---

## 8. 壓縮與加密管線

組裝後：

```
原始封包（184+ bytes）
    ↓
[XOR 欄位混淆 — 對選定範圍每 byte 用 0x90]
    ↓
[Zstd 壓縮 — sub_FFFFF807C1E11C00 → sub_FFFFF807C1E13100]
    輸出：約 30-80 bytes，取決於內容
    ↓
[P-256 ECDSA 簽名 — sub_FFFFF807C1E226E0]
    附加：64 bytes（ECDSA 的 r、s 值）
    ↓
[透過 IOCTL 輸出緩衝區回傳到 user-mode]
    ↓
[User-mode EAC 包裝成 HTTPS 請求]
    ↓
[發送到 EAC 後端：https://*.easyanticheat.net]
```

伺服器收到：`[compressed_payload | ecdsa_signature]`，在解壓縮和處理報告之前驗證簽名。

---

## 9. 回報頻率

根據 driver 的時序基礎設施：

- **每約 5 秒**：從 user-mode 到 kernel driver 的 heartbeat IOCTL（反除錯 / 存活檢查）
- **每個可疑事件**：任何偵測到的 IOC 立即發送遙測封包（例如載入了新的未簽名 driver、找到 RWX 記憶體）
- **每約 30 秒**：完整系統掃描遙測批次（process 列表、模組列表、硬體快照）
- **遊戲啟動時**：包含所有 HWID 收集的完整綜合掃描
- **定期 callback**：基於計時器的 DPC（Deferred Procedure Call）觸發重新掃描

30 秒批次間隔是從清理函式中看到的多個 `FFFFF807C206A838/A83C` 計數器 globals 被清零/設置重建出來的。

---

*← [加密與混淆](crypto_and_obfuscation.md) | [Spoofer 偵測 →](spoofer_detection.md)*
