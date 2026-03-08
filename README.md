# Easy Anti-Cheat — Kernel Driver 靜態分析筆記

> **免責聲明：** 本 repo 僅供安全研究與教育用途。所有內容均來自對公開發行 kernel driver 的靜態逆向工程，分析工具為 IDA Pro。本 repo 不包含任何作弊程式、漏洞利用或繞過手段，也無意提供此類內容。這類分析對安全研究人員、遊戲開發者及 kernel 安全領域的從業者均有參考價值。所有商標歸各自所有者所有。

---

## 文件索引

| 檔案 | 涵蓋內容 |
|---|---|
| [`README.md`](README.md) | 本文 — 整體架構、子系統概覽、binary 基本資訊 |
| [`detection_methods.md`](detection_methods.md) | EPROCESS 掃描、VAD tree、handle 檢查、SSDT hook 偵測、反 VM |
| [`ioctl_and_driver_tracking.md`](ioctl_and_driver_tracking.md) | Ring3↔Ring0 IOCTL 通訊、加密函式分派機制、driver 黑名單 |
| [`crypto_and_obfuscation.md`](crypto_and_obfuscation.md) | P-256 ECC 實作、NTT 運算、SHA/MD5 套件、字串與函式混淆手法 |
| [`telemetry.md`](telemetry.md) | 184 byte 遙測封包逐欄位分析、XOR 混淆層、傳輸流程 |
| [`spoofer_detection.md`](spoofer_detection.md) | 六個 HWID 來源、跨來源一致性驗證、韌體層偵測 |
| [`function_map.md`](function_map.md) | 200+ 個 IDA 標注函式的位址對照表 |
| [`external_cheat_detection.md`](external_cheat_detection.md) | 記憶體讀取器偵測、DMA 缺口、overlay 偵測、handle 掃描 |
| [`internal_cheats_and_injectors.md`](internal_cheats_and_injectors.md) | 各種 DLL 注入技術及對應的 EAC 偵測方式 |
| [`usermode_eac_app.md`](usermode_eac_app.md) | Ring3 EAC 服務 — 啟動流程、heartbeat 機制、反除錯、後端認證 |
| [`vulnerabilities_and_gaps.md`](vulnerabilities_and_gaps.md) | 各子系統偵測缺口整理，附嚴重程度評級 |
| [`usermode_techniques.md`](usermode_techniques.md) | 純 Ring3 手法 — 不需要 driver 就能在 EAC 保護的遊戲環境下操作的技術 |

---

## EAC 背景

**Easy Anti-Cheat** 是一套 kernel-mode 反作弊系統，最初由 Kamu 開發，2018 年被 Epic Games 收購。目前部署在數百款遊戲中，包括 **Fortnite、Apex Legends、Rust、Dead by Daylight、The Finals、Naraka: Bladepoint** 等。只要你近期玩過競技 PC 遊戲，機器上幾乎肯定跑過 EAC 的 kernel driver。

整個系統橫跨兩個權限層：

```
╔══════════════════════════════════════════════════════╗
║         EAC 雲端後端 (Epic 伺服器)                    ║
║  • 接收加密 + 壓縮的遙測報告                           ║
║  • 決定封禁                                            ║
║  • 推送黑名單與特徵碼更新                               ║
╚══════════════════┬───────────────────────────────────╝
                   │  HTTPS + ECC 簽名封包
╔══════════════════▼═══════════════════════════════════╗
║     使用者模式 EAC 程序 (Ring 3)                      ║
║  EasyAntiCheat.exe / EasyAntiCheat_EOS.exe           ║
║  • 從使用者空間監視遊戲程序                             ║
║  • 向 kernel driver 發送 IOCTL                        ║
║  • 遊戲啟動前驗證遊戲檔案                               ║
║  • 透過 HTTPS 將遙測資料傳送到 EAC 伺服器              ║
╚══════════════════┬═══════════════════════════════════╝
                   │  DeviceIoControl (IOCTL)
╔══════════════════▼═══════════════════════════════════╗
║  KERNEL DRIVER Ring-0  (EasyAntiCheat.sys)           ║
║                                                      ║
║  ┌─────────────────┐  ┌───────────────────────────┐  ║
║  │  Process/Memory │  │  Driver/Module 列舉器       │  ║
║  │  掃描器          │  │  (PsLoadedModuleList 遍歷)  │  ║
║  └─────────────────┘  └───────────────────────────┘  ║
║  ┌─────────────────┐  ┌───────────────────────────┐  ║
║  │  VAD Tree 遍歷器 │  │  Handle Table 檢查器       │  ║
║  │  (注入記憶體偵測) │  │  (對遊戲開啟的 handle)     │  ║
║  └─────────────────┘  └───────────────────────────┘  ║
║  ┌─────────────────┐  ┌───────────────────────────┐  ║
║  │  HW ID 收集器    │  │  Kernel 完整性檢查器        │  ║
║  │  (磁碟/GPU/MAC)  │  │  (SSDT / inline hook 掃描) │  ║
║  └─────────────────┘  └───────────────────────────┘  ║
║  ┌─────────────────┐  ┌───────────────────────────┐  ║
║  │  ECC/NTT 加密    │  │  Zstd 壓縮器               │  ║
║  │  (P-256 簽名)    │  │  (AVX2 Huffman 串流)       │  ║
║  └─────────────────┘  └───────────────────────────┘  ║
╚══════════════════════════════════════════════════════╝
```

核心工作都在 kernel driver 裡完成。它跑在 Ring-0，與 Windows 本身相同的權限層 — user-mode hook 無法攔截它，它發出的 API 呼叫也無法輕易被監控。要搞清楚它實際在做什麼，只能直接看 binary。

---

## 分析樣本基本資訊

| 屬性 | 值 |
|---|---|
| **檔案類型** | PE32+ Windows Kernel Mode Driver (.sys) |
| **架構** | AMD64 (x86-64) |
| **載入基址** | `0xFFFFF807C1E10000` |
| **DriverEntry** | `0xFFFFF807C1F8B8F0` |
| **映射大小** | 約 8 MB |
| **編譯器** | MSVC |
| **除錯符號** | 完全移除 — 無 PDB，無具名 export |
| **Import table** | **不存在** — 所有 API 在執行時透過加密分派解析 |
| **呼叫慣例** | 全程 `__fastcall`（標準 x64 ABI）|
| **混淆手法** | 加密函式指標（64-bit 乘法-XOR）、字串打亂、大量 SIMD 例程 |
| **程式碼簽名** | 有效的 Microsoft Authenticode/WHQL 簽名 |
| **特殊參考** | `0xFFFFF78000000014` = `KUSER_SHARED_DATA.TickCountLow` |

最值得注意的一點：**完全沒有 import table**。每一個 Windows kernel API 呼叫都在執行時透過加密函式指標表進行。這是靜態分析困難的主要原因 — 光看 import 什麼都看不到，所有東西都被刻意藏起來了。詳細說明在 [crypto_and_obfuscation.md](crypto_and_obfuscation.md)。

---

## 子系統速查表

| 子系統 | 功能說明 | 關鍵位址 |
|---|---|---|
| **DriverEntry** | 建立裝置物件、註冊 callback、初始化各子系統 | `0xFFFFF807C1F8B8F0` |
| **加密 API 分派** | 隱藏所有 kernel API 呼叫的中間層 | `0xFFFFF807C1ED4320` |
| **遙測組裝器** | 從 EPROCESS 資料建構二進位掃描報告 | `0xFFFFF807C1E1DD80` |
| **P-256 field multiply** | ECC 核心運算（9-limb 30-bit radix）| `0xFFFFF807C1E21280` |
| **ECC scalar multiply** | Constant-time double-and-add 簽名運算 | `0xFFFFF807C1E226E0` |
| **NTT / Montgomery** | 大整數模化簡（62-bit 質數域）| `0xFFFFF807C1E1AF00` |
| **Hash 選擇器** | MD5 / SHA-1 / 224 / 256 / 384 / 512 切換 | `0xFFFFF807C1E3A4C0` |
| **Zstd 頻率建構器** | Huffman 頻率直方圖（SSE2）| `0xFFFFF807C1E11C00` |
| **Zstd AVX2 Huffman** | 高速壓縮，每次迭代 15 bytes | `0xFFFFF807C1E13100` |
| **Authenticode 解析器** | 完整 X.509/DER kernel 內驗證，不呼叫 CryptoAPI | `0xFFFFF807C1EAD280` |
| **Driver 卸載器** | 帶 canary 驗證的清理流程（`0xBC44A31CA74B4AAF`）| `0xFFFFF807C1E50D40` |

---

## 章節導覽

- [偵測機制詳解 →](detection_methods.md)
- [外部作弊與記憶體讀取器 →](external_cheat_detection.md)
- [DLL 注入與內部作弊 →](internal_cheats_and_injectors.md)
- [IOCTL 系統與 Driver 追蹤 →](ioctl_and_driver_tracking.md)
- [加密與混淆實作 →](crypto_and_obfuscation.md)
- [遙測封包逐欄位解析 →](telemetry.md)
- [Spoofer 與 HWID 偵測 →](spoofer_detection.md)
- [使用者模式 EAC 應用程式 →](usermode_eac_app.md)
- [已知偵測缺口 →](vulnerabilities_and_gaps.md)
- [純使用者模式技術 →](usermode_techniques.md)
- [完整函式位址對照表 →](function_map.md)

---

*使用 IDA Pro 8.x + Hex-Rays decompiler 進行靜態分析。所有位址對應本次分析的特定 binary — EAC 更新頻繁，位址會隨版本變動，但整體架構保持一致。*
