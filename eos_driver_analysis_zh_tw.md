# EOS kernel driver：硬體身分、遙測與 CPU 探針

> **免責聲明：** 這裡只做安全研究與教育用途。內容是整理自公開技術報告的執行時觀察，
> 出處集中在下方「來源資訊」。這裡沒有作弊程式，也沒有任何繞過手法。

---

## 這篇在講什麼

2026 年 9 月有一份很長的 EOS kernel driver 研究：把 `eos.sys`（Fortnite 版本）丟進
自製的 Windows 模擬環境 **KEVLAR** 裡跑，累積出 **8,538 萬筆已驗證事件**，
然後一條一條拆出它在「硬體身分蒐集、開機信任狀態、PCI/ACPI 探測、ETW 遙測、反虛擬化 CPU 探針」
這些路徑上到底做了什麼。

它最值錢的地方不是「公布了什麼神奇手法」，而是**它是一份逐指令的行為地圖**：
哪個 RVA 讀了什麼、資料被編碼進哪個結構、用什麼演算法加密、掛在哪條 list 上、什麼時候釋放。
本 repo 原本都是靜態分析，這一篇剛好補上「**同一條路徑在執行時長什麼樣子**」。

- 來源清單：[SOURCES.md](SOURCES.md)
- 原始報告：<https://www.unknowncheats.me/forum/anti-cheat-research/772181-inside-eac-eos-driver-hardware-identity-collection-kernel-telemetry-cpu-probes.html>

---

## 來源資訊

| 項目 | 內容 |
|---|---|
| 標題 | *Inside EAC/EOS driver: hardware identity collection, kernel telemetry and CPU probes* |
| 作者 | `lauralex` |
| 來源 | #772181 |
| 發表時間 | 主文 2026-09-15；更新 2026-09-17；補充章節 2026-09-22（GMT） |
| 規模 | 4 頁、72 篇；整理時最後活動為 2026-09-24 |
| 分析對象 | `eos.sys`（Fortnite 版本），x64，44,666,520 bytes，Entry RVA `0x2594F8` |
| 樣本 SHA-256 | `020d5da6b881408ced33be09b92dc45e12e641b8b3c91f3a327429e5027fef74` |
| 方法 | 自製模擬器 KEVLAR（作者 `lolz5465az`）＋授權擷取 ＋ 舊 kernel dump ＋ 建模狀態 |
| 規模 | 1,800 秒穩態觀察、8,538 萬筆事件、作者自述超過 1 TB log |
| 後續 | 作者預告 pt. 2 會轉向 user-mode 服務（`EasyAntiCheat_EOS.exe`）與手動映射進遊戲的 EOS payload |

---

## 跟本 repo 既有章節的關係

本 repo 原本走的是**靜態**逆向（IDA Pro、radare2、section／import／函式層級），
另外有一條 `2026-03-11` 樣本的再驗證線。這份執行時研究補的是不同角度：

| 面向 | 本 repo 既有內容 | 這篇外部研究補上什麼 |
|---|---|---|
| 觀察方式 | 靜態反組譯、結構重建 | 執行時逐指令追蹤＋呼叫結果記錄 |
| 粒度 | 子系統／函式群 | 單一指令（RVA）＋對應的事件編號 |
| 資料流 | 遙測封包欄位、加密演算法推測 | 從「讀到硬體值」到「加密進紀錄、掛上 list」的完整鏈路 |
| 反虛擬化 | 反 VM 檢查的靜態線索 | CPUID / TF / BTF / MSR / VMREAD / 頁表等探針清單與觸發位置 |
| 限制 | 各章節都有標示 | 作者自己寫了「證據邊界」專節，誠實標示哪些是模擬出來的 |

換句話說：**它不是取代既有章節，而是讓既有章節的推論多一個可以對照的參照點。**

---

## 先搞懂這些數字是怎麼來的

這一節很重要。不先理解數字的產生方式，很容易把它們當成「真機上量到的值」。

### KEVLAR 模擬環境

`eos.sys` 不是在真機上跑，是丟進 KEVLAR 這個模擬的 Windows 環境裡執行：

- 原始 EOS 指令以 guest code 執行
- EOS 對 Windows 的呼叫，可能收到**有型別的模型回應**、**擷取到的機器資料**，或在狀態足夠時**複製真實 Windows 行為**
- 輸入不是單一次開機的完整快照，而是「授權擷取 ＋ 一份舊 kernel dump ＋ 建模的行程狀態」
- C317 這個主 run 內含**加速執行與語意重播（semantic replay）**；被重播的操作不算成「又一次獨立執行」

**那 KEVLAR 到底被改了多少？** 作者自己列過一份清單（2026-09-15 的回覆），
目標寫得很直白：*「讓沙箱與宿主機盡可能 1:1 對齊」*。這份清單值得看，
因為它直接回答了「哪些數值是模擬出來的」：

| 面向 | 內容 |
|---|---|
| KEVLAR — Windows 環境 | 補上建模的 kernel state、行程、模組、registry、檔案、裝置與硬體回應，讓 EOS 能看到一個「講得通」的環境 |
| KEVLAR — Kernel API | 補實作缺的呼叫，並修正結構、回傳值、輸出緩衝、handle 與物件生命週期 |
| KEVLAR — Memory | 修正權限、lazy page 載入、行程掛載、physical-memory alias，以及不同映射之間的一致性 |
| KEVLAR — Scheduling | 修正 worker 執行、阻塞等待、週期 timer、跨處理器 callback 與卸載順序 |
| KEVLAR — CPU 行為 | 新增或修正特權指令、MSR、debug state、效能計數器、processor tracing、例外投遞 |
| KEVLAR — Virtual time | 讓時戳、共享時鐘與排程 deadline 一致（含依時間而定的初始化行為） |
| KEVLAR — OS 互動 | 實作 callback 投遞，修正 registry 通知、IRP dispatch/completion、cancellation 與 storage 回應 |
| KEVLAR — 加速調查 | 降低 mapping／hook 開銷、加上受控最佳化；**durable checkpoint 仍未實作** |
| Unicorn — 正確性 | 修正 AVX/SSE state、upper vector lanes、`PUSHF`、`CR8`、delivered-exception state 與時戳觀測邊界 |
| Unicorn — 觀測與效能 | 加上 MSR hook、branch stepping、instruction-retirement 觀測；最佳化 memory-map 查找 |

換句話說：**這套模擬環境本身就是被大量補強過的作品**；清單上沒寫的，就是它當時還做不到的事 ——
這也解釋了為什麼「modeled response」這條界線一直要強調。

### 三種證據，不要混在一起看

作者自己把每一條結論標成三種等級，這點很值得學：

| 證據種類 | 意思 |
|---|---|
| Observed execution | 在某個已命名的 run 裡，某條指令／呼叫／存取確實發生了 |
| Modeled response | 回應是 KEVLAR 給的；模型的限制會標在會影響結論的地方 |
| Original-code control | 原始位元組在保留或宣告的狀態下被執行過；**「有一條分支存在」不等於「那條分支被執行過」** |

看每一條結論時，先問它是哪一種，不要全部當成同一種確定性。

### 常出現的 run 標籤

| 標籤 | 用途 |
|---|---|
| **C317** | 主 run：`20260914T033348.817Z-6220`，30 分鐘穩態觀察，大部分彙總數字來自這裡 |
| **P185** | 同一份 root image 的較早一次執行，暴露了「初始化時間預算」那條時間相關分支 |
| **C460 / C500** | 補捉特定行為（ETW 消費者設定、DriverUnload 期間的釋放順序） |
| **C388 / C399** | 短時間診斷型 run（PCI 回應消費者、早期 comparator 的對照） |
| **C401c / C402** | 帶「還原的歷史 PiDDB cache」的 run（注意：開機條件與主 run 不同） |

另外作者自己註明：**這份 writeup 是 AI 協助撰寫的**（原句：*AI-written*），
資料本身來自他的追蹤與 log。這件事不影響資料，但會影響你對行文精確度的期待。

---

## 主要發現

每一條都會標明它屬於哪一種證據等級。**所有數字都來自模擬環境。**

> 節號約定：這裡的 1～13 是**本篇自己的**分類；文中若寫「原文第 N 節」，指的是原始報告的節號
> （原文共 21 節，其中第 5、12、13、14、18、20 節在後續貼文裡）。

### 1. 生命週期與「61 秒初始化時間預算」

C317 的骨幹時間軸（事件編號 / 虛擬秒）：

```
DriverEntry 回傳成功              18398543
穩態觀察開始                      13.2266385 虛擬秒
觀察結束                          1800.0000337 秒（30 分鐘）
DriverUnload 進入 / 返回          79695124 / 85383716（耗時 42.3739071 虛擬秒）
```

真正的重點是**初始化有一個依賴時間的分支**：

- 較早的 P185 run 在完成 `FltStartFiltering`、`IoCreateSymbolicLink` 後（94.4187147 秒）進入 rollback
- 固定 frame 實驗只變動經過的 `SystemTime`，得到一條乾淨的界線：
  - `60.9999999 秒` → 走 `0x39F3B0`，回傳 `0x259518`，`RAX = 0`
  - `61.0000000 秒` → 走 `0x41C1BE`，進入 rollback routine `0x216CAD`
- 後來從原始指令**推導出同一個門檻**：`0xAF4640-0xAF46C8` 對 `61,000,000,000 ns` 做有號比較，
  常數被拆進受保護的 limb 運算（`0x0FFFFF1C` = -228、`0x0C1DDE00` = 203,283,968，`-228 × 2^28 + 203,283,968 = -61,000,000,000`）
- 失敗側的行為：P185 在 `18394312` 取消註冊 filter，`DriverEntry` 在 `19738271` 回傳 `0xC000026C`
  ＝ `STATUS_DRIVER_UNABLE_TO_LOAD`
- 同一個 timing 區塊還會把 device flags 的 bit `0x80`（`DO_DEVICE_INITIALIZING`）清掉

**作者明確說沒有拿到的東西：** 這條路徑沒有被證明連到任何 hypervisor 判定、debugger 判定或回報行為，
也不能推廣到「共用這個 comparator 的每一次呼叫」（C399 的早期呼叫中，兩個方向都選到同一個目標）。

### 2. Worker 樹

- C317 建立 **17 條 EOS 系統執行緒**，全部進入同一個受保護的 worker 入口 **RVA `0x1CBE5B`**
- 最後都走到 `PsTerminateSystemThread(0)`
- worker **404** 包辦全部 **21 次 TPM 提交**、4 次儲存裝置回應、firmware variable、WMI、PCI 活動
- worker **484** 取得並釋放網路介面表
- 五條共用 context pointer `0x22569B` 的 worker 對應到 **ETW real-time consumer**（由 C460 佐證）
- 有一條 worker（TID 2064）在觀察結束前幾秒才被建立

作者的自我節制也值得記：他說 context `+0x10` 那一欄**只是程式碼指標，不是任務名稱**，
共用入口位址不代表兩條 worker 做同一件事。

### 3. 硬體與開機信任狀態（這一塊直接對應本 repo 的 HWID / spoofer 章節）

EOS 問的不只是身分，還問「這次開機的信任與虛擬化脈絡」。C317 的查詢次數：

```
Boot-environment queries（class 90）      2
Secure Boot 查詢                           2
Code Integrity 查詢                        3
Build-version 查詢（class 222）           42
DMA-guard 政策（class 202）                1
Isolated user mode（class 165）            1
Enlightenment information（class 91）      1
Speculation-control（class 201）           1
自訂 kernel signer 授權查詢                1
```

模型交付的狀態包含：firmware type、boot flags、Secure Boot enabled/capable、
Code Integrity options `0x5`、Windows build `22631`、QFE `7517`、`DesktopEditions`、
DMA guard（模型中為 disabled）、IUM flags、hypervisor/enlightenment 欄位（模型中不存在）。

**身分來源清單**（原文第 18 節「目前全貌」整理，作者自稱是目前為止最完整的一份）：

```
MachineGuid / ComputerHardwareId
SMBIOS、registry 與 firmware 來源
Boot environment / firmware type
Secure Boot state、Code Integrity state
Windows build / QFE、custom-kernel-signer policy
Boot variables（BootCurrent、Boot0000…）、OfflineUniqueIDRandomSeed
ATA identity（SMART 與 pass-through）
快取的 STORAGE_DEVICE_DESCRIPTOR 序號直讀
螢幕識別（WmiMonitorID）、TPM public material
MAC / 網路介面識別
Version-1 UUID node（被拿去當 ETW session ID）
含 GPU 的物件與其 16-byte reference
CPU vendor / signature
```

### 4. PCI / ACPI / MMIO：實體層探測

- **512 次 `HalGetBusDataByOffset`**（TID 328 與 404 各 256），其中 32 次回 4 bytes、480 次沒匹配；
  第一個成功回應 `86 80 53 9B` → `8086:9B53`
- 另一個 worker 做了 **272 次 `HalpPCIConfig`**；模型身分為 `8086:9B53` 與 `8086:1901`；
  結果分類為「260 個不存在的 virtual function、8 次已配置 header 讀取、4 次未建模的 extended-tail 存取」
- **一個具體的消費端**（C388）：EOS 讀 offset `0x04` 的 8 bytes（回傳 `00 00 00 00 05 00 00 06`），
  在 RVA `0x21E4450` 整段載入後與 `FFFFFFFFFFFFFFFF` 比較；
  受控測試顯示**只有整段全 1 才會走另一條續行**（`0x3E65AF` vs `0x39EE09`）。
  作者特別聲明：這是**all-ones 有效性／哨兵判定**，不是 vendor/device 比對，也還沒證明是 DMA/IOMMU 偵測結果
- 要求 **12 張 ACPI 表**：`DMAR ×3`、`IVRS ×2`、`APIC ×3`、`WAET ×2`、`HPET ×1`、`DSDT ×1`
  （DMAR/IVRS 開了 IOMMU 設定的檢視路徑，但沒有取回最終判定）
- HPET `0xFED00000`（value `0x0429B17F8086A201`）、local APIC `0xFEE000F0`（value `0x1FF`）
- MMIO 觀察 6,118 筆（6,116 筆 `fixture=none`）、I/O-space map/unmap 各 2,298、physical-copy 操作 9,056
  —— 作者提醒：大部分被歸類成 MMIO 的紀錄，其實只是透過 coherent physical alias 讀到的普通位元組，不是硬體暫存器

### 5. 從 GPU 物件到「加密紀錄掛上受保護 list」

這是修訂版新增、也是整篇最完整的一段資料流。觀察到的流程：

1. `MmCopyMemory` 先複製 16 bytes reference 到 stack，再複製一個 8,192 bytes 的物件
2. EOS 在複製內容裡搜尋這個 reference：標記位元組 `01h` 在 `CD4h`、16-byte reference 在 `CD5h`
3. 複製用畢後**整段清零**並 `ExFreePoolWithTag`（tag `ClfC`）
4. reference 被逐位元組編碼進一筆 `CM13` 紀錄（offset `26h`）；受控測試（65,536 組輸入/mask 對）
   顯示該局部編碼為 `output = input XOR mask`（作者註明 mask 產生器尚未重建，所以這只是局部操作）
5. 紀錄表頭 `+20h` 以 `old_value XOR 1Ah` 更新
6. 複製進一個 `70h` 的 wrapper 配置（tag `61434D43h` = `CMCa`）
7. **進行 XXTEA 就地加密**：16 words、9 rounds，4 個 key word 就存在 wrapper 表頭裡
   （本 run 捕獲值 `3DA7B79A` / `D3CA47F0` / `4657CF65` / `DC3C0140`）
8. 用 `image+30A830h` 的 mutex 保護，把 wrapper **附加到 `image+30A900h` 的 list**（事件 `19872239`）
9. 明文整段擦除（`REP STOSB`，44,156 bytes）並釋放；計數器同步下降
10. wrapper 本身在 `DriverUnload` 期間被釋放（事件 `20255930`，tag `CMCa`）

額外兩點：儲存裝置序號有**第二條來源**（走進快取的 kernel memory 找到 `STORAGE_DEVICE_DESCRIPTOR` 直讀序號，
與 ATA 回應獨立）；PiDDB 那份 inventory 紀錄走**同一條加密與附加路徑**，但是 64 words / 6 rounds。

### 6. Kernel driver 的「多視角」發現

EOS 看 driver 不是只有一份清單，而是同時用了：

```
系統 module 目錄、\Driver 物件命名空間、PsLoadedModuleResource / loader entries
PiDDB 同步、image-load 通知、image-verification callback
big-pool inventory、pool-tag 資訊、code-integrity 狀態、hotpatch 狀態
address → image 歸屬（RtlPcToFileHeader）
```

其中 PiDDB 部分：`PiDDBLock` RVA `0xC5C8C0`、`PiDDBCacheTable` `0xD55320`、`PiDDBCacheList` `0xD54F30`；
EOS 以 `Wait=FALSE` 傳入該 lock 位址做 `ExAcquireResourceExclusiveLite`。
帶還原快取的 run 裡出現「populated walk」、**20 筆的 count gate（索引 19）**、
45 筆表的 pool-tag 輪替、以及在 `0x101` → `0x102` 之間退讓的檔名 fallback。

### 7. 行程／映像檢查與「例外清單」邏輯

這一段對本 repo 的偵測章節最有參考價值：

- PEB / loader 走訪（`0x86BF8`、`0x1F3C61`），在第六次比較時選到 `winsrv.dll`
- PE 結構驗證（`0x1F2FFC`）：MZ（受測種子為 `0x5A4D`）、`e_lfanew` 邊界、PE signature、PE32/PE32+、section table 範圍
- **針對特定 detour 的檢查**：`DbgUiRemoteBreakin` 的 E9 首 byte 判定、位移與 `LdrShutdownProcess` detour 的比對
- **權限判定**：某個 flags dword 的 bit `20h`、Administrators SID 判定產生 bit `21`、
  token integrity 檢查在 `0x3FFF` 以上就放棄
- 過了那道 gate 之後：`NtOpenProcess` 的 transfer bytes 檢查 → 找到模組檔案 → 取憑證名稱／SHA-1
- 最後把該筆紀錄清零並釋放

### 8. ETW 遙測與網路

- **5 條 trace session、5 個 real-time consumer**；consumer worker 的 context 由模板建立，callback 指標是編碼過的
  （`mov rax, [rcx+60h]` → `add rax, [rsp+160h]` → `call rax`）
- 訂閱的 Threat Intelligence provider GUID：`f4e1897c-bb5d-5668-f1d8-040f4d8dd344`，
  `MatchAnyKeyword = 0x03FFF0FF`、Level 0；複製的 publisher manifest 解出 **22 個 bit**
  （涵蓋配置、保護變更、遠端 APC、執行緒 context、記憶體讀寫、行程／執行緒的 suspend/resume/freeze/thaw）
- 解析器讀 classic timestamp 時是從紀錄的 `+10h` 讀（作者把它列為讀錯 offset 的一條）；callback 讀 opcode 並在 **25** 的位置分岔
- 有 IPv4 send/receive payload reader、loopback 與 PID 4 比對、**per-process × per-destination-port 的計數表**、
  以 PID 保存執行檔路徑；失敗路徑會把整張表擦掉
- 網路小結：kernel 側的已驗證 inventory 裡**沒有封包發送操作**；TDI 註冊只取得既有位址；
  ETW 本機投遞與 catalog RPC 都不等於對外連線。作者的 run 裡也沒有正常的 EOS user-mode 服務

### 9. 反虛擬化與 CPU 探針（標題上的「CPU probes」）

作者重選了 **22,527 筆 CPU／例外紀錄**逐一比對來源串流與原始映像位元組，涵蓋：

```
Hypervisor CPUID leaves 40000000h / 40000100h
Windows hypervisor-information 查詢（class 197）
100 次計時 CPUID 迴圈 vs 100 次純時戳 baseline
TF / BTF 探針（含與不含 MOV SS reload）
256 次合成 MSR 讀取（40000000h–400000FFh）
VMREAD status/fault 探針、debug register 讀寫
RTM read/execute、physical-alias 回傳探針
PMU 最小取樣、XGETBV/XSETBV、RDTSC、Intel Processor Trace
CR3 read/reload、替代頁表根實驗、APIC 效能中斷屏蔽
跨處理器 IPI 與進度量測、persistent-thread-state 取得
```

幾個值得注意的細節：

- **計時 CPUID 的 150 vs 1** 是 KEVLAR 虛擬時鐘的政策下限（`SampleVirtualTsc`），不是真實 150 倍慢
- **合成 MSR 掃描（`0x40000000`–`0x400000FF`）要注意讀法**：fault 與成功會收斂到同一條結果路徑
  （`0x38BF2E` / `0x38BF37`），所以 fault 之後的 `RAX` 不能當成有效 MSR 資料
- VMREAD 探針在 C317 記錄到的是 VMX inactive／無 VMCS／架構 #UD（正常完成時會編碼 0=成功、1=VMfailValid、2=VMfailInvalid，
  但這個 run 沒走到那裡）
- **替代頁表根實驗**是目前最「主動」的一段：EOS 保存 CR3、複製並改寫分頁項、切到自建 root，
  在那個 mapping 下執行 `CPUID`、`SIDT`、`SGDT`，再還原；並且**在實驗前屏蔽 local APIC 的
  performance-monitor 中斷**（xAPIC offset `0x340` / x2APIC MSR `0x834`，LVT mask 為 bit 16），實驗後還原
- 但是：**C317 沒有執行到該探針本體**（整場 666 筆 CPUID 事件中沒有 `0x35FB6C` 那一筆），
  所以這條路徑目前是「原始碼重建 ＋ 有限合成測試」，不是實機頁表改動
- 「NMI storm」維持假設狀態：該路徑沒有設 NMI delivery mode、沒有程式化 counter overflow、
  沒有寫 interrupt-command register，也沒有重複產生迴圈

### 10. 另外兩個值得記的發現

**（a）暫時寫進 `win32kbase` 的 callback slot**

EOS 會把 `eos.sys + 0x237A00` 暫時寫進 `win32kbase.sys + 0x28E058`（原始 store：`0294984A  mov qword ptr [r10], r11`），
大約 **0.5000021 虛擬秒**之後原本的 0 值就回來了。對應 Windows 映像的 `LeaveCrit` 常式會載入這個 slot、
檢查是否為 null，然後在非空時透過 Control Flow Guard helper 分派過去 —— 這解釋了為什麼一個放在那裡的資料指標
會變成執行 hook。作者同時劃了界線：**沒有觀察到 `LeaveCrit` 真的透過該指標被呼叫**，
而且半秒的存活時間也不足以稱它為「常駐 hook」。

**（b）堆疊回溯：目前的證據是「沒有證據」**

EOS 的 kernel-call catalog 裡**零筆**名為 `RtlVirtualUnwind`、`RtlWalkFrameChain`、`RtlCaptureStackBackTrace`、
`RtlLookupFunctionEntry`、`RtlCaptureContext` 的呼叫；C317 那 5 筆 unwind 紀錄來自 KEVLAR 的例外分派器。
作者保留「可能是自製 inline walker」的可能，但明說現有證據不足以成立。
（`RtlVirtualUnwind` 這個名字出現在 EOS 解析的 `um.exe` / `conhost.exe` import 清單裡 ——
那是它在讀別人的 import table，不是在呼叫這個函式。）

這兩點特別放在這裡，是因為它們正好是本 repo [detection_methods.md](detection_methods.md) 與
[external_cheat_detection.md](external_cheat_detection.md) 最常被問的兩個問題：
「它有沒有動 win32k」以及「它有沒有做 stack walk」。而這一串裡也正好有人對 (b) 提出反例，見下面的「外部質疑」。

### 11. 裝置介面與 IOCTL 候選

- 建立 `\Device\EasyAntiCheat_EOS`
- dispatch：CREATE/CLOSE `0xCCA29`、DEVICE_CONTROL `0xCCAAF`
- 131 個命令探針中，有 **15 個值**能走到 request 或初始化狀態讀取，**全部編碼為 `METHOD_NEITHER`**
- 作者定義得很保守：這些是「**協議重建的候選**」，不是 15 個已接受的命令
- 另外提出「user-mode relay」假設（收集路徑最終都收斂到同一條受保護紀錄），並明說那是**可被測試的假設**，不是結論

### 12. 卸載與殘留

`DriverUnload` RVA `0xCE846`；卸載後快照：

```
被追蹤的 guest-pool 配置：11 筆 / 1,132 bytes（其中 2 筆是 OS 快取，共 412 bytes）
kernel handle：10、referenced object：10
file/registry handle、IRP、device、filter、可執行 context：全部為 0
```

另外 EOS 會在初始化與卸載各寫一次 `HKLM\System\CurrentControlSet\Control\CI\DebugFlags = 0x10`。

### 13. 覆蓋率與現況（作者自己怎麼評估這份研究）

```
Validated events              85,388,481
Paired call scopes             2,122,595
Operation groups                     667
Catalog categories                    52
Kernel-call groups                   218
Lifecycle checks passed          19 / 20
已見到的直接條件結果           937 / 1,456（64.35%）
兩份資料集都沒出現的替代分支   519
已收束的研究家族               1 / 17
全 driver 指令／分支覆蓋率     無法計算
```

作者自己解釋了為什麼「覆蓋率會隨著覆蓋變多而下降」，也列出仍未解的主要區域：
最終 HWID 縮減路徑、處理器量測結果的消費者、共享紀錄 list 的讀取端與傳輸、
kernel-image 通知覆蓋、憑證／信任決策邏輯、正常 user-mode IOCTL 協議、卸載後的所有權殘留。

---

## 跟本 repo 各章節的對照

| 本 repo 章節 | 原文的對應內容（節號為原文編號） |
|---|---|
| [spoofer_detection.md](spoofer_detection.md) | 第 4／18 節的身分來源清單、ATA 序號雙來源、SMBIOS/registry/firmware 交叉、TPM public material |
| [telemetry.md](telemetry.md) | 第 11／16 節的 ETW session 與 consumer、provider GUID、22 個 keyword bit、網路紀錄與計數表 |
| [crypto_and_obfuscation.md](crypto_and_obfuscation.md) | XXTEA（16 words/9 rounds、64 words/6 rounds）、per-record key、pool-tag 輪替、六字串加密字面值解碼 |
| [detection_methods.md](detection_methods.md) | 第 8／9／12 節的行程映像檢查、通知註冊清單、反虛擬化探針 |
| [ioctl_and_driver_tracking.md](ioctl_and_driver_tracking.md) | 第 15 節的裝置介面與 15 個 `METHOD_NEITHER` 候選；第 7 節的 PiDDB 與 driver 發現 |
| [external_cheat_detection.md](external_cheat_detection.md) | `DbgUiRemoteBreakin` E9 判定、`LdrShutdownProcess` detour 比對、`RtlPcToFileHeader` 歸屬 |
| [usermode_eac_app.md](usermode_eac_app.md) | 第 16 節（run 中沒有 user-mode 服務）與作者預告的 pt. 2 user-mode 方向 |
| [startup_runtime_analysis.md](startup_runtime_analysis.md) | 第 2 節的初始化時間預算與 `DO_DEVICE_INITIALIZING` |
| [vulnerabilities_and_gaps.md](vulnerabilities_and_gaps.md) | 第 19 節「證據邊界」＋第 21 節仍未收束的清單 |
| [eos_sys_2026_05_static_revalidation.md](eos_sys_2026_05_static_revalidation.md) | 同一支產品的不同 build；可對照方法論，**但位址不可互套** |

---

## 有人提出的反例

一份研究值不值得讀，不只看作者說了什麼，也看別人怎麼挑戰它：

- 有回覆者（`alexanderyy`，2026-09-16）主張真實環境下 EAC 會用 `RtlVirtualUnwind` 與
  `RtlLookupFunctionEntry` 做 hook 檢查（連 EPT hook 都能抓），懷疑 KEVLAR 沒收到這些呼叫，
  並附上 Rust 版 EAC 的 RVAs。
- 作者的回覆（貼文編號 **4801129** / **4801141**）比一般摘要寫得具體，值得完整看一次：
  - 他認為有**手寫 unwinder** 的明顯跡象，但「不敢說 100% 可用、沒有但書」；
    手動走訪的邏輯本身被虛擬化，而抓 `PRUNTIME_FUNCTION` 的函式只是混淆（Rust 版某個 RVA 約在 `0x1400DB6FF`）。
  - EOS 有自己版本的 `RtlCaptureContext`（與 `RtlCaptureContext` 幾乎相同），
    作者還提供了可直接在 driver 內搜尋的 byte signature。
  - 對於「為什麼記錄不到呼叫」，他的假設是**被 EAC inline 掉了**，所以模擬器不會記錄到；
    同時也承認模擬環境可能沒跑到完整行為。
  - 他也說明了為什麼只跑 30 分鐘虛擬時間：這些函式「應該一開始就會被呼叫」。
  - 當時仍未解的其中一項是 **NMI storm**：他明說要查的是「在什麼條件下才會發生」。
- 同一串裡也有 `ExFreePool` 提出 `KernelMul`、`notaskid65` 提出 kernemul 之類的替代工具建議
  （模擬器工具鏈的現況整理在 [eac_tiers_and_community_signal_zh_tw.md](eac_tiers_and_community_signal_zh_tw.md)）。
- 有人直接問 pt. 2 會不會談「比賽開始後 runtime 對裝置做了什麼」；作者回覆 pt. 2 會先簡短交代
  user-mode 服務與 EOS bootstrapper，重點放在手動映射的 EOS payload 與 heartbeat 邏輯。

這種「外部提出反例 → 作者更新證據邊界」的來回，本身就是這篇值得留存的原因；這份整理把兩邊的說法都留下來了。

---

## 讀之前要注意的事

1. **所有數值都來自模擬環境。** 作者自己在原文第 19 節列了邊界：虛擬化／DMA／Secure Boot／簽章政策的值
   來自「宣告的模型平台」，查詢點是真的，**回傳值不是真機量測**。
2. **不要把它的 RVA 當成你手上樣本的 RVA。** 這篇的 root image 是 `eos.sys`（Fortnite 版，44 MB）；
   本 repo 早期分析的是另一份樣本，`2026-03-11` 那份靜態再驗證又是另一支。
   EAC 不同遊戲／不同 build 差異很大，這條在 repo 首頁就寫過了。
3. **注意「有分支」不等於「被執行」。** 這是作者自己反覆強調的紀律，尤其適用在替代頁表根實驗上。
4. **populated PiDDB 走訪不是同一次開機。** 那 20 筆／6 筆格式化紀錄來自帶還原歷史快取的 run，
   開機條件與主 run 不同，不能當成同一次開機的異常。
5. **計時類數值受模擬器政策影響。** 150 vs 1 是 `SampleVirtualTsc` 的最低值政策，不是真機的 150 倍差異。
6. **它是一份 AI 協助撰寫的長文，而且 AI 出過事。** 作者自己在第 3 篇回覆裡說，AI「刪掉了一些
   很重要的資訊」（他舉的例子是**所有 MMIO 存取、PCI config 讀取**等），他之後才回頭修補
   （貼文編號 `4800179`）。也就是說：資料是真的，但**這份 writeup 的完整度曾經被 AI 影響過**。
   引用時請回溯到原始指令與事件編號，不要只引句子。
7. **不是本 repo 的驗證結果。** 這頁只是導讀，本 repo 沒有重現其中任何一項。

---

## 這些東西可以怎麼用

- 想理解「**從實體硬體到加密紀錄**」的完整鏈路時，原文第 4 節那條 GPU→XXTEA→list 是最具體的範本
- 想補強 HWID／spoofer 章節時，用原文第 18 節的身分來源清單當 checklist，逐項對回本 repo 的靜態觀察
- 想理解反虛擬化成本時，原文第 12 節的探針清單可以直接當成「一支 anti-cheat 願意花多少指令做環境檢查」的參考
- 想追 ETW 遙測時，provider GUID、`MatchAnyKeyword`、22 個 bit 與解析器的 offset 錯誤都是可驗證的錨點
- 想找「它有沒有動 win32k」「它有沒有做 stack walk」這類問題的線索時，看上面的第 10 節（本篇編號）
- 想學研究方法論時，它的「三種證據等級」與「證據邊界」兩節比技術內容更值得抄

---

## 參考資料

資料來源清單（作者、時間、網址、用到的部分）：

- [SOURCES.md](SOURCES.md) — 作者、時間、網址，以及各來源用到的部分
  - 本文引用的來源編號（`4800440` KEVLAR 改造清單、`4800179` AI 刪過內容、`4801129`／`4801141` unwinder 討論）都用本機快照核對過
  - 原文不收錄在本資料夾；要對照請連到上面的網址

原始出處：

- <https://www.unknowncheats.me/forum/anti-cheat-research/772181-inside-eac-eos-driver-hardware-identity-collection-kernel-telemetry-cpu-probes.html>

---

## 導航

- 回目錄：[README.md](README.md)
- 相關章節：[spoofer_detection.md](spoofer_detection.md) · [telemetry.md](telemetry.md) · [crypto_and_obfuscation.md](crypto_and_obfuscation.md)
- 上一篇：[eos_sys_beginner_walkthrough_zh_tw.md](eos_sys_beginner_walkthrough_zh_tw.md)
