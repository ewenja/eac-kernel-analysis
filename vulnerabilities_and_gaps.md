# EAC 偵測缺口與弱點彙整 — 主要參考

> 本文是 [EAC Kernel Driver 分析](README.md) 系列的一部分。
>
> **注意：** 這是一份研究與教育用途的文件。以下弱點均透過靜態 binary 分析找出 — 目的是記錄偵測邏輯的缺口，而非提供利用指南。

老實說，EAC 是目前較強的反作弊系統之一。但沒有任何反作弊是完美的，這裡列出的缺口都是真實存在的 — 其中部分是 EAC 所依賴的 kernel 架構本身的根本性限制。以下是各子系統中找到的所有弱點，附嚴重程度評級與對實際利用難度的誠實評估。

---

## 嚴重程度說明

| 評級 | 說明 |
|---|---|
| **嚴重** | 完全繞過 EAC 偵測；實際可利用 |
| **高** | 繞過特定偵測層；需要一定技術才能利用 |
| **中** | 繞過一個檢查但其他檢查仍然存在；部分逃避 |
| **低** | 理論性或需要特殊硬體/權限 |

---

## 目錄
1. [外部作弊偵測缺口](#1-外部作弊偵測缺口)
2. [內部作弊 / 注入器偵測缺口](#2-內部作弊--注入器偵測缺口)
3. [Spoofer 偵測缺口](#3-spoofer-偵測缺口)
4. [User-Mode EAC 應用程式偵測缺口](#4-user-mode-eac-應用程式偵測缺口)
5. [Kernel Driver 架構缺口](#5-kernel-driver-架構缺口)
6. [加密與協定缺口](#6-加密與協定缺口)
7. [整體分析觀察](#7-整體分析觀察)

---

## 1. 外部作弊偵測缺口

### [嚴重] GAP-EXT-01：DMA（直接記憶體存取）硬體攻擊
**摘要**：PCIe 裝置（FPGA 或專用 DMA 硬體）可以透過 PCIe 匯流排直接讀取主機的實體 RAM。受害機器上完全沒有軟體執行 — 沒有 driver、沒有 handle、沒有 kernel 模組。

**EAC 為何漏掉它**：
- 沒有 kernel driver 可偵測（DMA 裝置不出現在 `PsLoadedModuleList`）
- 沒有開啟 process handle（handle table 掃描器什麼都找不到）
- 受害機器上沒有網路足跡（命令透過 PCIe 發送到第二台電腦）

**來自 IDA 的分析依據**：EAC 的整個偵測套件假設軟體在受害機器上執行。分析的 binary 中沒有找到任何反 DMA 硬體列舉邏輯。

**EAC 可加入的緩解措施**：伺服器端行為分析（異常瞄準模式、不可能的反應時間）。

---

### [嚴重] GAP-EXT-02：Driver 層 Kernel 記憶體讀取（不需要 Process Handle）
**摘要**：擁有已載入 kernel driver 的攻擊者可以呼叫 `MmCopyMemory(targetProcess, ...)` 讀取任何 process 的記憶體，完全不需要開啟 process handle。`MmCopyMemory` 直接接受 EPROCESS 指標。

**EAC 為何漏掉它**：
- `MmCopyMemory` 不建立 handle 項目 → handle 掃描器什麼都找不到
- 如果讀取器 driver 本身從 `PsLoadedModuleList` 中移除（DKOM），它對模組掃描器不可見
- DKOM + MmCopyMemory = 沒有實體記憶體掃描實際上無法偵測

**EAC 現有的緩解措施**：對隱藏 PE image 的實體記憶體掃描（`detection_methods.md` 中的 EAC DKOM 反制措施）。但完全清除 PE header 的 driver 仍然可以逃避這個。

---

### [高] GAP-EXT-03：在 EAC 初始化前預先開啟 Handle
**摘要**：如果攻擊者在 EAC 開始監控之前就對遊戲 process 開啟 handle，並在讀取所需資料後立即關閉，EAC 的定期 handle table 掃描永遠看不到那個 handle。

**利用難度**：中等 — 需要掌握 EAC 相對於遊戲啟動的確切初始化時機，並在那個視窗內準備好執行的程式碼。

---

### [高] GAP-EXT-04：Process 名稱白名單繞過
**摘要**：EAC 透過 image 名稱把某些已知良好的 process（NVIDIA overlay 等）列入白名單。把可執行檔命名為符合白名單名稱的作弊可能避開初始標記。

**不完整的緩解措施**：EAC 可能也檢查完整的模組路徑和簽名，但如果路徑檢查未實作或快取了結果，冒充可能短暫有效。

---

### [中] GAP-EXT-05：僅使用 PROCESS_QUERY_LIMITED_INFORMATION
**摘要**：僅以 `PROCESS_QUERY_LIMITED_INFORMATION` 開啟遊戲 process 不授予記憶體存取。作弊可以用這個透過 `NtQueryInformationProcess(ProcessBasicInformation)` 找到遊戲的模組基址，再用 kernel driver 進行實際的記憶體讀取 — 把攻擊分散在兩種技術上，每種單獨看起來都不那麼可疑。

---

## 2. 內部作弊 / 注入器偵測缺口

### [嚴重] GAP-INJ-01：VAD 節點 DKOM（Kernel VAD 操控）
**摘要**：kernel driver 可以直接操控 VAD tree 節點 — 完全移除注入區域的 VAD 節點，或把它的類型從「私有可執行」改為「映射 image」。看起來像帶有有效 section 物件的合法 file-backed image 的注入區域將通過 EAC 的 VAD 掃描。

**利用難度**：極高 — 不正確的 VAD 操控會立即導致藍屏。但複雜的攻擊者已展示在謹慎實作下這是可行的。

**嚴重性**：嚴重，因為它擊敗了主要的內部偵測機制。

---

### [高] GAP-INJ-02：早期注入視窗（在 EAC 第一次掃描之前）
**摘要**：EAC 在遊戲啟動時初始化，但在 Windows loader 映射遊戲 DLL 和 EAC 完成初始掃描之間存在一個視窗。在這個視窗關閉前完成的注入器會被掃描 — 但如果注入的 DLL 是包含後續次要 payload 載入的合法已簽名 binary，初始掃描就會通過。

---

### [高] GAP-INJ-03：Thread Pool 執行劫持
**摘要**：注入器不建立新 thread（這會觸發 `PsSetCreateThreadNotifyRoutine`），而是向現有的 thread pool thread 排隊工作。Thread pool thread 有有效的、白名單的起始位址（在 ntdll/kernelbase 內）。EAC 的 thread 建立 callback 永遠不會觸發。

**EAC 現有的緩解措施**：定期掃描執行中 thread 的指令指標，但這有輪詢間隙。

---

### [高] GAP-INJ-04：APC 注入執行後
**摘要**：User-mode APC 在 thread 進入可警示等待時執行。等 EAC 輪詢並發現沒有待處理的 APC 時，APC 已經執行、載入了 DLL，佇列是空的。EAC 此時必須依賴模組出現在 PEB 中的偵測，這確實能抓到它 — 但只有在注入已經成功之後。

---

### [中] GAP-INJ-05：已簽名 DLL 漏洞利用鏈（ROP/Heap Spray）
**摘要**：載入一個完全合法的、已簽名的 DLL，恰好有可利用的漏洞。在那個 DLL 的程式碼中使用 ROP chain 或 heap spray 達成程式碼執行。從 EAC 的角度來看，只有合法的 DLL 被載入 — 沒有注入特徵碼。

---

### [中] GAP-INJ-06：Section 物件替換（磁碟上的檔案交換）
**摘要**：建立一個由精心製作的檔案 backing 的記憶體映射 section。檔案通過 Authenticode，因為它是合法簽名的。在 section 建立並快取後，用作弊程式碼替換磁碟上的檔案。如果 EAC 重新讀取檔案進行 hash 驗證，它讀取的是快取的 section（而非新檔案）。注入的程式碼從「已簽名」的 section 執行。

**緩解措施**：如果 EAC 對開啟的檔案 handle（而非快取的路徑）做檔案 hash 檢查，這就被封鎖了。僅從靜態分析無法確定。

---

## 3. Spoofer 偵測缺口

### [嚴重] GAP-SPF-01：基於 DMA 的韌體重新燒錄（離線 Spoofer）
**摘要**：實體重新燒錄儲存裝置的韌體（M.2 NVMe 磁碟使用自訂韌體工具很常見）來在 ATA 層面回傳自訂序號。EAC 的原始 ATA IDENTIFY 命令得到假值 — 沒有更高層可以抓到它，因為謊言發生在磁碟韌體中。

**來自 IDA 的分析依據**：EAC 透過 `IOCTL_ATA_PASS_THROUGH` 讀取原始 ATA 序號，完全信任它。沒有對韌體完整性或已簽名磁碟憑證的交叉比對。

---

### [高] GAP-SPF-02：透過 Hypervisor 模擬 SMBIOS
**摘要**：Type-1 hypervisor（在 Windows/EAC 下面執行）可以在 hypervisor 層面攔截並修改韌體表查詢（`SystemFirmwareTableInformation`），在 EAC 看到結果之前。即使 EAC 透過 `MmMapIoSpace` 對 ACPI 表的實體記憶體讀取，也可以被控制 EPT（Extended Page Tables）的 hypervisor 攔截。

**利用難度**：需要建立自訂 hypervisor — 非常複雜但有充分文件（例如：HVPP、SimpleSvm）。

---

### [高] GAP-SPF-03：GPU PnP 實例 ID 未交叉驗證
**摘要**：EAC 從 Windows 裝置樹（`DEVPKEY_Device_InstanceId`）讀取 GPU PnP 實例 ID。這個值來自 PnP manager 的 registry 快取 — 並非直接來自 PCI config space。修改對應 registry 鍵（`HKLM\SYSTEM\CurrentControlSet\Enum\PCI\...`）的 driver 可以在 EAC 讀取之前提供假的 GPU ID。

**緩解措施**：Registry 寫入可能需要 SYSTEM 權限和重啟才能生效；PnP manager 可能不會在即時 session 期間立即反映變更。

---

### [中] GAP-SPF-04：某些介面卡上的 NDIS PERMANENT_ADDRESS
**摘要**：EAC 特別請求 `OID_802_3_PERMANENT_ADDRESS`（燒錄的 MAC）而非 `OID_802_3_CURRENT_ADDRESS`（軟體可設定的）。但部分 USB WiFi 介面卡和許多虛擬介面卡把它們的「永久」位址儲存在可透過介面卡自身管理軟體寫入的 EEPROM 中 — 讓 `PERMANENT_ADDRESS` 在那些平台上可以被偽造。

---

### [中] GAP-SPF-05：Volume GUID Registry 持久性
**摘要**：儲存在 `HKLM\SYSTEM\MountedDevices` 中的 volume GUID 可以用 SYSTEM 權限寫入。離線 spoofer 可以修改這個值，使其與 ATA 序號偽造回傳的內容一致，消除 EAC 尋找的跨來源不一致。

---

## 4. User-Mode EAC 應用程式偵測缺口

### [嚴重] GAP-UM-01：所有 Ring3 反除錯均可輕易繞過
**摘要**：每個 user-mode 反除錯檢查（PEB.BeingDebugged、NtGlobalFlag、heap 旗標、RDTSC 時序）都可以被繞過。`PEB.BeingDebugged` 可以被修補為 0。ScyllaHide 和類似工具會自動處理這件事。

**影響**：Ring3 EAC 可以自由除錯，沒有 ring0 後果 — 對 IOCTL 協定和行為的偵察很有用。

---

### [高] GAP-UM-02：在 Heartbeat 視窗內暫停 Process
**摘要**：EAC 的 heartbeat 每約 5 秒一次。Hypervisor 或 kernel driver 可以暫停 EAC 4.99 秒，用外部工具執行一次掃描，然後在下一個 heartbeat 截止前恢復 EAC。

---

### [高] GAP-UM-03：User-Mode 視窗列舉可被 Hook
**摘要**：EAC 的 overlay 偵測使用 `EnumWindows`，它呼叫 user-mode callback。在 EAC process 中 hook `EnumWindows`（或底層的 `NtUserBuildHwndList`）的作弊可以對 EAC 的列舉隱藏 overlay 視窗。

**複雜因素**：EAC 可能定期驗證自身的函式 hook；kernel-mode 視窗列舉作為備用方案存在。

---

### [中] GAP-UM-04：透過模擬分析 IOCTL 協定
**摘要**：由於 EAC user-mode 應用程式可以被除錯（見 GAP-UM-01），攻擊者可以追蹤所有 `DeviceIoControl` 呼叫來學習確切的 IOCTL 碼和封包格式。這讓建立自訂中繼器成為可能，向伺服器發送完全「乾淨」的遙測資料。

---

## 5. Kernel Driver 架構缺口

### [高] GAP-KRN-01：PatchGuard 時序視窗
**摘要**：PatchGuard（Kernel Patch Protection）定期驗證關鍵結構（隨機間隔，大約每 3-10 分鐘）。在兩次驗證之間，kernel 結構可以被暫時修改後恢復。EAC 的定期掃描同樣有輪詢間隙。

**組合攻擊**：在 EAC 掃描 + PatchGuard 驗證之間修改 VAD 節點 → 讀取/寫入遊戲記憶體 → 在任何一個抓到之前恢復。

---

### [高] GAP-KRN-02：實體記憶體掃描覆蓋範圍有限
**摘要**：EAC 掃描實體記憶體頁面尋找隱藏的 PE image（DKOM 隱藏的 driver）。但這個掃描計算成本高昂，可能只覆蓋特定範圍（kernel non-paged pool、driver section 範圍）。在典型位址範圍之外載入或使用 paged pool 的 driver 可能避開掃描。

---

### [中] GAP-KRN-03：加密 API 呼叫常數在每次建置中為靜態值
**摘要**：EAC 的加密函式分派使用像 `0x936ACF702E4281A9` 這樣的常數，這些是編譯時常數，直接烘焙進 binary 中。一旦從某個建置版本中提取，攻擊者就知道哪個常數對應哪個 API。這個知識在 EAC 以新常數重新建置之前持續有效。

**影響**：一旦任何單一建置被分析（如本次），逆向工程就變得顯著更容易。

---

### [中] GAP-KRN-04：Callback Table 註冊對外可見
**摘要**：EAC 透過 `PsSetCreateProcessNotifyRoutine`、`PsSetCreateThreadNotifyRoutine` 等註冊 callback。這些 callback 註冊對其他 kernel 程式碼是可見的 — 複雜的攻擊者可以列舉 callback table 並找到 EAC 的 callback 函式位址，進而把它們修補為 no-op。

**緩解措施**：PatchGuard 監控 callback table — 修補它們有藍屏/bugcheck 的風險。

---

## 6. 加密與協定缺口

### [中] GAP-CRY-01：透過 Hypervisor 提取 P-256 私鑰
**摘要**：EAC 的 P-256 私鑰永遠不離開 kernel 位址空間，也不寫入磁碟。但擁有 EPT 控制的 hypervisor 可以在 EAC 的 `P256_ScalarMul` 函式設置斷點，並在執行期間從 CPU 暫存器提取純量（私鑰）。

**難度**：需要自訂 hypervisor 且不觸發 EAC 的 hypervisor 偵測（EAC 檢查 CPUID hypervisor bit 和廠商字串）。

---

### [中] GAP-CRY-02：遙測重放在客戶端無法驗證
**摘要**：EAC 的遙測簽名防止偽造，但一旦有效的已簽名封包被發送，伺服器無法判斷那個封包代表當前狀態還是從之前「乾淨」掃描重放的。如果攻擊者凍結 EAC 的遙測分派並重放舊的乾淨簽名，伺服器可能不會標記那個 session。

**EAC 現有的緩解措施**：時間戳（`KUSER_SHARED_DATA.TickCountLow` + `KeQuerySystemTime`）與每個封包一起簽名 — 重放的封包有過時的時間戳。伺服器應該拒絕時間戳超過 N 秒的封包。

---

## 7. 整體分析觀察

### EAC 表現較強的地方
| 優勢 | 強在哪裡 |
|---|---|
| **多來源 HWID** | 跨來源不一致偵測讓部分 spoofer 可被偵測 |
| **Kernel 內 Authenticode** | 沒有 user-mode hook 可以偽造 driver 簽名驗證 |
| **加密函式分派** | 讓 API 使用的靜態分析顯著更困難 |
| **P-256 簽名遙測** | 伺服器可以驗證遙測沒有被篡改 |
| **VAD tree 掃描** | 不依賴 PEB 模組列表就能抓到 manual map |
| **實體記憶體 PE 掃描** | 抓到 DKOM 隱藏的 driver |
| **硬編碼時間戳交叉比對** | 兩個獨立的時間來源讓時間操控可被偵測 |

### 需要攻擊者具備一定技術才能繞過的防禦
| 防禦機制 | 繞過難度 |
|---|---|
| VAD 掃描 | 需要 kernel driver + 有風險的 VAD 操控 |
| Handle table 檢查 | 需要 DMA 硬體或 kernel driver DKOM |
| 模組簽名驗證 | 需要 BYOVD 或洩漏的簽名憑證 |
| Heartbeat 時序 | 需要 hypervisor 層級的 process 控制 |
| HWID 跨來源檢查 | 需要同時偽造 4 個以上獨立的硬體來源 |

### 最有效的攻擊組合（研究背景）
能可靠逃避 EAC 的最複雜攻擊鏈需要：
1. **自訂 Type-1 hypervisor**（攔截 SMBIOS/韌體查詢並繞過 EAC 的 hypervisor 偵測）
2. **BYOVD 漏洞利用**或硬體燒錄的儲存韌體（在硬體層面偽造 HWID）
3. **DMA 硬體**（在受害機器上沒有任何軟體足跡的情況下讀取遊戲記憶體）
4. **不使用 DKOM**（不隱藏任何 driver — 有 EAC 的實體記憶體掃描 + PatchGuard 太危險）

這個組合幾乎繞過了本 binary 中分析的每個偵測向量。這個組合的成本和複雜性正是 EAC 被認為是較強反作弊之一的原因 — 全面擊敗它需要硬體層級的資源。

---

*← [使用者模式 EAC 應用程式](usermode_eac_app.md) | [回到 README](README.md)*
