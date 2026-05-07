# EasyAntiCheat_EOS.sys 啟動路徑觀察 — Runtime 補充筆記

> 這份筆記整理的是一篇 2026-05-08 的社群 runtime 觀察文，主題是 **EasyAntiCheat_EOS.sys 在啟動時到底做了哪些事**。  
> 它不是我們自己動態 trace 出來的結果，所以本文會刻意把內容分成：
>
> - 跟本 repo 已有分析能互相印證的部分
> - 值得記錄、但要保守看待的 runtime 觀察
> - 目前還不適合寫死成事實的細節

---

## 先講結論

如果把這篇啟動分析濃縮成一句話，那大概是：

> EAC 在真正開始掃 process、thread、memory 之前，會先花不少力氣確認「這台機器現在的執行環境值不值得信」。

而且從這篇的描述來看，啟動流程不是單純：

- 建 device
- 開 worker
- 開始掃

比較像是：

1. 先留一份初始化狀態到 registry
2. 進入自己包起來的 VM / 混淆層
3. 跑幾輪 anti-debug / anti-instrumentation 檢查
4. 再開始碰 system modules、code integrity、firmware、PCI、WMI、憑證、catalog
5. 最後才把持續監控交給 worker threads

這個觀察跟本 repo 原本的方向其實很一致：  
**EAC 不是一載入就直接掃遊戲，它會先確認「你現在給我的這個 Windows 環境，有沒有問題」。**

---

## 1. 這篇最值得收的部分

### 1-1. DriverEntry 只是入口，不是全部

這篇文裡最值得記的其中一點，是它很明白地指出：

- `DriverEntry` 負責初始化
- 真正持續跑的工作在 worker threads
- 就算 `DriverEntry` 後面走到某些清理或回傳路徑，worker 也可能已經被拉起來

這個觀念很重要，因為很多人看 driver 時會太執著在 `DriverEntry` 本身，以為只要把那段看懂就差不多了。

但如果這篇觀察沒看錯，EAC 的設計比較像：

- `DriverEntry`：啟動、驗證、配置、建基礎設施
- `worker thread`：真正長時間運作的監控主體

這跟我們 repo 裡對「初始化」和「持續監控」分層的理解是相容的。

### 1-2. 啟動初期非常重視例外處理行為

文中最醒目的點，是它把 **INT 1 / INT 3 + SEH** 描述成一個很關鍵的啟動門檻。

白話講就是：

- EAC 故意觸發某些例外
- 它預期 Windows 會照它想要的方式，把控制流送進本地 SEH handler
- 如果這個行為不對，EAC 會認為執行環境不可信

這種檢查的重點不是「有沒有 debugger」這麼簡單，而是：

> 你現在這個環境，對例外、單步、斷點的處理，有沒有被別人改過、吃掉、攔走，或變得不像正常 Windows。

這點跟一般反作弊很常見的「偵測 attach debugger」比起來，層次更深一點。

### 1-3. 啟動後會大量碰系統模組、憑證與 catalog

這篇文提到的幾條線，跟本 repo 現有內容非常能互相對上：

- `NtQuerySystemInformation(SystemModuleInformation)` 類型的模組列舉
- 對 `CI.dll`、`cng.sys`、`hal.dll`、`FLTMGR.SYS` 的讀取
- 憑證 store 列舉
- `CatRoot` 下面的 `.cat` 讀取

這些都在告訴我們同一件事：

> EAC 啟動時不只是看遊戲，也會花很大力氣確認 Windows 信任鏈、系統模組、簽章生態本身是不是正常。

這跟 [crypto_and_obfuscation.md](crypto_and_obfuscation.md)、[usermode_eac_app.md](usermode_eac_app.md)、[telemetry.md](telemetry.md) 那幾條線是可以接起來的。

### 1-4. 啟動期就開始做硬體與虛擬化環境摸底

文中提到的這些行為很值得收：

- WMI / SMBIOS
- PCI config space 掃描
- ACPI table probe
- BCD boot config 檢查
- Hypervisor 相關系統資訊查詢

如果這些觀察成立，那就很清楚了：

EAC 不只是後面在跑 HWID / anti-VM，  
而是**從啟動期就開始建立這台機器的背景輪廓**。

也就是說，anti-debug、anti-VM、硬體指紋、信任鏈驗證，對它來說不是幾個互不相關的小功能，而是一整套啟動期信任建立流程。

---

## 2. 跟現有 repo 哪些章節最有關

### [usermode_eac_app.md](usermode_eac_app.md)

這篇可以補強我們原本對「EAC 啟動流程」的理解。  
原本比較偏 user-mode 到 driver 怎麼啟動、怎麼 heartbeat；這篇則把 **driver 啟動後前幾輪到底忙什麼** 補得更立體。

### [crypto_and_obfuscation.md](crypto_and_obfuscation.md)

文中提到 `.sec7`、大量 handler、自己的 VM layer，跟我們目前對混淆路線的理解很接近。  
這可以拿來補一句很實際的話：

> 很多真正關鍵的啟動決策，不會大剌剌躺在一般反編譯結果裡，而是藏在 EAC 自己的 VM / control-flow 包裝層後面。

### [spoofer_detection.md](spoofer_detection.md)

文中對：

- SMBIOS
- WMI
- ACPI
- PCI

這幾條線的描述，剛好能強化「EAC 的硬體觀察不是單一路徑」這件事。

### [telemetry.md](telemetry.md)

如果 startup 期就已經在蒐集這麼多環境資訊，那麼遙測章節裡談到的「封包不只是 process 資料，還包括系統層資訊」就更合理了。

---

## 3. 這篇裡面哪些地方要保守寫

這篇很有價值，但不是每個細節都適合直接寫死。

### 3-1. 精確 RVA、thread ID、call count

像是：

- 某個 `RVA`
- 某個 worker thread 編號
- 某個 API 被呼叫幾千次

這些東西比較適合標成：

> 特定樣本、特定觀察環境下的 runtime 結果

原因很簡單：不同 build、不同系統版本、不同環境，這些數字都可能變。

### 3-2. 某些 `NtQuerySystemInformation` 類別編號

文中提到很多 class code，例如：

- `0x91`
- `0x67`
- `0x5A`
- `0xC5`

其中有些能用官方文件部分對上，有些則比較偏 undocumented / 社群 enum 對照。

比較穩的寫法應該是：

- `SystemCodeIntegrityInformation` 類型的查詢，官方有文件能對應
- `SystemBootEnvironmentInformation` 這種名稱在社群與部分文件脈絡中常見
- `SystemHypervisorSharedPageInformation` 這種名稱，目前比較像是 undocumented enum 生態裡的常見對應，**合理但不要寫成 Microsoft 正式公開保證的 API 合約**

### 3-3. 「0x1AD000 就是 DTB」這種單點解釋

這類觀察可以記，但不建議直接升格成主結論。  
比較適合寫成：

> 文中觀察到 EAC 啟動時有實體記憶體探測行為，且研究者把其中一個位址解讀為 DTB 相關探針；這條線值得記，但仍需要更多樣本或自己的 trace 佐證。

### 3-4. AMD / Intel 行為完全一致

這個說法也不要寫太滿。  
更穩的版本是：

> 在文中給出的兩種測試環境裡，沒有看到明顯的 CPU vendor 分歧路徑；這至少表示「EAC 一看到 Intel 就走完全不同啟動線」這件事沒有被這次觀察證實。

---

## 4. 關於你提到的 `0xC5`，我的看法

你說最有趣的是 `0xC5` 這條，我也同意，它很值得注意。

### 為什麼這條特別值得看

因為如果 EAC 真的會去查一個和 **hypervisor shared page** 相關的系統資訊，
那代表它不是只靠：

- 看 VM driver 名稱
- 看 SMBIOS
- 看 PCI Vendor/Device

這種比較傳統的 anti-VM 訊號。

它還會去問：

> Windows 本身現在有沒有暴露出跟 hypervisor 存在有關的系統層資訊？

這就更偏向「從 OS 自己的狀態回報來判斷」，而不是只看外圍痕跡。

### 但這條目前要怎麼寫才穩

我會建議寫成這樣：

> 社群 runtime 觀察提到，EAC 啟動時會查詢一個被普遍對應到 `SystemHypervisorSharedPageInformation` 的 `NtQuerySystemInformation` 類別，藉此判斷目前系統是否暴露 hypervisor 相關共享頁資訊。這代表 EAC 的 anti-VM 視角可能不只限於裝置、模組與 SMBIOS，而是也會碰 Windows 自己對 hypervisor 狀態的描述。

這樣的好處是：

- 保留這條觀察的價值
- 不會把 undocumented enum 當成百分之百官方契約

### 跟現有 anti-VM 線怎麼接

這條很適合補進 [spoofer_detection.md](spoofer_detection.md) 或之後另外拆一篇 anti-VM 筆記。  
因為它說明了一個很重要的方向：

> EAC 可能不是用單一 VM 判斷訊號，而是把 module、PCI、SMBIOS、ACPI、hypervisor shared page 這些一起看。

這種多訊號拼圖式判斷，才比較符合它整體設計風格。

---

## 5. 如果把這篇濃縮成可寫進總報告的版本

我會寫成這樣：

> 近期社群 runtime 觀察顯示，EasyAntiCheat_EOS.sys 在啟動初期就會先驗證例外處理、時序與執行環境，再進一步列舉系統模組、信任鏈、憑證、catalog、WMI/SMBIOS、PCI 與 boot/config 狀態，之後才把長時間監控交給 worker threads。這代表 EAC 的 startup 不只是「把 driver 載起來」，而是一個先建立環境信任、再開始持續監控的多階段流程。

這樣就夠穩，也夠有資訊量。

---

## 6. 我對這篇的整體評價

如果只問我值不值得收，我會說：

> 值得，而且比一般論壇留言有價值很多。

原因是它不是只丟一句「EAC 會掃這個」就跑掉，而是把 startup 行為拆成幾個能理解的 phase：

- registry diagnostic state
- VM / anti-debug gate
- system module baseline
- environment / firmware / CI / boot probes
- worker thread fan-out
- certificate / catalog work
- 之後的 process / thread / handle / memory 監控

即使裡面有一些細節還需要保守處理，整體方向仍然很有參考價值。

---

## 參考說明

- 本筆記主要依據：你提供的 2026-05-08 社群 runtime 觀察文字
- 官方可對照部分：
  - `NtQuerySystemInformation` 官方文件  
    https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
  - Code Integrity / Memory Integrity 背景  
    https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/code-integrity-checking
- undocumented enum 對照可參考：
  - NtDoc 的 `SYSTEM_INFORMATION_CLASS`  
    https://ntdoc.m417z.com/system_information_class

---

## 導航

- 上一篇：[Apex dump 工具筆記 — `CApexDumpWasm`](apex_dump.md)
- 下一篇：[EAC Kernel Driver 靜態分析筆記](README.md)
- 回主索引：[README.md](README.md)
