# 更新紀錄（eac-kernel-analysis）

> 這個資料夾就是對外發布的單位，所以更新紀錄放在這裡。
> repo 根目錄的 `CHANGELOG.md` 是本機工作用的草稿紀錄（連草稿區的更動一起記），
> **發布內容以本檔為準**。

---

## 2026-09-25

### 修改

- **不再收錄原文，改為只放來源清單。** 原本放在資料夾內的逐字封存已移出發布範圍（移到 repo 根目錄的 `_sources_unpublished/`，本機保留供查證），改以 [SOURCES.md](SOURCES.md) 列出作者、時間、網址與用到的部分；相關連結與用語一併更新。這樣發布的內容就是自己的整理與判讀，不含轉貼。

### 新增

- 新增 [eac_vs_javelin_zh_tw.md](eac_vs_javelin_zh_tw.md) — **跨產品對照**：把 EAC / EOS 與 EA Javelin（EAAC）放在同一張表比，包含保護哲學（「一直檢查你」vs「讓你看不懂」）、成本結構、研究者入手點、可重現性，以及**兩邊不能互套**的地方（位址、版本、強弱比較），最後列出目前仍未解的問題。同一份內容也存在於並列的 `ea-javelin-anticheat` 資料夾，兩邊都刻意保持可單獨發布。

### 修改

- 語氣整理：把 [eos_driver_analysis_zh_tw.md](eos_driver_analysis_zh_tw.md) 的敘述改寫得更口語、更短句（標題、開頭、章節導語與結論段），**所有數字、位址與結論不變**；並把原站框架字眼收斂到「來源資訊」一節。
- 同步調整 [eac_tiers_and_community_signal_zh_tw.md](eac_tiers_and_community_signal_zh_tw.md) 的用語一致性。

---

## 2026-09-24

### 新增

- 新增 [eos_driver_analysis_zh_tw.md](eos_driver_analysis_zh_tw.md) — 公開技術報告 #772181 那份長篇 EOS driver runtime 研究的中文導讀。內容包含來源標註、KEVLAR 模擬環境的實驗方式與三種證據等級、13 個主題的重點整理（初始化 61 秒時間預算、worker 樹、硬體與開機信任狀態、PCI/ACPI/MMIO、GPU 物件到 XXTEA 加密紀錄的鏈路、PiDDB 與 loader 視角、行程映像檢查、ETW 遙測、反虛擬化 CPU 探針、win32k 暫時 callback slot 與 stack walk 證據、裝置介面與 IOCTL 候選、卸載殘留、覆蓋率現況）、與本資料夾各章節的對照表，以及外部質疑與閱讀注意事項。
- 新增 [SOURCES.md](SOURCES.md) — 上述研究的原文逐字封存（原作者四篇長文：主文、9/17 更新、9/22 兩篇補充章節），並附 72 篇完整索引。**這是外部來源，不是本資料夾的驗證結果。**
- 新增 [eac_tiers_and_community_signal_zh_tw.md](eac_tiers_and_community_signal_zh_tw.md) — 把公開提問串 #772975（*EAC free version detection vectors*，提問串）做成**來源判讀**：9 條「串裡說法 vs 本資料夾證據」的逐條判定（一致／不符／未證實）、「裝了不等於開了」的實例（test-signing 觀測的真正解釋）、模擬器工具鏈現況（KEVLAR、kernemul），以及讀社群串的三個檢查點。

### 回復

- 把 [eos_sys_2026_05_static_revalidation.md](eos_sys_2026_05_static_revalidation.md) 與 [eos_sys_beginner_walkthrough_zh_tw.md](eos_sys_beginner_walkthrough_zh_tw.md) 複製回本資料夾（先前被移到 repo 根目錄）。兩份都是逐 byte 相同，沒有做任何技術內容修改。

### 修正

- 2026-09-24 **全串複驗**（重新抓取全部 4 頁原始頁面、共 72 篇後逐項檢查）：
  - 檢查本機快照的忠實度：以「忽略空白與標點的字元流」比對線上版本，Post #44／#61／#64 完全相同，Post #1 的線上內容完整包含於快照 → **無缺漏**。並記下「print view 會截斷超長貼文（實測 Post #1 只回傳約 16K／170K 字元）」，日後重抓要改用完整檢視頁面。
  - 修正文末索引 72 列的摘要欄：改為取自各篇作者**自己的文字**（改用瀏覽器 DOM 抽掉引言區塊），並移除先前混入的引言開頭與「All times are GMT」頁尾；#、作者、日期三欄未變動，72 列摘要逐列驗證可在對應貼文中找到。
  - 補強 [eos_driver_analysis_zh_tw.md](eos_driver_analysis_zh_tw.md) 的方法論段：新增作者自列的 **KEVLAR／Unicorn 改造清單**（8 項 KEVLAR ＋ 2 組 Unicorn，貼文編號 4800440）與其「與宿主機 1:1 對齊」的目標。
  - 補強同一篇的 AI 警語：作者自述 AI 曾「刪掉一些很重要的資訊」（例如所有 MMIO 存取、PCI config 讀取，貼文編號 4800179）。
  - 補強同一篇的外部質疑段：加入作者回覆的具體內容（手寫 unwinder 跡象、`0x1400DB6FF`、copy-cat `RtlCaptureContext` 的 byte signature、inline 假設、只跑 30 分鐘的理由、NMI storm 仍未解）。
  - **作者其餘 12 篇回覆也納入本機快照**：讓報告引用的來源編號（`4800440`、`4800179`、`4801129`、`4801141` 等）都有對應的擷取紀錄可核對（快照不隨 repo 發布）。同時修正程式碼區塊的換行（來源網站改用 Google PrettyPrint，程式碼每行是 `<li>`，先前的抽取會把它壓成一行）。
- 修掉會讓「只發布本資料夾」破圖的連結，共 4 處：
  - `README.md` 的導覽移除指向根目錄的 `../README.md`
  - `eos_driver_analysis_zh_tw.md` 的 `../eos_sys_*` 改為資料夾內連結，並移除 `../README.md`
  - `apex_dump.md` 的舊檔名自連結 `apex%20dump.md` 改為 `apex_dump.md`（2026-05-07 改名後漏改）
- 去識別化：`eos_sys_2026_05_static_revalidation.md`（8 處）與 `eos_sys_beginner_walkthrough_zh_tw.md`（1 處）裡的本機樣本路徑，把 `C:\Users\<本機使用者>\...` 改成 `C:\Users\<user>\...`；六條驗證指令（`Get-FileHash`、`Get-AuthenticodeSignature`、`GetVersionInfo`、`llvm-readobj`、`rabin2`、`radare2`）的工具名、參數與檔名都沒有變動。
- 修正 `usermode_techniques.md` 目錄的 2 條頁內錨點（目錄文字沒跟著標題更新，點了不會跳）：
  - 第 4 項「ETW — 遊戲洩漏很多資訊」→ 對齊標題「ETW — 遊戲洩漏的資訊」
  - 第 12 項「為什麼這些對 EAC 有效」→ 對齊標題「為什麼這些技術對 EAC 有效」

### 備註

- 本資料夾內的所有 Markdown 連結都指向資料夾內部：整包丟上 GitHub 即可獨立閱讀，不需要根目錄的任何檔案。
- 來源貼文中的 `C:\Windows\...` 等路徑屬於原作者文章內容，整理時保留原樣。
- 免責聲明配合本次新增調整措辭：原本寫「不包含任何作弊程式、漏洞利用或繞過手段」，但新章附錄逐字節錄了一段第三方社群的規避建議，因此改為「不包含任何作弊程式，也不提供任何繞過手法；引用的第三方發言僅為來源存檔與判讀材料，已標示作者與出處，不代表本 repo 立場」。若之後決定移除該附錄，這行可直接改回原句。
