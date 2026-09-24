# 更新紀錄（eac-kernel-analysis）

> 這個資料夾就是對外發布的單位，所以更新紀錄放在這裡。
> repo 根目錄的 `CHANGELOG.md` 是本機工作用的草稿紀錄（連草稿區的更動一起記），
> **發布內容以本檔為準**。

---

## 2026-09-24

### 新增

- 新增 [uc_eos_driver_writeup_zh_tw.md](uc_eos_driver_writeup_zh_tw.md) — UnKnoWnCheaTs（Anti-Cheat Research #772181）那篇長篇 EOS driver runtime 研究的中文導讀。內容包含來源標註、KEVLAR 模擬環境的實驗方式與三種證據等級、13 個主題的重點整理（初始化 61 秒時間預算、worker 樹、硬體與開機信任狀態、PCI/ACPI/MMIO、GPU 物件到 XXTEA 加密紀錄的鏈路、PiDDB 與 loader 視角、行程映像檢查、ETW 遙測、反虛擬化 CPU 探針、win32k 暫時 callback slot 與 stack walk 證據、裝置介面與 IOCTL 候選、卸載殘留、覆蓋率現況）、與本資料夾各章節的對照表，以及外部質疑與閱讀注意事項。
- 新增 [uc_eos_driver_writeup_original_en.md](uc_eos_driver_writeup_original_en.md) — 上述研究的原文逐字封存（原作者四篇長文：主文、9/17 更新、9/22 兩篇補充章節），並附 72 篇討論串索引。**這是外部來源，不是本資料夾的驗證結果。**

### 回復

- 把 [eos_sys_2026_05_static_revalidation.md](eos_sys_2026_05_static_revalidation.md) 與 [eos_sys_beginner_walkthrough_zh_tw.md](eos_sys_beginner_walkthrough_zh_tw.md) 複製回本資料夾（先前被移到 repo 根目錄）。兩份都是逐 byte 相同，沒有做任何技術內容修改。

### 修正

- 修掉會讓「只發布本資料夾」破圖的連結，共 4 處：
  - `README.md` 的導覽移除指向根目錄的 `../README.md`
  - `uc_eos_driver_writeup_zh_tw.md` 的 `../eos_sys_*` 改為資料夾內連結，並移除 `../README.md`
  - `apex_dump.md` 的舊檔名自連結 `apex%20dump.md` 改為 `apex_dump.md`（2026-05-07 改名後漏改）
- 去識別化：`eos_sys_2026_05_static_revalidation.md`（8 處）與 `eos_sys_beginner_walkthrough_zh_tw.md`（1 處）裡的本機樣本路徑，把 `C:\Users\<本機使用者>\...` 改成 `C:\Users\<user>\...`；六條驗證指令（`Get-FileHash`、`Get-AuthenticodeSignature`、`GetVersionInfo`、`llvm-readobj`、`rabin2`、`radare2`）的工具名、參數與檔名都沒有變動。
- 修正 `usermode_techniques.md` 目錄的 2 條頁內錨點（目錄文字沒跟著標題更新，點了不會跳）：
  - 第 4 項「ETW — 遊戲洩漏很多資訊」→ 對齊標題「ETW — 遊戲洩漏的資訊」
  - 第 12 項「為什麼這些對 EAC 有效」→ 對齊標題「為什麼這些技術對 EAC 有效」

### 備註

- 本資料夾內的所有 Markdown 連結都指向資料夾內部：整包丟上 GitHub 即可獨立閱讀，不需要根目錄的任何檔案。
- 原文封存檔中的 `C:\Windows\...` 等路徑是原作者文章的一部分，屬於引用內容，刻意保持原樣。
