# 資料來源

這個資料夾裡的技術章節是自己的靜態分析；其中那篇 EOS 執行時研究是整理自公開來源。

**原始貼文沒有收錄在這個資料夾裡** —— 這裡放的是自己的整理與判讀，不是轉貼。
想查原始敘述，請直接連到下面的網址；（本機）查證用的快照另外放在 repo 根目錄的
`_sources_unpublished/`，不隨這個資料夾發布。

---

## [1] Inside EAC/EOS driver: hardware identity collection, kernel telemetry and CPU probes

| | |
|---|---|
| 作者 | `lauralex` |
| 時間 | 2026-09-15（主文）／2026-09-17（更新）／2026-09-22（補充章節） |
| 網址 | <https://www.unknowncheats.me/forum/anti-cheat-research/772181-inside-eac-eos-driver-hardware-identity-collection-kernel-telemetry-cpu-probes.html> |
| 用到的部分 | 整篇執行時研究：生命週期與初始化時間預算、worker 樹、硬體與開機信任狀態、PCI/ACPI/MMIO、GPU 物件到 XXTEA 加密紀錄、driver 發現、行程映像檢查、ETW 遙測、CPU 探針、卸載殘留、覆蓋率；以及作者後續回覆裡的 KEVLAR 改造清單、證據邊界與反例討論 |
| 本機快照 | 有（2026-09-25 擷取，未發布） |

## [2] EAC free version detection vectors

| | |
|---|---|
| 發文者 | `asinio` |
| 時間 | 2026-09-20 ~ 2026-09-24 |
| 網址 | <https://www.unknowncheats.me/forum/anti-cheat-research/772975-eac-free-version-detection-vectors.html> |
| 用到的部分 | 只用來做「社群說法 vs 我們的證據」的交叉比對，以及「裝了不等於開了」的案例 |
| 本機快照 | 有（未發布） |

---

## 為什麼不收錄原文

1. **著作權在原作者身上。** 那些貼文不是我寫的，貼進來只會變成轉貼。
2. **這裡要放的是自己的整理。** 需要查證時再連回上面網址。
3. **本機快照是為了查核。** 我在本機保留了擷取當下的副本，用來核對數字；
   它不會跟著發布，也不會出現在 repo 的歷史裡。
