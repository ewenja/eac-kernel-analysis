# EA Javelin Anti-Cheat — 研究整理

> **免責聲明：** 這個資料夾只做安全研究與教育用途。內容整理自公開技術報告，
> 技術敘述以原始報告為準；出處請看 [SOURCES.md](SOURCES.md)。
> **這裡沒有作弊程式，也沒有任何繞過手法。** 商標歸各自所有者。

---

## 這裡在講什麼

**EA Javelin**（內部叫 EAAC）是 EA 自家的反作弊。它最有特色的地方是
**Griffin** —— 一套把原生程式碼轉成虛擬機器 bytecode 的虛擬化器。

這個資料夾把兩件事整理成可以獨立閱讀的報告：

- 一篇**技術分析與反虛擬化**研究（2026-09-21）
- 一則**Apex 要換成 Javelin** 的官方消息（2026-09-25）

再加上兩者都依賴的**前置研究**，以及一份和 EAC 的對照。

---

## 文件索引

| 檔案 | 內容 |
|---|---|
| [`README.md`](README.md) | 本頁：導覽、來源、閱讀順序 |
| [`javelin_analysis_zh_tw.md`](javelin_analysis_zh_tw.md) | **主文**：載入鏈、Griffin、Secure Boot 的兩次檢查、E111 錯誤表、packer30、ARM64/CHPEv2、核心驅動、使用者模式的解密擷取與反虛擬化 |
| [`apex_migration_zh_tw.md`](apex_migration_zh_tw.md) | Apex 換用 Javelin：官方說法與我們的判讀分開寫，附「上線後可以看什麼」 |
| [`eac_vs_javelin_zh_tw.md`](eac_vs_javelin_zh_tw.md) | **跨產品對照**：EAC 與 Javelin 的保護模型、成本、可重現性放在同一張表比 |
| [`SOURCES.md`](SOURCES.md) | **資料來源清單**：作者、時間、網址與各來源用到的部分 |
| [`CHANGELOG.md`](CHANGELOG.md) | 本資料夾的更新紀錄 |

---

## 建議這樣讀

1. **先看** [`javelin_analysis_zh_tw.md`](javelin_analysis_zh_tw.md)。它是唯一有技術內容的一篇，
   開頭有「先讀這段」（前置研究）和「它是怎麼被載進去的」，沒讀過原始報告也跟得上。
2. **再看** [`eac_vs_javelin_zh_tw.md`](eac_vs_javelin_zh_tw.md)，把兩套反作弊放在一起比。
3. **然後看** [`apex_migration_zh_tw.md`](apex_migration_zh_tw.md) —— 2026-09-29 之後，Apex 就是最大的
   Javelin 部署之一了。
4. **想知道數字從哪來**就看 [SOURCES.md](SOURCES.md)，裡面有每個來源的網址；
   本機也留了擷取當下的快照可以核對。

---

## 來源

| 主題 | 時間 | 性質 |
|---|---|---|
| EA Javelin analysis and devirtualization | 2026-09-21 | 技術研究 |
| Apex will switch to EA Javelin Anticheat | 2026-09-25 | 消息轉述 |
| Javelin Journey | 2025-09 起連載 | 前置研究 |

外部參考：Mowokuma 的 Griffin Notes（GitHub）—— 主文作者建議先讀那份筆記。

---

## 跟 repo 裡另一個資料夾的關係

同一個 repo 裡還有 **`eac-kernel-analysis`**（研究 EAC / EOS）。
兩套是不同產品，**位址和常數不能互套**，能共用的只有方法論與提問方式。
詳細差異寫在 [`eac_vs_javelin_zh_tw.md`](eac_vs_javelin_zh_tw.md)。

> 本資料夾刻意**不連結資料夾外**，這樣可以單獨發布；上面提到的另一個資料夾請自己前往。

---

## 讀之前先記住三件事

1. **這是一個 build 的快照。** Javelin 每個 patch 都出新 build，原作者用 SHA-256 釘住自己那份；
   位址會漂，形狀才會像。
2. **反虛擬化還沒完工。** 「已經 devirt」不等於「已經看懂」。
3. **AI 參與很深。** 腳本大多是 LLM 產生的，原作者也提醒便宜模型容易幻覺、很多結論是他手工複驗的。
   要引用就引位址和雜湊。

---

## 導航

- 主文：[javelin_analysis_zh_tw.md](javelin_analysis_zh_tw.md)
- 跨產品對照：[eac_vs_javelin_zh_tw.md](eac_vs_javelin_zh_tw.md)
- 更新紀錄：[CHANGELOG.md](CHANGELOG.md)
