# 更新紀錄（ea-javelin-anticheat）

> 這個資料夾是對外發布的單位（與 repo 內的 `eac-kernel-analysis/` 並列、互不依賴），
> 所以更新紀錄放在這裡。

---

## 2026-09-25

### 新增

- 建立本資料夾，主題為 **EA Javelin（EAAC）** 反作弊，收錄兩份公開技術報告的整理與逐字封存。
- 新增 [README.md](README.md) — 資料夾導覽、來源、閱讀順序與閱讀前需知。
- 新增 [javelin_analysis_zh_tw.md](javelin_analysis_zh_tw.md) — #773123《EA Javelin analysis and devirtualization》的中文導讀。涵蓋：前置研究（domme007《Javelin Journey》）、完整安裝鏈、方法論（IDA + ghidrasql + Qiling + lift→simplify→emit 管線），以及原文 §1–§8 與 §11 的主要發現：
  - 進入點魔術參數 `0x25665CD7`、UD2 例外陷阱（RVA `0xB030` → handler `0x2040` → mapper `0x2390`）
  - 單一位元組滾動 XOR 的字串加密與可暴力還原的字串清單
  - `EAAntiCheat.cfg` 與 `stub.dll`（gRPC 1.51.1 / Protobuf 3.x / xDS；`.grfn20` 條目與標記）
  - Qiling 模擬流程與卡住的位置（`LdrGetProcedureAddress` 的 16-byte hash）
  - **Secure Boot 的雙重檢查**（`NtQuerySystemInformationEx` classes `0x91`/`0x92`/`0x162` ＋ 直接讀 `KUSER_SHARED_DATA` 的 `DbgSecureBootEnabled` 位元）與 **E111 錯誤表**（RVA `0x6B98`，含 `E111000D`／`E111000F` 沒有靜態產生者這件事）
  - packer30 的**無分支 MBA** E111 產生器（dispatcher RVA `0x373D1C`、19 個 helper、payload RVA `0xC727C8`）
  - ARM64 / CHPEv2 混合體：同一份位元組在 x64 解成 UD2、在 ARM64 解成 UDF
  - 核心驅動（minifilter altitude `363250`、PDB 路徑、VMCALL/VMMCALL 數量、resolver）
  - 使用者模式 Griffin 的**解密映射擷取**（兩份 20 MB 映射、熵 8.0 vs 3.25、指紋計數 2,503／4／449）與 `.grfn20` 的 per-slot 描述子圖
  - 反分析片段（RDTSCP 時序、CPUID、特權埠 I/O 探測）
- 新增 [apex_migration_zh_tw.md](apex_migration_zh_tw.md) — #773650《Apex will switch to EA Javelin Anticheat》的消息整理。**官方說法與本 repo 判讀分欄呈現**，並說明「Secure Boot 不要求 ≠ 不檢查」，附上線後可觀察的清單。
- 新增 [eac_vs_javelin_zh_tw.md](eac_vs_javelin_zh_tw.md) — **跨產品對照**：把 EAC / EOS 與 EA Javelin（EAAC）放在同一張表比，包含保護哲學（「一直檢查你」vs「讓你看不懂」）、成本結構、研究者入手點、可重現性，以及**兩邊不能互套**的地方，最後列出仍未解的問題。同一份內容也存在於並列的 `eac-kernel-analysis` 資料夾，兩邊都保持可單獨發布。
- 新增三份逐字封存：
  - [SOURCES.md](SOURCES.md)（6 篇，主文約 71K 字元）
  - [SOURCES.md](SOURCES.md)（1 篇）
  - [SOURCES.md](SOURCES.md)（前置研究，20 篇）

### 修改

- **不再收錄原文，改為只放來源清單。** 三份逐字封存已移出發布範圍（移到 repo 根目錄的 `_sources_unpublished/`，本機保留供查證），改以 [SOURCES.md](SOURCES.md) 列出作者、時間、網址與用到的部分。這樣發布的內容就是自己的整理與判讀，不含轉貼。

### 備註

- **語氣整理：** 主文、Apex 篇與本 README 的敘述改成更口語、更短句的寫法，**數字、位址與結論都沒有變**；原站框架的字眼收斂到各篇的「來源」一節。
- **來源性質：** 三份封存都是外部社群內容，著作權屬原作者；本資料夾不對文中結論背書，檔內皆已註明。
- **圖片未下載：** 原文的圖放在 imgur 等外部圖床，不隨本資料夾散布。
- **不收錄的來源：** #702353《bypassing EA Javelin Anticheat》只有提問、沒有內容，故未收錄。
- **可追溯性：** 主文中的每個位址／數值都用本機快照核對過；`0x25665CD7`、RVA `0xB030`、E111 表 RVA `0x6B98`、altitude `363250`、計數 `2,503`／`5,114`／`449` 等皆已逐項驗證。
- **資料夾獨立性：** 本資料夾內所有 Markdown 連結都指向資料夾內部，不含任何指向資料夾外的相對連結；可整包單獨發布。
