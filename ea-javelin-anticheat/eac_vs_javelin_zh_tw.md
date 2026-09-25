# EAC 與 Javelin 對照：兩套反作弊，兩種做法

> **免責聲明：** 這裡只做安全研究與教育用途。技術資料來自公開研究報告（出處見文末），
> 對照與判讀是本資料夾自己做的整理。這裡沒有作弊程式，也沒有繞過手法。
>
> 這一篇的內容**同時放在 `eac-kernel-analysis` 與 `ea-javelin-anticheat` 兩個資料夾**，
> 兩邊都刻意保持「可以單獨發布」，所以不互相連結。

---

## 為什麼要對照

EAC 和 Javelin 都是 EA 用的反作弊，所以常被當成同一件事。**其實不是。**

- **EAC / EOS**：Easy Anti-Cheat，Epic 旗下，用在數百款遊戲（Apex、Rust、Fortnite…）。
- **EA Javelin / EAAC**：EA 自家，目前主要用在 EA 的遊戲上（Apex 也在 2026-09-29 換過去）。

兩套的設計哲學差很多，這個差異會直接影響「研究者該從哪裡下手」。

---

## 一張表看完

| 面向 | EAC / EOS | EA Javelin / EAAC |
|---|---|---|
| **主要手法** | 一直檢查你：大量執行時查詢與遙測 | 讓你看不懂：把程式碼變成虛擬機器 bytecode |
| **程式碼保護** | 混淆、字串打亂、控制流展開、加密函式指標 | **Griffin 虛擬化器**（bin-to-bin），程式碼本身是 VM |
| **進入方式** | 服務 + kernel driver 常駐 | Installer → preloader（手動映射）→ launcher DLL → cfg payload → driver |
| **核心模式元件** | `eos.sys`（約 44.6 MB），17 條 worker 執行緒 | `eadriver.sys`（約 46.8 MB），以 minifilter、altitude `363250` 註冊 |
| **使用者模式元件** | 服務（`EasyAntiCheat_EOS.exe`）＋遊戲內手動映射模組 | `EAAntiCheat.GameServiceLauncher` 系列＋手動映射的 theia 模組 |
| **加密紀錄** | XXTEA（每筆紀錄自己的 key），掛在受 mutex 保護的 list 上 | 各 section 靜置加密、熵約 8.0；Griffin 按需解密、用完立刻加密回去 |
| **對外通訊** | ETW 遙測（多條 session 與 consumer）、本機事件 | 服務與後端（`*.ac.ea.com:443`），gRPC 1.51.1 + Protobuf 3.x + xDS |
| **反分析特徵** | CPUID／MSR／VMREAD／RTM／PMU、CR3 重載、替代頁表根實驗、IPI 進度量測 | 序列化時序檢查（`rdtscp`）、CPUID、**特權埠 I/O**、opaque predicate |
| **硬體信任狀態** | Secure Boot、Code Integrity、DMA guard、隔離使用者模式、TPM | Secure Boot 檢查兩次（含直讀 `KUSER_SHARED_DATA`，繞過 syscall hook） |
| **身分蒐集** | 大量：SMBIOS、TPM、ATA 序號、GPU 物件、螢幕、MAC、UUID… | 目前公開資料較少（研究重點在 VM 與載入鏈，不是身分） |
| **跨 CPU** | x64 | x64 **與 ARM64**：同一份位元組在兩種 CPU 都 fault（UD2／UDF） |
| **錯誤呈現** | 各子系統自己的狀態碼 | 一張 E111 錯誤表（含 Wine／Proton／Steam Deck 明示不支援） |
| **靜態分析難點** | import 被抹掉、字串混淆、控制流不直觀 | **VM context、沒有虛擬堆疊、per-block lifted function** |
| **動態觀察難點** | 需要完整環境才能讓檢查真的跑起來 | **要抓對時間點**，錯過就是加密狀態 |
| **可重現性** | 位址隨版本變動，但架構相對穩定 | **每個 patch 都是不同 build**，連作者都用雜湊釘住樣本 |
| **社群研究成熟度** | 多年累積，資料多但分散 | 2025 年才開始連載，2026-09 才把兩個模組都拿到 |

---

## 兩種哲學

**EAC 像海關。** 它假設你會來，所以到處設檢查點：你開了什麼行程、載了什麼模組、
硬體跟上次一不一樣、有沒有 VM、甚至開機時信任鏈是什麼狀態。它的難點不在「藏」，
而在**你根本不知道它有多少道檢查**。

**Javelin 像保險箱。** 它不太管你在外面做什麼，而是**讓裡面的東西讀不出來**。
Griffin 把原生程式碼換成 VM bytecode，你就算把檔案拿到手，看到的也是一堆看不出意圖的區塊。
它的難點變成「你要先把 VM 拆開，才能開始談它到底在檢查什麼」。

這個差異決定了一件事：**要理解 EAC，你需要的是一個能跑起來的環境；
要理解 Javelin，你需要的是一條能拆 VM 的管線。**

---

## 成本放在哪（防守方的角度）

| | EAC | Javelin |
|---|---|---|
| 開發成本主要花在 | 蒐集面：越多來源越好、越多檢查越好 | 保護面：編譯期轉換、VM 設計、反分析 |
| 執行期成本 | 高（大量 API 呼叫、遙測、多執行緒） | 相對低（虛擬化後的程式碼照跑，但解密／加密有成本） |
| 維護成本 | 跟著 Windows 改版跑 | 每個 patch 重新編譯一次 |
| 被針對的代價 | 檢查被逐項繞過 | 一旦 VM 被拆，保護就掉一大半 |

---

## 研究者從哪裡下手

| 目標 | 常見做法 | 最容易卡住的地方 |
|---|---|---|
| 看 EAC 做了哪些查詢 | 把驅動放進模擬環境或真機，記錄呼叫與回傳 | 模擬環境給的回應不是真機值，容易誤讀 |
| 看 EAC 的遙測內容 | 觀察 ETW 與加密紀錄的組裝流程 | 紀錄是加密的，而且 key 在旁邊 |
| 看 Javelin 的載入鏈 | 從 installer 與 preloader 開始追 | 手動映射 + UD2 陷阱 + 版本資源檢查 |
| 看 Javelin 的 VM | 反虛擬化（lift → simplify → emit） | 按需解密，**時機抓錯就拿不到明文** |
| 兩者的反分析 | 逐一比對 CPUID／時序／I/O 這類探針 | 你看到的可能只是模擬器的產物 |

---

## 哪些能比、哪些不能比

**可以比：** 設計哲學、保護層次、研究者要面對的困難、成本結構。

**不能比：**

- **位址與常數**。兩套是不同的二進位，就算看起來很像也不能互相套用。
- **版本之間的位址**。兩邊都會隨更新漂移；EAC 是不同遊戲／不同 build 差很多，
  Javelin 是**每個 patch 都是新 build**。
- **「哪個比較強」**。這個問題目前沒有可比較的資料 —— 一邊有大量執行時證據、一邊連 VM 都還在拆。

---

## 我們的未解問題

整理完這兩套之後，仍然沒有答案的問題：

1. Javelin 的 Secure Boot 檢查在 Apex 上到底會不會要求？（官方說「不要求」，但檢查程式碼擺在那裡）
2. Javelin 反虛擬化之後，那些檢查邏輯實際在做什麼？目前只看到片段，不是全貌。
3. EAC 的遙測送出去之後怎麼被後端使用？公開資料只能看到本機端的組裝。
4. 兩套產品在**同一台機器上是否會並存**、會不會互相影響？
5. Apex 從 EAC 換到 Javelin 之後，原本針對 EAC 的研究還有多少適用？（依上面「不能比」那節，答案恐怕是：幾乎不能直接套）
6. Javelin 的身分蒐集面目前公開資料很少 —— 是它真的做得少，還是只是還沒被研究到？

---

## 參考資料

- EAC 側：`eac-kernel-analysis` 資料夾內的技術章節與外部研究導讀、原文封存
- Javelin 側：[javelin_analysis_zh_tw.md](javelin_analysis_zh_tw.md)（若你在另一個資料夾，請至 `ea-javelin-anticheat`）
  與 [SOURCES.md](SOURCES.md)
- 前置研究：[SOURCES.md](SOURCES.md)

---

## 導航

- 回目錄：[README.md](README.md)
- 更新紀錄：[CHANGELOG.md](CHANGELOG.md)
