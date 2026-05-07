# Apex dump 工具筆記 — `CApexDumpWasm`

> 來源專案：[`ccdescipline/CApexDumpWasm`](https://github.com/ccdescipline/CApexDumpWasm)  
> 本筆記整理時間：2026-05-07  
> 觀察基準：GitHub 公開 repo、最新推送時間為 **2026-05-06**

---

## 先講它是什麼

這個專案不是 EAC driver 分析工具，本質上比較像一個：

> **Apex Legends 用戶端 dump 解析器**

它吃進去的是 **Apex 遊戲模組的 PE dump 檔**，不是 EAC 本身的 `.sys`。  
它做的事情也不是分析 anti-cheat 邏輯，而是把 dump 裡跟遊戲資料結構有關的東西抽出來，整理成比較好讀的 offset / table / config 結果。

所以如果把它放回你現在這個 repo 的脈絡裡，它比較適合被歸類成：

- 跟 **Apex 遊戲本體**有關的 dump 工具
- 跟 **offset 研究、資料結構重建**有關
- 跟 **EAC 核心防護邏輯**是不同路線

但它還是值得收，因為 **Apex 本身是 EAC 保護目標之一**。研究 Apex 偏移、資料表、資料結構的人，常常也會一起碰到 EAC 的保護環境。

---

## 這個專案最值得注意的點

### 1. 它是瀏覽器工具，不是傳統桌面 dump 工具

這個 repo 最有意思的地方，是它不是單純一支 C++ exe。

它的架構是：

- **C++ 核心**
- 編譯成 **WebAssembly**
- 前端用 **Vue 3 + Vite**
- 在瀏覽器裡直接上傳 dump 檔並解析

換句話說，這個工具的核心想法不是「把 dump 工具做得多底層」，而是：

> 把原本 C++ 的 dump 邏輯包成 WASM，讓使用者可以直接在瀏覽器裡跑。

這種做法的優點很明顯：

- 使用門檻低
- 不用自己編本地工具也能跑
- 不需要後端伺服器就能處理檔案
- 可以直接輸出 JSON，方便後續接別的工具

---

## 專案結構大概長怎樣

從 repo 結構看，它主要分兩塊：

### `DumpWasm/`

這是 C++ 主體，負責真的去解析 PE dump。

裡面可以看到幾個重點模組：

- `DumpCore.cpp`
- `Mics.cpp`
- `dataTable.cpp`
- `dataMap.cpp`
- `Convar.cpp`
- `buttons.cpp`
- `weaponSettings.cpp`
- `Pattern.h / Pattern.cpp`

簡單講，真正的「抽資料邏輯」都在這裡。

### `WASMLoader/`

這是前端。

它的工作是：

- 讓使用者選檔
- 把檔案丟進 Web Worker
- 呼叫 WASM 模組
- 顯示結果
- 提供搜尋、複製、匯出 JSON

也就是說，這整套東西其實是很標準的：

- 一個 C++ engine
- 一個 Web UI shell

---

## 它實際會抽什麼

根據 `DumpCore.cpp`，這個工具會整理出幾個主要輸出區塊：

- `Convars`
- `RecvTable`
- `Buttons`
- `dataMap`
- `Mics`
- `weaponSettings`
- `version`

其中最有價值的通常是下面這幾類。

### `Mics`

這裡比較像 miscellaneous offsets，專案裡實際有在抓的內容包含：

- `LocalPlayer`
- `EntityList`
- `ViewRender`
- `ViewMatrix`
- `NameList`
- `GlobalVars`
- `InputSystem`
- `LevelName`
- `highlightSetting`
- `studioHdr`
- `lastVisibleTime`
- `m_viewangle`
- `m_vecAbsOrigin`
- `camera_origin`
- `commandNumber`
- `cinput`
- `CHLClient`
- `observerList`
- `observer_index`
- `netChannel`
- `ClientState`
- `SignonState`
- `localplayerHandle`
- `WeaponNames`
- `ModelNames`

這一看就知道，它不是在做單一 offset dump，而是想把常見會用到的遊戲狀態與客戶端結構一次整理出來。

### `RecvTable`

這塊是 networked properties，也就是常見的 recvprop / netvar 路線。

`dataTable.cpp` 裡可以看到它不是憑空猜，而是直接對：

- `RecvTable`
- `RecvProp`

這類結構做 pattern 解析，再把表名、欄位名、offset 整理出來。

這對重建遊戲內部結構非常有用，因為你不一定每次都要硬靠純 signature 追單一欄位。

### `dataMap`

這塊通常對追一些不完全走 RecvTable 的欄位很有幫助。  
如果你有碰 Source / Respawn 這一系的資料結構，會知道 datamap 常常能補足一些 RecvTable 沒有直接覆蓋到的內容。

### `Convars`

這類資料適合拿來看 console variable 的位置或值。  
對研究遊戲內部狀態、行為切換、debug 路徑，都可能有參考價值。

### `Buttons`

顧名思義，就是跟 console command / input command 之類相關的 offset。

### `weaponSettings`

這塊是在補武器設定結構。  
從 repo 名稱與核心輸出來看，作者顯然不是只想 dump 一般 entity 資料，而是連武器相關配置也想一起抽出來。

---

## 它怎麼做的

### 1. 先把上傳的檔案當成 PE 來檢查

`DumpCore.cpp` 一開始就會先檢查：

- DOS header
- NT header
- PE signature
- ImageBase

這代表它假設輸入檔是**合法 PE dump 資料**，不是亂塞任何二進位都能吃。

### 2. 之後靠 pattern + 結構解析往下抽

這個工具核心不是什麼黑盒魔法，比較像是：

- pattern scan
- RIP-relative / RVA 解析
- 結構體欄位定位
- 字串 xref 輔助定位

像 `Pattern.h` 裡就能看到，核心的 pattern helper 很直白：

- 找 byte pattern
- 如果指定 `RVAsize`，就往後解 RIP-relative RVA
- 或交給 callback 做自訂後處理

這也表示它的風格是：

> **規則型、樣本導向的 dump 工具**

不是泛用到什麼版本都永遠不壞的那種東西。

### 3. 某些欄位會混用 signature 與字串 xref

`Mics.cpp` 裡最明顯的例子是 `lastVisibleTime`。

作者不是硬塞一條固定長 signature，而是改成：

1. 先找字串 `"lastVisibleTime"`
2. 再去找 `.text` 裡的 `lea` xref
3. 再從引用後面的指令模式回推出 entity field offset

這種做法比單純一條長 pattern 稍微聰明一點，因為它至少有在想：

- 有些欄位 pattern 不穩
- 直接靠字串與使用點回推，反而更能活久一點

但它本質上還是規則驅動，不是全自動語意分析。

---

## WebAssembly 這條線有什麼意思

從 `wasm_main.cpp` 跟 `wasmWorker.js` 可以看出它的執行流程大概是：

1. 前端拿到使用者上傳的檔案
2. 把檔案丟給 Web Worker
3. Worker 把資料 copy 進 WASM 記憶體
4. 呼叫 `_dumpAll`
5. 把回傳的 JSON 與 warning 再送回 UI

這裡有幾個很實際的優點：

- 不會卡主 UI thread
- 不需要把檔案送到伺服器
- 資料處理都在本地瀏覽器完成

如果你只是想做一個「方便看 dump 結果」的工具，這條路其實滿合理。

---

## 前端做了哪些事

`loadWasm.vue` 不是只有一個上傳按鈕而已，它其實有把使用體驗整理得不錯：

- 選檔後直接跑解析
- 顯示 dump 結果
- 可以搜尋關鍵字
- 搜尋結果會標 section
- 點搜尋結果可以跳到對應位置
- 一鍵複製
- 一鍵匯出 JSON
- 畫面上直接顯示 WASM module 版本

所以如果要一句話形容：

> 這個 repo 不只是研究腳本，它已經很接近「可用工具」了。

---

## 這個工具的價值在哪

如果你是從研究角度看，這個 repo 的價值主要有三個。

### 1. 把 dump 流程標準化

很多人做 offset 研究都會有一堆自己手上的 pattern、記事本、臨時腳本。  
這個專案把那套流程整理成可重複跑的輸出工具，這本身就很有價值。

### 2. 把輸出做成 JSON

這意味著它很容易接：

- 自己的比對腳本
- 前後版本差異比對
- 自動化更新流程
- 其他 UI 或資料展示工具

### 3. 把門檻往下拉

不是每個人都想先架 C++ 專案、配 Emscripten、自己寫 parser。  
瀏覽器就能跑的工具，對很多人來說入手門檻低很多。

---

## 它的限制也很明顯

這部分也要講，不然會太像在吹。

### 1. 它不是 anti-cheat 分析工具

這點一定要切清楚。

它分析的是：

- Apex 遊戲 dump
- 遊戲 offset
- 資料表與結構

不是：

- EAC 的 driver 邏輯
- EAC 的遙測協定
- EAC 的偵測策略

所以這份筆記適合放進這個 repo，但它在整體研究裡扮演的是**補充線**，不是主線。

### 2. 很依賴 pattern 穩定度

從 `Mics.cpp` 和 `dataTable.cpp` 看得很清楚，這工具大量依賴：

- 固定 byte pattern
- 固定程式碼形狀
- 特定字串存在
- 特定結構布局沒變太多

所以只要遊戲更新、編譯器行為變、某段 inline 方式改掉，pattern 就可能壞。

### 3. 對輸入品質有要求

它不是從執行中程序自己抓資料，而是吃你提供的 **PE dump 檔**。  
也就是說：

- dump 如果不完整
- PE header 如果壞掉
- section 排列如果不符合預期

結果就可能不準，甚至直接失敗。

### 4. 沒有辦法保證跨版本永遠可用

這類工具很適合「追目前版本」，
但不太適合被神化成「一勞永逸的萬用 dump 解法」。

---

## 跟這份 EAC repo 的關係怎麼放比較對

我建議把它定位成：

### 它不是 EAC 本體研究

但它是 **Apex 生態研究** 很實用的一塊拼圖。

原因是：

- Apex 是 EAC 保護目標
- 很多人研究 Apex 時，會同時碰到 offset、dump、EAC 環境
- 這個工具剛好補上「遊戲本體資料層」那條線

如果 EAC 研究是在看：

- 它怎麼防
- 它怎麼抓
- 它怎麼傳遙測

那 `CApexDumpWasm` 比較像是在看：

- 遊戲本體裡有哪些資料可抽
- 用什麼方式把 offset 與 table 系統化整理出來

兩者不是同一個主題，但放在同一份研究資料夾裡是合理的。

---

## 如果把它放回 Apex x EAC 的整體脈絡

這邊可以用一個更直觀的方式理解：

### `CApexDumpWasm` 在看的是「遊戲裡有什麼」

它關心的是：

- 玩家相關欄位在哪
- EntityList 在哪
- ViewMatrix 在哪
- RecvTable / DataMap 長怎樣
- 武器設定怎麼排

也就是說，它是在整理 **Apex 遊戲本體的資料地圖**。

### 這個 repo 其他 EAC 章節，比較像在看「EAC 怎麼盯著這些東西」

例如：

- [external_cheat_detection.md](external_cheat_detection.md) 在講誰去碰這些資料會被盯上
- [internal_cheats_and_injectors.md](internal_cheats_and_injectors.md) 在講如果你把邏輯放進遊戲內，EAC 怎麼抓
- [telemetry.md](telemetry.md) 在講 EAC 可能會把哪些資訊整理後送出去
- [usermode_eac_app.md](usermode_eac_app.md) 在講 user-mode 跟 driver 怎麼配合

所以最簡單的理解方式是：

> `CApexDumpWasm` 告訴你「Apex 裡面的資料在哪」，  
> EAC 分析則是在告訴你「你怎麼碰那些資料，EAC 可能會從哪裡看到你」。

---

## 為什麼這兩條線常常會一起研究

因為實務上，很多人不是只做其中一邊。

如果你研究 Apex，本來就常會同時碰到兩個問題：

### 問題 1：我要先知道資料在哪

這時你會需要：

- dump
- offset
- netvar / datamap
- weapon / player / render 結構

這就是 `CApexDumpWasm` 這條線。

### 問題 2：我碰這些資料時，EAC 會不會看到

這時你就會開始碰到：

- handle 掃描
- 記憶體區域檢查
- overlay 偵測
- driver / module 完整性
- heartbeat / telemetry / user-kernel 通訊

這就是你現在這份 EAC repo 的主線。

所以這兩條線其實是前後相接的，不是互相取代。

---

## 一個比較實際的閱讀順序

如果有人是為了研究 Apex 環境才來看這個 repo，我會建議這樣讀：

1. 先讀 [apex dump.md](apex%20dump.md)  
   先知道 `CApexDumpWasm` 到底能抽出什麼、它看的是哪層資料

2. 再讀 [eac_beginner_report_zh_tw.md](eac_beginner_report_zh_tw.md)  
   建立 EAC 的全貌，不然很容易只盯著 offset 忘了 anti-cheat 的存在

3. 接著讀 [external_cheat_detection.md](external_cheat_detection.md)  
   因為多數「先拿 dump / offset 的人」通常第一步碰的是外部讀取

4. 再讀 [internal_cheats_and_injectors.md](internal_cheats_and_injectors.md)  
   看進一步把邏輯放進遊戲內時，風險會變成什麼樣

5. 最後讀 [telemetry.md](telemetry.md) 跟 [crypto_and_obfuscation.md](crypto_and_obfuscation.md)  
   這時再看資料怎麼被整理、壓縮、保護，就會比較有感覺

---

## 如果要用一句話總結這篇的定位

我會這樣寫：

> `CApexDumpWasm` 不是在解釋 EAC 怎麼防守，而是在補上另一半地圖：Apex 遊戲本體有哪些值得追的資料、那些資料可以怎麼被系統化整理出來。

這樣把它放進你這個 repo，就會很順。

---

## 我對這個 repo 的整體評價

如果只看定位，我會給它這樣的評價：

> 這是一個把「Apex dump 解析」做成實用化工具的專案，技術路線很清楚，工程切分也算乾淨，重點不是炫技，而是把既有的 C++ dump 邏輯包成一個比較容易用的瀏覽器工具。

它最強的地方不是演算法多神，而是：

- 目標明確
- 輸出實用
- 架構簡單
- 能直接拿來跑

如果你是在做 Apex 版本追蹤、offset 對照、資料結構整理，這種工具就很有參考價值。

---

## 值得記下來的重點摘要

- `CApexDumpWasm` 是 **Apex PE dump 解析工具**，不是 EAC driver 分析工具。
- 核心是 **C++ parser + WebAssembly + Vue 前端**。
- 支援輸出 `Mics`、`RecvTable`、`DataMap`、`Convars`、`Buttons`、`weaponSettings` 等結果。
- 主要技術路線是 **pattern scan + RVA 解析 + 結構重建 + 部分字串 xref 輔助**。
- 工具化程度不錯，支援搜尋、跳轉、複製、匯出 JSON。
- 限制也很明顯：它高度依賴 pattern 與 dump 品質，版本變動後需要維護。

---

## 參考來源

- GitHub repo  
  https://github.com/ccdescipline/CApexDumpWasm

- GitHub API repo metadata  
  https://api.github.com/repos/ccdescipline/CApexDumpWasm

---

## 導航

- 上一篇：[EAC 保護遊戲中的使用者模式技術 — 技術整理](usermode_techniques.md)
- 下一篇：[EasyAntiCheat_EOS.sys 啟動路徑觀察 — Runtime 補充筆記](startup_runtime_analysis.md)
- 回主索引：[README.md](README.md)
