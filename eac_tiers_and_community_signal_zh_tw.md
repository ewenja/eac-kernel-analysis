# 怎麼讀「免費版 vs 完整版」這類討論

> **章節級免責聲明：** 這裡是**來源判讀**，不是操作指南。
> 文末「附錄」節錄了一段社群成員的規避建議，那是**引用第三方說法**（有標作者與日期），
> **不是這裡提供的作法**，也沒有任何驗證。要照著做之前，請先把整篇對照表看完。

---

## 來源

| 項目 | 內容 |
|---|---|
| 標題 | *EAC free version detection vectors*（提問類） |
| 來源編號 | Anti-Cheat Research / **#772975** |
| 作者 | `asinio`（新手帳號，2026-09 註冊） |
| 時間 | 2026-09-20 ~ 2026-09-24（18 篇） |
| 網址 | <https://www.unknowncheats.me/forum/anti-cheat-research/772975-eac-free-version-detection-vectors.html> |
| 性質 | **提問串**，不是研究。整串沒有任何原始資料、log、位址或工具輸出 |

---

## 先講結論：這串能當什麼、不能當什麼

**能用的有三點：**

1. 它多給了一個「EAC 會依遊戲分級、強度不同」的實際情境（雖然只是提問者的自述）。
2. 它印證了那篇 EOS 研究**用的方法不是特例** —— 串裡直接推薦用核心模擬器（kernemul）自己跑分析，
   跟另一篇用的 KEVLAR 是同一類工具。
3. 它是一份**資訊品質的活教材**：串裡有一篇講得很像回事的技術主張，被其他人指出是低階 LLM 生成的猜測，
   而且跟我們手上的證據對不上。這剛好呼應我們在第一篇來源裡標的「AI 協助撰寫」警語。

**不能用的：**

- 它**不是偵測向量清單**。整串沒有一項附證據、位址、工具輸出或可重現步驟。
- 它**不能當事實引用**。串內成員互相矛盾，部分說法還跟我們手上第一份逐指令級研究的觀察**直接衝突**（見下表）。

---

## 串裡說法 vs 本 repo 的證據

每一列都是「某人說了什麼」對照「我們手上有什麼」。**判定欄是重點：一致 / 不符 / 未證實。**

| 串裡的主張 | 誰說的 | 本資料夾手上的證據 | 判定 |
|---|---|---|---|
| 免費版 EAC **完全不載 kernel driver**，全 usermode；所以 test-signing 才過得去 | `PhilJackson`（2026-09-23） | 本資料夾分析的樣本與第一篇研究的對象**都是 kernel driver**；`EasyAntiCheat_EOS.sys` 就是 ring0 元件。串內也有人直接反駁同一段 | ❌ **不符** |
| 「免費版**有** kernel driver；apex 就是免費版，fortnite 版本最好」 | `bigslim04`（2026-09-24） | 與我們「EAC 依遊戲／版本調整」的既有結論方向一致，但「apex = 免費版、fortnite = 最好」這種對應**我們沒有證據** | ⚠️ 方向一致、細節未證實 |
| 完整版會用 **ObRegisterCallbacks 剝奪 handle 權限** | `PhilJackson` | 第一篇的通知清單裡確實註冊了 **Object pre（`0xEA9B9`）與 Object post（`0xEBD81`）callback**，並在穩態期間被大量觸發（object handles 2,116 次） | ✅ **一致** |
| 完整版有 **NMI callback** | `PhilJackson` | 第一篇的 CPU 探針清單裡有 APIC 效能中斷屏蔽與 PMU 取樣，但**沒有** NMI callback 的證據 | ❓ 未證實 |
| 完整版會做 **stack walking** | `PhilJackson` | 第一篇明確寫：`RtlVirtualUnwind`／`RtlWalkFrameChain`／`RtlCaptureStackBackTrace`／`RtlLookupFunctionEntry`／`RtlCaptureContext` 的**呼叫數為 0**；5 筆 unwind 紀錄來自 KEVLAR 的例外分派器。作者保留了「可能有自製 inline walker」的可能，但沒有成立 | ⚠️ **我們手上的證據不支持** |
| 完整版會做 **PFN walking** | `PhilJackson` | 第一篇取得的 256 KiB persistent-thread-state 裡，**預設 PFN 資料庫位址是缺的／為零**（模型限制）；只有 physical-copy 與 MMIO 計數 | ❓ 未證實 |
| 免費版的 test-signing 能過 → 代表「kernel level 沒有在檢查 CI policy」 | `PhilJackson` | 第一篇的第 4 節有 **3 次 Code Integrity 查詢**，第 10 節還記錄 EOS 在初始化與卸載各寫一次 `HKLM\...\Control\CI\DebugFlags = 0x10`。這不等於「測 test-signing」，但足以說明 CI 狀態是它會碰的介面 | ❌ **不符（至少對 EOS build 不成立）** |
| 多數 EAC 遊戲「該有的東西都在」，只是廠商沒付錢所以不 ban | `alexanderyy`（2026-09-23） | 這是推測性說法，我們沒有任何後端或處置流程的證據 | ❓ 未證實 |
| 有些遊戲的 EAC **根本沒在跑**（舉例：Dirty Bomb；`ZeroMemory` 對 GO 說的「關掉但留 logo」） | `bigslim04`、`ZeroMemory`（2026-09-24） | 與本 repo「不同遊戲、不同 build 差異很大」的既有告誡一致，而且**這就是 OP 那個 test-signing 觀測最可能的解釋** | ✅ 一致（方法論上最有價值的一條） |

---

## 「裝了不等於開了」——test-signing 事件真正的教訓

提問者的推理鏈是這樣的：

> 我開了 test-signing → 遊戲還是能開、EAC 還在 → 所以免費版 EAC 大概不檢查核心層。

串裡最後的走向卻是另一件事：**先確認 EAC 到底有沒有在跑**。
`bigslim04` 直接建議對方用 Process Hacker 去看服務列表，並舉自己的例子：

> use process hacker and search easy anti cheat in services, it happened to me for example dirty bomb had EAC but it was not even active anymore

而 `ZeroMemory` 對那個開源遊戲（GO）的說法更直接：

> these idiots made thousand$ from donations but they're skill limited and didn't success in simple eac implement so they switched it off and kept it on their logo.

**這件事值得寫進報告的理由：** 它是一個現成的反例，說明「我在某個 EAC 遊戲上觀察到 X」這種句子，在沒有先確認 *EAC 是否真的啟用、哪個 tier、哪個 build* 之前，**不能拿來推論 EAC 的能力**。本 repo 首頁那句「不要把某一篇研究看到的常數當成所有 EAC 的永遠真相」，在這裡多了一個具體案例。

---

## 模擬器工具鏈現況（KEVLAR、kernemul）

串裡對「你要怎麼知道免費版偵測什麼」的回答是：

> multiple kernel emulators have been released so you can easily analyze them at runtime and come to your own conclusions

後續指名推薦的是 **kernemul**（搭配 Hyper-V）：

> use kernemul with HyperV, its not a trojan its open source and checked by UC Mods and you can go through yourself if you still feel uneasy

這對本資料夾的意義：第一篇那套研究方法（把 `eos.sys` 放進模擬的 Windows 環境跑，再逐指令追蹤）**不是某個人的特例做法**，而是該社群已經有多套工具（KEVLAR、kernemul）在支撐的常態路線。反過來說，這也提醒讀者：**模擬環境的觀察會受工具限制影響** —— 這正是第一篇作者自己反覆標示「modeled response」的原因，也是串裡 `alexanderyy` 質疑 KEVLAR 可能沒收到 `RtlVirtualUnwind` 呼叫的同一個問題點。

---

## 讀社群串的紀律（以本串為例）

`PhilJackson` 那篇的形狀很典型：**條列清楚、術語密集、聽起來很專業**（ObRegisterCallbacks、NMI callback、PFN walking、stack walking 全寫上了）。
但它在同一天就被兩位成員反駁，`ecco271k` 的說法是：

> all your posts are nothing but useless guesswork by some bottom tier llm, your brain is fried man

而我們拿去對照第一篇的證據之後，那份清單裡至少有一項（CI policy）**與觀察直接衝突**、兩項（NMI、PFN）**無法證實**、只有一項（object callback）**與證據一致**。

實務上的三個檢查點：

1. **有沒有原始資料？** 位址、log、事件編號、指令切片 —— 沒有這些，就只是意見。
2. **同串有沒有人反駁？有沒有舉反例？** 這串的反駁附了 Dirty Bomb 這種可驗證的對照經驗。
3. **能不能用我們手上的證據交叉比對？** 這是最有效的一關：本檔那張表就是這樣做出來的。

---

## 附錄：串內規避建議節錄（第三方說法，未經驗證）

> **以下是 `bigslim04` 於 2026-09-23 在該討論中的發言節錄**，逐字引用、僅刪去原站自動遮蔽的字眼與重複語句。
> 這是**社群成員的個人建議**，不是本資料夾的立場、也沒有任何一項經過驗證。
> 它被收錄的原因只有一個：它同時反映了「該社群認為哪些面會被偵測」，可以拿去對照本資料夾的偵測章節。

```
You cant use standard apis because they are blocked by the Ac, so yes writing a driver
(not a simple driver like you said) would be the best choice ... no devices, no symbolic
links, if you create a system thread you need to spoof the win32startaddress, and normal
start address find offsets for your version and if you are external be careful to not let
any other detection vector ... the ac wont ban you just because of one thing, its usually
a sum of detections, and the ideal communication is shared memory, not dataptr, or worse
ioctl that will likely get you clapped in an hour ... second way is legitimately buying a
certificate, and keeping the driver only to yourself and never share it
```

**怎麼讀這段：** 它提到的每一個「面」，在本資料夾都有對應的章節與觀察：

| 它提到的面 | 本資料夾的對應觀察 |
|---|---|
| 不要有 device object / symbolic link | EOS 建立 `\Device\EasyAntiCheat_EOS`，並有 `\Driver` 命名空間與系統 module 目錄的列舉路徑（第一篇第 7、15 節） |
| 系統執行緒的起始位址 | EOS 自身建立的 17 條系統執行緒全部進入同一個受保護入口，並把 private-context code pointer 存在 `+0x10`；模組歸屬另有 `RtlPcToFileHeader` 路徑（第一篇第 3、7 節） |
| 通訊介面（IOCTL / 共享記憶體） | 第一篇第 15 節記錄了 131 個命令探針、15 個 `METHOD_NEITHER` 候選；第 16 節則說明 kernel 側的網路 inventory 裡**沒有封包發送操作** |
| 「不是單一項，而是多項累加」 | 與本資料夾 `vulnerabilities_and_gaps.md` 的整體觀察方向一致 |
| 憑證 | 本資料夾的樣本簽章與 `usermode_eac_app.md` 的 Authenticode 驗證章節是對應的觀察面 |

換句話說：**這段的用處是拿來當「偵測面索引」，不是拿來當做法清單。** 具體怎麼做，不在本 repo 的範圍內。

---

## 導航

- 回目錄：[README.md](README.md)
- 相關章節：[eos_driver_analysis_zh_tw.md](eos_driver_analysis_zh_tw.md) · [vulnerabilities_and_gaps.md](vulnerabilities_and_gaps.md) · [eac_beginner_report_zh_tw.md](eac_beginner_report_zh_tw.md)
- 更新紀錄：[CHANGELOG.md](CHANGELOG.md)
