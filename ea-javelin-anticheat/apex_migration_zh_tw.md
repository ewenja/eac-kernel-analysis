# Apex 要換成 EA Javelin 了

> **免責聲明：** 這裡只做安全研究與教育用途。下面分成「官方講了什麼」和「我們怎麼看」兩塊，
> 刻意分開寫 —— 官方數字我們沒辦法驗證。

---

## 來源

| 項目 | 內容 |
|---|---|
| 主題 | Apex 會用 EA Javelin 取代 Easy Anti-Cheat |
| 性質 | 消息轉述，**不是技術分析** |
| 發表 | 2026-09-25 |
| 篇幅 | 1 篇（發文當下還沒有人回） |
| 原始出處 | <https://www.unknowncheats.me/forum/apex-legends/773650-apex-switch-ea-javelin-anticheat.html> |
| 來源 | [SOURCES.md](SOURCES.md) |

---

## 官方講了什麼

原文是這樣寫的：

> Apex Legends Will Replace Easy Anti-Cheat With EA Javelin
>
> • Goes live September 29
> • EA reports 99%+ detection accuracy on supported titles
> • Secure Boot is NOT required for Apex at launch
>
> Players will automatically migrate after updating.

重點四條：

1. **Apex 會把 EAC 換成 EA Javelin。**
2. **2026-09-29 上線。**
3. **EA 說在支援的遊戲上有「99%+ 偵測準確率」。**
4. **Apex 上市時不要求 Secure Boot。**
5. 玩家**更新後自動遷移**（不用自己換，也沒得選）。

---

## 我們怎麼看

| 官方說法 | 我們的看法 |
|---|---|
| 99%+ 偵測準確率 | **沒辦法驗證。** 而且「準確率」是什麼意思也沒說 —— 是抓到多少、還是誤判多少？樣本是什麼？沒有方法論的數字，只能當宣傳看。 |
| Secure Boot **不要求** | **不等於不檢查。** 技術分析顯示 Javelin 會檢查 Secure Boot **兩次**，其中一次還是直接讀記憶體、不發系統呼叫。比較合理的解釋是：**政策可以依遊戲調整** —— 這也符合我們原本的結論：不同遊戲、不同設定，強度就不一樣。 |
| 9/29 上線 | 這是少數**事後可以驗證**的項目。 |
| 自動遷移 | 對玩家來說就是「不能不要」；對研究者來說，**以前針對 EAC 的觀察不能直接套到 Apex 上**（產品換了）。 |

### 上線之後可以看什麼

這些都是可以實際去確認的，比官方說法可靠：

- Apex 的安裝目錄有沒有出現 Javelin 的檔案（`eadriver.sys`、`preloader_*.dll`、`EAAntiCheat.*`）
- 原本的 EAC 服務和驅動是被移除了，還是只是停用
- 有沒有出現技術分析裡描述的那類錯誤碼（E111 系列）
- 相容性回報：Javelin 的錯誤訊息明白寫著 **Wine、Proton、Steam Deck 不支援**，
  而且要求 **Windows 10 1809 以上**；Linux 與掌機使用者會最先有反應
- 「不要求 Secure Boot」在實務上是不是等於「不檢查」—— 這個只能看，不能聽

---

## 為什麼要和技術那篇一起讀

因為這件事把技術分析拉回現實：Apex 是全球最大的 Javelin 部署之一。
Griffin 虛擬化器、E111 錯誤表、Secure Boot 的兩次檢查，都在
[javelin_analysis_zh_tw.md](javelin_analysis_zh_tw.md)；
兩套反作弊的差異則在 [eac_vs_javelin_zh_tw.md](eac_vs_javelin_zh_tw.md)。

---

## 相關的公開討論（未收錄）

| 主題 | 說明 |
|---|---|
| Javelin Journey | 前置研究，已封存：[SOURCES.md](SOURCES.md) |
| bypassing EA Javelin Anticheat | 只有提問、沒有內容，**這裡不收** |

---

## 要注意的事

1. **這裡沒有技術內容**，只有轉述。要技術請看分析那篇。
2. **官方數字不等於事實**，我們沒有能力驗證，也不替它背書。
3. **「不要求」不等於「不檢查」**，理由在上面。
4. 這串目前只有一篇，之後如果有人回報，值得回頭補。

---

## 導航

- 回目錄：[README.md](README.md)
- 技術主文：[javelin_analysis_zh_tw.md](javelin_analysis_zh_tw.md)
- 更新紀錄：[CHANGELOG.md](CHANGELOG.md)
