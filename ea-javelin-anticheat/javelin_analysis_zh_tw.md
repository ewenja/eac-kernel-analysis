# EA Javelin 分析與反虛擬化

> **免責聲明：** 這裡只做安全研究與教育用途。內容整理自公開技術報告，技術敘述以原始報告為準；
> 出處集中在文末「參考資料」。這裡沒有作弊程式，也沒有任何繞過手法。商標歸各自所有者。

---

## 這篇在講什麼

EA 的反作弊叫 **Javelin**（內部簡稱 EAAC）。它的核心不是東檢查一點、西檢查一點，而是把程式碼本身
丟進一台**虛擬機器**裡跑 —— 那套工具叫 **Griffin**，是 EA 自己的虛擬化器。

2026 年 9 月有人把這件事推得很遠：**兩個受保護的模組都拿到手了**，一個在使用者模式、一個在核心模式，
而且把反虛擬化推到相當程度。這篇就是那份工作的整理。

有三點值得記住：

1. **兩份 stub 都到手。** 核心驅動裡直接帶了一份 VM 的明文副本（社群叫它 `stub.dll`）；
   使用者模式那份，是從活著的行程裡抓到**已經解密**的 20 MB 映射。
2. **「什麼時候 dump」是關鍵。** Griffin 只解密當下要跑的部分，用完馬上加密回去。
   在錯的時間點 dump，你拿到的就是一堆亂碼。
3. **反虛擬化是一條還在跑的路。** 作者自己說管線還沒完工，也還沒細看反虛擬化出來的程式碼在做什麼。

---

## 來源

| 項目 | 內容 |
|---|---|
| 主題 | EA Javelin analysis and devirtualization |
| 性質 | 技術研究貼文，含程式碼、位址與檔案雜湊 |
| 發表 | 2026-09-21 |
| 篇幅 | 主文約 71,000 字元，另有 5 則簡短回覆 |
| 原始報告 | <https://www.unknowncheats.me/forum/anti-cheat-research/773123-ea-javelin-analysis-devirtualization.html> |
| 前置研究 | Javelin Journey（2025-09 起連載）與 Mowokuma 的 Griffin Notes（GitHub） |
| 來源 | [SOURCES.md](SOURCES.md) |

> 原文的圖放在 imgur 之類的外部圖床。這裡**不下載、不重散布**，要看請連回原始報告。

---

## 先讀這段：前面那份研究講了什麼

Javelin Journey 從 2025 年 10 月開始連載，用免費的 BF6 Beta 起步，重點有三個：

- **preloader 是手動映射器。** 它把另一個反作弊 DLL 手動塞進行程，呼叫進入點時會傳一個結構進去
  （回覆的人確認那就是 theia 主模組）。
- **字串解密自己做出來之後**，挖到了對外端點與服務字串，例如
  `dev-skyfall.dev.ac.ea.com:443`、`staging-skyfall.dev.ac.ea.com:443`、`eaanticheat.ac.ea.com:443`，
  以及 `EAAntiCheatService`、`Failed retrieving service path.`、`Game service executable missing.`。
- 「skyfall」這個名字後來又出現一次 —— 在驅動的 PDB 路徑裡（後面會看到）。

封存：[SOURCES.md](SOURCES.md)

---

## 它是怎麼被載進去的

整條鏈長這樣：

```
[ Installer ] ──> 放下 preloader_l / preloader_s

[ Launcher exe ] ──> 載入 preloader_l
  [ preloader_l ] ──> 碰到 UD2（0xB030）──> 0x2390 手動映射 [ Launcher DLL ]
    [ Launcher DLL ] ──> 載入 [ cfg payload ]
      [ packer30 0x373D1C ] ──> 19 個 helper ──> CALL 0x413BBD ──> E111 出口
        │ 失敗 ──> [rax+0x68]（preloader 錯誤處理器 0x35B0）顯示 E111000D
        │ 成功 ──> 遊戲 + [ Service / Driver ] 的 attestation
[ Driver（eadriver.sys）] ──> Griffin .grfn + CR3 + hypercall，整條鏈靠它撐住
```

一句話：**驅動才是底**，前面那些東西只是負責把它安全地放進來。

---

## 他們怎麼做的（方法論）

- **人工用 IDA，AI 用 ghidrasql。** 也試過 Qiling 與 WinDbg 搭 VM，但「連 snapshot → dump → 重開」
  太慢，所以驅動沒有鑽得那麼深。
- 作者的機器老、會過熱，長時間跑 hypervisor 玩遊戲不可行。所以策略是**靜態分析 + 短時間的針對性擷取**。
- 反虛擬化是自己寫的 **lift → simplify → emit** 管線，**還沒完工**：跑一次約 4 小時，
  修一個 bug 又要再 4 小時確認。
- 他講了一句很實在的話：**「只有一份 mem dump 對 Griffin 沒用」**，要在不同時間點湊出 corpus。

原報告有一整節在談 LLM 怎麼用：腳本（lifter、symexec）大多是 LLM 寫的，他換到便宜模型繞過資安限制，
也明說**便宜的模型更容易幻覺，很多結論他都得手工複驗**。

---

## 主要發現

### 1. 進入點與開場的把戲

- 被映射的 DLL 進入點會收到一個**魔術參數 `0x25665CD7`**。兩個 preloader 變體在 raw offset `0x27F8`
  都帶著同樣的 5 個位元組（`BA D7 5C 66 25`），呼叫點在 `preloader_l.dll` 的 RVA `0x33F9`–`0x3404`，
  走 `.data:0xA07C` 的間接呼叫。
- **六個 import 全部對得上**前面的研究：`NtTerminateProcess`、`ZwCreateUserProcess`、
  `ZwQueryInformationProcess`、`CallNextHookEx`、`MessageBoxW`、`MD5Init`。
- **UD2 陷阱：** 進入點 RVA `0xB030` 就是兩個位元組 `0F 0B`。unwind handler（RVA `0x2040`）改掉
  `ContextRecord->Rip`，回傳 `ExceptionContinueExecution`，落到 RVA `0x37E2` 的 trampoline，
  再進到位於 `0x2390` 的手動映射器。
- 這份 build 只用了**一個 `VMCALL` 和一個 `VMMCALL`**，不是舊筆記寫的九個／兩個 —— 作者特別註明這個差異。

### 2. 字串加密比想像中簡單

不是什麼複雜方案，就是**單一位元組、一個字串一把 key 的滾動 XOR**，用一小段迴圈解開。
拿 255 個 key 去暴力比對就能乾淨還原，撈到的字串包括
`Security Violation`、`skyfall`、`Pack`、`Javelin`、`DiscordOverlay`、`Virtual Machine`、
`root\cimv2`、`\drivers\etc\hosts`、`Wine`、`Proton`、`Conflicting software`。
（他的字典只有約 1,000 字，所以清單應該還能再長。）

### 3. `EAAntiCheat.cfg` 與 `stub.dll`

- 手上的好幾份 `.cfg` 長得差很多。BF6 那份只是帶兩個 section 的空 DLL，裡面有 `bf6.exe`、`bf6Trial.exe`
  和版本資源 —— 推測是不同時期的設計變更，或上傳的人命名不一致。
- 真正重要的是社群叫 `stub.dll` 的那份：從字串可以認出 **gRPC 1.51.1、Protobuf 3.x 和一個 xDS client**；
  **唯一的 import 是 `preloader_l.dll` 的 ordinal 1**。
- 在他的 stubdll 裡，`.grfn20` 有 **1,391 筆可變長度條目**，用 8 位元組標記
  `78 5c cc 00 88 5c cc 00` 分隔（這是靜置加密狀態下的樣子）。Griffin 各 section 靜置時熵值約 8.0。

### 4. 用 Qiling 模擬，卡在哪裡

在最小的 Windows x64 rootfs 上把 RVA `0xB030` 勾掉、跳過 UD2，然後一路觀察：

- **Wine 探測**：`wine_get_version_` 字串被塞進 XMM6，接著分支。
- ISA 判定用 `RtlWow64GetProcessMachines`；是 ARM64EC 時 `bpl = 1`，走 CHPE 那條路。
- **原子重入鎖**：`lock cmpxchg [rip+7D83h], di`。
- 組路徑：`RtlPcToFileHeader` → 找最後一個反斜線 → 接上 `EAAntiCheat.GameServiceLauncher.dll`
  → `RtlDosPathNameToNtPathName_U_WithStatus`。
- 手動映射前會**檢查版本資源**（`0x50002`／`0x60000` 與 `VS_VERSION_INFO` 魔數 `0xFEEF04BD`）。

最後卡在 RVA `0x25F7` 的 `LdrGetProcedureAddress`：它要用一個 16 位元組雜湊
（`fc2c2433f9a2c47bfcd86944b07b33eb`，來自 `.rdata:0x5360`）查自己的表，模擬器回 null、載入器就拋錯。
作者猜**這裡就是驅動 attestation 進場的地方**。

### 5. Secure Boot 檢查兩次，還有那張 E111 錯誤表

**檢查真的做了兩次：**

1. `NtQuerySystemInformationEx` 的 class `0x91`、`0x92`、`0x162`。
2. **直接讀 `KUSER_SHARED_DATA`**：`0x7FFE0000 + 0x3C8` 的 bit 7（`DbgSecureBootEnabled`），**完全不發 syscall**。

第二種才是重點，因為它**繞過任何 syscall hook**。作者是在模擬器裡把那一位偽造掉再追蹤，才確認這個檢查真的發生。

**E111 錯誤表**在 `preloader_l.dll` 的 RVA `0x6B98`（8 位元組一筆），index `0x0D` 的
「Conflicting software detected!」在 `0x54D0`：

```
 0  0xE1110000  Unexpected error during initialization
 1  0xE1110001  This Operating System version is not supported!
 2  0xE1110002  Windows XP x64 is not supported...
 3  0xE1110003  Windows Vista is not supported...
 5  0xE1110005  Windows 7 is not supported...
 6  0xE1110006  Windows 8 is not supported...
 8  0xE1110008  Windows 8.1 is not supported...
 9  0xE1110009  Windows 10 Beta is not supported...
10  0xE111000A  Your Windows 10 install is too outdated（要 1809 以上）
11  0xE111000B  Wine, Proton, and Steam Deck are not supported by this application!
12  0xE111000C  Invalid version info structure!
13  0xE111000D  Conflicting software detected!
14  0xE111000E  File version mismatch between the preloader and runtime DLLs...
15  0xE111000F  Syscall emulation is disabled in this Wine build...
17  0xE1110011  Windows 10 is not supported...
18  0xE1110012  Windows on ARM is not supported. Please use a x86-64 CPU!
19  0xE1110013  Windows on ARM requires Windows 11 24H2 or later...
```

（4、7、16 是空的。）

**兩個例外值得一提：** `E111000D` 和 `E111000F` **在 preloader 裡找不到任何靜態的產生者** ——
它們不像其他錯誤是寫死的，而是**執行時才算出來的**。
錯誤往上拋的路徑在 `EAAntiCheat.GameServiceLauncher.dll` 的 RVA `0x373E24`，指令是 `FF 50 68`
（`call [rax+0x68]`），`[rax+0x68]` 就是 preloader 的錯誤處理器 `0x35B0`。

### 6. packer30：不用分支就能算出錯誤碼

launcher 的 packer30 dispatcher 在 RVA `0x373D1C`，**一路呼叫 19 個 helper** 才走到錯誤回呼。
作者用記憶體 watchpoint 抓到真正算出 `0xE111000D` 的那段（payload RVA `0xC727C8`）：

```
imul    edx, r9d, 4B2B1C8Fh
mov     qword ptr [rsp+230h], rdx
```

當時 `R9D = 0x168F9FA3`，而 `(0x168F9FA3 × 0x4B2B1C8F) mod 2^32 = 0xE111000D`。
完整的產生器是一段**沒有分支的 MBA（混合布林運算）**，吃三個堆疊輸入 A、B、Y 與常數 K1–K5；
作者把確切的表示式、重播用的數值，以及 U/V/W 被展開成 NAND 的組合都還原了出來。

### 7. 同一份位元組，在兩種 CPU 上都會爆

- 兩個 preloader 都是 **CHPEv2 混合體**：`Machine = 0x8664`，但 `CHPEMetadataPointer` 非零（version 2），
  code map 同時涵蓋兩種指令集。作者用腳本把範圍解出來（IDA 一次只顯示一種）：
  `0x1000–0x184C` 是 ARM64，`0x2000–0x3B76` 是 x64。
- 進入點的 `0xB010`／`0xB030` 位元組**在 x64 解成 UD2、在 ARM64 解成 UDF** ——
  所以**同一個位元組在兩種 CPU 上都會 fault**，例外處理的開場因此跟 CPU 無關。
- 兩種 ISA 各有一份 unwind info：x64 的在 `0x750C`（handler `0x2040`），ARM64 的在 `0x82C4`（handler `0x1060`）。

### 8. 核心驅動：Griffin、CR3，還有一個沒在檢查的 resolver

這一節最長，約 22,000 字元。重點：

- `eadriver.sys` 以 **minifilter、altitude `363250`** 註冊，而且**還帶著 PDB 路徑**：
  `C:\dev\gitlab-runner\builds\yWayJBsk\0\anticheat\skyfall\Build\Retail\EAAntiCheat.Driver.pdb`。
  （這是原始報告裡的內容，不是本機路徑。）
- 驅動由 installer／launcher 載入。作者靠一次失敗的 WPR ETW 追蹤，拿到啟動時序：
  launcher 先起、9 秒後服務起、19 秒後……
- 這節還附了縮寫表（MBA／PFN／IPI／TLB），以及 **resolver** 的分析：
  他自己的副本在 RVA `0x3CFA00`；另一份公開 runtime dump 的 resolver 在 RVA `0x4C8F80`、modulus `9299`。
  標題直接寫 **unchecked resolver**，意思是它少了某些檢查。
- VMCALL／VMMCALL 的數量也和舊筆記不同（這份 build 各一個）。

### 9. 使用者模式：抓到解密的那一份，然後批次反虛擬化

- 反作弊鏈活著的時候，一個**只用 `ReadProcessMemory` 的被動掃描器**發現
  `EAAntiCheat.GameServiceLauncher.exe` 同時持有**同一個模組的兩份 20 MB 映射**：
  一份還是加密的（熵約 8.0），一份是**解密過的**（熵約 3.25）。後面整節都建立在那份低熵的雙胞胎上。
- `.grfn20` 是**每個函式的 (start, end, meta-pointer) 三元組**，作者數到 **5,114 筆**。
  它同時會列出 `.grfn10` 裡每個 16 位元組 slot 與它的 key（實際上是
  `push rbx; movabs rbx, <key>; nop×3; pop rbx; ret` 這種 stub）。meta 指向 `.grfn20` 內的可變長度 payload，
  payload 裡又有 `.text`／`.rdata` 指標對與巢狀三元組 → **看起來是一張 per-slot 的描述子圖**。
- **加密與解密映射的差別，用出現次數就看得出來：**

| 特徵 | 加密那份 | 解密那份 |
|---|---|---|
| `r11` shuttle `4c 8b 9c 24` | 0 | **2,503** |
| `pushfq; lea rsp,[rsp-0x210]` | 0 | 4 |

- **回傳 shuttle：** `pop rbp/rdi/rsi/r12..r15; jmp reg` 這串出現 **449 次**，
  代表虛擬化函式的返回 —— 它從 VM context 還原原生暫存器，再跳回呼叫端的返回位址。

### 10. 反虛擬化之後看到的三個小片段

- **序列化時序檢查**（block `0x111613c`）：先一個 opaque predicate 守衛，再用 `rdtscp` 讀 TSC 並存高位。
- **CPUID 查詢**（block `0x1183bd1`）：查 hypervisor／CPU feature，前後**刻意保存與還原 RCX、RDX**。
- **特權埠 I/O 探測**（block `0x11ab78d`）：`out 0x5D, al` 與 `in eax, dx` ——
  使用者模式直接摸 I/O port，典型的反分析手法。

---

## 他手上那幾份檔案的雜湊

Javelin 每個 patch 都出不同 build，所以作者用 SHA-256 釘住自己的樣本。
**位元組不同，RVA 就會漂移，但形狀應該相似：**

| 檔案 | SHA-256 |
|---|---|
| `preloader_l.dll`（46,840 bytes） | `0f5ff4ef5558ca7fb5678d1f09ff54b0bd2ca50c86c3b69eb7abc3921f2f2172` |
| `EAAntiCheat.GameServiceLauncher.dll` | `195f4933a39f164fcd0e4e0fbbe9fff564412acb12d8da6054f0a80fdee70218` |
| `EAAntiCheat.GameServiceLauncher.exe` | `13f0c760f79b756a17686704b5e5491bcedce2548284eadbbd70392b6b9c6d54` |
| `eadriver.sys`（46,807,424 bytes） | `4a19a78e2e7c41b52fd979b13272b070b765b24c4c15f7b3701d803de1f2098b` |
| `dump_eaanticheat.sys`（公開 runtime dump） | `f6e1c531f104a0cb99cbb1fe04874f87ad378e0f81e12ee147e7965a9d4d6177` |

---

## 跟 EAC 放在一起看

EAC 和 Javelin 常常被混為一談，其實是兩套不同的東西。詳細對照見
[eac_vs_javelin_zh_tw.md](eac_vs_javelin_zh_tw.md)，這裡先講一句：
**EAC 是「一直檢查你」，Javelin 是「讓你看不懂它在幹嘛」。**

---

## 讀這篇要注意的事

1. **這是一個 build 的快照。** 每個 patch 都不同，引用位址前先確認雜湊一致。
2. **反虛擬化管線還沒完工。** 「已經 devirt」不等於「已經看懂」。
3. **AI 參與很深。** 腳本多是 LLM 產生的，作者也提醒便宜模型容易幻覺、很多結論是他手工複驗的。
   所以要引用就引位址和雜湊，不要引句子。
4. **圖不在這裡。** 原文的圖都在 imgur，要看請連回原始報告。
5. **Javelin 不是 EAC 的替代品。** 兩套是不同產品，位址不能互套。

---

## 參考資料

- 資料來源（作者、時間、網址）：[SOURCES.md](SOURCES.md)
- 跨產品對照：[eac_vs_javelin_zh_tw.md](eac_vs_javelin_zh_tw.md)

---

## 導航

- 回目錄：[README.md](README.md)
- 下一章：[apex_migration_zh_tw.md](apex_migration_zh_tw.md)
- 更新紀錄：[CHANGELOG.md](CHANGELOG.md)
