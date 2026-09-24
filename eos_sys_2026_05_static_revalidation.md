# EasyAntiCheat_EOS.sys 靜態重驗證報告

更新日期: `2026-05-10`  
樣本路徑: `C:\Users\<user>\Desktop\EAC\EasyAntiCheat_EOS.sys`

## 目的

本報告針對 `2026-03-11` 版本的 `EasyAntiCheat_EOS.sys` 做一次從 PE 結構、簽章、入口流程、保護節區與少量關鍵控制流開始的靜態重驗證。  
這份版本只保留已由工具直接驗證的事實，避免把前期筆記中的推測混入結論。

## 工具與驗證來源

- `rabin2 6.1.4`
- `radare2 6.1.4`
- `llvm-readobj 18.1.8`
- PowerShell `Get-FileHash`
- PowerShell `Get-AuthenticodeSignature`
- PowerShell `System.Diagnostics.FileVersionInfo`

## 研究環境校驗

這一輪先確認工具鏈不是舊版殘留，再進行重驗證，避免把解析異常誤判成樣本特性。

| 項目 | 值 |
|---|---|
| 工作日期 | `2026-05-10` |
| 樣本位置 | `C:\Users\<user>\Desktop\EAC\EasyAntiCheat_EOS.sys` |
| `radare2 -v` | `6.1.4` |
| `rabin2 -v` | `6.1.4` |
| `llvm-readobj --version` | `18.1.8` |

本節的目的不是增加技術結論，而是把「不是因為 LLVM 太舊造成誤讀」這件事明確寫進報告。

## 樣本識別

| 欄位 | 值 |
|---|---|
| SHA256 | `A423D526F8C680DE7D117719B3479DDD47F9D57DD46BA5B0DA284E066422D61F` |
| 檔案大小 | `39,142,928` bytes |
| TimeDateStamp | `2026-03-11 09:46:43 UTC` |
| FileVersionRaw | `3.2.0.0` |
| ProductVersionRaw | `3.2.0.0` |
| 類型 | `PE32+ / AMD64 / Native subsystem` |
| PDB | `Core.pdb` |
| 簽章狀態 | `Valid` |

## Authenticode 驗證

PowerShell `Get-AuthenticodeSignature` 顯示:

- Signer Subject: `CN=EasyAntiCheat Oy, O=EasyAntiCheat Oy`
- Issuer: `GlobalSign GCC R45 EV CodeSigning CA 2020`
- Timestamp Subject: `DigiCert SHA256 RSA4096 Timestamp Responder 2025 1`
- Status: `Valid`

這代表目前樣本不是隨手拼接出的未簽章測試驅動，而是正式簽署的 production driver 映像。

## PE / COFF 基本結構

`llvm-readobj --file-headers --sections --coff-imports` 可驗證以下事實:

- Machine: `IMAGE_FILE_MACHINE_AMD64`
- EntryPoint RVA: `0x17E150`
- ImageBase: `0x140000000`
- SizeOfImage: `0x25BE000` (`39,579,648`)
- SectionCount: `9`
- Subsystem: `IMAGE_SUBSYSTEM_NATIVE`
- DLL Characteristics:
  - `IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA`
  - `IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE`
  - `IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY`
  - `IMAGE_DLL_CHARACTERISTICS_NX_COMPAT`

這些欄位與一個正常載入於核心態的 x64 驅動一致，沒有顯示出手工改壞 Header 的跡象。

## Import Surface

本樣本的 import surface 極小，經 `llvm-readobj` 與 `rabin2 -I` 一致確認僅有兩個導入符號:

- `FLTMGR.SYS!FltRegisterFilter`
- `ntoskrnl.exe!__chkstk`

這是本樣本最重要的靜態特徵之一。  
驅動沒有大量直接匯入一般核心 API，而是把解析與分派邏輯藏在映像內部，這與大型 dispatcher / resolver / 虛擬化樣式相符。

## Section 佈局

| Section | RVA | RawSize | VirtualSize | 權限 | 備註 |
|---|---:|---:|---:|---|---|
| `.text` | `0x1000` | `0x17D400` | `0x17D242` | `R-X` | 一般程式碼區 |
| `.rdata` | `0x17F000` | `0x8E000` | `0x8DFB8` | `R--` | IAT / load config / 常數 |
| `.data` | `0x20D000` | `0xB600` | `0x7618D` | `RW-` | 全域狀態 |
| unnamed (`sect_3`) | `0x284000` | `0x6600` | `0x6438` | `R--` | 額外資料區 |
| `.rsrc` | `0x28B000` | `0x400` | `0x330` | `R--` | 資源 |
| `.reloc` | `0x28C000` | `0xA00` | `0x990` | `R--` | 重定位 |
| unnamed (`sect_6`) | `0x28D000` | `0x2800` | `0x2800` | `R-X` | 小型執行區 |
| unnamed (`sect_7`) | `0x290000` | `0x2322800` | `0x2323000` | `R-X` | 超大型執行區 |
| `.pdata` | `0x25B3000` | `0xBC00` | `0xC000` | `R--` | x64 unwind / function table |

### 重點觀察

1. `sect_7` 佔用 `0x2322800` bytes，遠大於正常驅動中的單一輔助節區。
2. `sect_6` 雖然只有 `0x2800` bytes，但確實包含可執行程式碼與硬體指令。
3. 多個節區名稱刻意留空，這本身就是降低可讀性的保護訊號。

## `.pdata` / Exception Table 取樣

這一輪額外直接取樣 `.pdata` 對應的 exception table，而不是只靠反組譯器自動切函式。  
理由很簡單: `llvm-readobj --unwind` 在這份樣本上會崩潰，因此不能把單一工具的 unwind 顯示當成唯一依據。

基於 PE header 已驗證的 exception table 位置:

- ExceptionTable RVA: `0x25B3000`
- ExceptionTable Size: `0xBBE0`
- Runtime function entry count: `4008`

其中可直接確認:

- 落在 `sect_7` 範圍內的 runtime function entry 至少有 `2731` 個
- 這批 entry 的可見覆蓋範圍約從 `0x14029029D` 延伸到 `0x14032C442`
- `sect_6` 範圍內沒有對應的 runtime function entry

這三點很重要，因為它們把兩個保護節區的性質區分得更清楚:

- `sect_7` 雖然巨大且高度混淆，但仍保留大量可被 Windows x64 例外機制識別的函式邊界
- `sect_6` 則更像刻意不提供正常 unwind metadata 的輔助執行區

因此在後續報告裡，不能把 `sect_6` 和 `sect_7` 一概而論成同一種「殼區」。

## 入口流程重驗證

`radare2` 對 `entry0` 的反組譯結果如下:

- `0x14017E150` 保存 `rbx/rdi`
- `0x14017E160` 呼叫 `0x14017E17C`
- `0x14017E16B` 呼叫 `0x1400A5C00`

### `0x14017E17C`: security cookie 初始化

此函式會:

- 讀取 `[0x14020D030]`
- 與常數 `0x2B992DDFA232` 比較
- 若值為 `0` 或等於該常數，走 `int 0x29`
- 否則把 `not(cookie)` 寫入 `[0x14020D038]`

這不是推測，而是可直接從下列指令看出:

- `0x14017E17C mov rax, [0x14020D030]`
- `0x14017E188 movabs rcx, 0x2B992DDFA232`
- `0x14017E197 not rax`
- `0x14017E19A mov [0x14020D038], rax`
- `0x14017E1A8 int 0x29`

結論: 入口前置流程確實包含 cookie 驗證與 fail-fast。

### `0x1400A5C00`: 純 trampoline

`0x1400A5C00` 本身只做一件事:

- `jmp 0x1402E9770`

因此它不是實際初始化主體，而是把控制流再導向下一個 dispatcher / wrapper 層。

## `sect_7` 重驗證

`0x140290000` 為 `sect_7` 開頭的關鍵函式。  
從前 0x100 多 bytes 可以明確確認:

- 保存大量 GP 暫存器到 stack frame
- 保存多個 XMM 暫存器
- 以 `pushfq / pop rax` 方式保存 `RFLAGS`
- 把 `r12` 指向一個大型 frame
- 呼叫 `0x14029010B`

對應的關鍵指令包括:

- `0x140290005 movups [rsp+...], xmm1`
- `0x1402900A1 pushfq`
- `0x1402900D6 call 0x14029010B`
- `0x140290105 lea r12, [rsp+8]`

`0x14029010B` 則把 `rbx + 0xFFFFFFFFFFD6914D` 的結果寫到 frame 某欄位，顯示這個 wrapper 還夾帶了位址轉換或偏移混淆。

### 對 `sect_7` 的結論

可驗證的最低風險結論是:

- `sect_7` 不是單純資料節區。
- 它包含大規模 context save / restore wrapper。
- 該 wrapper 很可能是內部 dispatcher、虛擬機入口或保護層呼叫慣例的一部分。
- `.pdata` 顯示 `sect_7` 內至少還有數千個可被例外表識別的子函式，而不是只有單一巨型 blob。

目前還不能只靠這一段就斷言完整虛擬機 ISA，但已足夠證明它不是一般 MSVC 生成的正常函式前言。

## `sect_7` 小函式群分型

在 `.pdata` 已確認 `sect_7` 內含大量 runtime function entry 之後，這一輪再往前抽樣前段與尾段函式，目的是判斷它們是否只是雜亂碎片，還是有穩定模板。

### 長度分布

就目前從 exception table 萃出的 `2731` 個 `sect_7` runtime function entry 來看，長度高度集中在少數幾種尺寸:

- `0x3C`: `701` 個
- `0x3A`: `488` 個
- `0x34`: `462` 個
- `0x4D`: `432` 個
- `0x32`: `418` 個
- `0x31`: `97` 個
- `0x39`: `66` 個

這個分布很不像一般編譯器自然生成、大小各異的大量業務函式，反而更像一批反覆套用模板產生的微型 stub。

### 可直接驗證的模板例子

前段樣本可見:

- `0x14029029D-0x1402902CF` (`len=0x32`)
  - 從 `[rsp+0x190]` 取指標
  - 讀取 `byte [rax]`
  - 把結果寫回 frame
- `0x1402902FC-0x140290336` (`len=0x3A`)
  - 從 `[rsp+0x190]` 取指標
  - 讀取 `dword [rax]`
  - 把結果寫回 frame
- `0x1402906C7-0x140290703` (`len=0x3C`)
  - 從 `[rsp+0x190]` 取目標位址
  - 從 `[rsp+0x198]` 取來源值
  - 執行 `mov qword [rax], rbx`

尾段樣本也重複相同風格:

- `0x14032BF5C-0x14032BF98` (`len=0x3C`)
  - 取 `[rsp+0x170]`
  - 寫入 `qword [rax]`
- `0x14032BFD8-0x14032C014` (`len=0x3C`)
  - 取 `qword [rax]`
  - 回填到 frame

再往下抽樣後，還能把其他高頻長度補得更具體:

- `0x140290D0B-0x140290D3F` (`len=0x34`)
  - `rbp = [rsp+0x198]`
  - `rax = [rsp+0x190]`
  - `mov rax, [rax]`
  - 把 `qword` 結果寫回 `[rsp+0x190]`
  - 把 `[rsp+0x198]` 歸零後 `jmp rbp`
- `0x14029510B-0x14029513F` (`len=0x34`)
  - `rbp = [rsp+0x1A0]`
  - `rax = [rsp+0x190]`
  - `rbx = [rsp+0x198]`
  - `mov [rax], rbx`
  - 把 `[rsp+0x190]` 歸零後 `jmp rbp`
- `0x140291F37-0x140291F68` (`len=0x31`)
  - `rbp = [rsp+0x198]`
  - `rax = [rsp+0x190]`
  - `movups xmm1, [rsp+0x20]`
  - `movups [rax], xmm1`
  - 把 `[rsp+0x190]` 歸零後 `jmp rbp`
- `0x140294DBC-0x140294DF5` (`len=0x39`)
  - `rbp = [rsp+0x198]`
  - `rax = [rsp+0x190]`
  - `movups xmm1, [rsp+8]`
  - `movups [rax], xmm1`
  - 把 `[rsp+0x198]` 歸零，並把 `rax` 回寫到 `[rsp+0x190]`，再 `jmp rbp`
- `0x140290622-0x14029066F` (`len=0x4D`)
  - 先 `call 0x140290128`
  - 把 `rsp` 暫時還原，經由 `[rsp+8]` 做一次間接 `call`
  - 再次把 `rsp` 拉回保護 frame
  - 將 `[rsp+0x190]` 設成 `0` 或 `1`
  - `call 0x1402904FA`
  - 最後 `jmp` 到內部目標
- `0x1402920B5-0x140292102` (`len=0x4D`)
  - 與上例同型
  - 只差 tail jump 的真正落點不同，這裡跳到 `0x1417B2F02`

### 目前可成立的次級分組

目前至少可以把高頻尺寸拆成下列幾類:

- `0x32`
  - 窄寬度 load stub
  - 已直接驗證 `byte` 讀取變體
- `0x3A`
  - 中等寬度 load stub
  - 已直接驗證 `dword` 讀取變體
- `0x34`
  - 單一 `qword` 搬移 stub
  - 同尺寸下同時存在 load 與 store 變體，只是 continuation slot 不同
- `0x3C`
  - `qword` 級 accessor / store family
  - 目前已看到多個前後段重複的 store / load 樣式
- `0x31` / `0x39`
  - `movups` 風格的 128-bit store family
  - 差異主要在來源 spill slot 與是否保留目的指標回填到 frame
- `0x4D`
  - wrapper-bridged route / result builder
  - 這類 stub 會暫離 `sect_7` 保護 frame 呼叫外部目標，再把結果重新編碼進 frame 後跳往下一個內部落點

### `cmp/test` 類樣本目前的保守結論

這一輪另外用 `llvm-objdump -D` 直接掃過 `0x14029029D -> 0x14032C442` 這段可見 `sect_7` runtime-function 區間。  
目前找到的早段 `test/cmp` 樣本，主要落在:

- `0x1402903F6 test rax, rax`
- `0x140290421 cmp rcx, rdi`
- `0x140290A02 test rax, rax`
- `0x140290A2D cmp rcx, rdi`

但把前後文拉開後，可以確認這兩段更像:

- 依 `rax` 正負決定正向或反向複製
- 以 `movups` 迴圈搬移 `r12` frame 內容到目標位址
- 最後 `jmp rbx`

也就是說，這些 `cmp/test` 並不是高語意的 decision stub，而更像 frame-copy / frame-relocation helper 的分支控制。  
因此目前還不應把它們直接算進「compare/test micro-op family」。

### 目前最穩妥的解讀

這批函式更像是 frame-based micro-ops:

- 小型 load / store accessor
- state slot 搬移器
- 在 `fcn.140290000` / `fcn.140290128` 包裝下執行的受保護子操作

因此現在可以更具體地說:

- `sect_7` 不是只有一個大 dispatcher
- 它還包含大量尺寸固定、語意狹窄、重複模板化的微操作函式群

但仍然不該直接把它們命名成完整 VM ISA 指令集，因為目前只證明了「模板化 accessor / state transform 行為」，還沒有完整的 opcode 映射。

## `0x1402E9770` 分派樞紐

接在 `entry0 -> 0x1400A5C00` 後面的 `0x1402E9770`，這一輪已可確認不是單純中繼，而是高頻率使用 `sect_7` frame 的 dispatcher hub。

### 已驗證行為

- 開頭先用 `lea rsp, [rsp-0x1c0]` 建立大型暫存區
- 立即 `call 0x140290000`，也就是再次進入 `sect_7` context wrapper
- 隨後依不同路徑 `jmp` 到 `0x141694ACC`、`0x141694AED`、`0x141694B0E`、`0x141694B2F`、`0x141694B50`、`0x141694B71` 等多個子路由
- 若需要離開保護包裝，會呼叫 `0x140290128`，再把 `rsp` 調回，之後再經由 `[rsp+8]` 的保存目標做 `call`
- 多個分支會把結果寫回 `rsp+0x190`、`rsp+0x198`、`rsp+0x1A0` 之類欄位，再 `jmp rbp`

這表示 `0x1402E9770` 是一個以固定 frame 佈局為核心的控制流中樞，而不是一般函式呼叫鏈。

### 可直接引用的指令特徵

- `0x1402E9770 lea rsp, [rsp-0x1c0]`
- `0x1402E9778 call 0x140290000`
- `0x1402E977D jmp 0x141694ACC`
- `0x1402E9782 call 0x140290128`
- `0x1402E978F call qword [rsp+8]`
- `0x1402E9819 jmp 0x141694B71`

## `0x141694ACC` 到 `0x141694B50`

這幾個目標點的樣式非常一致:

- 先把一個 64-bit 常數寫到 `r12` frame 中
- 再取一個小的正整數偏移
- 用 `add rax, [r12+0x150]`
- 以 `jmp rax` 跳到真正目標

例如:

- `0x141694ACC`
  - 常數 `0x1225275646B765E1` -> `[r12+0x190]`
  - 偏移 `0x31B0AE` + `[r12+0x150]`
- `0x141694AED`
  - 常數 `0x646391EB2E568D25` -> `[r12+0x190]`
  - 偏移 `0x3140DB` + `[r12+0x150]`
- `0x141694B0E`
  - 常數 `0xB5DCB96F0CC50FD7` -> `[r12+0x1A0]`
  - 偏移 `0x2ABF6D` + `[r12+0x150]`
- `0x141694B2F`
  - 常數 `0x66481D98FAD14C9D` -> `[r12+0x190]`
  - 偏移 `0x2BBD9E` + `[r12+0x150]`
- `0x141694B50`
  - 常數 `0xA32EDD16DC80187D` -> `[r12+0x190]`
  - 偏移 `0x2DFE32` + `[r12+0x150]`

### 這代表什麼

目前最穩妥的說法是:

- 這些點是「路由前置器」或「目標建構器」
- 它們不直接執行完整功能，而是利用 frame 狀態與 `[r12+0x150]` 的基底位址推導真正跳轉目標
- 多數路由器把 64-bit 常數寫入 `[r12+0x190]`，但 `0x141694B0E` 這條明確改寫的是 `[r12+0x1A0]`
- 這代表相同的 jump-builder 模板下，仍存在至少兩種 frame-slot 變體，而不是所有子路由都消費同一個狀態欄位

## `0x141694B71` 的特徵

`0x141694B71` 與前面幾個 `jmp-builder` 不同，它本身就是一個較大的運算子流程。

### 已驗證事實

- 進入時讀取 `r12` frame 中的多個欄位:
  - `[r12+0x198]`
  - `[r12+0x30]`
  - `[r12+0x88]`
  - `[r12+0x150]`
  - 後續還會讀取更深的結構欄位，如 `[rdx+0xA8]`
- 使用大量固定 64-bit 常數混合:
  - `imul`
  - `xor`
  - `shr`
  - `seta`
  - `setb`
  - `sete`
  - `or`
  - `sub`
- 會把布林判斷結果與中間值暫存在本地 stack slot

更具體地說，前半段已可直接看到多組比較與條件位元建構:

- `0x141694B8E cmp rax, r13` 後接 `0x141694B91 seta r8b`
- `0x141694BB3 cmp rcx, r13` 後接 `0x141694BB6 setb sil`
- `0x141694BCC cmp rcx, r13` 後接 `0x141694BCF seta r15b`
- `0x141694BF2 cmp rcx, r13` 後接 `0x141694BF5 seta bpl`
- `0x141694D4C cmp rdx, rcx` 後接 `0x141694D4F sete al`
- `0x141694D57 setne [rsp+7]`
- `0x141694F32 cmp rax, rcx` 後接 `0x141694F35 sete bl`
- `0x141695071 cmp rdx, rax` 後接 `0x1416950B9 sete dil`

這讓 `0x141694B71` 的定位可以再更精確一點:

- 它不是單純的數值混合器
- 它明確包含 compare/decision construction
- 而且這些 decision bit 會被後續 `or` / `and` / `imul` 鏈拿去參與 state 更新

### 較保守的結論

這段更像是:

- frame-driven state transformer
- 或帶條件分支的目標 / 金鑰 / 索引推導器

目前還不能只靠這一段就精確命名其業務功能，但可以確認它不是普通的資料搬移 stub，而是實際參與控制流決策與數值混合的主體邏輯。

### 新增觀察: 會下鑽到次級結構體

從 `0x141694B71` 後半段可再確認一件事: 它不只操作 `r12` frame，本身還會沿著 frame 中的指標去處理更深一層的結構。

已驗證到的欄位讀取包括:

- 先取 `rbx = [rsp+0x68]`，其來源是先前保存的 `r12`
- 然後讀:
  - `[rbx+0x70]`
  - `[rbx+0xB0]`
  - `[rbx+0xC8]`
  - `[rbx+0xD0]`
  - `[rbx+0x170]`
  - `[rbx+0x190]`

接著可直接看到兩個就地寫回:

- `0x1416950E2 mov [rbx], r15`
- `0x14169513A mov [rbx+0x30], r15`

再往後看，這個 state block 的寫回集合比前一版記錄得更大:

- `0x14169514C mov [rbx+0x58], r8`
- `0x1416951AC mov [rbx+0x70], r8`
- `0x141695233 mov [rbx+0x88], r8`
- `0x14169529A mov [rbx+0xC8], rdx`
- `0x1416952BA mov [rbx+0x170], rax`
- `0x1416952E6 mov [rbx+0x190], rdx`
- `0x1416952F7 mov [rbx+0x198], 0x230B796219F71C67`

### 這代表什麼

這讓我們可以把描述再往前推一點:

- `0x141694B71` 不只是純計算器
- 它會消費一個由 frame 指到的 state block
- 並且把混合運算後的結果寫回該 block 的多個欄位，而不是只有兩個 slot
- 從目前可見寫回範圍來看，它至少會更新:
  - base field `0x00`
  - `0x30`
  - `0x58`
  - `0x70`
  - `0x88`
  - `0xC8`
  - `0x170`
  - `0x190`
  - `0x198`

因此比起單純的「索引推導器」，它更像是:

- state mutator
- context transformer
- 或受保護的子分派前置邏輯

目前仍不足以精確命名每個欄位的語意，但「有讀有寫、而且是就地更新」這點已經成立。

## `0x1416953C5` 的特徵

`0x1416953C5` 緊接在 `0x141694B71` 之後，從目前靜態形狀來看，它不是單純延續前一段的常數混合，而是更偏向 bit-sliced recomposition 的運算子流程。

### 已驗證事實

- 開頭直接消費 `r12` frame 的既有結果:
  - `[r12+0x88]`
  - `[r12+0x190]`
  - `[r12+0x170]`
  - `[r12+0x150]`
- 進入早期就有多組 threshold compare:
  - `0x1416953F5 cmp r13, 0x665BCCF87D4C35AC`
  - `0x141695409 cmp r13, 0xF37F6D97E1A1010B`
  - `0x141695428 cmp r13, 0x665BCCF87D4C35AB`
  - `0x14169543F cmp r13, 0x146C4AAD1E12E427`
  - `0x14169544F cmp r13, 0x146C4AAD1E12E428`
  - `0x14169545F cmp r13, 0x55F1A0198FD74F7D`
- 這些比較會建出多個 decision bit / flag slot:
  - `setb [rsp+3]`
  - `seta cl` 後存到 `[rsp+0x58]`
  - `seta cl` 後存到 `[rsp+0x50]`
  - `seta al`
  - `setb cl`
  - `seta bpl`

### 與 `0x141694B71` 不同的地方

`0x141694B71` 比較像「先比較、再把 bit decision 混入 state」。  
而 `0x1416953C5` 則進一步出現很明顯的固定寬度欄位切割與重組:

- 大量遮罩:
  - `0x7FFFFF`
  - `0x1FFFFFF`
  - `0x7FFFFFF`
- 大量位移:
  - `shr 0x17`
  - `shr 0x18`
  - `shr 0x19`
  - `shr 0x1B`
  - `shr 0x2E`
  - `shr 0x31`
  - `shr 0x32`
  - `shr 0x36`
- 並搭配:
  - `seta`
  - `sete`
  - `adcl`
  - `neg`
  - `and/or`
  - 多段 `imul`

尤其下面這些片段很有代表性:

- `0x14169549D and r11d, 0x7FFFFF`
- `0x1416954A8 and r9d, 0x7FFFFF`
- `0x1416954C0 and r15d, 0x7FFFFF`
- `0x1416957AE and edi, 0x1FFFFFF`
- `0x1416957B4 and esi, 0x1FFFFFF`
- `0x141695816 and r12d, 0x1FFFFFF`
- `0x141695844 and r14d, 0x7FFFFFF`
- `0x1416958D4 adcl r8d, ecx`
- `0x14169591B sete cl`

這些特徵合在一起，比較像:

- 把較大的整數 state 拆成固定寬度 limb
- 在 limb 之間傳遞 carry / borrow 類資訊
- 再把結果重新封裝回新的 state word

### 目前最穩妥的解讀

現在比較安全的寫法是:

- `0x1416953C5` 是 compare-driven、bit-sliced 的 state recomposition 流程
- 它承接 `0x141694B71` 先前算出的欄位，再做更細的欄位切分與重組
- 它不像單純 branch-builder，也不像一般 accessor stub
- 但目前仍不足以只靠靜態形狀就把它直接命名成某個特定加密、雜湊或大數演算法實作

因此這段最適合先標成:

- protected arithmetic / limb-recomposition stage
- 或 compare-assisted state normalizer

### 尾端落點與寫回行為

把 `0x1416953C5` 往後拉完整之後，現在還能再確認兩件重要事情。

第一，它不是算完就結束，而是會先更新多個 `r12` state 欄位:

- `0x141695EDB mov [r12+0x70], r9`
- `0x141695FCF mov [r12+0x88], rcx`
- `0x141695FFE mov [r12+0xB0], rax`
- `0x141696010 mov [r12+0x190], 0x3DF082C9A4D460FD`

第二，尾端不是一般 `ret`，而是重新建出一個目標位址後直接跳轉:

- `0x141696045 add rsi, [rsp+0xA8]`
- `0x14169604D add rsp, 0xB8`
- `0x141696054 pop rbp`
- `0x141696055 jmp rsi`

而緊接著可見的下一個可辨識落點就是:

- `0x141696057`
  - 新的函式前言 `push rbp / sub rsp, 0xB8`
  - 直接讀 `[r12+0x88]` 與 `[r12+0x198]`
  - 立即進入另一組 `cmp + setb/seta` decision construction

這代表 `0x1416953C5` 不是孤立的大數樣式函式，而是:

- 先做 bit-sliced recomposition
- 再把結果回填進共享 state
- 再透過內部計算出的目標位址，尾跳到下一個 compare-heavy stage

因此目前可以把 `0x141694B71 -> 0x1416953C5 -> 0x141696057` 看成一段連續的受保護 state-processing pipeline，而不是三個彼此無關的大函式。

## `0x141696057` 的特徵

`0x141696057` 是前述 pipeline 的下一個明顯 stage。  
它延續了 compare-heavy + stateful 的風格，但內部結構又比 `0x1416953C5` 再分得更細。

### 已驗證事實

- 開頭直接讀取前段剛留下的 state:
  - `[r12+0x88]`
  - `[r12+0x198]`
- 一開始就有一組新的 threshold compare:
  - `0x141696079 cmp rbx, 0x9130237481109080`
  - `0x14169608B cmp rbx, 0x913023748110907F`
  - 對應 `setb [rsp+7]` 與 `seta cl`
- 中段先進入另一輪 hash / mixer 樣式的數值混合，但之後很快切到固定寬度 limb 操作

### 新的固定寬度欄位特徵

這一段最顯眼的變化，是欄位寬度不再是 `0x1416953C5` 裡那種 `23/25/27-bit` 組合，而是轉成新的 slicing 規律:

- `0x141696209 and r11d, 0x0FFFFFFF`
- `0x141696212 and esi, 0x0FFFFFFF`
- `0x141696235 and ecx, 0x0FFFFFFF`
- `0x141696241 test r9d, 0x0FFFFFFF`
- `0x141696279 and r11d, 0x0FFFFFFF`
- `0x1416962A1 test r10d, 0x0FFFFFFF`

並且搭配:

- `shr 0x1C`
- `shr 0x38`
- `seta`
- `sete`
- `and/or`
- limb 間的加總與 carry-like 修正

因此目前可以把這一塊保守描述成:

- 28-bit limb recomposition / normalization stage

### 後半段的新訊號: byte / sub-byte 級處理

和 `0x1416953C5` 相比，`0x141696057` 還多了一個更細的後半段，會明顯消費較小寬度欄位:

- 讀取多個 state 欄位與 byte-sized 值:
  - `[r12+0x18]` as byte
  - `[r12+0x30]`
  - `[r12+0x58]`
  - `[r12+0x70]`
  - `[r12+0x90]` as byte
  - `[r12+0xC8]` as byte
  - `[r12+0xD0]`
  - `[r12+0x150]`
  - `[r12+0x158]`
  - `[r12+0x190]`
- 可直接看到一組 `16-bit -> 6-bit` 風格的拆解與進位判斷:
  - `movzwl (%rsi), edx`
  - `shr esi, 0xC`
  - `shr r9d, 0x6`
  - `and sil, 0x3F`
  - `and al, 0x3F`
  - `cmp bpl, al`
  - `test r14b, 0x3F`
  - `and r12b, 0x3F`

這表示 `0x141696057` 不只是沿用前一段的大欄位重組，它還會再下鑽到 byte / 6-bit 級別去組裝更細的 decision / state 值。

### 目前最穩妥的解讀

對 `0x141696057`，現在最安全的描述是:

- 它是 `0x1416953C5` 後續的另一個 protected state-processing stage
- 前半段偏 28-bit limb recomposition
- 後半段則引入 byte / 6-bit 級的細粒度 decision 與資料重組
- 它不像單一演算法的直白實作，反而更像內部 state pipeline 中的多層 normalization / transformation 節點

因此到目前為止，這條鏈可以再更精確地寫成:

- `0x141694B71`
  - compare-driven state mutator
- `0x1416953C5`
  - bit-sliced recomposition / protected arithmetic stage
- `0x141696057`
  - 28-bit limb recomposition + byte/6-bit sub-stage

### 尾端寫回與下一個 route-builder

把 `0x141696057` 再往後拉完整之後，現在可以再確認它不是只做中間態整理，而是會實際回寫共享 state，再跳到下一個內部路由點。

先看已驗證寫回:

- `0x141696CFD mov [rcx+0x58], rsi`
- `0x141696D17 mov [rcx+0x70], rax`
- `0x141696E37 mov [r12+0x88], rax`
- `0x141696E8B mov [r12+0xD0], rax`
- `0x141696F3C mov [r12+0x190], rcx`

其中 `rcx` 在 `0x141696CF8` 來自先前保存的 `[rsp+0x50]`，而那個值是 `0x141696308 mov [rsp+0x50], r12` 保存下來的 state 基底指標。  
也就是說，這些寫回仍然是對同一個共享 state block 就地更新，而不是寫往臨時 scratch 區。

尾端控制流也已可直接確認:

- `0x141696F57 xor rax, 0x3218FD`
- `0x141696F5D add rax, [rsp+0x60]`
- `0x141696F6A jmp rax`

而 `[rsp+0x60]` 在前面是由 `0x141696361 mov rax, [r12+0x150]` / `0x141696369 mov [rsp+0x60], rax` 保存下來。  
因此這裡仍然符合目前對整條鏈的既有理解:

- 先更新 state
- 再以固定偏移加上 `[r12+0x150]` 基底位址建出下一個內部目標
- 最後用 `jmp` 直接進入後續 stage

### `0x141696F6C`: route-builder

`0x141696F6C` 本身不是新的大型運算函式，而是另一個短小的路由前置器:

- `0x141696F6C movabs rax, 0xF46285DD5D8A16FB`
- `0x141696F76 mov [r12+0x198], rax`
- `0x141696F7E mov eax, 0x2DBE59`
- `0x141696F83 add rax, [r12+0x150]`
- `0x141696F8B jmp rax`

這和先前 `0x141694ACC` 到 `0x141694B50` 那批 jump-builder 家族非常接近，只是這次改寫的是:

- `[r12+0x198]`

而不是前面較常見的 `[r12+0x190]` 或少數變體的 `[r12+0x1A0]`。  
因此目前最穩妥的寫法是:

- `0x141696F6C` 是 pipeline 後續可見的另一個 route-builder
- 它把新的 64-bit 常數塞進 `[r12+0x198]`
- 再以偏移 `0x2DBE59` 配合 `[r12+0x150]` 跳往下一個運算 stage

### `0x141696F8D`: 下一個 compare-heavy stage

`0x141696F6C` 之後可直接落到的下一個大函式是 `0x141696F8D`。  
就目前只看前段，也已能驗證它延續了同樣的設計語言:

- 有新的函式前言 `push rbp / sub rsp, 0x1C8`
- 一開始就消費:
  - `[r12+0x88]`
  - `[r12+0x190]`
  - `[r12+0xD0]`
- 開頭立即出現多組新的 threshold compare:
  - `0x141696FC3 cmp r14, 0xC74B1E8B86091DA0`
  - `0x141696FDB cmp r14, 0x8306803476B856C4`
  - `0x141696FF2 cmp r14, 0xC74B1E8B86091D9F`
  - `0x141697007 cmp r14, 0x3CE4914736332E65`
  - `0x141697017 cmp r14, 0x3CE4914736332E66`
  - `0x141697029 cmp r14, 0x8306803476B856C3`
- 對應可見的 `setb/seta` decision construction:
  - `setb cl`
  - `setb [rsp+0xC8]`
  - `seta cl`
  - `seta dl`
  - `setb cl`
  - `seta sil`

因此目前至少可以安全地把 pipeline 再往後接成:

- `0x141694B71`
  - compare-driven state mutator
- `0x1416953C5`
  - bit-sliced recomposition / protected arithmetic stage
- `0x141696057`
  - 28-bit limb recomposition + byte/6-bit sub-stage
- `0x141696F6C`
  - route-builder，改寫 `[r12+0x198]`
- `0x141696F8D`
  - 下一個 compare-heavy state-processing stage

### `0x141696F8D` 的多寬度 limb 特徵

把 `0x141696F8D` 往中後段拉開後，現在可以更清楚地看到它不是單一寬度的重組流程，而是至少包含兩層不同欄位寬度的 state normalization。

先看前一層，可直接驗證的遮罩與位移包括:

- `0x1416973F1 and eax, 0x7FFFFFF`
- `0x141697421 and esi, 0x7FFFFFF`
- `0x14169743D and eax, 0x7FFFFFF`
- `0x14169745A and ecx, 0x7FFFFFF`
- `0x141697509 and r9d, 0x7FFFFFF`
- `0x141697537 shrl 0x1B`
- `0x141697560 shrl 0x11`
- `0x1416975A9 shll 0x12`
- `0x1416975AE shrq 0x23`
- `0x14169753A shrdq 0x36`

同時又可見:

- `0x1416973D7 movabs rbp, 0xFFFFFFFFF`
- `0x1416974B9 shrq 0x24`
- `0x14169761A movabs rsi, 0xFFFFFFFFF`

這代表前半段不是單純的 `27-bit` limb 鏈，而是把:

- `27-bit` 切片 (`0x7FFFFFF`, `shr 0x1B`)
- `36-bit` 邊界 (`0xFFFFFFFFF`, `shr 0x24`)

混在一起做跨欄位重組與 carry-like 修正。

再往後一層，`0x14169821D` 之後又切進更窄的子階段:

- `0x14169821F and edx, 0x3FFFF`
- `0x14169823C and edi, 0x3FFFF`
- `0x141698258 shrq 0x12`
- `0x14169831B shrl 0x12`
- `0x1416983AF and eax, 0xFFC0000`
- `0x1416983B4 shrl 0x12`

因此目前最保守、但也最貼近靜態證據的描述是:

- `0x141696F8D` 是 mixed-width limb recomposition stage
- 前半段明顯混合 `27-bit` 與 `36-bit` 邊界
- 後半段再下鑽到 `18-bit` 子欄位重組

### `0x141696F8D` 已驗證 state 寫回

這段不像只在 stack 上暫存，後半段可直接看到它把結果批次寫回共享 state block。  
目前已直接驗證的寫回包括:

- `0x141698103 mov [rax], rsi`
  - 其中 `rax` 來自 `0x141697180 mov [rsp+0x180], rbx`
  - 而 `rbx` 來自 `0x14169713F xor rbx, r8`
  - 這顯示它會透過 state 內部保存的指標做一次間接寫回
- `0x141698123 mov [rax], rcx`
  - `rax` 來自 `0x14169739B mov [rsp+0xD8], rcx`
  - 同樣屬於透過已保存目標位址做的間接寫回
- `0x1416984F0 mov [r12], rax`
- `0x1416984FC mov [r12+0x58], rax`
- `0x141698509 mov [r12+0x70], rax`
- `0x14169856B mov [r12+0x88], rdx`
- `0x1416985AD mov [r12+0xA8], rdx`
- `0x14169860B mov [r12+0xB0], rcx`
- `0x14169864B mov [r12+0xC8], rsi`
- `0x14169867A mov [r12+0x158], rdx`
- `0x1416986A6 mov [r12+0x178], rax`
- `0x141698768 mov [r12+0x190], rcx`
- `0x14169877A mov [r12+0x198], 0xB1FF127C635B3E8F`
- `0x14169878C mov [r12+0x1A0], 0x44C83FA3FE163924`
- `0x14169879E mov [r12+0x1A8], 0xB902C17475E00D43`

這讓 `0x141696F8D` 的定位可以再收斂一點:

- 它不是單純比較器
- 也不是只做局部 arithmetic normalization
- 它明確是一個大規模 state-mutating stage

### `0x141696F8D` 尾端控制流

尾端也已經可以直接確認，它和前幾段一樣不是 `ret`，而是重新建出內部目標後 `jmp`:

- `0x141698878 xor rax, 0x2AD15F`
- `0x14169888B add rax, r13`
- `0x141698896 jmp rax`

而 `r13` 在先前來自:

- `0x1416975DE mov r13, [rsp+0x68]`

而 `[rsp+0x68]` 又是先前保存的:

- `[r12+0x150]`

所以這裡仍然符合整條保護鏈的一貫模式:

- 先做 compare-heavy / limb-heavy state processing
- 批次回寫多個 state slot
- 再用「固定偏移 + `[r12+0x150]` 基底」建出下一個內部落點

### 尾端後可見的短 stub

`0x141698896` 之後，鄰近可見的短函式還包括幾個值得先記下來的型態:

- `0x141698898`
  - 會把 `[r12+0x190]` / `[r12+0x191]` 壓成新值
  - 改寫 `[r12+0x194]`
  - 設定常數到 `[r12+0x19C]`
  - 再以 `0x307140 + [r12+0x150]` 跳轉
- `0x14169897F`
  - 改寫 `[r12+0x190]`
  - 改寫 `[r12+0x198]`
  - 再以 `0x307E19 + [r12+0x150]` 跳轉
- `0x141698A50`
  - 改寫 `[r12+0x198]`
  - 再以 `0x2FE010 + [r12+0x150]` 跳轉

目前還不能只靠鄰近位址就斷言它們一定是 `0x141696F8D` 的唯一直接後繼，  
但至少可以保守地記錄:

- `0x141696F8D` 尾端鄰域仍然密集存在 route-builder / state-shaper 類短 stub
- 這和前面觀察到的 `sect_7` 模板化控制流完全一致

## `0x141698A71` 的特徵

`0x141698A71` 是 `0x141698A50` 後面可見的下一個大函式。  
它的形狀和前面幾段不太一樣: 前半段仍然有 compare-driven decision 建構，但中後段更明顯地轉成 stateful structure rewrite，而不是純粹 limb arithmetic。

### 已驗證事實

- 開頭直接消費:
  - `[r12+0x88]`
  - `[r12+0x150]`
  - `[r12+0x198]`
- 一開始就以 `[r12+0x198]` 為核心做 threshold compare:
  - `0x141698ABC cmp rsi, 0xD071A93CB90D7A75`
  - `0x141698ACC cmp rsi, 0x15C8E0008D68D8CE`
  - 對應 `seta al` / `setb cl`
  - 並以 `orb` 合成 decision bit
- 很早就會把另一批 state 載入進來:
  - `[r12]`
  - `[r12+0x30]`
  - `[r12+0x58]`
  - `[r12+0x70]`
  - `[r12+0xB0]`
  - `[r12+0x190]`

因此 `0x141698A71` 一開始就很像是:

- 以 `[r12+0x198]` 為條件來源
- 以既有 state block 多欄位為操作對象
- 進行一輪新的 state rewrite / pointer selection

### 可直接驗證的寫回

這一段不是只在 stack 上做暫存，中後段已有明確的共享 state 寫回:

- `0x141698C6B mov [rax], rbp`
  - 這是透過先前算出的目標指標做的間接寫回
- `0x141698C88 mov [r12], rax`
- `0x141698CBD mov [r12+0x58], rax`
- `0x141698CDE mov [r12+0x70], rdi`
- `0x141698D10 mov [r12+0xB0], r9`

這代表 `0x141698A71` 雖然沒有像 `0x141696F8D` 那樣一次覆蓋十多個 slot，  
但它仍然明確屬於 state-mutating stage，而不是單純 route-builder。

### 尾端控制流

尾端也已可直接確認仍然遵循同一種內部路由模板:

- `0x141698D1B xor rcx, 0x2F0145`
- `0x141698D22 add rcx, r14`
- `0x141698D2A jmp rcx`

而 `r14` 在這段前面來自:

- `0x141698CA6 mov r14, rcx`

其中 `rcx` 是先前保存的 `[r12+0x150]` 基底位址。  
因此這裡仍然是:

- 先讀 state
- 做 compare-driven mutation
- 最後以固定偏移加上 `[r12+0x150]` 的方式尾跳到下一個內部 stage

### `0x141698D4D`: 結構重寫 / 選路節點

`0x141698D4D` 的前段和前面幾個 arithmetic-heavy stage 不太一樣。  
目前已能直接確認它會讀取並重組多個結構欄位:

- `[r12+0x10]`
- `[r12]`
- `[r12+0x8]`
- `[r12+0x28]`
- `[r12+0x20]`
- `[r12+0x58]`
- `[r12+0x70]`
- `[r12+0x88]`
- `[r12+0x90]`
- `[r12+0x148]`
- `[r12+0x150]`
- `[r12+0x170]`
- `[r12+0x178]`

同時可直接看到多個條件搬移 / 指標選路:

- `cmovbq`
- `cmovaeq`
- `cmoveq`
- `cmovneq`
- `bt`
- `setb`
- `sete`
- `setbe`

這讓它目前最適合的保守描述是:

- structure rewrite / pointer-selection stage
- 或 compare-driven state router

它已驗證的共享 state 寫回包括:

- `0x141698FA3 mov [r12+0x10], r14`
- `0x141698FA8 mov [r12+0x8], rbp`
- `0x141698FB2 mov [r12+0x18], r9`
- `0x141698FB7 mov [r12+0x28], r13`
- `0x141698FBC mov [r12+0x20], r15`
- `0x141698FC8 mov [r12+0x58], rdx`
- `0x141698FD3 mov [r12+0x70], r8`
- `0x141698FD8 mov [r12+0x88], rsi`
- `0x141698FE0 mov [r12+0x90], rax`
- `0x141698FE8 mov [r12+0x178], r11`

尾端則是:

- `0x141698FF0 add rcx, [rsp+0x20]`
- `0x141698FFD jmp rcx`

而 `[rsp+0x20]` 在前段保存的是 `[r12+0x150]`。  
因此這一段同樣以基底位址加固定偏移做內部跳轉。

### `0x141699000` 的特徵

緊接 `0x141698D4D` 之後可見的 `0x141699000`，又把 pipeline 拉回比較明顯的 multi-width arithmetic 樣式。  
現在這段已不只看前中段，而是已可確認它會回寫多個共享 state slot，尾端同樣以內部路由跳出。

### 已驗證事實

- 開頭消費:
  - `[r12+0x30]`
  - `[r12+0x88]`
  - `[r12+0x190]`
  - `[r12+0x158]`
- 一開始仍有多組 threshold compare on `[r12+0x190]`:
  - `0x141699054 cmp rbp, 0x77B0D8972E3DCEFA`
  - `0x141699068 cmp rbp, 0x77B0D8972E3DCEF9`
  - `0x141699080 cmp rbp, 0x08F29A8845677713`
  - `0x14169909E cmp rbp, 0x08F29A8845677714`
- 前中段很早就會把另一批 state 載入到本地暫存:
  - `[r12]`
  - `[r12+0x20]`
  - `[r12+0x28]`
  - `[r12+0x58]`
  - `[r12+0x70]`
  - `[r12+0xB0]`
  - `[r12+0x120]`
  - `[r12+0x148]`
  - `[r12+0x150]`
  - `[r12+0x170]`
  - `[r12+0x178]`

### mixed-width limb 規律

目前可直接確認它至少有三層不同欄位寬度:

第一層是 `29-bit` / `58-bit` 邊界:

- `0x1416990F0 and r14d, 0x1FFFFFFF`
- `0x1416990FE and r8d, 0x1FFFFFFF`
- `0x141699113 shrq 0x1D`
- `0x141699143 shrq 0x3A`
- `0x141699183 shlq 0x3A`

第二層切進 `21-bit` 類欄位:

- `0x141699773 and esi, 0x1FFFFF`
- `0x141699783 and r10d, 0x1FFFFF`
- `0x1416997BC shrq 0x15`
- `0x1416998A9 shll 0x16`

第三層又切進 `24-bit` 類欄位:

- `0x14169981F and edx, 0xFFFFFF`
- `0x141699825 and ecx, 0xFFFFFF`
- `0x14169982B and ebp, 0xFFFFFF`
- `0x141699831 shrq 0x18`

因此目前最穩妥的描述是:

- `0x141699000` 是 mixed-width arithmetic / recomposition stage
- 前半段偏 `29-bit` / `58-bit` 邊界
- 後半段再切成 `21-bit` 與 `24-bit` 類子欄位重組

### 已驗證 state 寫回

這段後半段已經有明確的共享 state 寫回，而不是只停留在 stack scratch:

- `0x141699FBE mov [r11+0x20], rax`
- `0x141699FC2 mov [r11+0x28], rdx`
- `0x14169A0EC mov [rcx+0x58], rax`
- `0x14169A29C mov [rbx+0x70], rax`
- `0x14169A2F7 mov [rbx+0x88], rdx`
- `0x14169A324 mov [rbx+0xB0], rdx`
- `0x14169A39C mov [r12+0x170], rax`
- `0x14169A3A7 mov [r12+0x178], rdx`
- `0x14169A3B7 mov [r12+0x190], rdi`
- `0x14169A3CC mov [r12+0x198], rax`
- `0x14169A3DE mov [r12+0x1A0], 0x460E26FD52A75DB9`
- `0x14169A3F0 mov [r12+0x1A8], 0x54F979794659D995`

其中前兩筆 `0x20/0x28` 寫回是透過先前算出的目標指標 `[r11+...]` 完成的間接寫回，  
後面則是直接回寫到共享 state block。

這讓 `0x141699000` 的定位可以再收斂成:

- mixed-width arithmetic stage
- 同時帶有多 slot state mutation
- 而不是單純的局部 normalization helper

### 尾端控制流

尾端也已可直接確認仍然遵守同一種內部跳轉模板:

- `0x14169A423 xor rax, 0x2C3068`
- `0x14169A468 add r11, [rsp+0xB8]`
- `0x14169A478 jmp r11`

而 `[rsp+0xB8]` 在前面保存的是:

- `[r12+0x150]`

所以它依舊符合這條主 pipeline 的一貫模式:

- 先做 multi-width recomposition
- 回寫共享 state
- 再以固定偏移加上 `[r12+0x150]` 做 tail-jump

### `0x14169A47B` 之後的 route-builder 家族

`0x14169A478` 之後，鄰近又能看到一串短小的 route-builder:

- `0x14169A47B`
  - 寫常數到 `[r12+0x190]`
  - `0x302BE3 + [r12+0x150]`
  - `jmp`
- `0x14169A49C`
  - 寫常數到 `[r12+0x190]`
  - `0x2F332B + [r12+0x150]`
  - `jmp`
- `0x14169A4BD`
  - 寫常數到 `[r12+0x190]`
  - `0x2A0188 + [r12+0x150]`
  - `jmp`
- `0x14169A4DE`
  - 寫常數到 `[r12+0x190]`
  - `0x317826 + [r12+0x150]`
  - `jmp`

這批短 stub 很像更前面已看到的 `0x141694ACC` / `0x141696F6C` 一系 family，只是這裡目前可見的變體都集中改寫:

- `[r12+0x190]`

因此目前可以把 `0x141699000` 的尾端鄰域先保守記成:

- arithmetic stage 後緊接一串 `[r12+0x190]`-oriented route-builders

### `0x14169A4FF` 的下一個大 stage

再往後可見的 `0x14169A4FF`，已經不是短 stub，而是另一個新的大函式前言:

- `push rbp / sub rsp, 0x58`
- 直接讀:
  - `[r12+0x30]`
  - `[r12+0xC8]`
  - `[r12+0x198]`
  - `[r12+0x190]`
- 開頭仍有 threshold compare on `[r12+0x198]`:
  - `0x14169A539 cmp rdi, 0xB7DEAEEC199D4CAE`
  - `0x14169A54D cmp rdi, 0xB7DEAEEC199D4CAD`

把這段往後完整拉開後，現在可以確認它不是單純延續前一段的 compare-heavy mixer，而是會先下鑽到次級 state block，再回到外層 shared state 做第二輪回寫。

### `0x14169A4FF` 的雙層 state 形狀

這段一開始先保存原始 `r12` 到 `r14`，接著在:

- `0x14169A557 mov r12, [r12+0x190]`

把工作基底切到另一個次級 state block。  
因此這段後半段看到的寫回，不能全部直接當成外層 shared state；其中有一大批其實是在改寫 `[orig_r12+0x190]` 指到的內層結構。

### 已驗證的欄位寬度訊號

這段中後段已可直接看到多組固定欄位寬度，而不是只有前半段那種常數混合:

- `42-bit` / `0x2A` 邊界:
  - `0x14169AA5A movabs rcx, 0x3FFFFFFFFFF`
  - `0x14169AAC8 shlq 0x2A`
- `26-bit` 類欄位:
  - `0x14169AB07 and edi, 0x3FFFFFF`
  - `0x14169AB10 shrq 0x1A`
  - `0x14169AB17 shrq 0x19`
  - `0x14169AB81 shlq 0x1A`
  - `0x14169AB8B shrq 0x34`
  - `0x14169AB8F shrq 0x33`
- `21-bit` 類欄位:
  - `0x14169B491 and r9d, 0x1FFFFF`
  - `0x14169B4A0 and r10d, 0x1FFFFF`
  - `0x14169B456 shr 0x15`
  - `0x14169B45C shr 0x14`
  - `0x14169B4E0 shl 0x15`
- 另有 byte 級混合:
  - `mulb`
  - `xorb`
  - `movzbl`

因此目前最穩妥的描述是:

- `0x14169A4FF` 是 mixed-width recomposition + byte-sliced mutation stage
- 前半段先做 compare-driven / hash-like state 混合
- 中後段再切進 `42-bit`、`26-bit`、`21-bit` 與 byte 級欄位重組

### 內層 state block 的已驗證寫回

在 `0x14169B7D8` 之後，`r11` 來自先前保存的原始 state 指標，這批指令可直接確認會把中後段結果回寫到 `[orig_r12+0x190]` 指到的次級結構:

- `0x14169B7E5 mov [r11+0x70], rdi`
- `0x14169B7F1 mov [r11+0x88], rdi`
- `0x14169B800 mov [r11+0xC8], rdi`
- `0x14169B80C mov [r11+0x108], rdi`
- `0x14169B813 mov [r11+0x190], r14d`
- `0x14169B81A mov [r11+0x194], esi`
- `0x14169B87C mov [r11+0x198], sil`
- `0x14169B8BF movw [r11+0x199], cx`
- `0x14169B8CA mov [r11+0x19B], cl`
- `0x14169B977 mov [r11+0x19C], edi`

這組寫回和前面幾個 stage 很不一樣，因為它不是只改少數幾個 `qword` slot，  
而是明顯在重建一個帶有 `byte/word/dword/qword` 混合欄位的次級 state 區塊。

### 外層 shared state 的已驗證寫回

在 `0x14169AC12` 把原始 `r12` 從 stack 還原後，這段又回到外層 shared state，並可直接確認下列寫回:

- `0x14169AC27 mov [r12+0x30], rbp`
- `0x14169ACBD mov [r12+0x88], rsi`
- `0x14169AD18 mov [r12+0xB0], rax`
- `0x14169AD97 mov [r12+0x190], r14`
- `0x14169ADF5 mov [r12+0x198], rcx`

因此 `0x14169A4FF` 的定位可以再收斂成:

- 它不是單層 state mixer
- 它會先重寫 `[orig_r12+0x190]` 指到的次級 block
- 再把結果折回外層 shared state 的多個核心 slot

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`，而是重新算出目標後尾跳:

- `0x14169AE84 add rax, rbx`
- `0x14169AE87 add rsp, 0x58`
- `0x14169AE8B pop rbp`
- `0x14169AE8C jmp rax`

其中 `rbx` 在 `0x14169AC1F` 來自:

- `[r12+0x150]`

所以這段仍然符合整條 pipeline 的大方向:

- 先改寫 state
- 再把計算出的內部目標加到 `[r12+0x150]`
- 最後 `jmp` 進下一個內部落點

尾端鄰近還可直接看到兩個新的 `[r12+0x190]`-oriented route-builder:

- `0x14169AE8E`
  - 常數 `0xF196556421C7D909` -> `[r12+0x190]`
  - `0x3131E4 + [r12+0x150]`
- `0x14169AEAF`
  - 常數 `0x9ED8DBFE503C08EF` -> `[r12+0x190]`
  - `0x2F4EEB + [r12+0x150]`

而下一個可見的大型 stage 會從 `0x14169AED0` 開始，開頭已可直接確認它會讀:

- `[r12+0x30]`
- `[r12+0x70]`
- `[r12+0x108]`
- `[r12+0x198]`

因此目前可以把這段後續骨架更新成:

- `0x141699000`
  - mixed-width arithmetic / state-mutation stage
- `0x14169A47B / 0x14169A49C / 0x14169A4BD / 0x14169A4DE`
  - `[r12+0x190]`-oriented route-builder family
- `0x14169A4FF`
  - dual-layer mixed-width recomposition + byte-sliced mutation stage
- `0x14169AE8E / 0x14169AEAF`
  - 新增可見的 `[r12+0x190]` route-builder 變體
- `0x14169AED0`
  - 下一個大 stage 的新起點

### `0x14169AED0` 的特徵

`0x14169AED0` 可以獨立看成 `0x14169A4FF` 後面的下一個完整大 stage，因為它在:

- `0x14169BA65 jmp rdx`

結束，而 `0x14169BA67` 已經是新的函式前言。  
這段的形狀和 `0x14169A4FF` 很接近，同樣不是單層 arithmetic block，而是先重寫次級 state block，再以外層 shared state 基底做尾跳。

### 開頭輸入與比較來源

開頭已可直接確認它消費:

- `[r12+0x30]`
- `[r12+0x70]`
- `[r12+0x108]`
- `[r12+0x198]`

前段的 compare-driven decision 主要圍繞 `[r12+0x198]` 展開，例如:

- `0x14169AF28 cmp rdi, 0x558A909FA108BE6B`
- `0x14169AF3E cmp rdi, 0x558A909FA108BE6C`

對應可見:

- `seta`
- `setb`
- `notb`
- `movzbl`
- `or`

因此前半段很像是:

- 以 `[r12+0x198]` 為條件來源
- 把 decision bit 折進後續 state 混合與索引建構

### 雙層 state 結構仍然存在

這段沒有像 `0x14169A4FF` 那樣一開始直接 `mov r12, [r12+0x190]`，  
但中段仍明確下鑽到次級 state block。可直接看到它沿著原始 `r12` 去讀:

- `[r13+0x88]`
- `[r13+0x190]`
- `[r13+0x150]`
- `[r13+0x30]`
- `[r13+0xC8]`

其中 `[r13+0x190]` 後半段被拿來做固定寬度重組，  
而 `[r13+0x150]` 則在尾端重新作為內部跳轉的基底位址。

### 已驗證的欄位寬度訊號

這段目前可直接驗證到多層不同欄位寬度:

- `41-bit` / `0x29` 邊界:
  - `0x14169B10B shrq 0x29`
  - `0x14169B18C shlq 0x29`
  - `0x14169B14A movabs r15, 0x1FFFFFFFFFF`
- `21-bit` 類欄位:
  - `0x14169B491 and r9d, 0x1FFFFF`
  - `0x14169B4A0 and r10d, 0x1FFFFF`
  - `0x14169B456 shr 0x15`
  - `0x14169B45C shr 0x14`
  - `0x14169B4E0 shl 0x15`
- `23-bit` 類欄位:
  - `0x14169B821 mov ecx, 0x7FFFFF`
  - `0x14169B826 sbb ecx, 0`
- 額外 byte / sub-byte 級混合:
  - `mulb`
  - `xorb`
  - `movzbl`
  - `andb 0x7`
  - `shrb 0x3`
  - `shrb 0x6`
  - `andb 0x3F`

因此目前最穩妥的描述是:

- `0x14169AED0` 是 compare-driven mixed-width recomposition stage
- 中段以 `41-bit + 21-bit + 23-bit` 為主
- 後半段再切進 byte / 6-bit 級欄位混合

### 次級 state block 的已驗證寫回

這段在 `0x14169B7D8` 之後可直接確認對次級 block 寫回:

- `0x14169B7E5 mov [r11+0x70], rdi`
- `0x14169B7F1 mov [r11+0x88], rdi`
- `0x14169B800 mov [r11+0xC8], rdi`
- `0x14169B80C mov [r11+0x108], rdi`
- `0x14169B813 mov [r11+0x190], r14d`
- `0x14169B81A mov [r11+0x194], esi`
- `0x14169B87C mov [r11+0x198], sil`
- `0x14169B8BF movw [r11+0x199], cx`
- `0x14169B8CA mov [r11+0x19B], cl`
- `0x14169B977 mov [r11+0x19C], edi`
- `0x14169B99F mov [r11+0x1A0], al`
- `0x14169B9AA movw [r11+0x1A1], cx`
- `0x14169B9B5 mov [r11+0x1A3], cl`

這表示 `0x14169AED0` 對次級 block 的更新比 `0x14169A4FF` 更深，  
不只延續到 `0x19C`，還繼續擴張到 `0x1A0`、`0x1A1`、`0x1A3`。

### 尾端控制流

尾端已可直接確認不是 `ret`:

- `0x14169BA50 xor rdx, 0x3321BE`
- `0x14169BA57 add rdx, rbp`
- `0x14169BA5D add rsp, 0xA0`
- `0x14169BA64 pop rbp`
- `0x14169BA65 jmp rdx`

其中 `rbp` 在中段來自先前保存的:

- `[r13+0x150]`

所以這裡仍然符合主 pipeline 的共同模板:

- 先改寫次級 state block
- 再用計算出的偏移結果加上 `[r12+0x150]`
- 最後 `jmp` 到下一個內部 stage

### `0x14169BA67` 的特徵

`0x14169BA67` 現在已可從「新起點骨架」補成一個完整 stage。  
它在:

- `0x14169C949 mov [r12+0x190], rsi`
- `0x14169C959 jmp rdx`

收尾，因此本體可視為 `0x14169BA67 -> 0x14169C959`。

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12+0x70]`
- `[r12+0x88]`
- `[r12+0xB0]`
- `[r12+0xC8]`
- `[r12+0x120]`
- `[r12+0x150]`
- `[r12+0x170]`
- `[r12+0x190]`

前段仍有明顯 compare-driven decision construction，主要圍繞 `[r12+0x190]` 展開，例如:

- `0x14169BAE7 cmp rbx, 0x6E46ADDB7FE1887E`
- `0x14169BAEA setb [rsp+8]`
- `0x14169BAFB cmp rbx, 0x6E46ADDB7FE1887D`
- `0x14169BAFE seta sil`
- `0x14169BC9A cmp rcx, 0xB0209AD809BFCE8E`
- `0x14169BC9D sete dl`
- `0x14169BD17 cmp rbx, 0xC53030160D16730D`
- `0x14169BD1D seta r13b`
- `0x14169BE80 cmp rax, 0xB0209AD809BFCE8E`
- `0x14169BE83 sete cl`

因此這段不是單純的 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段前中段可直接看到固定寬度與子欄位重組訊號:

- `31-bit` 類欄位:
  - `0x14169C336 and eax, 0x7FFFFFFF`
  - `0x14169C358 and r11d, 0x7FFFFFFF`
  - `0x14169C37C and esi, 0x7FFFFFFF`
  - `0x14169C3A6 and edx, 0x7FFFFFFF`
  - `0x14169C3C8 and edx, 0x7FFFFFFF`
  - `0x14169C400 and r13d, 0x7FFFFFFF`
- `bit 31` / sign-carry 類處理:
  - `0x14169C362 shr r12d, 0x1F`
  - `0x14169C369 shr ebx, 0x1E`
  - `0x14169C3C1 shl rsi, 0x1F`
  - `0x14169C548 shl r9, 0x1F`
  - `0x14169C678 shl r8, 0x1F`
- `2-bit` 高位封裝:
  - `0x14169C41B shl rax, 0x3E`
  - `0x14169C42F movabs rcx, 0x3FFFFFFFFFFFFFFF`
  - `0x14169C599 shl rdx, 0x3E`
  - `0x14169C59D movabs rbp, 0x3FFFFFFFFFFFFFFF`
- byte / 3-bit / 6-bit 子欄位:
  - `0x14169C100 and bl, 0x7`
  - `0x14169C10A mulb [rsp+0x68]`
  - `0x14169C119 shr r14b, 0x3`
  - `0x14169C120 shr r8b, 0x3`
  - `0x14169C13D shr r10b, 0x6`
  - `0x14169C141 shr al, 0x6`
  - `0x14169C16A and cl, 0x3F`

這些訊號合在一起，讓目前最穩妥的描述是:

- `0x14169BA67` 是 compare-driven mixed-width recomposition stage
- 其中主體偏 `31-bit` 欄位與高位 carry / 封裝
- 後半段再切進 byte / `3-bit` / `6-bit` 子欄位重組

### 共享 state 的已驗證寫回

這段目前看起來仍以單層 shared state 為主，沒有像 `0x14169A4FF` / `0x14169AED0` 那樣明確下鑽到次級 block。  
中後段可直接確認的寫回包括:

- `0x14169C6B7 mov [r12+0x70], rdi`
- `0x14169C6BC mov [r12+0xB0], rax`
- `0x14169C6C7 mov [r12+0xC8], rdx`
- `0x14169C709 mov [r12+0x120], r13`
- `0x14169C904 mov [r12+0x170], rbx`
- `0x14169C949 mov [r12+0x190], rsi`

因此比起前兩個雙層 stage，這段目前更像:

- 單層 shared-state mutation / recomposition stage
- 而不是明顯的 nested-state rewrite stage

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x14169C831 mov rax, [rsp+0x70]`
- `0x14169C836 add rdx, rax`
- `0x14169C951 add rsp, 0xB8`
- `0x14169C958 pop rbp`
- `0x14169C959 jmp rdx`

其中 `[rsp+0x70]` 來自開頭保存的 `[r12+0x150]`，  
因此它仍遵循這條主 pipeline 的共同模板:

- 先做 compare-driven mixed-width recomposition
- 再回寫共享 state
- 最後以計算出的目標加上 `[r12+0x150]` 做尾跳

尾端鄰近已可再看到一個新的短 route-builder:

- `0x14169C95B`
  - `0x30D0E7 + [r12+0x150]`
  - 讀 `[r12+0x88]` 指到的結構
  - 回寫 `[r12+0x20]`、`[r12+0x28]`、`[r12+0x88]`

而下一個可見的大型 stage 起點已再前推到:

- `0x14169CA0E`
  - 開頭直接讀 `[r12+0x30]`、`[r12+0x58]`、`[r12+0x88]`、`[r12+0x90]`、`[r12+0xB0]`、`[r12+0xD0]`、`[r12+0x150]`、`[r12+0x158]`、`[r12+0x170]`、`[r12+0x190]`

因此目前可以把後續骨架再往下推成:

- `0x14169A4FF`
  - dual-layer mixed-width recomposition + byte-sliced mutation stage
- `0x14169AE8E / 0x14169AEAF`
  - `[r12+0x190]`-oriented route-builder family
- `0x14169AED0`
  - compare-driven `41-bit/21-bit/23-bit` mixed-width stage
  - 深化次級 block 到 `0x1A0+`
- `0x14169BA67`
  - compare-driven `31-bit` + byte / `3-bit` / `6-bit` shared-state stage
- `0x14169C95B`
  - 結構抽取型 route-builder / state shaper
- `0x14169CA0E`
  - 下一個大 stage 的新起點

### `0x14169CA0E` 的特徵

`0x14169CA0E` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x14169EBC8 mov [r12+0x190], rax`
- `0x14169EC5B jmp rax`

收尾，因此本體可視為 `0x14169CA0E -> 0x14169EC5B`。

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12+0x30]`
- `[r12+0x58]`
- `[r12+0x88]`
- `[r12+0x90]`
- `[r12+0xB0]`
- `[r12+0xD0]`
- `[r12+0x150]`
- `[r12+0x158]`
- `[r12+0x170]`
- `[r12+0x190]`

前段仍以 `[r12+0x190]` 為主做 compare-driven decision construction，例如:

- `0x14169CA8D cmp rax, 0x36CCF898509F5AF1`
- `0x14169CA90 seta r13b`
- `0x14169CAD4 cmp rax, 0x0FC94923AA6365EC`
- `0x14169CAD7 setb sil`
- `0x14169CAE8 cmp rax, 0x0FC94923AA6365EB`
- `0x14169CAEB seta r8b`

中後段還會再出現多組比較與 decision bit 累積，例如:

- `0x14169D3F9 cmp rax, 0x38D010838F01D151`
- `0x14169D3FC sete cl`
- `0x14169D40A setne [rsp+0xB0]`
- `0x14169D9B0 cmp rsi, 0x38D010838F01D151`
- `0x14169D9B3 setne [rsp+0x90]`
- `0x14169D9BB sete dil`

因此這段同樣不是單純 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段比 `0x14169BA67` 更明顯地偏向 mixed-width 欄位重組，至少可直接確認:

- `22-bit` 類欄位:
  - `0x14169D561 and eax, 0x3FFFFF`
  - `0x14169D56E and ebx, 0x3FFFFF`
  - `0x14169D59E and ecx, 0x3FFFFF`
  - `0x14169D5A7 and r11d, 0x3FFFFF`
  - `0x14169D6B9 and r12d, 0x3FFFFF`
  - `0x14169D6E6 movabs rdx, 0xFFFFFFFFFFF`
  - `0x14169D6E2 shl rcx, 0x2C`
  - `0x14169D6F6 shr eax, 0x13`
- 第二組 `22-bit` / `0x16` 邊界:
  - `0x14169E13E and eax, 0x3FFFFF`
  - `0x14169E14C and edx, 0x3FFFFF`
  - `0x14169E172 shr rsi, 0x16`
  - `0x14169E18D shr r15, 0x16`
  - `0x14169E22A shl rax, 0x16`
- `44-bit` / `0x2C` 邊界:
  - `0x14169E234 shr r10, 0x2C`
  - `0x14169E23B shr rax, 0x2C`
  - `0x14169E24A shr rcx, 0x2B`
  - `0x14169E341 shl rax, 0x2C`
  - `0x14169E345 movabs rcx, 0xFFFFFFFFFFF`
- byte / 5-bit 子欄位:
  - `0x14169EA81 xor al, 0x41`
  - `0x14169EA83 add al, 0x18`
  - `0x14169EA9F shr bl, 0x5`
  - `0x14169EACC and r9b, 0x1F`
  - `0x14169EAD0 and bpl, 0x1F`
  - `0x14169EAE6 shl r9b, 0x5`

這些訊號合在一起，讓目前最穩妥的描述是:

- `0x14169CA0E` 是 compare-driven mixed-width recomposition stage
- 主體偏 `22-bit` 與 `44-bit` 邊界
- 後半段再混入 byte / `5-bit` 子欄位與多輪乘法式 state 混合

### 共享 state 的已驗證寫回

這段目前仍以外層 shared state 為主，雖然中段可見多個經指標間接寫回的暫存目標，但目前沒有前兩個雙層 stage 那種明確的 `[orig_r12+0x190]` 次級 block 重寫證據。  
已直接驗證的外層 shared state 寫回包括:

- `0x14169E792 mov [r12], r9`
- `0x14169E795 mov [r12+0x30], r12`
- `0x14169E79E mov [r12+0x58], r9`
- `0x14169E7A6 mov [r12+0x70], r14`
- `0x14169E8DD mov [r12+0x88], rax`
- `0x14169E910 mov [r12+0xA8], rcx`
- `0x14169E948 mov [r12+0xB0], rax`
- `0x14169E99A mov [r12+0xC8], rax`
- `0x14169EA4E mov [r12+0xD0], rcx`
- `0x14169EADE mov [r12+0x120], rdx`
- `0x14169EB78 mov [r12+0x170], rax`
- `0x14169EBC8 mov [r12+0x190], rax`

另外中段還可直接看到多個經計算指標完成的間接寫回:

- `0x14169D64D mov [r15], rax`
- `0x14169D655 mov [rax], rdx`
- `0x14169D660 mov [rax], rcx`
- `0x14169D668 mov [rax], r8`
- `0x14169D673 mov [rax], rsi`
- `0x14169D682 mov [r9], rax`

因此目前更適合把它標成:

- 單層 shared-state recomposition / mutation stage
- 但夾帶多個 pointer-mediated side write

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x14169EC4B add rax, [rsp+0x120]`
- `0x14169EC53 add rsp, 0x168`
- `0x14169EC5A pop rbp`
- `0x14169EC5B jmp rax`

其中 `[rsp+0x120]` 來自開頭保存的 `[r12+0x150]`，  
因此它仍遵循主 pipeline 的共同模板:

- 先做 compare-driven mixed-width recomposition
- 回寫外層 shared state
- 再以計算出的目標加上 `[r12+0x150]` 做尾跳

尾端之後可見的新節點包括:

- `0x14169EC5D`
  - 下一個大 stage 起點
  - 開頭直接讀 `[r12+0x148]`、`[r12+0x190]`、`[r12+0x198]`
- `0x14169F93C`
  - 結構選路型 route-builder
  - 會依 `[r12+0x1A0]` 決定從 `[r12+0x70]` 或 `[r12+0x190]` 族欄位取值，並回寫 `[r12+0x70]`、`[r12+0x88]`、`[r12+0x190]`、`[r12+0x198]`、`[r12+0x1A0]`

因此目前可以把後續骨架再往下推成:

- `0x14169CA0E`
  - compare-driven `22-bit/44-bit` mixed-width stage
  - 單層 shared-state + 多個間接寫回
- `0x14169EC5D`
  - 下一個大 stage 的新起點
- `0x14169F93C`
  - 結構選路型 route-builder / state shaper

### `0x14169EC5D` 的特徵

`0x14169EC5D` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x14169F932 add rsp, 0x98`
- `0x14169F93A jmp rdx`

收尾，因此本體可視為 `0x14169EC5D -> 0x14169F93A`。  
這段和前面的 `0x14169CA0E` 不同，前半段先以 `[r12+0x198]` 做 compare-driven decision construction，  
中後段再把重組結果直接回寫到外層 shared state 的多個欄位。

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12+0x148]`
- `[r12+0x190]`
- `[r12+0x198]`

前段的 compare-driven decision construction 主要圍繞 `[r12+0x198]` 展開，例如:

- `0x14169EC8A cmp rsi, 0x9E2AD11A15097BBA`
- `0x14169EC8D setb [rsp+8]`
- `0x14169EC9E cmp rsi, 0x9E2AD11A15097BB9`
- `0x14169ECA1 seta al`

後續還會再對混合後的中間值做比較，例如:

- `0x14169EDBE cmp rcx, 0xF9968406C10DF1F4`
- `0x14169EDC1 sete sil`
- `0x14169EEC2 cmp r8, 0xF9968406C10DF1F4`
- `0x14169EEC5 setne dl`
- `0x14169EECD sete cl`
- `0x14169EFE0 cmp rcx, 0x4A793F3DE3D79DB6`
- `0x14169EFE3 sete dl`
- `0x14169F0D8 cmp rcx, 0x4A793F3DE3D79DB6`
- `0x14169F0E2 sete r8b`

因此這段同樣不是短 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段中後段可直接確認多組固定寬度欄位重組，至少包括:

- `41-bit` / `0x29` 邊界:
  - `0x14169F250 movabs r9, 0x1FFFFFFFFFF`
  - `0x14169F25A and rax, r9`
  - `0x14169F294 shl rcx, 0x29`
  - `0x14169F636 movabs rdx, 0x1FFFFFFFFFF`
  - `0x14169F648 and [rsp+8], rdx`
  - `0x14169F6BB shr rax, 0x29`
- `21-bit` 類欄位:
  - `0x14169F3CB and esi, 0x1FFFFF`
  - `0x14169F3D8 and edi, 0x1FFFFF`
  - `0x14169F3F6 and ecx, 0x1FFFFF`
  - `0x14169F40F shl ecx, 0x15`
- `18-bit` / `0x12` 邊界:
  - `0x14169F44D and r9d, 0x3FFFF`
  - `0x14169F471 and r11d, 0x3FFFF`
  - `0x14169F482 and r8d, 0x3FFFF`
  - `0x14169F4A0 and eax, 0x3FFFF`
  - `0x14169F4B3 shl eax, 0x12`
- 伴隨 carry / borrow 與位段封裝:
  - `adcl`
  - `sbbw`
  - `seta`
  - `setb`
  - `sete`
  - `movzbl`

這些訊號合在一起，讓目前最穩妥的描述是:

- `0x14169EC5D` 是 compare-driven mixed-width recomposition stage
- 其中可直接驗證的主體欄位至少包含 `41-bit`、`21-bit`、`18-bit`
- 後半段還混入 flag / carry-based packing，而不只是單純 limb 加減

### 外層 shared state 的已驗證寫回

這段目前看起來偏單層 shared-state mutation，尚未看到 `0x14169A4FF` / `0x14169AED0` 那種明確先下鑽 `[orig_r12+0x190]` 次級 block 再回寫外層的雙層結構。  
已直接驗證的外層 shared state 寫回包括:

- `0x14169F14A mov [rbx], rcx`
- `0x14169F162 mov [rbx+0x58], rcx`
- `0x14169F286 mov [rbx+0x70], rcx`
- `0x14169F2EE mov [rbx+0xC8], rdx`
- `0x14169F333 mov [rbx+0x120], rax`
- `0x14169F755 mov [rbp+0x178], rdx`
- `0x14169F75C mov [rbp+0x190], r12d`
- `0x14169F763 mov [rbp+0x194], ebx`
- `0x14169F7D8 mov [rbp+0x198], r8d`
- `0x14169F880 mov [rbp+0x19C], ecx`
- `0x14169F89B mov [rbp+0x1A0], eax`
- `0x14169F8A5 mov [rbp+0x1A4], ecx`

其中 `rbx` / `rbp` 都可回溯到原始外層 state，  
所以目前比較合理的定位是:

- 單層 shared-state recomposition / mutation stage
- 但對外層 state 的覆蓋範圍，已從先前常見的 `qword` slot 延伸到 `0x190..0x1A4` 的密集子欄位

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x14169F928 xor rdx, 0x2DE99B`
- `0x14169F92F add rdx, r13`
- `0x14169F932 add rsp, 0x98`
- `0x14169F939 pop rbp`
- `0x14169F93A jmp rdx`

其中 `r13` 在開頭來自:

- `[r12+0x190]`

因此這段尾跳基底和前面多個依賴 `[r12+0x150]` 的 stage 不同，  
目前只能保守寫成:

- 它會用計算出的目標再加上來自 `[r12+0x190]` 的基底做尾跳

尾端鄰近可見的後續節點包括:

- `0x14169F93C`
  - 結構選路型 route-builder
  - `cmp [r12+0x1A0], 1`
  - `cmove` / `cmovne` 在 `[r12+0x70]`、`[r12+0x88]`、`[r12+0x190]`-family 之間切換來源
  - 回寫 `[r12+0x70]`、`[r12+0x88]`、`[r12+0x190]`、`[r12+0x198]`、`[r12+0x1A0]`
- `0x14169F9C7`
  - 下一個大 stage 起點
  - 開頭直接讀 `[r12+0x88]`、`[r12+0x190]`
  - 很早就出現 `and 0xFFF` 與後續 `0x3FFFFFFFFF` / `shr 0x26` / `shl 0x1A` 類欄位訊號

因此目前可以把後續骨架再往下推成:

- `0x14169EC5D`
  - compare-driven `41-bit/21-bit/18-bit` mixed-width stage
  - 單層 shared-state 寫回覆蓋延伸到 `0x1A4`
- `0x14169F93C`
  - 結構選路型 route-builder / state shaper
- `0x14169F9C7`
  - 下一個大 stage 的新起點

### `0x14169F9C7` 的特徵

`0x14169F9C7` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x1416A0D1A add r8, rdx`
- `0x1416A0D25 jmp r8`

收尾，因此本體可視為 `0x14169F9C7 -> 0x1416A0D25`。  
這段的形狀再次偏向雙層 state stage，而不是單純外層 shared-state mixer。

### 開頭輸入與 decision construction

開頭已可直接確認它先讀:

- `[r12+0x88]`
- `[r12+0x190]`

而且很早就把原始外層 state 保存起來，再下鑽到次級 block:

- `0x14169F9DC mov rcx, r12`
- `0x14169F9EA mov r12, [r12+0x190]`
- `0x14169FAA5 mov [rsp+0x90], rsi`

前段的 compare-driven decision construction 主要圍繞新的 `r12` 展開，也就是內層 block，例如:

- `0x14169F9FF cmp r12, 0x35F399A65EFEFAD8`
- `0x14169FA02 setb [rsp+0x28]`
- `0x14169FA13 cmp r12, 0x35F399A65EFEFAD7`
- `0x14169FA16 seta dl`
- `0x14169FA39 cmp r12, 0x45B670643F42C641`
- `0x14169FA3C seta al`
- `0x14169FA7C cmp r12, 0xC3624DBE1304E9E8`
- `0x14169FA7F setb [rsp+7]`
- `0x14169FA90 cmp r12, 0xC3624DBE1304E9E7`
- `0x14169FA93 seta al`

中後段還會再對重組結果做多輪比較與 decision-bit 累積，例如:

- `0x14169FC0A cmp rsi, 0xAF2B92403E754704`
- `0x14169FC12 sete sil`
- `0x14169FD9A cmp rax, 0x828DBF9721080E31`
- `0x14169FD9D setne cl`
- `0x14169FDAA sete al`
- `0x14169FF37 cmp r14, r8`
- `0x14169FF3A seta bl`
- `0x14169FF47 sete r9b`
- `0x14169FF59 cmp rdx, r8`
- `0x14169FF5C seta cl`
- `0x14169FF6B sete bl`

因此這段同樣不是 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段的固定寬度訊號比前一段更集中在 `26-bit/27-bit` 邊界，至少可直接確認:

- `12-bit` 起手訊號:
  - `0x14169F9E3 and r10d, 0xFFF`
- `38-bit` / `0x26` 邊界:
  - `0x14169FE57 movabs rax, 0x3FFFFFFFFF`
  - `0x14169FE69 and rdx, rax`
  - `0x14169FE94 shld r10, rbx, 0x1A`
  - `0x14169FE9D shr rsi, 0x26`
  - `0x14169FEBB shl rcx, 0x26`
  - `0x14169FEC6 shl r10, 0x26`
  - `0x14169FF0D shr rax, 0x26`
  - `0x14169FF14 shr rdx, 0x26`
- `39-bit` / `0x27` 邊界:
  - `0x14169FE47 movabs rbp, 0x7FFFFFFFFF`
  - `0x14169FE54 and r14, rbp`
  - `0x14169FEF9 shr r10, 0x27`
  - `0x14169FF03 shr rax, 0x27`
  - `0x14169FF77 shl rax, 0x27`
- carry / borrow / bit packing:
  - `adcl 0x1000`
  - `adcl`
  - `sbbl`
  - `movzbl`
  - `xorb 0x1`

這些訊號合在一起，讓目前最穩妥的描述是:

- `0x14169F9C7` 是 compare-driven mixed-width recomposition stage
- 主體偏 `26-bit/27-bit` 欄位與 carry-based packing
- 開頭另混入 `12-bit` 子欄位訊號

### 雙層 state 結構仍然存在

這段和 `0x14169A4FF` / `0x14169AED0` 一樣，再次呈現出明確的雙層 state 形狀。  
除了前段直接 `mov r12, [r12+0x190]` 之外，中段也會回頭消費保存於 `[rsp+0x90]` 的原始外層 state:

- `0x1416A009C mov rdx, [rsp+0x90]`
- `0x1416A00A4 mov rax, [rdx+0x28]`
- `0x1416A00B0 mov r14, [rdx]`
- `0x1416A00B3 mov rax, [rdx+0x20]`
- `0x1416A00BF mov rax, [rdx+0x58]`
- `0x1416A00CB mov rax, [rdx+0x70]`
- `0x1416A00D7 mov rax, [rdx+0xB0]`
- `0x1416A00E6 mov rax, [rdx+0x150]`
- `0x1416A00F2 mov rax, [rdx+0x158]`

因此目前比較合理的定位是:

- 先以下鑽後的內層 block 做 compare-driven mixed-width recomposition
- 再把結果折回外層 state 的結構欄位與路由欄位

### 內層 state block 的已驗證寫回

目前可直接確認對內層 block 的寫回包括:

- `0x1416A00F9 mov [rdi], r11`
- `0x1416A0127 mov [rcx+0x8], rsi`
- `0x1416A012B mov [rcx], rdi`
- `0x1416A0528 mov [rax], r15`
- `0x1416A0614 mov [rax+0x28], rcx`
- `0x1416A0618 mov [rax+0x20], rbx`
- `0x1416A0B06 mov [rdx+0x70], rcx`
- `0x1416A0B61 mov [rdx+0x88], rsi`
- `0x1416A0BAC mov [r9+0xB0], rax`
- `0x1416A0C52 mov [r9+0x190], rbp`
- `0x1416A0C7A mov [r9+0x198], rax`

這代表內層 block 的已驗證覆蓋範圍，至少已包含:

- `0x00`
- `0x08`
- `0x20`
- `0x28`
- `0x70`
- `0x88`
- `0xB0`
- `0x190`
- `0x198`

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x1416A0CA1 xor rax, 0x2E858A`
- `0x1416A0D05 xor r8, 0x2E858A`
- `0x1416A0D1A add r8, rdx`
- `0x1416A0D1D add rsp, 0x130`
- `0x1416A0D24 pop rbp`
- `0x1416A0D25 jmp r8`

其中 `rdx` 在尾端來自:

- `0x1416A0C59 mov rdx, [rsp+0x58]`

而 `[rsp+0x58]` 可回溯到:

- `0x1416A00E6 mov rax, [rdx+0x150]`
- `0x1416A00ED mov [rsp+0x58], rax`

也就是原始外層 state 的 `[+0x150]`。  
因此這段的尾跳模板又回到比較熟悉的形狀:

- 先重寫內層 state block
- 再用計算出的偏移結果加上 `[orig_state+0x150]`
- 最後 `jmp` 到下一個內部 stage

尾端鄰近可見的後續節點包括:

- `0x1416A0D28`
  - 短 route-builder
  - `0xF3B40A129104782B -> [r12+0x198]`
  - `0x2E6D12 + [r12+0x150]`
- `0x1416A0D49`
  - 短 route-builder
  - `0x6ADC56B007D8D889 -> [r12+0x190]`
  - `0x2F9FD0 + [r12+0x150]`
- `0x1416A0D6A`
  - 短 route-builder
  - `0x5B13DFD55198F303 -> [r12+0x190]`
  - `0x3078BC + [r12+0x150]`
- `0x1416A0D8B`
  - 結構重寫 / state shaper
  - 會更新 `[r12+0xB0]`、`[r12+0x148]`、`[r12+0x170]`
- `0x1416A0F09`
  - 下一個大 stage 起點

因此目前可以把後續骨架再往下推成:

- `0x14169F9C7`
  - dual-layer compare-driven `26-bit/27-bit` mixed-width stage
  - 內層 block 寫回至少涵蓋 `0x00/0x08/0x20/0x28/0x70/0x88/0xB0/0x190/0x198`
- `0x1416A0D28 / 0x1416A0D49 / 0x1416A0D6A`
  - 短 route-builder family
- `0x1416A0D8B`
  - 結構重寫 / state shaper
- `0x1416A0F09`
  - 下一個大 stage 的新起點

### `0x1416A0F09` 的特徵

`0x1416A0F09` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x1416A23C9 add rdi, [rsp+0x68]`
- `0x1416A23D6 jmp rdi`

收尾，因此本體可視為 `0x1416A0F09 -> 0x1416A23D6`。  
從目前可直接驗證的控制流與寫回形狀來看，這段偏單層 shared-state stage，尚未出現像 `0x14169A4FF`、`0x14169AED0`、`0x14169F9C7` 那種明確 `mov r12, [r12+0x190]` 下鑽到次級 block 的證據。

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12+0x20]`
- `[r12+0x28]`
- `[r12+0x30]`
- `[r12+0x58]`
- `[r12+0x70]`
- `[r12+0x88]`
- `[r12+0xA8]`
- `[r12+0xB0]`
- `[r12+0xC8]`
- `[r12+0xD0]`
- `[r12+0x120]`
- `[r12+0x150]`
- `[r12+0x158]`
- `[r12+0x170]`
- `[r12+0x190]`

前段的 compare-driven decision construction 仍以 `[r12+0x190]` 為主，例如:

- `0x1416A0F50 cmp [r12+0x190], 0xADE91028BBCF85DD`
- `0x1416A0F53 seta r10b`
- `0x1416A0F64 cmp [r12+0x190], 0x02672A7D27E09CC1`
- `0x1416A0F67 seta r8b`
- `0x1416A0F85 cmp [r12+0x190], 0x02672A7D27E09CC2`
- `0x1416A0F88 setb al`

中後段還會再出現多組 equality-style compare，例如:

- `0x1416A14D0 sete dil`
- `0x1416A14D9 setne cl`
- `0x1416A16DE cmp rcx, 0xB181A0304348F9D7`
- `0x1416A16E6 sete cl`
- `0x1416A1B5A cmp rax, 0xB181A0304348F9D7`
- `0x1416A1B62 sete al`
- `0x1416A1D19 cmp rcx, 0x6334852D4E59B144`
- `0x1416A1D1C sete bl`
- `0x1416A1E2D cmp rcx, 0x6334852D4E59B144`
- `0x1416A1E3D sete r13b`

因此這段同樣不是短 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段最明顯的主體仍是 `26-bit` 邊界的 limb recomposition，至少可直接確認:

- `26-bit` / `0x1A` 邊界:
  - `0x1416A1107 shl edi, 0x1A`
  - `0x1416A110D shr r11, 0x26`
  - `0x1416A1177 shr r9, 0x26`
  - `0x1416A1196 shl r11, 0x26`
  - `0x1416A1532 shr r8, 0x26`
  - `0x1416A154B shl rbp, 0x26`
  - `0x1416A15DF shl rax, 0x26`
  - `0x1416A17E1 shr r8, 0x26`
  - `0x1416A17EC shl r8, 0x26`
  - `0x1416A1821 shr rcx, 0x26`
  - `0x1416A1832 shl rcx, 0x26`
- `26-bit` carry / borrow 打包:
  - `adcl`
  - `sbbl`
  - `cmp` 後接 `adcl/sbbl`
- `10-bit` / `0xA` 子欄位:
  - `0x1416A192C and r8d, 0x3FF`
  - `0x1416A193B and esi, 0x3FF`
  - `0x1416A1941 shr eax, 0xA`
  - `0x1416A1944 shr r13d, 0xA`
  - `0x1416A1953 shl eax, 0xA`
- `16-bit` 子欄位與 byte 級混合:
  - `0x1416A190C movzwl (rax), eax`
  - `0x1416A1912 xorb cl, 0x3E`
  - `0x1416A1915 add cl, -0xA`
  - `0x1416A1958 movzwl ax, eax`
  - `0x1416A20B9 shl rsi, 0x10`

這些訊號合在一起，讓目前最穩妥的描述是:

- `0x1416A0F09` 是 compare-driven mixed-width recomposition stage
- 主體偏 `26-bit` limb 重組
- 中後段再混入 `10-bit/16-bit` 子欄位與 byte 級 decision / packing

### 外層 shared state 的已驗證寫回

這段目前看起來偏單層 shared-state mutation。  
已直接驗證的外層 shared state 寫回包括:

- `0x1416A1E35 mov [state+0x28], r10`
- `0x1416A1E39 mov [state+0x20], rbp`
- `0x1416A1F4A mov [state+0x58], rdi`
- `0x1416A2070 mov [state+0x70], r8`
- `0x1416A21C6 mov [state+0x88], rdx`
- `0x1416A2295 mov [state+0x120], r9`
- `0x1416A22D5 mov [state+0x170], r9`
- `0x1416A2326 mov [state+0x190], r10`

另外中段還可直接看到多個 pointer-mediated side write:

- `0x1416A10C6 mov [r9+0x8], rdi`
- `0x1416A10CA mov [r9], r11`
- `0x1416A182F mov [rax], r8`
- `0x1416A1963 mov [rbx], rax`
- `0x1416A1A51 mov [rdx], rsi`

因此目前更適合把它標成:

- 單層 shared-state recomposition / mutation stage
- 但夾帶多個經計算指標完成的 side write

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x1416A2396 xor r8, 0x308960`
- `0x1416A23B4 xor rdi, 0x308960`
- `0x1416A23C2 xor rdi, 0x308960`
- `0x1416A23C9 add rdi, [rsp+0x68]`
- `0x1416A23D6 jmp rdi`

其中 `[rsp+0x68]` 在開頭來自:

- `[r12+0x150]`

因此這段的尾跳模板仍回到主 pipeline 常見的形狀:

- 先做 compare-driven mixed-width recomposition
- 回寫外層 shared state
- 再以計算出的目標加上 `[r12+0x150]` 做尾跳

尾端鄰近可見的新節點包括:

- `0x1416A23D8`
  - 短 route-builder
  - `0xECE84718034A40F5 -> [r12+0x190]`
  - `0x31F1D8 + [r12+0x150]`

因此目前可以把後續骨架再往下推成:

- `0x1416A0F09`
  - compare-driven `26-bit` 主體 + `10-bit/16-bit` 子欄位的單層 shared-state stage
- `0x1416A23D8`
  - 新的 `[r12+0x190]`-oriented route-builder

### `0x1416A23F9` 的特徵

`0x1416A23F9` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x1416A33E0 add rax, [rsp+0xC0]`
- `0x1416A33F0 jmp rax`

收尾，因此本體可視為 `0x1416A23F9 -> 0x1416A33F0`。  
從目前可直接驗證的控制流與寫回形狀來看，這段仍偏單層 shared-state stage，尚未看到明確 `mov r12, [r12+0x190]` 下鑽到次級 block 的證據。

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12+0x88]`
- `[r12+0x190]`

中前段再陸續讀入:

- `[r12]`
- `[r12+0x18]`
- `[r12+0x30]`
- `[r12+0xB0]`
- `[r12+0x150]`
- `[r12+0x158]`

前段的 compare-driven decision construction 仍以 `[r12+0x190]` 為主，例如:

- `0x1416A2420 cmp [r12+0x190], 0x770AFDD85B18350B`
- `0x1416A2423 seta dl`
- `0x1416A2435 cmp [r12+0x190], 0x55BDF86FBBC55A8C`
- `0x1416A2438 setb al`

中後段還會再出現多組 equality / inequality compare，例如:

- `0x1416A25B8 cmp rcx, 0xEE3A415F55C7CCE5`
- `0x1416A25BB setne [rsp+0x18]`
- `0x1416A25C0 sete r8b`
- `0x1416A27F9 cmp rax, 0xEE3A415F55C7CCE5`
- `0x1416A27FC sete cl`
- `0x1416A2804 setne al`
- `0x1416A2AE7 cmp rcx, 0xEE3A415F55C7CCE5`
- `0x1416A2AEE setne sil`
- `0x1416A2AFA sete dl`
- `0x1416A2C01 cmp rcx, 0x5AD5E8B9850016BB`
- `0x1416A2C04 sete r13b`

因此這段同樣不是短 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段的寬度結構比前面幾段更雜，至少可直接確認:

- `35-bit` / `0x23` 邊界:
  - `0x1416A2457 movabs rcx, 0x7FFFFFFFF`
  - `0x1416A248B shr rcx, 0x23`
  - `0x1416A248F shr rax, 0x23`
  - `0x1416A2498 shl rax, 0x23`
- `42-bit` / `0x2A` 邊界:
  - `0x1416A2E4D movabs r13, 0x3FFFFFFFFFF`
  - `0x1416A2E57 and rax, r13`
  - `0x1416A2E97 shl rbx, 0x2A`
  - `0x1416A2F20 shl rdx, 0x2A`
- `17-bit` / `0x11` 邊界:
  - `0x1416A38E4 and r13d, 0x1FFFF`
  - `0x1416A38EE and r12d, 0x1FFFF`
  - `0x1416A38F5 and r11d, 0x1FFFF`
  - `0x1416A3894 shr edi, 0x11`
  - `0x1416A3899 shr ecx, 0x11`
  - `0x1416A38DE shr eax, 0x11`
- `15-bit` / `0xF` 邊界:
  - `0x1416A2CF8 and ecx, 0x7FFF`
  - `0x1416A2CD1 shr ecx, 0xF`
  - `0x1416A2CF2 shl eax, 0xF`
- `10-bit` / `0xA` 邊界:
  - `0x1416A2CBD and r8d, 0x3FF`
  - `0x1416A2C92 movzwl cx, esi`
  - `0x1416A2C95 shr esi, 0xA`
  - `0x1416A2CBA shl edx, 0xA`
- byte / sub-byte 混合:
  - `andb 0x1F`
  - `shrb 0x5`
  - `shlb 0x5`
  - `andb 0x7`
  - `shrb 0x3`
  - `andl 0xFF00`
  - `shlq 0x10`

這些訊號合在一起，讓目前最穩妥的描述是:

- `0x1416A23F9` 是 compare-driven mixed-width recomposition stage
- 前半段主體偏 `35-bit`
- 中後段再切到 `42-bit`
- 後面還混入 `17-bit/15-bit/10-bit` 與 byte 級子欄位重組

### 外層 shared state 的已驗證寫回

這段目前看起來偏單層 shared-state mutation。  
已直接驗證的外層 shared state 寫回包括:

- `0x1416A3195 mov [state], rdi`
- `0x1416A319D mov [state+0x18], r11`
- `0x1416A3299 mov [state+0x88], rcx`
- `0x1416A32C5 mov [state+0xB0], r8`
- `0x1416A337C mov [state+0x190], r10`
- `0x1416A338E mov [state+0x198], 0x0A4FFF4F5A1BB6C9`

另外中段還可直接看到至少一個 pointer-mediated side write:

- `0x1416A2856 mov [rsi], rcx`

因此目前更適合把它標成:

- 單層 shared-state recomposition / mutation stage
- 但夾帶至少一個經計算指標完成的 side write

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x1416A333F xor r9, 0x305705`
- `0x1416A3399 xor rdi, 0x305705`
- `0x1416A33BD xor rax, 0x305705`
- `0x1416A33CD xor rax, 0x305705`
- `0x1416A33E0 add rax, [rsp+0xC0]`
- `0x1416A33F0 jmp rax`

其中 `[rsp+0xC0]` 在前段來自:

- `[r12+0x150]`

因此這段尾跳模板仍遵循主 pipeline 的共同形狀:

- 先做 compare-driven mixed-width recomposition
- 回寫外層 shared state
- 再以計算出的目標加上 `[r12+0x150]` 做尾跳

尾端鄰近可見的新節點包括:

- `0x1416A33F2`
  - 短 route-builder
  - `0x48A2951136500FB7 -> [r12+0x1A8]`
  - `0x3005C4 + [r12+0x150]`
- `0x1416A3413`
  - 短 route-builder
  - `0xEF7589217F7E947B -> [r12+0x190]`
  - `0x321770 + [r12+0x150]`
- `0x1416A3434`
  - 下一個大 stage 起點
  - 開頭已可見讀取 `[r12]`、`[r12+0x30]`、`[r12+0x58]`、`[r12+0x70]`、`[r12+0x88]`、`[r12+0xA8]`、`[r12+0xB0]`、`[r12+0xC8]`、`[r12+0xD0]`、`[r12+0x148]`、`[r12+0x150]`、`[r12+0x158]`、`[r12+0x170]`、`[r12+0x178]`、`[r12+0x190]`

因此目前可以把後續骨架再往下推成:

- `0x1416A23F9`
  - compare-driven `35-bit/42-bit` 主體，後接 `17-bit/15-bit/10-bit` 與 byte 級子欄位的單層 shared-state stage
- `0x1416A33F2 / 0x1416A3413`
  - 新的 route-builder family
- `0x1416A3434`
  - 現已可視為完整 stage，不再只是起點骨架

### `0x1416A3434` 的特徵

`0x1416A3434` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x1416A7D96 add rax, r10`
- `0x1416A7DA1 jmp rax`

收尾，因此本體可視為 `0x1416A3434 -> 0x1416A7DA1`。  
從目前可直接驗證的控制流與寫回形狀來看，這段偏單層 shared-state stage，尚未看到像 `0x14169A4FF`、`0x14169AED0`、`0x14169F9C7` 那種明確 `mov r12, [r12+0x190]` 的下鑽證據。

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12]`
- `[r12+0x30]`
- `[r12+0x58]`
- `[r12+0x70]`
- `[r12+0x88]`
- `[r12+0x190]`

中前段再陸續讀入:

- `[r12+0xA8]`
- `[r12+0xB0]`
- `[r12+0xC8]`
- `[r12+0xD0]`
- `[r12+0x148]`
- `[r12+0x150]`
- `[r12+0x158]`
- `[r12+0x170]`
- `[r12+0x178]`

前段的 compare-driven decision construction 仍以 `[r12+0x190]` 為主，例如:

- `0x1416A3481 cmp [r12+0x190], 0x434BCB0AED705904`
- `0x1416A348E setb [rsp+7]`
- `0x1416A3493 cmp [r12+0x190], 0x434BCB0AED705903`
- `0x1416A34A2 seta cl`
- `0x1416A34EE cmp [r12+0x190], 0x1D97708C9ED08310`
- `0x1416A34FB setb [rsp+0x50]`
- `0x1416A3500 cmp [r12+0x190], 0x1D97708C9ED0830F`
- `0x1416A3597 seta dil`

中後段仍可看到大量 equality / inequality compare 與 carry-style flag 累積，例如:

- `0x1416A36B5 cmp rcx, 0xA6F738A3AFEA6308`
- `0x1416A36B8 setne [rsp+5]`
- `0x1416A36BD sete dl`
- `0x1416A37B8 cmp rcx, 0xA6F738A3AFEA6308`
- `0x1416A37BB setne [rsp+6]`
- `0x1416A37C0 sete cl`
- `0x1416A4B3A cmp rsi, 0xA6F738A3AFEA6308`
- `0x1416A4B3D setne cl`
- `0x1416A69C9 cmp [rsp+0x50], r12d`
- `0x1416A69EA seta al`

因此這段同樣不是短 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段的寬度結構比前面幾段更混合，至少可直接確認:

- `40-bit` / `0x28` 邊界:
  - `0x1416A3838 movabs rax, 0xFFFFFFFFFF`
  - `0x1416A3859 shr rax, 0x28`
  - `0x1416A3877 shl r14, 0x28`
- `17-bit` / `0x11` 邊界:
  - `0x1416A3894 shr edi, 0x11`
  - `0x1416A38E4 and r13d, 0x1FFFF`
  - `0x1416A38EE and r12d, 0x1FFFF`
  - `0x1416A3920 shl eax, 0x11`
- `25-bit` / `0x19` 邊界:
  - `0x1416A47CC shl rdi, 0x19`
  - `0x1416A49B4 shr ecx, 0x0D`
  - `0x1416A4A2D shl rcx, 0x32`
  - `0x1416A4F3D shr rdx, 0x19`
  - `0x1416A4FCD shl rax, 0x19`
- `50-bit` / `0x32` 邊界:
  - `0x1416A47D3 shl rax, 0x32`
  - `0x1416A47D7 movabs rcx, 0x3FFFFFFFFFFFF`
  - `0x1416A50B4 shl r9, 0x32`
- `24-bit` / `0x18` 邊界:
  - `0x1416A6416 shr r11, 0x18`
  - `0x1416A64B6 shl r11d, 0x18`
  - `0x1416A66A9 andl 0xFFFFFF`
  - `0x1416A6764 shl r14d, 0x10`
- `21-bit` / `0x15` 邊界:
  - `0x1416A64D5 andl 0x1FFFFF`
  - `0x1416A64FE shr rdx, 0x15`
  - `0x1416A6598 shl r10d, 0x15`
- `12-bit` / byte 級子欄位:
  - `0x1416A6229 andl 0xFFF`
  - `0x1416A6233 shr r10d, 0x0C`
  - `0x1416A62A5 shl r13d, 0x0C`
  - `0x1416A62B0 andb 0x7`
  - `0x1416A6328 shl eax, 0x18`

這些訊號合在一起，讓目前最穩妥的描述是:

- `0x1416A3434` 是 compare-driven mixed-width recomposition stage
- 前中段可明確見到 `40-bit/17-bit/25-bit`
- 後段再切到 `24-bit/21-bit/12-bit` 與 byte 級子欄位重組

### 外層 shared state 與 pointer-mediated 寫回

這段目前看起來偏單層 shared-state mutation。  
已直接驗證的外層 shared state 寫回包括:

- `0x1416A5093 mov [state], rcx`
- `0x1416A7918 mov [state+0x30], rax`
- `0x1416A793F mov [state+0x58], rax`
- `0x1416A79D0 mov [state+0x70], rdi`
- `0x1416A7BAB mov [state+0x88], r13`
- `0x1416A7C14 mov [state+0xC8], r12`
- `0x1416A7C44 mov [state+0xD0], rdi`
- `0x1416A7C7B mov [state+0x170], rsi`
- `0x1416A7CC2 mov [state+0x190], rcx`
- `0x1416A7CE3 mov [state+0x198], rsi`

另外中後段還可直接看到一組 pointer-mediated block write:

- `0x1416A69DD mov [target+0x190], eax`
- `0x1416A69E3 mov [target+0x194], r11d`
- `0x1416A6A3E mov [target+0x198], r14d`
- `0x1416A6B38 mov [target+0x19C], esi`
- `0x1416A6BA1 mov [target+0x1A0], r14d`

因此目前更適合把它標成:

- 單層 shared-state recomposition / mutation stage
- 但夾帶一個對次級 target block 的擴張寫回區段

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x1416A7D47 xor r8, 0x2F73E3`
- `0x1416A7D55 xor rsi, 0x2F73E3`
- `0x1416A7D66 xor rdx, 0x2F73E3`
- `0x1416A7D83 xor rax, 0x2F73E3`
- `0x1416A7D96 add rax, r10`
- `0x1416A7DA1 jmp rax`

這段尾端與前幾個 stage 相比稍微不同:  
最後的 `add` 直接使用尾端當下持有的 `r10`，而不是在目前可見切片裡清楚保留成單純的 `[r12+0x150]` 加總模板。  
因此這裡較保守的寫法是:

- 尾端仍屬於「先做混合，再算目標，再 `jmp`」的主 pipeline 模板
- 但最後一步不是最簡單的 `offset + [r12+0x150]` 直觀形狀

尾端鄰近可見的新節點包括:

- `0x1416A7DA3`
  - 結構抽取 / state shaper
  - 讀 `[r12+0x30]`、`[r12+0xB0]`、`[r12+0x150]`
  - 回寫 `[r12+0x70]` 與 `[target+0x8]`
  - `0x2BA52D + [r12+0x150]`
- `0x1416A7DD1`
  - 短 route-builder
  - `0xADF2C921D315BD27 -> [r12+0x1A0]`
  - `0x2CFCAE + [r12+0x150]`
- `0x1416A7DF2`
  - 結構抽取 / state shaper
  - 讀 `[r12+0x30]`、`[r12+0xD0]`、`[r12+0x150]`、`[r12+0x88]`
  - 回寫 `[r12+0x58]`、`[r12+0x70]` 與 `[target+0x8]`
  - `0x32ED0D + [r12+0x150]`
- `0x1416A7E49`
  - 結構抽取 / state shaper
  - 讀 `[r12+0x30]`、`[r12+0x88]`、`[r12+0x150]`
  - 回寫 `[r12+0x58]`、`[r12+0x70]`、`[r12+0x88]` 與 `[target+0x8]`
  - `0x326B1E + [r12+0x150]`
- `0x1416A7E9C`
  - 現已可視為完整 stage，不再只是起點骨架

### `0x1416A7E9C` 的特徵

`0x1416A7E9C` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x1416A9536 add r8, [rsp+0xC8]`
- `0x1416A9546 jmp r8`

收尾，因此本體可視為 `0x1416A7E9C -> 0x1416A9546`。  
從目前可直接驗證的控制流與寫回形狀來看，這段仍偏單層 shared-state stage，尚未看到明確 `mov r12, [r12+0x190]` 的 nested-state 下鑽。

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12+0x88]`
- `[r12+0xD0]`
- `[r12+0x148]`
- `[r12+0x190]`

中前段再陸續讀入:

- `[r12+0x30]`
- `[r12+0x10]`
- `[r12]`
- `[r12+0x8]`
- `[r12+0x20]`
- `[r12+0x28]`
- `[r12+0x58]`
- `[r12+0x70]`
- `[r12+0xA8]`
- `[r12+0x120]`
- `[r12+0x150]`
- `[r12+0x158]`
- `[r12+0x170]`
- `[r12+0x178]`

前段的 compare-driven decision construction 仍以 `[r12+0x190]` 為主，例如:

- `0x1416A7F15 cmp [r12+0x190], 0xCB00818704BD238C`
- `0x1416A7F18 setb [rsp+0xF]`
- `0x1416A7F1D cmp [r12+0x190], 0xCB00818704BD238B`
- `0x1416A7F2D seta r15b`
- `0x1416A7F31 cmp [r12+0x190], 0x259D270DC21E4397`
- `0x1416A7F41 seta r13b`
- `0x1416A7F45 cmp [r12+0x190], 0x259D270DC21E4398`
- `0x1416A7F52 setb dl`
- `0x1416A8255 cmp [r12+0x190], 0x1AFA94FBF7A606E7`
- `0x1416A8264 seta sil`

因此這段同樣不是短 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段目前可直接確認的欄位寬度包含:

- `sign-bit / 全寬符號延伸`:
  - `0x1416A7EB7 sar rcx, 0x3F`
  - `0x1416A7ED5 sar rax, 0x3F`
- `28-bit` / `0x1C` 邊界:
  - `0x1416A8360 and r8d, 0xFFFFFFF`
  - `0x1416A836D and r11d, 0xFFFFFFF`
  - `0x1416A838B shr r15, 0x1C`
  - `0x1416A83A5 shl r13, 0x1C`
  - `0x1416A83AC shr rax, 0x1C`
- `22-bit` / `0x16` 邊界:
  - `0x1416A8414 and edx, 0x3FFFFF`
  - `0x1416A841A and r9d, 0x3FFFFF`
  - `0x1416A8421 and ebp, 0x3FFFFF`
  - `0x1416A842A shr rcx, 0x16`
  - `0x1416A842E shr r8, 0x16`
- `36-bit` / `0x24` 邊界:
  - `0x1416A9661 shr r13, 0x24`
  - `0x1416A96D9 shr r11, 0x24`
  - `0x1416A96E5 shr r10, 0x24`
  - `0x1416A96E9 movabs r8, 0xFFFFFFFFF`
  - `0x1416A96F6 and rbx, r8`
  - `0x1416A96FC and r14, r8`

這些訊號合在一起，讓目前最穩妥的描述是:

- `0x1416A7E9C` 是 compare-driven mixed-width recomposition stage
- 前中段主體可直接見到 `28-bit/22-bit`
- 後段再切到 `36-bit` limb 與 sign-bit 相關處理

### 外層 shared state 與 pointer-mediated 寫回

這段目前看起來偏單層 shared-state mutation。  
已直接驗證的外層 shared state 寫回包括:

- `0x1416A93D9 mov [state+0x120], rax`
- `0x1416A9414 mov [state+0x158], rdi`
- `0x1416A9439 mov [state+0x170], rax`
- `0x1416A94AE mov [state+0x190], rbp`

另外中段可直接看到至少兩個 pointer-mediated side write:

- `0x1416A81A6 mov [target], r14`
- `0x1416A81D2 mov [target], r12`
- `0x1416A8451 mov [target], rsi`

因此目前更適合把它標成:

- 單層 shared-state recomposition / mutation stage
- 但夾帶多個經計算指標完成的 side write

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x1416A94E2 xor r9, 0x2E1295`
- `0x1416A9521 xor r8, 0x2E1295`
- `0x1416A952F xor r8, 0x2E1295`
- `0x1416A9536 add r8, [rsp+0xC8]`
- `0x1416A9546 jmp r8`

其中 `[rsp+0xC8]` 在前段來自:

- `[r12+0x150]`

因此這段尾跳模板又回到主 pipeline 常見的形狀:

- 先做 compare-driven mixed-width recomposition
- 回寫外層 shared state
- 再以計算出的目標加上 `[r12+0x150]` 做尾跳

尾端鄰近可見的新節點包括:

- `0x1416A9549`
  - 短 route-builder
  - `0xE77D00D248CB3A45 -> [r12+0x190]`
  - `0x30FD13 + [r12+0x150]`
- `0x1416A956A`
  - 結構選路型 route-builder / state shaper
  - 讀 `[r12+0x150]`
  - 依 `test rcx, rcx` / `cmovneq` 回寫 `[r12+0x88]`、`[r12+0x190]`
  - 在 `0x33011F` 與 `0x2A8C3D` 兩條目標之間選路

### `0x1416A95AE` 的特徵

`0x1416A95AE` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x1416AA799 add rax, [rsp+0xE8]`
- `0x1416AA8D8 jmp rax`

收尾，因此本體可視為 `0x1416A95AE -> 0x1416AA8D8`。  
從目前可直接驗證的控制流與寫回形狀來看，這段仍偏單層 shared-state stage，尚未看到像 `0x14169A4FF`、`0x14169AED0`、`0x14169F9C7` 那種明確 `mov r12, [r12+0x190]` 的 nested-state 下鑽。  
中段雖然一度把 `r10` 當作結構基底連續讀取多個欄位，但可直接追到:

- `0x1416A9BE0 mov r10, [rsp+0x38]`

而 `[rsp+0x38]` 來自開頭保存的原始 `r12`，因此目前較保守的寫法仍是:

- 這段會對原始 shared state 做多欄位讀寫
- 但尚未證明它切到獨立的次級 state block

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12+0xC8]`
- `[r12+0x158]`
- `[r12+0x190]`

中前段再陸續讀入:

- `[r12]`
- `[r12+0x8]`
- `[r12+0x18]`
- `[r12+0x20]`
- `[r12+0x28]`
- `[r12+0x58]`
- `[r12+0x88]`
- `[r12+0x90]`
- `[r12+0xA8]`
- `[r12+0xB0]`
- `[r12+0xD0]`
- `[r12+0x120]`
- `[r12+0x148]`
- `[r12+0x150]`
- `[r12+0x170]`
- `[r12+0x178]`

前段的 compare-driven decision construction 仍以 `[r12+0x190]` 為主，例如:

- `0x1416A95EF cmp rbp, 0x7EE444ED55EFA8AF`
- `0x1416A95F2 seta dl`
- `0x1416A9605 cmp rbp, 0xA127AFDD0782BF30`
- `0x1416A9608 setb dl`
- `0x1416A961D cmp rbp, 0xA127AFDD0782BF2F`
- `0x1416A9625 seta cl`

中後段還會再出現多組 equality / inequality compare，例如:

- `0x1416AAE54 cmp rcx, 0xD615CF96BDD2EEE5`
- `0x1416AAE57 sete r15b`
- `0x1416AAFAC cmp r8, 0xD615CF96BDD2EEE5`
- `0x1416AAFAF sete cl`
- `0x1416AB266 cmp rcx, 0xD615CF96BDD2EEE5`
- `0x1416AB26F setne r13b`

因此這段同樣不是短 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段目前可直接確認的欄位寬度包含:

- `36-bit` / `0x24` 邊界:
  - `0x1416A9661 shr r13, 0x24`
  - `0x1416A96D9 shr r11, 0x24`
  - `0x1416A96E5 shr r10, 0x24`
  - `0x1416A96E9 movabs r8, 0xFFFFFFFFF`
  - `0x1416A96F6 and rbx, r8`
  - `0x1416A96FC and r14, r8`
- `28-bit` / decision-bit 混合:
  - `0x1416A980D shr r10d, 0x1B`
  - `0x1416A9811 and r10d, 0x1`
  - `0x1416A98B4 movabs rcx, 0xFFFFFFF00`
  - `0x1416A98C1 shr rcx, 0x8`
  - `0x1416A98C5 and ecx, 0xFFFFFFF`
  - `0x1416A98F4 shr r8d, 0x1B`
- `39-bit` / `0x27` 邊界:
  - `0x1416AACDB movabs r11, 0x7FFFFFFFFF`
  - `0x1416AAD2C shr r11, 0x27`
  - `0x1416AAD38 shr rdx, 0x27`
  - `0x1416AAD42 shl rdx, 0x27`
  - `0x1416AB156 shr rax, 0x27`
  - `0x1416AB15F shr r15, 0x27`
  - `0x1416AB169 shl r15, 0x27`

這些訊號合在一起，讓目前最穩妥的描述是:

- `0x1416A95AE` 是 compare-driven mixed-width recomposition stage
- 前段先出現 `36-bit` limb
- 中前段混入 `28-bit` 與 `1-bit` decision-bit packing
- 後段再切到 `39-bit` limb / recomposition

### 外層 shared state 與 pointer-mediated 寫回

這段目前看起來偏單層 shared-state mutation。  
已直接驗證的外層 shared state 寫回包括:

- `0x1416A9D13 mov [state+0x8], rbx`
- `0x1416A9D18 mov [state], rbp`
- `0x1416AA611 mov [state+0x148], r13`
- `0x1416AA660 mov [state+0x158], rbx`
- `0x1416AA825 mov [state+0x170], rbx`
- `0x1416AA860 mov [state+0x178], rdi`
- `0x1416AA896 mov [state+0x190], r14`
- `0x1416AA8A7 mov [state+0x198], 0xAC0E58AABBA30B73`
- `0x1416AA8B8 mov [state+0x1A0], 0x969C7A21BA0AA74B`
- `0x1416AA8C9 mov [state+0x1A8], 0xFD706BAD33337659`

另外中前段還可直接看到多個 pointer-mediated side write:

- `0x1416A9D01 mov [target+0x8], rbx`
- `0x1416A9D0A mov [target], rbp`
- `0x1416AAED9 mov [target], rbp`
- `0x1416AAFE9 mov [target], rcx`

因此目前更適合把它標成:

- 單層 shared-state recomposition / mutation stage
- 但夾帶多個經計算指標完成的 side write

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x1416AA734 xor rdx, 0x2B4F6B`
- `0x1416AA74D xor rsi, 0x2B4F6B`
- `0x1416AA761 xor rax, 0x2B4F6B`
- `0x1416AA77E xor rax, 0x2B4F6B`
- `0x1416AA799 add rax, [rsp+0xE8]`
- `0x1416AA8D8 jmp rax`

其中 `[rsp+0xE8]` 在中段來自:

- `[state+0x150]`

因此這段尾跳模板仍屬於主 pipeline 常見的形狀:

- 先做 compare-driven mixed-width recomposition
- 回寫外層 shared state
- 再以計算出的目標加上 `[state+0x150]` 做尾跳

尾端鄰近可見的新節點包括:

- `0x1416AA8DA`
  - 結構重寫 / state shaper
  - `movb 1 -> [r12+0xC8]`
  - `([r12+0x150] + 0x30CDB0) -> [r12+0x190]`
  - `0x2EBDD8 + [r12+0x150]`
- `0x1416AA902`
  - 短 route-builder
  - `0xDBAD3A46F201CD67 -> [r12+0x198]`
  - `0x3265C1 + [r12+0x150]`
- `0x1416AA923`
  - 結構選路型 state shaper
  - 讀 `[r12]`、`[r12+0x90]`、`[r12+0xB0]`、`[r12+0xD0]`、`[r12+0x120]`、`[r12+0x150]`
  - 會做 `mov [target+0x140], edi`
  - 回寫 `[r12+0x90]`
  - 在 `0x327CBA` / `0x2F6856` 兩條目標間選路
- `0x1416AA97D`
  - 多 slot route-builder
  - `0x58A68E2CB7E37550 -> [r12+0x190]`
  - `0xBB3604EB62E12DF2 -> [r12+0x198]`
  - `0x3BCD3C82AAD7AD39 -> [r12+0x1A0]`
  - `0xFC524C691CEDCF8F -> [r12+0x1A8]`
  - `0x318EEE + [r12+0x150]`
- `0x1416AA9D4`
  - 結構抽取 / state shaper
  - 讀 `[r12+0x70]`、`[r12+0x88]`、`[r12+0xD0]`、`[r12+0x108]`、`[r12+0x148]`、`[r12+0x150]`、`[r12+0x170]`
  - 回寫 `[r12+0x70]`、`[r12+0x170]`
  - 另可見三個 pointer-mediated side write
  - 在 `0x2974FE` / `0x2F0C6E` 兩條目標間選路
- `0x1416AAA87`
  - 短 route-builder
  - `0xB7FF91DDAC7DC02F -> [r12+0x190]`
  - `0x29FB86 + [r12+0x150]`
- `0x1416AAAA8`
  - 結構重寫 / pointer-mediated state shaper
  - 讀 `[r12+0x30]`、`[r12+0xB0]`、`[r12+0xC8]`、`[r12+0x150]`、`[r12+0x170]`、`[r12+0x198]`
  - 回寫 `[r12+0x170]`、`[r12+0x190]`、`[r12+0x198]`
  - 另可見 `mov [target], r9` 與 `mov [target], rdi`
  - `0x2977BF` / `0x313C8D` 類 offset 混合後尾跳
- `0x1416AABCD`
  - 短 route-builder
  - `0x302D508D170F9389 -> [r12+0x190]`
  - `0x2C95D7 + [r12+0x150]`
- `0x1416AABEE`
  - 現已可視為完整 stage，不再只是起點骨架
  - 本體在 `0x1416ABB9E jmp rcx` 結束
  - 開頭讀 `[r12]`、`[r12+0x30]`、`[r12+0x198]`
  - 中前段再擴張讀取 `[r12+0x190]`、`[r12+0x58]`、`[r12+0x70]`、`[r12+0x88]`、`[r12+0xA8]`、`[r12+0xB0]`、`[r12+0x150]`、`[r12+0x178]`
  - compare 來源已驗證包含:
    - `cmp [r12+0x198], 0x7AB16AA0500D4625`
    - `cmp [r12+0x198], 0x1B4B67B74CE02642`
    - 後接 `seta/setb/or`
  - 中後段 equality compare 已驗證包含:
    - `cmp ..., 0xD615CF96BDD2EEE5`
    - 後接 `sete`

### `0x1416AABEE` 的特徵

`0x1416AABEE` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x1416ABB91 add rcx, [rsp+0x68]`
- `0x1416ABB9E jmp rcx`

收尾，因此本體可視為 `0x1416AABEE -> 0x1416ABB9E`。  
從目前可直接驗證的控制流與寫回形狀來看，這段仍偏單層 shared-state stage，尚未看到像 `0x14169A4FF`、`0x14169AED0`、`0x14169F9C7` 那種明確 `mov r12, [r12+0x190]` 的 nested-state 下鑽。

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12]`
- `[r12+0x30]`
- `[r12+0x198]`

中前段再陸續讀入:

- `[r12+0x190]`
- `[r12+0x58]`
- `[r12+0x70]`
- `[r12+0x88]`
- `[r12+0xA8]`
- `[r12+0xB0]`
- `[r12+0x150]`
- `[r12+0x178]`

前段的 compare-driven decision construction 仍以 `[r12+0x198]` 為主，例如:

- `0x1416AAC29 cmp [r12+0x198], 0x7AB16AA0500D4625`
- `0x1416AAC36 seta cl`
- `0x1416AAC39 cmp [r12+0x198], 0x1B4B67B74CE02642`
- `0x1416AAC46 setb al`
- `0x1416AAC49 orb cl, al`

中後段還會再出現 equality compare，例如:

- `0x1416AAE54 cmp rcx, 0xD615CF96BDD2EEE5`
- `0x1416AAE57 sete r15b`
- `0x1416AAFAC cmp r8, 0xD615CF96BDD2EEE5`
- `0x1416AAFAF sete cl`

因此這段同樣不是短 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段目前可直接確認的欄位寬度包含:

- `39-bit` / `0x27` 邊界:
  - `0x1416AACDB movabs r11, 0x7FFFFFFFFF`
  - `0x1416AAD2C shr r11, 0x27`
  - `0x1416AAD38 shr rdx, 0x27`
  - `0x1416AAD42 shl rdx, 0x27`
  - `0x1416AB156 shr rax, 0x27`
- byte / 1-bit decision packing:
  - `0x1416AAC70 andb dil, cl`
  - `0x1416AAC73 movzbl cl, eax`
  - `0x1416AB6C0 movzbl [r15], eax`
  - `0x1416AB91D movzbl [rsp+7], esi`
  - `0x1416AB922 mov [target], sil`

這些訊號讓目前最穩妥的描述是:

- `0x1416AABEE` 是 compare-driven mixed-width recomposition stage
- 已能直接確認 `39-bit` limb / carry-style重組
- 並混入 byte / 1-bit decision-bit packing 與 side write

目前還沒有足夠證據把它寫成更窄的 `13-bit/12-bit/26-bit/34-bit` 主體 stage；至少在這輪直接交叉驗證裡，最穩的寬度訊號仍是 `39-bit` 與 byte 級重組。

### 外層 shared state 與 pointer-mediated 寫回

這段目前看起來偏單層 shared-state mutation。  
已直接驗證的外層 shared state 寫回包括:

- `0x1416AB935 mov [state], rcx`
- `0x1416AB939 mov [state+0x30], rdx`
- `0x1416AB9F2 mov [state+0x88], r9`
- `0x1416ABA54 mov [state+0xB0], rax`
- `0x1416ABAB6 mov [state+0x178], rcx`
- `0x1416ABAF1 mov [state+0x190], rdx`
- `0x1416ABB03 mov [state+0x198], 0xB68E668902299777`

另外中段還可直接看到多個 pointer-mediated side write:

- `0x1416AAED9 mov [target], rbp`
- `0x1416AAFE9 mov [target], rcx`
- `0x1416AB7C2 mov [target], rbp`
- `0x1416AB922 mov [target], sil`

因此目前更適合把它標成:

- 單層 shared-state recomposition / mutation stage
- 但夾帶多個經計算指標完成的 side write

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x1416ABB3E imul rdi, 0x29F96B`
- `0x1416ABB57 xor rdi, 0x29F96B`
- `0x1416ABB65 xor rdx, 0x29F96B`
- `0x1416ABB7C xor rcx, 0x29F96B`
- `0x1416ABB8A xor rcx, 0x29F96B`
- `0x1416ABB91 add rcx, [rsp+0x68]`
- `0x1416ABB9E jmp rcx`

其中 `[rsp+0x68]` 在中段來自:

- `[r12+0x150]`

因此這段尾跳模板仍屬於主 pipeline 常見的形狀:

- 先做 compare-driven mixed-width recomposition
- 回寫外層 shared state
- 再以計算出的目標加上 `[r12+0x150]` 做尾跳

尾端鄰近可見的新節點包括:

- `0x1416ABBA0`
  - 現已可視為完整 stage，不再只是起點骨架
  - 本體在 `0x1416ADF15 jmp rax` 結束
  - 開頭讀 `[r12+0xC8]`、`[r12+0x190]`
  - 中前段再擴張讀取 `[r12+0x120]`、`[r12+0x30]`、`[r12+0x18]`、`[r12+0x58]`、`[r12+0x70]`、`[r12+0x88]`、`[r12+0xD0]`、`[r12+0x148]`、`[r12+0x150]`、`[r12+0x178]`
  - compare 來源已驗證包含:
    - `cmp [r12+0x190], 0xB3B6DD620EA128E2`
    - `cmp [r12+0x190], 0xB3B6DD620EA128E1`
    - `cmp [r12+0x190], 0x98E6B29EE56276CC`
    - `cmp [r12+0x190], 0x98E6B29EE56276CB`
    - `cmp [r12+0x190], 0x464BA3B4EC16A75A`
    - 後接 `seta/setb/or`
  - 中後段 equality compare 已驗證包含:
    - `cmp ..., 0x8100191FD41DCF48`
    - 後接 `sete/setne`

### `0x1416ABBA0` 的特徵

`0x1416ABBA0` 現在也已可從起點骨架補成一個完整 stage。  
它在:

- `0x1416ADF02 add rax, [rsp+0x188]`
- `0x1416ADF15 jmp rax`

收尾，因此本體可視為 `0x1416ABBA0 -> 0x1416ADF15`。  
從目前可直接驗證的控制流與寫回形狀來看，這段仍偏單層 shared-state stage，尚未看到明確 `mov r12, [r12+0x190]` 的 nested-state 下鑽。

### 開頭輸入與 decision construction

開頭已可直接確認它消費:

- `[r12+0xC8]`
- `[r12+0x190]`

中前段再陸續讀入:

- `[r12+0x120]`
- `[r12+0x30]`
- `[r12+0x18]`
- `[r12+0x58]`
- `[r12+0x70]`
- `[r12+0x88]`
- `[r12+0xD0]`
- `[r12+0x148]`
- `[r12+0x150]`
- `[r12+0x178]`

前段的 compare-driven decision construction 仍以 `[r12+0x190]` 為主，例如:

- `0x1416ABBC2 cmp [r12+0x190], 0xB3B6DD620EA128E2`
- `0x1416ABBC5 setb [rsp+0x140]`
- `0x1416ABBD9 cmp [r12+0x190], 0xB3B6DD620EA128E1`
- `0x1416ABBDC seta dl`
- `0x1416ABCFB setb [rsp+0x30]`
- `0x1416ABD0F seta bl`
- `0x1416ABD23 cmp [r12+0x190], 0x464BA3B4EC16A75A`
- `0x1416ABD29 orb bl, al`

中後段還會再出現 equality / inequality compare，例如:

- `0x1416AC00C cmp rax, 0x8100191FD41DCF48`
- `0x1416AC00F setne cl`
- `0x1416AC01A sete sil`

因此這段同樣不是短 route-builder，而是新的 compare-driven state-processing stage。

### 已驗證的欄位寬度訊號

這段目前可直接確認的欄位寬度包含:

- `12-bit` / `0x0C` 邊界:
  - `0x1416ABE4A and r10d, 0xFFF`
  - `0x1416ABE71 and r13d, 0xFFF`
  - `0x1416ABE85 and ebx, 0xFFF`
  - `0x1416ABE8D shr ecx, 0x0C`
  - `0x1416ABEBD shl r10d, 0x0C`
- `13-bit` / `0x0D` 邊界:
  - `0x1416AC4F5 shr ecx, 0x0D`
  - `0x1416AC502 shr r12d, 0x0D`
  - `0x1416AC52B shr ecx, 0x0D`
  - 大量 `and/test 0x1FFF`
- `26-bit` / `0x1A` 邊界:
  - `0x1416AC3C6 shl eax, 0x1A`
  - `0x1416AC3C9 and esi, 0x3FFFFFF`
  - `0x1416AC6A8 shr eax, 0x1A`
  - `0x1416AC6BB shr r11d, 0x1A`
  - `0x1416ACC5A shl eax, 0x1A`
  - `0x1416ACC61 and ecx, 0x3FFFFFF`
- `34-bit` / `0x22` 邊界:
  - `0x1416AD566 movabs r9, 0x3FFFFFFFF`
  - `0x1416AD5DA movabs rdi, 0x3FFFFFFFF`
  - `0x1416AD65B movabs rax, 0x3FFFFFFFF`
  - `0x1416AD72E shl r8, 0x22`

另外整段反覆混入 byte / decision-bit packing:

- `movzbl`
- `andb`
- `orb`
- `addb/subb`

這些訊號讓目前最穩妥的描述是:

- `0x1416ABBA0` 是 compare-driven mixed-width recomposition stage
- 前段以 `12-bit/13-bit` 子欄位為主
- 中段明確切到 `26-bit`
- 後段再切到 `34-bit` limb / carry-style 重組

### 外層 shared state、pointer-mediated 寫回與次級 block side write

這段目前看起來偏單層 shared-state mutation。  
已直接驗證的外層 shared state 寫回包括:

- `0x1416AE05D mov [state+0x30], rdi`
- `0x1416AE07A mov [state+0x88], rsi`
- `0x1416AE0A6 mov [state+0x190], r11`
- `0x1416AE0BF mov [state+0x198], r14`
- `0x1416AE0CE mov [state+0x1A0], rcx`

另外中段還可直接看到多個 pointer-mediated / side write:

- `0x1416AC608 mov [target], rdi`
- `0x1416AC70A mov [target], r9d`
- `0x1416AC78A mov [target], ebx`
- `0x1416AC80D mov [target], edi`

並且可見一個以保存的原始 `r12` 為基底的次級 block side write:

- `0x1416ADE9F mov [orig_state+0x198], rdi`

目前較保守的寫法仍是:

- 主體仍是單層 shared-state recomposition / mutation stage
- 但夾帶多個經計算指標完成的 side write，且至少有一處寫回到保存的原始 state block 偏移 `0x198`

### 尾端控制流與後續鄰域

尾端已可直接確認不是 `ret`:

- `0x1416ADE82 xor r10, 0x30DF86`
- `0x1416ADEAF xor r14, 0x30DF86`
- `0x1416ADEC6 xor r8, 0x30DF86`
- `0x1416ADEEF xor rax, 0x30DF86`
- `0x1416ADEFC xor rax, 0x30DF86`
- `0x1416ADF02 add rax, [rsp+0x188]`
- `0x1416ADF15 jmp rax`

其中 `[rsp+0x188]` 在前段來自:

- `[r12+0x150]`

因此這段尾跳模板仍屬於主 pipeline 常見的形狀:

- 先做 compare-driven mixed-width recomposition
- 回寫外層 shared state
- 再以計算出的目標加上 `[r12+0x150]` 做尾跳

尾端鄰近可見的新節點包括:

- `0x1416ADF17`
  - 短 state shaper / pointer-mediated route-builder
  - 讀 `[r12+0x30]`、`[r12+0x88]`、`[r12+0x190]`、`[r12+0x150]`
  - 回寫 `[r12+0x30]`、`[r12+0x88]`、`[r12+0x190]`、`[r12+0x198]`、`[r12+0x1A0]`
  - `0x2977BF` / `0x2971B3` / `0x2FCD9A` / `0x2E5015` 類 offset 混合後尾跳
- `0x1416AE0E7`
  - 下一個大 stage 起點
  - 開頭已可見讀 `[r12+0x30]`、`[r12+0x190]`

因此目前可以把後續骨架再往下推成:

- `0x1416A95AE`
  - compare-driven `36-bit` 主體，後接 `28-bit` / `1-bit` decision-bit packing 與 `39-bit` limb 的單層 shared-state stage
- `0x1416AA8DA / 0x1416AA923 / 0x1416AA9D4 / 0x1416AAAA8`
  - 結構重寫 / state-shaper family
- `0x1416AA902`
  - 新的 `[r12+0x198]`-oriented route-builder
- `0x1416AAA87 / 0x1416AABCD`
  - 新的 `[r12+0x190]`-oriented route-builder family
- `0x1416AA97D`
  - 多 slot route-builder
- `0x1416AABEE`
  - compare-driven `39-bit` 主體，混入 byte / `1-bit` decision-bit packing 的單層 shared-state stage
- `0x1416ABBA0`
  - compare-driven `12-bit/13-bit` 主體、後接 `26-bit/34-bit` limb 與 byte 級 decision packing 的單層 shared-state stage
- `0x1416ADF17`
  - 短 state-shaper / pointer-mediated route-builder
- `0x1416AE0E7`
  - 下一個大 stage 的新起點

## `sect_6` 重驗證

`sect_6` 開頭不是乾淨線性程式，而是混合跳躍、常數、間接表與硬體指令。  
其中一段已可直接確認包含環境探測:

- `0x14028D0BA sidt [rax]`
- `0x14028D0C5 cpuid`
- `0x14028D0DA sgdt [rax]`

這段邏輯還會把 `cpuid` 結果寫到由 `r8` 指向的輸出緩衝區:

- `mov [r8], eax`
- `mov [r8+4], ebx`
- `mov [r8+8], ecx`
- `mov [r8+0xC], edx`

### 對 `sect_6` 的結論

可直接成立的結論是:

- `sect_6` 內含真實的硬體 / 描述表讀取指令。
- 這些指令足以支撐 anti-VM / anti-instrumentation / execution environment fingerprinting 類分析。
- 它不是純填充、也不是單純的不可達垃圾碼。
- 它目前看不到對應的 unwind metadata，與 `sect_7` 的函式呈現方式明顯不同。

## `FltRegisterFilter` 的意義

IAT 中明確存在 `FLTMGR.SYS!FltRegisterFilter`，因此樣本確實具備與 Filter Manager 互動的能力。  
但在這一輪靜態抽樣中，沒有直接從簡單的線性 XREF 找到乾淨明顯的呼叫點。

這與前述極小 import surface 完全一致，代表:

- 呼叫點很可能被內部 resolver / dispatcher 包裝
- 或透過保護層導向 IAT
- 僅靠入口附近與節區開頭不能直接還原完整 minifilter 註冊流程

所以這裡的正確表述應是:

- `FltRegisterFilter` 的存在已被驗證
- 其具體註冊路徑在這一版報告中尚未完全還原

相對地，`ntoskrnl.exe!__chkstk` 則存在清楚的 import thunk:

- `0x14017D790 jmp qword [0x14017F010]`

這代表兩個 import 雖然同樣出現在 IAT 中，但靜態可見度並不對稱:

- `__chkstk` 有直接可見的跳板
- `FltRegisterFilter` 目前仍只看到 IAT / relocation 層級的存在證據

## 目前能安全下的結論

1. 此樣本為正式簽署的 x64 Native kernel driver，版本欄位為 `3.2.0.0`。
2. import surface 極小，只直接導入 `FltRegisterFilter` 與 `__chkstk`。
3. 入口流程先做 security cookie 驗證，再跳入內部 trampoline / dispatcher。
4. `sect_7` 明確扮演大型 context wrapper 的角色。
5. `sect_6` 明確包含 `sidt/cpuid/sgdt` 類環境探測邏輯。
6. `.pdata` 顯示 `sect_7` 與 `sect_6` 的函式可見性差異很大，前者有大量 runtime function entry，後者則沒有。
7. `sect_7` 內大量小函式的尺寸高度集中，顯示它包含重複模板化的 micro-op / accessor 類 stub。
8. 樣本大量依賴空白節區名、巨大執行節區與間接控制流來降低靜態可讀性。

## 尚未完成但應列為後續工作

1. 以 `.pdata` 為基礎重建 `sect_7` 中更大範圍的函式邊界，特別是 `0x14029029D` 之後的批量小函式群。
2. 為 `0x32` / `0x34` / `0x3A` / `0x3C` / `0x4D` 這幾種高頻 stub 長度建立更完整的語意分組，確認哪些是 load、store、compare、branch-builder。
3. 針對 `0x1402E9770` 後續鏈路補完整的 dispatch path，特別是 `0x141694ACC` 到 `0x141694B71` 之後的真實落點。
4. 確認 `0x141694B71` 所就地更新的 state block 欄位語意，至少釐清 `[rbx]`、`[rbx+0x30]`、`[rbx+0x70]`、`[rbx+0x170]` 的角色。
5. 追 `FltRegisterFilter` 的真正呼叫點，確認是否為 minifilter 初始化或延遲註冊。
6. 擴大 `sect_6` 鄰近區塊的控制流還原，分辨環境探測、混淆輔助函式與實際保護策略，並確認它是否刻意不參與標準 unwind 登錄。
7. 交叉比對既有 `function_map.md` 與 `startup_runtime_analysis.md`，把已驗證與待驗證項目分開。

## 報告修正原則

本版有意避免把「看起來像」寫成「已證明是」。  
例如:

- 可以說 `sect_7` 具有 dispatcher / wrapper 特徵
- 不能在沒有更深 CFG 還原前，直接斷言整個區段就是完整 VM handler 區

同理:

- 可以說 `sect_6` 含有 anti-VM 類訊號
- 不能只靠 `sidt/cpuid/sgdt` 三個指令就聲稱全部保護策略都已完全還原

這樣寫法比較能扛住反覆核對。

## 可重現命令

以下命令是本報告直接依賴、且已在本機樣本上重跑過的一組最小驗證命令。之後若樣本更新，可先重跑這組再比對差異。

```powershell
Get-FileHash C:\Users\<user>\Desktop\EAC\EasyAntiCheat_EOS.sys -Algorithm SHA256
Get-AuthenticodeSignature C:\Users\<user>\Desktop\EAC\EasyAntiCheat_EOS.sys
[System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Users\<user>\Desktop\EAC\EasyAntiCheat_EOS.sys")
llvm-readobj --file-headers --sections --coff-imports C:\Users\<user>\Desktop\EAC\EasyAntiCheat_EOS.sys
rabin2 -I C:\Users\<user>\Desktop\EAC\EasyAntiCheat_EOS.sys
radare2 -AA -q -c "s entry0; pdf; s 0x140290000; pd 80; s 0x1402E9770; pd 120; s 0x14028D0BA; pd 32" C:\Users\<user>\Desktop\EAC\EasyAntiCheat_EOS.sys
```

若這組命令的輸出與本報告不一致，優先懷疑的是:

- 樣本 build 已更換
- 反組譯起點不同
- 分析時使用了另一份 runtime-dumped 映像
