# 內部作弊與 DLL 注入器 — 技術分析

> 本文是 [EAC Kernel Driver 分析](README.md) 系列的一部分。

內部作弊對反作弊系統來說是最棘手的偵測目標。作弊 DLL 直接跑在遊戲 process 內部 — 共用同一塊位址空間、擁有相同權限、可以存取所有遊戲資料。注入器負責把它送進去而不留下痕跡。本文整理了目前已知的各種注入手法，以及 EAC 針對每種手法的具體偵測邏輯。

---

## 目錄
1. [內部作弊的特殊性](#1-內部作弊的特殊性)
2. [LoadLibrary 注入偵測](#2-loadlibrary-注入偵測)
3. [Manual Mapping 偵測](#3-manual-mapping-偵測)
4. [APC 注入偵測](#4-apc-注入偵測)
5. [Thread Hijacking 偵測](#5-thread-hijacking-偵測)
6. [Process Hollowing / Doppelgänging 偵測](#6-process-hollowing--doppelgänging-偵測)
7. [Kernel-Mode DLL 注入偵測](#7-kernel-mode-dll-注入偵測)
8. [VAD Tree — 內部偵測的核心機制](#8-vad-tree--內部偵測的核心機制)
9. [PEB 模組列表完整性](#9-peb-模組列表完整性)
10. [Code Cave 與 Shellcode 偵測](#10-code-cave-與-shellcode-偵測)
11. [EAC 注入器偵測的已知缺口](#11-eac-注入器偵測的已知缺口)

---

## 1. 內部作弊的特殊性

內部作弊在**遊戲的位址空間內**執行 — 它們以 DLL 或 shellcode 的形式載入在 `Fortnite.exe`/`PUBG.exe` 等裡面。這給了它們：
- 不需要 `ReadProcessMemory` 就能直接存取所有遊戲記憶體
- 在組合語言層面 hook 遊戲函式的能力（inline hook、vtable hook）
- 存取遊戲的 DirectX/Vulkan context 來渲染

但這也意味著它們在**遊戲 process 內部**留下了 EAC 可以找到的痕跡。

---

## 2. LoadLibrary 注入偵測

### 技術說明

```c
// 注入器 process：
LPVOID addr = VirtualAllocEx(hGame, NULL, strlen(dllPath)+1, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hGame, addr, dllPath, strlen(dllPath)+1, NULL);
CreateRemoteThread(hGame, NULL, 0, LoadLibraryA, addr, 0, NULL);
```

這是最古老也最廣為人知的注入技術。EAC 透過多個向量偵測它：

### 偵測向量 1：Thread 建立 Callback

EAC 註冊 `PsSetCreateThreadNotifyRoutine`。當遊戲 process 中啟動新 thread 時：

```c
// EAC 的 thread 建立 callback：
VOID ThreadNotifyCallback(HANDLE pid, HANDLE tid, BOOLEAN create) {
    if (!create) return;
    if (pid != gamePID) return;  // 只關心遊戲 thread
    
    // 取得新 thread 的起始位址
    PVOID startAddr = PsGetThreadStartAddress(..);
    
    // 起始位址是否在已知的已載入模組內？
    if (!IsInKnownModule(startAddr)) {
        // Thread 從未知區域啟動 → 偵測到注入器
        flag_suspicious_thread(tid, startAddr);
    }
    
    // 起始位址是否 == LoadLibraryA / LoadLibraryW？
    // 經典遠端 thread 注入特徵
    if (startAddr == cached_LoadLibraryA || startAddr == cached_LoadLibraryW) {
        flag_loadlibrary_injection(pid, tid);
    }
}
```

### 偵測向量 2：Handle 檢查

注入器 process 必須以 `PROCESS_CREATE_THREAD | PROCESS_VM_WRITE` 開啟遊戲。這兩者都被 EAC 的 handle table 掃描器抓到（見 [外部作弊偵測](external_cheat_detection.md#2-handle-偵測)）。

### 偵測向量 3：載入後模組列表掃描

建立 thread 後，EAC 透過 `EPROCESS` 存取檢查遊戲的 `PEB.Ldr.InLoadOrderModuleList`。自上次掃描以來出現的任何新模組都會被檢查：
- 它在磁碟上嗎？（無檔案注入沒有 backing file）
- 它有簽名嗎？
- 它的 DiskHash == InMemoryHash 嗎？

---

## 3. Manual Mapping 偵測

Manual mapping 是注入技術中最複雜的一種。注入器手動複製 Windows loader 的工作，完全不呼叫 `LoadLibrary`：

```
注入器：
1. 在遊戲 process 中分配 RWX 記憶體（大小 = DLL 虛擬大小）
2. 把 PE header + section 複製到分配的記憶體中
3. 手動應用重定位（修補所有絕對位址）
4. 手動解析 import（查找所有 DLL export，修補 IAT）
5. 透過 CreateRemoteThread 直接呼叫 DllMain
6. 可選：從映射的記憶體中清除 PE header（反掃描）
```

結果是一個在**遊戲 process 內執行、但在 PEB 模組列表中沒有項目、磁碟上也沒有 backing file** 的 DLL。

### EAC 如何偵測 Manual Map

#### 偵測方式 1：VAD Tree 掃描（主要手段）

這是最強力也最可靠的偵測方式。VAD（Virtual Address Descriptor）tree 追蹤每個分配的記憶體區域。EAC 透過 `EPROCESS+240` 遍歷遊戲 process 的完整 VAD tree：

```c
// 遍歷遊戲 process 的 VAD tree：
PMMVAD node = *(PMMVAD*)(gameEPROCESS + 240);  // VadRoot
PMMVAD stack[256];  // DFS 遍歷 stack
int depth = 0;

while (node || depth > 0) {
    // 檢查每個 VAD 節點：
    ULONG_PTR startVA = node->StartingVpn << PAGE_SHIFT;
    ULONG_PTR endVA   = node->EndingVpn   << PAGE_SHIFT;
    ULONG     protect = node->u.VadFlags.Protection;  // 頁面保護
    ULONG     type    = node->u.VadFlags.VadType;     // 0=私有, 1=映射, 2=section
    
    // 可疑：私有、可執行、沒有 file section object backing
    if (type == 0 &&                          // VadNone（私有）
        (protect & PAGE_EXECUTE_READWRITE ||
         protect & PAGE_EXECUTE_READ) &&
        !node->SubSection) {                  // 沒有 file backing
        // 可執行的私有記憶體 → shellcode / manual map
        scan_region(startVA, endVA);
    }
    
    // 可疑：可執行 section 但不在模組列表中
    if (type == 1 /*mapped*/ && is_pe_image(startVA) && !in_module_list(startVA)) {
        flag_hidden_module(startVA, endVA);
    }
}
```

#### 偵測方式 2：私有記憶體中的 PE Header 掃描

即使注入器在映射後清除了 MZ/PE header，EAC 仍然能識別映射的 DLL，因為：
- Section 邊界在可預測的、頁面對齊的偏移處
- Import table 留下指紋（已解析函式指標的陣列）
- `.text` section 有特徵性的熵模式
- Export directory bytes 可能仍然部分存在

EAC 使用基於 SIMD 的熵估計和模式匹配來識別沒有 header 的 PE image。

#### 偵測方式 3：RWX 記憶體區域標記

`PAGE_EXECUTE_READWRITE`（`0x40`）是一個巨大的紅旗。合法的程式碼永遠不會是 RWX — 它要麼是 `RX`（可執行程式碼），要麼是 `RW`（可寫資料），永遠不會兩者都是。遊戲 process 中任何 RWX 區域都會：
- 立即被標記
- 被掃描 PE 特徵碼
- 即使沒有找到 PE 也會在遙測中回報（RWX 本身就值得回報）

---

## 4. APC 注入偵測

APC（Asynchronous Procedure Call）注入向目標 process 中的 thread 排隊一個 APC。APC 函式在 thread 進入可警示等待狀態時執行（例如呼叫 `SleepEx`）。

```c
// 注入器：
QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)remoteDllPath);
// 或 kernel-mode：
KeInsertQueueApc(apc, kernelRoutine, rundownRoutine, normalRoutine, normalCtx, mode);
```

### EAC 偵測

```c
// EAC 可以透過 ETHREAD 檢查每個 thread 的 APC 佇列：
// ETHREAD.ApcState.UserApcPending
// ETHREAD.ApcState.ApcListHead[UserMode] 

// 指向 LoadLibraryA 或非模組位址的排隊 APC = 注入
// EAC 也查看 OriginalApcContext，如果仍然存在的話可以揭露 DLL 路徑
```

弱點：等 EAC 檢查時，APC 可能已經執行完畢，佇列是空的。這讓 APC 注入在事後更難抓到 — 主要是透過後續的模組列表變化來抓。

---

## 5. Thread Hijacking 偵測

Thread hijacking 修改現有 thread 的執行 context（暫存器、指令指標）來重定向到注入的程式碼。

```c
// 注入器：
SuspendThread(hThread);
GetThreadContext(hThread, &ctx);
ctx.Rip = (DWORD64)shellcodeAddr;  // 重定向指令指標
SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
```

### EAC 偵測

Thread 建立 callback（`PsSetCreateThreadNotifyRoutine`）**不會**在 thread hijacking 時觸發 — 沒有建立新 thread。EAC 依賴：

1. **定期 thread 掃描**：遍歷遊戲 EPROCESS 中的所有 thread（`EPROCESS.ActiveThreads`），在掃描時檢查每個 thread 當前的 `Rip` — 如果 Rip 在所有已知模組之外，thread 被劫持了（或正在執行注入的程式碼）。

2. **Exception/trap callback**：`KiSetSystemAffinityThread` 和 context switch 期間的 trap frame 檢查可以暴露 thread 在意外位址執行的情況。

3. **劫持後的痕跡**：劫持後，新程式碼最終會呼叫 `LoadLibrary` 或分配記憶體，這會被 EAC 的其他掃描器抓到。

---

## 6. Process Hollowing / Doppelgänging 偵測

**Process Hollowing**：以暫停狀態啟動合法 process，取消映射其程式碼，用作弊程式碼替換，然後恢復執行。

**Process Doppelgänging**：相同概念但使用 NTFS 交易建立一個幻影檔案，Windows loader 映射它然後回滾，在磁碟上不留任何痕跡。

### EAC 偵測

```c
// Process hollowing 留下一個從 section 映射的 VAD 項目，
// 但不符合 process 的 image 檔案路徑。EAC 透過以下方式偵測：

// 1. 讀取 EPROCESS.SectionObject → 取得映射的 section
// 2. 讀取 section 的 FileObject 路徑
// 3. 與 EPROCESS.SeAuditProcessCreationInfo.ImageFileName 比對
// 如果不同 → process hollowing

// 對於 doppelgänging：
// NTFS 交易被回滾，所以 backing file 技術上不存在。
// EAC 偵測這個為：file-backed VAD section，其 file object 沒有有效的
// MftFileRecord → 幻影 file section
```

---

## 7. Kernel-Mode DLL 注入偵測

一些進階注入器使用 **kernel driver** 直接注入 DLL，繞過所有 user-mode 注入偵測：

```c
// Kernel 注入器技術：
// 1. 暫停所有遊戲 thread（透過 kernel thread 操控）
// 2. 透過目標 EPROCESS 上的 MmAllocateVirtualMemory 在遊戲 process 中分配記憶體
// 3. 直接複製 DLL bytes
// 4. 在 kernel 中手動修復重定位
// 5. 向遊戲主 thread 排隊 user-mode APC 來呼叫 DLL entry point
// 6. 恢復所有 thread
```

### EAC 偵測

這是 EAC 的 **DKOM 和 kernel driver 列舉**變得關鍵的地方。如果 kernel 注入器 driver 正在執行：

1. EAC 的模組掃描（`PsLoadedModuleList` + 實體記憶體 PE 掃描）找到注入器 driver
2. 注入器 driver 的 dispatch table 可能被 hook 或異常
3. 注入器通常呼叫目標 process 上的 `ObReferenceObjectByName` — EAC 可以監控 object manager callback

注入的 DLL 仍然出現在 VAD tree 和 PEB 掃描中，給 EAC 兩條獨立的偵測路徑。

---

## 8. VAD Tree — 內部偵測的核心機制

**Virtual Address Descriptor** tree 是偵測內部作弊最關鍵的資料結構。EAC 在 `EPROCESS+240`（`VadRoot`）直接存取它。

### EAC 對每個 VAD 節點的檢查項目

```
對遊戲 process 中的每個 VAD 節點：
├── VadFlags.Protection：
│   ├── PAGE_EXECUTE_READWRITE (0x40) → RWX = 立即標記
│   ├── PAGE_EXECUTE_WRITECOPY (0x80) → 可疑
│   ├── PAGE_EXECUTE_READ (0x20) → 進一步檢查
│   └── PAGE_NOACCESS (0x01) → 白名單
│
├── VadFlags.VadType：
│   ├── VadNone (0) = 私有分配
│   │   └── 如果可執行且沒有 backing section → shellcode / manual map
│   ├── VadImageMap (2) = 映射 image（合法 DLL）
│   │   └── 如果不在 PEB 模組列表中 → 隱藏注入
│   └── VadAwe (3) = AWE 記憶體（遊戲不常見）
│
├── SubSection 指標：
│   ├── NULL → 沒有 file backing（私有分配或手動映射）
│   └── 非 NULL → 檢查 ControlArea.FileObject.FileName
│       └── 檔案路徑不在白名單中 → 可疑模組
│
└── 大小檢查：
    └── 非常大的私有可執行區域（> 10MB）→ 標記
```

### 為什麼這很難繞過

要完全逃避 VAD 掃描，攻擊者必須：
1. 移除/修改注入區域的 VAD 節點
2. 這需要 kernel 權限
3. 但有 kernel 權限意味著 EAC 的 driver 掃描器應該能找到攻擊者的 driver
4. 形成一個非常難以打破的循環依賴

一些研究人員已經展示了 VAD 節點操控，但它需要極其精確的 kernel 物件操控，往往會導致藍屏。

---

## 9. PEB 模組列表完整性

Windows PEB（Process Environment Block）維護三個已載入模組的雙向鏈結串列：
- `Ldr.InLoadOrderModuleList` — 按載入時間排序
- `Ldr.InMemoryOrderModuleList` — 按記憶體位址排序
- `Ldr.InInitializationOrderModuleList` — 按初始化順序排序

作弊有時會把自己從這些列表中移除來隱藏。EAC 交叉驗證：

```c
// EAC 透過 EPROCESS.Peb 讀取 PEB（user-mode 可存取的結構）：
PPEB peb = *(PPEB*)(gameEPROCESS + PEB_OFFSET);

// 遍歷 InLoadOrderModuleList：
PEB_LDR_DATA* ldr = peb->Ldr;
LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
LIST_ENTRY* cur  = head->Flink;

while (cur != head) {
    LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    
    // 這個模組的基址是否符合 VAD tree？
    if (!FindVadNode(entry->DllBase)) {
        // 模組在 PEB 列表中但沒有 VAD 節點 → PEB 項目被損壞
        flag_peb_tampering();
    }
    
    cur = cur->Flink;
}

// 同時：遍歷 VAD tree 尋找不在 PEB 列表中的 IMAGE 類型節點
ForEachImageVad { 
    if (!FindPebEntry(vadBase)) {
        // Image 在 VAD tree 中但不在 PEB 列表中 → 隱藏注入
        flag_hidden_module();
    }
}
```

---

## 10. Code Cave 與 Shellcode 偵測

**Code cave** 是合法模組內未使用的 byte 序列（函式之間的間隙、填充 section），注入器用 shellcode 填充它們。這避免了分配新記憶體 — 程式碼在已白名單的區域內執行。

### EAC 偵測

```c
// 對每個已載入的模組，EAC 計算區域 hash：
// 1. 從 \Windows\System32 載入每個 DLL 的磁碟版本
// 2. 對特定記憶體範圍做 hash（不是整個 DLL — 太慢了）
//    具體是：.text section、IAT、export table、entry point ±512 bytes
// 3. 比對記憶體中的 hash 與磁碟上的 hash
// 如果不符 → 程式碼被修改了（code cave、inline hook 或修補）

// hash 演算法由 sub_FFFFF807C1E3A4C0 選擇（關鍵模組用 SHA-256）
// hash 透過 SIMD（sub_FFFFF807C1E3A568）計算以提高效能
```

### Code Cave 長什麼樣

```
合法的函式填充：
  48 8B C4          mov rax, rsp
  ...函式主體...
  C3                ret
  CC CC CC CC CC CC  ← 填充 NOP/INT3

Code cave 注入：
  48 8B C4          mov rax, rsp
  ...函式主體...
  C3                ret
  48 B8 XX XX XX XX  ← MOV RAX, cheatCodeAddress（注入器放的）
  XX XX XX XX     
  FF E0               JMP RAX → 跳到作弊程式碼
```

`INT3`（`0xCC`）bytes 被替換和/或原本均勻填充區域的熵發生變化，是可偵測的訊號。

---

## 11. EAC 注入器偵測的已知缺口

### 缺口 1：VAD 操控（記憶體區域的 DKOM）

有 kernel 權限的攻擊者可以直接修改 VAD tree — 移除注入區域的 VAD 節點，或把它的類型從 `VadNone` 改為帶有偽造 section 參考的 `VadImageMap`。這樣一來，RWX shellcode 看起來就像合法的映射 image。**操作難度極高且有藍屏風險**，但並非不可能。

### 缺口 2：PatchGuard 時序視窗

PatchGuard（KPP）定期驗證 kernel 結構。在兩次 PatchGuard 檢查之間，複雜的攻擊可以短暫修改 VAD 節點、提取遊戲資料，然後在 PatchGuard 或 EAC 察覺之前恢復。估計可用視窗：幾秒鐘。這是部分「hypervisor 作弊」的運作基礎。

### 缺口 3：Thread Pool 執行劫持

注入器不建立新 thread 或排隊明顯的 APC，而是劫持**現有的 thread pool thread**（EAC 把它們列入白名單，因為它們是正常的 `ntdll!TpCallbackMayRunLong` thread）。Pool thread 的**起始位址**在 ntdll 內 — 只有實際的工作項目 callback 是可疑的，而那更難被掃描到。

### 缺口 4：Section-Backed Shellcode（不需要 RWX）

攻擊者可以建立一個帶有 `PAGE_EXECUTE_READ` 的記憶體映射 section，由精心製作的檔案 backing，把它映射到遊戲中並執行。VAD 顯示一個看起來合法的 file-backed 可執行 section。EAC 需要實際讀取磁碟上的檔案內容才能抓到這個。位於異常路徑（暫存目錄）的檔案仍然會被標記，但放在看起來合法路徑的檔案可能溜過去。

### 缺口 5：合法已簽名 DLL 濫用

部分作弊載入完全合法的已簽名 DLL（如數學函式庫或壓縮函式庫），再利用那個 DLL 內的漏洞透過 ROP chain 執行任意程式碼。注入的 DLL 本身通過所有簽名檢查 — 漏洞利用程式碼是資料，不會被標記為可執行注入。

### 缺口 6：早期啟動注入（在 PE Header 驗證之前）

EAC 在遊戲啟動時初始化，但在遊戲自己的 loader 映射 DLL 和 EAC 完成初始掃描之間存在一個短暫視窗。在這個視窗關閉前完成的注入會被掃描 — 但如果注入的 DLL 是包含後續次要 payload 載入的合法已簽名 binary，初始掃描就會通過。注入的 DLL 只需要通過 hash 驗證 — 這意味著它必須是一個合法的已簽名 DLL，再從內部載入作弊 payload。

---

*← [外部作弊偵測](external_cheat_detection.md) | [使用者模式 EAC 應用程式分析 →](usermode_eac_app.md)*
