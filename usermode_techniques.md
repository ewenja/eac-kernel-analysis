# EAC 保護遊戲中的使用者模式技術

> 本文是 [EAC Kernel Driver 分析](README.md) 系列的一部分。

很多人以為只要 EAC 在跑，任何對遊戲有用的操作都需要 kernel driver。這並不完全正確。從本 repo 的分析可以知道 EAC 實際上檢查什麼 — 也就能推斷它**不**檢查什麼。有相當多的事情可以完全從 user-mode（Ring 3）完成，EAC 要麼沒有監控，要麼無法輕易與正常行為區分。

> **注意：** 這是一份研究文件。記錄這些技術是為了展示 EAC 監控的邊界，對理解（和改進）反作弊設計有參考價值。

---

## 偵測狀態說明

| 標記 | 說明 |
|---|---|
| **未偵測** | EAC 的 driver 沒有偵測這個的向量。沒有標記，沒有回報。|
| **僅伺服器端** | EAC 的 kernel driver 無法抓到它 — 但 EAC 後端伺服器可能隨時間標記可疑的行為模式。|
| **部分監控** | EAC 監控*某些*相關的東西，但不是這個特定路徑。謹慎使用風險低。|

---

## 快速參考表

| # | 技術 | EAC Driver 偵測？ | 伺服器端風險？ |
|---|---|---|---|
| 1 | KUSER_SHARED_DATA 時序讀取 | 未偵測 — 無法封鎖 | 無 |
| 2 | 最小 handle + NtQueryInformationProcess | 未偵測 — 存取遮罩不對 | 無 |
| 3 | SystemHandleInformation 列舉 | 未偵測 — 方向相反 | 無 |
| 4 | ETW 訂閱（DxgKrnl、Win32k 等）| 未偵測 — 被動監聽 | 無 |
| 5 | RawInput INPUTSINK | 未偵測 — 不是 hook | 無 |
| 6 | WH_SHELL hook | 未偵測 — 不是鍵盤/滑鼠 | 無 |
| 7 | 具名共享記憶體 section | 未偵測 — 讀取自己的 view | 無 |
| 8 | SystemProcessInformation 輪詢 | 未偵測 — 合法 API | 無 |
| 9 | DWM + GDI 螢幕擷取 | 未偵測 — 在遊戲 process 之外 | 無 |
| 10 | SendInput 注入 | 無 driver 偵測 | 有 — 不人性化的精確度/速度 |
| 11 | VirtualQueryEx（PROCESS_QUERY_INFORMATION）| 低 — EAC 可能記錄這個 handle | 無 |

---

## 目錄
1. [KUSER_SHARED_DATA — 免費的時序資訊](#1-kuser_shared_data--免費的時序資訊)
2. [不需要 PROCESS_VM_READ 的遊戲基址](#2-不需要-process_vm_read-的遊戲基址)
3. [NtQuerySystemInformation Handle 列舉](#3-ntquerysysteminformation-handle-列舉)
4. [ETW — 遊戲洩漏很多資訊](#4-etw--遊戲洩漏很多資訊)
5. [RawInput 攔截](#5-rawinput-攔截)
6. [從同一個 Desktop 使用 SetWindowsHookEx](#6-從同一個-desktop-使用-setwindowshookex)
7. [遊戲建立的共享記憶體 Section](#7-遊戲建立的共享記憶體-section)
8. [效能計數器濫用](#8-效能計數器濫用)
9. [不需要注入的視窗 / DWM 資訊](#9-不需要注入的視窗--dwm-資訊)
10. [透過 SendInput 注入輸入](#10-透過-sendinput-注入輸入)
11. [VirtualQueryEx — 不讀取記憶體的記憶體佈局](#11-virtualqueryex--不讀取記憶體的記憶體佈局)
12. [為什麼這些對 EAC 有效](#12-為什麼這些對-eac-有效)

---

## 1. KUSER_SHARED_DATA — 免費的時序資訊

> **EAC 偵測：無** — 這是一個硬體映射的共享頁面。Windows 無法限制對它的存取。EAC 本身讀取這個相同結構的 kernel-mode 鏡像。

`KUSER_SHARED_DATA` 是一個在**每個 user-mode process 中固定位址** `0x7FFE0000` 映射的唯讀頁面。不需要 handle，不需要 API，不需要任何權限。它就在那裡。

從分析中發現 EAC 本身在 `0xFFFFF78000000014`（kernel-mode 鏡像）讀取這個。從 user-mode，相同的資料在：

```c
#define KUSER_SHARED_DATA_BASE 0x7FFE0000

// Tick count — 每約 15ms 更新：
volatile ULONG* TickCountLow = (ULONG*)(KUSER_SHARED_DATA_BASE + 0x320);

// 系統時間（自 1601 年 1 月 1 日起的 100ns 間隔）：
volatile LARGE_INTEGER* SystemTime = (LARGE_INTEGER*)(KUSER_SHARED_DATA_BASE + 0x14);

// 中斷時間（自開機起的 100ns）：
volatile LARGE_INTEGER* InterruptTime = (LARGE_INTEGER*)(KUSER_SHARED_DATA_BASE + 0x08);
```

### 可以用這個做什麼
- **零 API 呼叫的高解析度時序** — `QueryPerformanceCounter` 反正也從這裡讀取，可以直接跳過那個呼叫
- **幀時序** — 精確知道遊戲引擎在哪個 tick 值上
- **負載偵測** — 如果 `InterruptTime` 落後 `SystemTime`，排程器在落後
- **知道 EAC 看到什麼** — 由於 EAC 交叉比對這個相同的值，可以確切知道什麼是一致的

---

## 2. 不需要 PROCESS_VM_READ 的遊戲基址

> **EAC 偵測：無** — 從分析結果來看，EAC 只標記 `PROCESS_VM_READ`（0x0010）、`PROCESS_VM_WRITE`（0x0020）和 `PROCESS_ALL_ACCESS`。`PROCESS_QUERY_LIMITED_INFORMATION`（0x1000）是工作管理員使用的，不被標記。

```c
HANDLE hGame = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, gamePID);

PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(hGame, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
// pbi.PebBaseAddress → 遊戲在記憶體中的 PEB 位址

// 這個存取層級也可以存取：
NtQueryInformationProcess(hGame, ProcessImageFileName, ...); // 磁碟上的完整 exe 路徑
NtQueryInformationProcess(hGame, ProcessCommandLine, ...);   // 啟動參數
NtQueryInformationProcess(hGame, ProcessTimes, ...);         // 確切的 CPU 使用量
```

### 這能取得什麼
- 遊戲的 **PEB 位址** — 結合遊戲版本的已知偏移，可以取得任何符號的絕對位址，而不需要讀取記憶體
- 遊戲的**磁碟上的完整 image 路徑** — 用於找到確切的遊戲版本並下載對應的 PDB/符號檔案
- **啟動參數** — 部分遊戲在命令列上傳遞地區伺服器或 session ID

---

## 3. NtQuerySystemInformation Handle 列舉

> **EAC 偵測：無** — EAC 的 handle 掃描器尋找*進入*遊戲 process 的 handle（其他 process 對遊戲有 VM_READ）。這個呼叫讀取 handle table 的*另一個*方向 — 遊戲本身持有什麼 handle。方向完全相反，EAC 不監控它。

```c
ULONG size = 1 << 20;
PSYSTEM_HANDLE_INFORMATION_EX info = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(size);

while (NtQuerySystemInformation(SystemExtendedHandleInformation, info, size, &size)
       == STATUS_INFO_LENGTH_MISMATCH) {
    info = realloc(info, size *= 2);
}

for (ULONG i = 0; i < info->NumberOfHandles; i++) {
    if (info->Handles[i].UniqueProcessId == gamePID) {
        printf("Handle: type=%d access=0x%X object=0x%llX\n",
            info->Handles[i].ObjectTypeIndex,
            info->Handles[i].GrantedAccess,
            info->Handles[i].Object);
    }
}
```

### 這揭露了什麼
- 遊戲開啟的每個**檔案** — 映射檔案、設定檔、EAC 自己的憑證檔案
- 遊戲映射的每個 **section/共享記憶體**
- 遊戲用於同步的每個 **mutex/event** — 告訴你遊戲狀態轉換時機
- 遊戲用來與 driver 通訊的確切 **EAC device handle** — 包含 kernel 物件位址

---

## 4. ETW — 遊戲洩漏的資訊

> **EAC 偵測：無** — ETW 是被動訂閱。只是在監聽 kernel 發出的事件。EAC 沒有機制監控誰訂閱了 ETW provider，分析中在 binary 裡沒有找到 ETW 訂閱者列舉的程式碼。

遊戲透過 DirectX、Windows thread pool 和 kernel 排程器自動發出 ETW 事件 — 通常連遊戲開發者自己都不知道。

```c
// 訂閱遊戲的 DirectX 幀事件 — 完全被動：
EnableTrace(session, DxgKrnlGuid, EVENT_ENABLE_PROPERTY_PROCESS_START_KEY, ...);
```

### 各 Provider 可取得的資訊

| ETW Provider | 提供的資訊 | 偵測風險 |
|---|---|---|
| `DxgKrnl` | 確切的幀開始/結束時間戳、GPU 佇列深度 | 無 |
| `Win32k` | 進入遊戲訊息佇列的輸入事件 | 無 |
| `Kernel-Process` | 遊戲載入的每個 DLL，附時間戳 | 無 |
| `DXGI` | SwapChain Present() 呼叫 — 原始幀時序 | 無 |
| `Heap` | 大型分配事件 — 地圖載入、比賽開始 | 無 |
| `ThreadPool` | 遊戲背景 thread 何時觸發 | 無 |

來自 `DxgKrnl` 的幀時序以**微秒精度**告訴你每一幀何時被渲染 — 這是觸發輸入事件以獲得最大一致性的確切視窗。

---

## 5. RawInput 攔截

> **EAC 偵測：無** — EAC 的 hook 掃描器特別針對 `SetWindowsHookEx` 鍵盤/滑鼠 hook。帶 `RIDEV_INPUTSINK` 的 `RegisterRawInputDevices` 是完全不同的 Windows 子系統 — 它註冊一個 HID 裝置監聽器，而非 hook。完全不在 EAC 的偵測路徑中。

```c
RAWINPUTDEVICE rid[2];

// 即使沒有焦點也接收所有滑鼠輸入：
rid[0].usUsagePage = 0x01;
rid[0].usUsage     = 0x02;
rid[0].dwFlags     = RIDEV_INPUTSINK;
rid[0].hwndTarget  = yourHwnd;

// 即使沒有焦點也接收所有鍵盤輸入：
rid[1].usUsagePage = 0x01;
rid[1].usUsage     = 0x06;
rid[1].dwFlags     = RIDEV_INPUTSINK;
rid[1].hwndTarget  = yourHwnd;

RegisterRawInputDevices(rid, 2, sizeof(RAWINPUTDEVICE));
// WM_INPUT 現在接收進入遊戲的每個滑鼠/鍵盤事件
```

### 這能取得什麼
- 即時的完整原始（未加速）滑鼠串流
- 所有鍵盤輸入 — 確切知道任何遊戲按鍵何時被按下
- **完全被動** — 遊戲仍然正常接收輸入，只是同時也得到一份副本
- 每個 `RAWINPUT` 結構中 HID 時間戳的亞毫秒精度

---

## 6. 從同一個 Desktop 使用 SetWindowsHookEx

> **EAC 偵測：無** — EAC 特別監控 `WH_KEYBOARD`、`WH_KEYBOARD_LL`、`WH_MOUSE` 和 `WH_MOUSE_LL` hook。根據 binary 分析，`WH_SHELL` 不在 EAC 監控的 hook 類型清單中。

`WH_SHELL` 在頂層視窗生命週期事件時觸發，不需要注入任何 process：

```c
// 在遊戲視窗獲得/失去焦點、建立/銷毀等時觸發：
HHOOK h = SetWindowsHookEx(WH_SHELL, ShellProc, NULL, 0);
// dwThreadId = 0 表示全域 — 適用於這個 desktop 上的所有 thread
```

### 這能取得什麼
- **確切的焦點獲得時間戳** — 知道遊戲視窗獲得焦點的毫秒
- **焦點失去偵測** — 知道玩家何時 Alt+Tab 出去（立即停止發送輸入）
- 對任何需要遊戲視窗有焦點的操作的時序很有用

---

## 7. 遊戲建立的共享記憶體 Section

> **EAC 偵測：無** — 透過名稱用標準 API 開啟一個具名 kernel 物件。不需要對遊戲 process 開啟 handle。EAC 對其他 process 發出的 `OpenFileMapping` 呼叫沒有監控機制。

遊戲和它們的反作弊服務通常建立具名共享記憶體 section 用於 IPC。一旦你知道名稱（從步驟 3，handle 列舉），你可以直接開啟它：

```c
// 透過名稱開啟具名共享記憶體 section — 不需要遊戲 handle：
HANDLE hSection = OpenFileMapping(FILE_MAP_READ, FALSE, L"Local\\GameSharedMem");
LPVOID view = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
// 你現在有一個遊戲寫入的相同記憶體的即時讀取 view
```

### 如何找到名稱
- 執行步驟 3（SystemHandleInformation），過濾 `ObjectTypeIndex == Section`
- 使用 `NtQueryObject(handle, ObjectNameInformation)` 取得每個 section handle 的名稱
- 通常命名為 `Local\GameName_SharedState` 或 `Global\EACSessionData` 之類

---

## 8. 效能計數器濫用

> **EAC 偵測：無** — `NtQuerySystemInformation(SystemProcessInformation)` 是標準系統呼叫。不需要遊戲的 handle。EAC 不對其他 process 的這個 API 呼叫進行監控。
```c
// 不需要遊戲的 handle — 只需輪詢系統範圍的 process 資訊：
SYSTEM_PROCESS_INFORMATION* proc; // 列舉找到遊戲 process
printf("WorkingSet: %zu MB | PageFaults: %u | Handles: %u | CPU: %llu\n",
    proc->WorkingSetPrivateSize / (1024*1024),
    proc->PageFaultCount,
    proc->HandleCount,
    proc->CycleTime);
```

### 這些數字代表什麼

| 指標 | 何時變化 | 代表什麼 |
|---|---|---|
| **Working set 峰值** | 新地圖/關卡串流進來 | 比賽/回合開始 |
| **Page fault 爆發** | 大型記憶體分配 | 遊戲生成新物件 |
| **Handle count 跳升** | 遊戲開啟新檔案 | 設定重載 / 資源載入 |
| **特定 thread 的 CPU 時間** | AI/物理大量計算 | NPC/敵人處理活躍 |

把這個與 KUSER_SHARED_DATA 時間戳結合，可以在不觸碰遊戲記憶體的情況下建立相當準確的遊戲狀態時間線。

---

## 9. 不需要注入的視窗 / DWM 資訊

> **EAC 偵測：無** — DWM 呼叫不需要遊戲 process 的 handle，EAC 沒有 DWM 監控。GDI 螢幕擷取 desktop 是標準 Windows 操作。binary 分析中沒有找到螢幕擷取偵測程式碼。
```c
// 取得確切的遊戲視窗螢幕矩形：
HWND gameHwnd = FindWindow(NULL, L"Fortnite");
RECT r;
DwmGetWindowAttribute(gameHwnd, DWMWA_EXTENDED_FRAME_BOUNDS, &r, sizeof(r));

// 截取確切的遊戲視窗區域 — 不需要遊戲 handle：
HDC screenDC = GetDC(NULL);
HDC memDC    = CreateCompatibleDC(screenDC);
HBITMAP bmp  = CreateCompatibleBitmap(screenDC, r.right-r.left, r.bottom-r.top);
SelectObject(memDC, bmp);
BitBlt(memDC, 0, 0, r.right-r.left, r.bottom-r.top,
       screenDC, r.left, r.top, SRCCOPY);
```

### 這能做什麼
- 零遊戲記憶體存取的全幀螢幕讀取器
- 純基於像素的顏色或 ML 敵人偵測
- 與步驟 1（KUSER_SHARED_DATA）結合進行幀同步 — 在 GPU 完成新幀時確切擷取
- **沒有注入、沒有 handle、沒有 driver** — EAC 沒有客戶端路徑可以偵測這個

> **唯一的防禦：** 部分遊戲以獨佔全螢幕模式執行，`BitBlt` 擷取黑色幀。在那些情況下需要 `IDXGIOutputDuplication::AcquireNextFrame`（DXGI 擷取 API），它同樣不需要注入就能工作。

---

## 10. 透過 SendInput 注入輸入

> **EAC Driver 偵測：無** — EAC 的 driver 針對滑鼠 filter driver 和直接 kernel HID 操控。`SendInput` 透過正常的 Win32 輸入 stack，EAC 對它沒有 hook。
>
> **伺服器端風險：有** — 如果輸入模式看起來不像人類（像素完美追蹤、零反應時間變異、不可能的快速移動一致性），EAC 後端會標記它。這是主要風險所在。

```c
// 平滑 aimbot 移動 — 不需要 driver：
void smoothMove(int targetX, int targetY, int steps) {
    POINT cur;
    GetCursorPos(&cur);
    float dx = (targetX - cur.x) / (float)steps;
    float dy = (targetY - cur.y) / (float)steps;
    for (int i = 0; i < steps; i++) {
        INPUT in = {0};
        in.type     = INPUT_MOUSE;
        in.mi.dx    = (LONG)dx;
        in.mi.dy    = (LONG)dy;
        in.mi.dwFlags = MOUSEEVENTF_MOVE;
        SendInput(1, &in, sizeof(INPUT));
        Sleep(1); // 加入時序變化讓它看起來像人類
    }
}
```

### 降低伺服器端可見度的方法
- 在移動 delta 中加入小的隨機偏移（±1-2px 噪音）
- 隨機化 `SendInput` 呼叫之間的延遲（不總是 1ms）
- 不要在 EAC 掃描觸發的確切幀開始追蹤
- 引入偶爾的「失誤」和修正 — 真實玩家不會完美追蹤

---

## 11. VirtualQueryEx — 不讀取記憶體的記憶體佈局

> **EAC 偵測：低風險** — `PROCESS_QUERY_INFORMATION`（0x0400）比 `PROCESS_QUERY_LIMITED_INFORMATION` 高一級。根據分析，EAC 的主要標記是 `PROCESS_VM_READ`/`WRITE`。單獨的 `PROCESS_QUERY_INFORMATION` 可能出現在 EAC 的遙測中，但不太可能觸發封禁 — 分析器和除錯器常規使用它。如果可能的話使用 `PROCESS_QUERY_LIMITED_INFORMATION`（0x1000）；在較新的 Windows 版本上它也允許 `VirtualQueryEx`。

```c
HANDLE hGame = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, gamePID);

MEMORY_BASIC_INFORMATION mbi;
ULONG_PTR addr = 0;
while (VirtualQueryEx(hGame, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
    if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT)
        printf("Module: 0x%llX  size: 0x%llX\n", mbi.BaseAddress, mbi.RegionSize);
    addr += mbi.RegionSize;
}
```

### 佈局能告訴你什麼（不讀取一個 byte）
- 每個已載入的 DLL 及其在遊戲中的確切基址 — 結合公開已知的偏移取得符號位址
- 私有 heap 區域 — 它們的大小隨遊戲分配/釋放物件而變化
- `MEM_PRIVATE | PAGE_EXECUTE_READWRITE` 區域 = 注入的程式碼（EAC 執行的相同檢查）
- 每個 thread 的遊戲 stack 區域 — 大小告訴你 thread 數量

---

## 12. 為什麼這些技術對 EAC 有效

直接基於 EAC binary 中找到的分析結果：

| 技術 | EAC 看不到它的原因 |
|---|---|
| KUSER_SHARED_DATA | 共享 kernel 頁面，無法進行存取控制 |
| PROCESS_QUERY_LIMITED_INFORMATION | EAC 只標記 `VM_READ`/`VM_WRITE` 存取位元 |
| SystemHandleInformation | EAC 掃描*進入*遊戲的 handle，不是*從*遊戲向外的 |
| ETW 訂閱 | 被動監聽器 — EAC 讀取的沒有可列舉的訂閱者列表 |
| RawInput INPUTSINK | HID 監聽器，不是 hook — 與 EAC 監控的不同子系統 |
| GDI/DWM 擷取 | 在遊戲 process 之外，EAC 被發現沒有 DWM 監控程式碼 |
| SendInput | 合法的 Win32 API，沒有被 EAC 攔截的 kernel driver 路徑 |
| VirtualQueryEx | 不需要 `VM_READ`，EAC 不單獨封禁 `QUERY_INFORMATION` |
| NtQuerySystemInformation | 不需要遊戲 handle，標準 user-mode syscall |
| ETW 幀時序 | EAC 不列舉 ETW session 訂閱者 |

**結論：** EAC 的 kernel driver 在它擅長的事情上確實很強 — 抓注入的程式碼、隱藏的 driver、被 hook 的函式和記憶體操控。它不是設計來抓完全待在遊戲之外並只使用合法 Windows API 的 process 的。那是一個完全不同的問題，EAC 對它的答案是伺服器端行為偵測 — 而非 driver。

---

*← [回到 README](README.md)*
