# 函式位址對照表 — IDA 靜態分析結果

> 本文是 [EAC Kernel Driver 分析](README.md) 系列的一部分。
> 
> 所有位址對應載入在基址 `0xFFFFF807C1E10000` 的特定分析 binary。
> 不同版本的 EAC 位址會有所不同，但功能分組保持相似。

---

## 標記說明

| 標記 | 子系統 |
|---|---|
| [加密] | 加密學 |
| [壓縮] | 壓縮（Zstd）|
| [遙測] | 遙測與資料收集 |
| [偵測] | 偵測 / 掃描 |
| [IOCTL] | IOCTL / Driver 通訊 |
| [完整性] | 完整性驗證 |
| [基礎] | 基礎設施 / 工具函式 |
| [初始化] | 初始化 / 啟動 |
| [清理] | 清理 / 卸載 |

---

## 核心子系統函式

| 位址 | 大小 | 標記 | 重建名稱 | 說明 |
|---|---|---|---|---|
| `0xFFFFF807C1F8B8F0` | ~varies | [初始化] | `DriverEntry` | Driver 初始化進入點 — 建立 device object、註冊 callback、初始化所有子系統 |
| `0xFFFFF807C1ED4320` | ~varies | [加密] | `DecryptFnPtr` | 加密函式指標解析器 — 讀取 slot，應用 64-bit XOR 產生真實的 kernel API 位址 |
| `0xFFFFF807C1E1DD80` | `0x844` | [遙測] | `AssembleTelemetryPacket` | 主要遙測建構器 — 在 6 個偏移讀取 EPROCESS、收集時間戳、遍歷模組鏈、編碼 184-byte 封包 |
| `0xFFFFF807C1E1E5C4` | `0xA4` | [遙測] | `InitPacketBuffer` | 清零初始化 184-byte 遙測緩衝區並設置封包 header |
| `0xFFFFF807C1E1E668` | `0x87` | [遙測] | `SerializeField_20087C0` | 把 process 保護旗標序列化到封包 |
| `0xFFFFF807C1E1E700` | `0x67` | [遙測] | `SerializeField_2008758` | 序列化基礎 EPROCESS 欄位 |
| `0xFFFFF807C1E1E780` | `0x53` | [遙測] | `SerializeField_2008730` | 序列化 PID 衍生值 |
| `0xFFFFF807C1E1E7D4` | `0x9A` | [遙測] | `SerializeField_20086F8` | 序列化系統時間（8-byte QWORD）|
| `0xFFFFF807C1E1E870` | `0x8B` | [遙測] | `SerializeField_20086C0` | 序列化來自 KUSER_SHARED_DATA 的 TickCount |
| `0xFFFFF807C1E1E8FC` | `0x99` | [遙測] | `SerializeField_2008688` | 序列化 session ID（4-byte DWORD）|
| `0xFFFFF807C1E1E9A0` | `0x92` | [遙測] | `SerializeField_2008658` | 序列化 image 名稱 hash |
| `0xFFFFF807C1E1EA40` | `0x92` | [遙測] | `SerializeField_2008628` | 序列化 VAD/PEB 指標（8 bytes，EPROCESS+240）|
| `0xFFFFF807C1E1EAD4` | `0x8C` | [遙測] | `SerializeField_20085F8` | 序列化 v30+12 處的模組數量（4 bytes）|
| `0xFFFFF807C1E1EB60` | `0x9A` | [遙測] | `SerializeField_20085C8` | 序列化模組基址 #1（8 bytes，v30+20）|
| `0xFFFFF807C1E1EBFC` | `0x8C` | [遙測] | `SerializeField_2008598` | 序列化模組基址 #2（8 bytes，v30+28）|
| `0xFFFFF807C1E1ECA0` | `0x92` | [遙測] | `SerializeField_2008568` | 序列化模組基址 #3（8 bytes，v30+36）|
| `0xFFFFF807C1E1ED34` | `0x8C` | [遙測] | `SerializeField_2008538` | 序列化模組基址 #4（8 bytes，v30+44）|
| `0xFFFFF807C1E1EDC0` | `0x8C` | [遙測] | `SerializeField_2008508` | 序列化完整模組路徑（461-byte 緩衝區，type=3）|
| `0xFFFFF807C1E1EE4C` | `0x99` | [遙測] | `SerializeField_20084D8` | 序列化模組二進位指紋（41-byte 緩衝區）|
| `0xFFFFF807C1E1F100` | `0x14` | [基礎] | `GetField_Stub1` | 小型 stub — 回傳欄位 key 查找的位址 |
| `0xFFFFF807C1E1F120` | `0x53` | [基礎] | `GetField_Stub2` | 較大的欄位 key 查找分派器 |

---

## 加密相關函式

| 位址 | 大小 | 標記 | 重建名稱 | 說明 |
|---|---|---|---|---|
| `0xFFFFF807C1E21280` | `0x409` | [加密] | `P256_FieldMul` | P-256 多項式 field 乘法 — 9-limb × 9-limb → 18-limb，帶進位傳播，30-bit radix |
| `0xFFFFF807C1E2168C` | `0x26C` | [加密] | `P256_FieldReduce` | 把乘法結果模化簡回 P-256 field element |
| `0xFFFFF807C1E21900` | `0x91` | [加密] | `P256_PointAdd_Prep` | 橢圓曲線點加法準備（Jacobian 座標轉換）|
| `0xFFFFF807C1E21994` | `0x137` | [加密] | `P256_FieldAdd` | 帶條件進位的 field 加法 |
| `0xFFFFF807C1E21ACC` | `0x175` | [加密] | `P256_FieldSub` | 帶借位的 field 減法 |
| `0xFFFFF807C1E21C44` | `0x175` | [加密] | `P256_FieldNeg` | Field 取反（p - x）|
| `0xFFFFF807C1E21DC0` | `0x81` | [加密] | `P256_FieldSqr` | Field 平方（最佳化的 double — 不是一般乘法）|
| `0xFFFFF807C1E21E60` | `0x15B` | [加密] | `P256_PointDouble` | Jacobian 座標中的橢圓曲線點倍增 |
| `0xFFFFF807C1E21FC0` | `0x17E` | [加密] | `P256_ConvertToAffine` | 把 Jacobian（X:Y:Z）轉換為仿射（x,y）座標 |
| `0xFFFFF807C1E22140` | `0x1F2` | [加密] | `P256_PointAdd` | 完整 Jacobian 點加法（統一公式）|
| `0xFFFFF807C1E22340` | `0x1D0` | [加密] | `P256_ConditionalSwap` | Montgomery ladder 的 constant-time 條件交換 |
| `0xFFFFF807C1E22520` | `0x17E` | [加密] | `P256_FieldInvert` | 透過費馬小定理的 field 求逆（exp to p-2）|
| `0xFFFFF807C1E226A0` | `0x35` | [加密] | `P256_ScalarMul_Entry` | P-256 純量乘法分派的進入點 |
| `0xFFFFF807C1E226E0` | `0x31D` | [加密] | `P256_ScalarMul` | Constant-time 2-bit NAF 純量乘法 — 核心 ECC 迴圈 |
| `0xFFFFF807C1E1AF00` | `0x5EB` | [加密] | `NTT_MontgomeryReduce` | 帶 Montgomery/Barrett 模化簡的 NTT — 62-bit 質數域中的多項式乘法 |
| `0xFFFFF807C1E1AB00` | `0x3E5` | [加密] | `NTT_Butterfly` | Cooley-Tukey NTT butterfly 操作 — 核心變換原語 |
| `0xFFFFF807C1E1AA80` | `0x68` | [加密] | `NTT_BitReverse` | NTT 輸入/輸出排序的位元反轉排列 |
| `0xFFFFF807C1E1A7C0` | `0x88` | [加密] | `NTT_Finalize` | NTT 後正規化 — 除以變換長度（Montgomery 縮放）|
| `0xFFFFF807C1E1A850` | `0x149` | [加密] | `NTT_Setup` | 初始化 NTT 工作空間，計算旋轉因子 |
| `0xFFFFF807C1E1A640` | `0x17D` | [加密] | `ECDSA_Sign` | 使用 P-256 和 NTT 作為後端的 ECDSA 簽名操作 |
| `0xFFFFF807C1E1A490` | `0x1A8` | [加密] | `ECDSA_Verify` | ECDSA 簽名驗證 |
| `0xFFFFF807C1E977E0` | ~varies | [加密] | `Montgomery_SqrStep` | 單步 Montgomery 平方（在 NTT 指數迴圈中呼叫）|

---

## Hash / 完整性驗證函式

| 位址 | 大小 | 標記 | 重建名稱 | 說明 |
|---|---|---|---|---|
| `0xFFFFF807C1E3A4C0` | `0x11A` | [完整性] | `HashContext_Init` | Hash 演算法選擇器 — 根據選擇器初始化 MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 context |
| `0xFFFFF807C1E3BB98` | ~varies | [完整性] | `SHA512_Init` | SHA-512 特定初始化（64-byte 初始向量）|
| `0xFFFFF807C1E3BCCC` | ~varies | [完整性] | `SHA384_Init` | SHA-384 特定初始化（48-byte 輸出變體）|
| `0xFFFFF807C1E3A568` | ~varies | [完整性] | `SHA256_BlockProcess` | SHA-256 block 壓縮函式（64-byte block）|
| `0xFFFFF807C1E3A5cd` | ~varies | [完整性] | `SHA1_BlockProcess` | SHA-1 block 壓縮函式 |
| `0xFFFFF807C1E8D840` | ~varies | [完整性] | `HashImageName` | 對 EPROCESS+96 的 15 字元 process image 名稱做 hash |
| `0xFFFFF807C1E28DA0` | `0xC3` | [完整性] | `VerifyModuleSignature` | 驗證已載入模組的 Authenticode 簽名 |
| `0xFFFFF807C1E29540` | `0x3B` | [完整性] | `CheckSignatureResult` | 驗證簽名驗證回傳碼 |
| `0xFFFFF807C1E2A4E0` | `0xCF` | [完整性] | `ComputeModuleFingerprint` | 計算模組的 41-byte 二進位指紋 |

---

## Zstd 壓縮引擎函式

| 位址 | 大小 | 標記 | 重建名稱 | 說明 |
|---|---|---|---|---|
| `0xFFFFF807C1E11C00` | `0x2D1` | [壓縮] | `Zstd_BuildFreqTable` | 從輸入資料建立 byte 頻率直方圖 — 核心 Huffman 表建構器（SSE2）|
| `0xFFFFF807C1E11EE0` | `0x579` | [壓縮] | `Zstd_Huffman_SSE2` | SSE2 6-stream Huffman 解碼器/編碼器 |
| `0xFFFFF807C1E12460` | `0x54D` | [壓縮] | `Zstd_Huffman_AVX2_v1` | AVX2 替代 Huffman 編碼器 |
| `0xFFFFF807C1E129C0` | `0x23A` | [壓縮] | `Zstd_BlockDecompress` | Zstd block 解壓縮處理器 |
| `0xFFFFF807C1E12C00` | `0x2E9` | [壓縮] | `Zstd_SequenceDecode` | Zstd 序列解碼（literal + match copy）|
| `0xFFFFF807C1E12F00` | `0x1FA` | [壓縮] | `Zstd_FSE_Decode` | Finite State Entropy（FSE）表解碼器 |
| `0xFFFFF807C1E13100` | `0x577` | [壓縮] | `Zstd_Huffman_AVX2_4stream` | 高效能 AVX2 4-to-6-stream Huffman — 每次迭代 15 bytes，vpinsrb/vmovdqu/vpaddq |
| `0xFFFFF807C1E13680` | `0x2DC` | [壓縮] | `Zstd_BuildHuffmanTree` | 從頻率表建構 Huffman tree |
| `0xFFFFF807C1E13960` | `0x28B` | [壓縮] | `Zstd_AssignCodeLengths` | 為 Huffman tree 節點分配標準碼長度 |
| `0xFFFFF807C1E13C00` | `0x274` | [壓縮] | `Zstd_FSE_BuildTable` | 建構 FSE 解碼/編碼表 |
| `0xFFFFF807C1E13E80` | `0x256` | [壓縮] | `Zstd_CompressBlock` | 壓縮單一資料 block（幀內容）|
| `0xFFFFF807C1E140E0` | `0x255` | [壓縮] | `Zstd_CompressLiterals` | 使用 Huffman 壓縮 literal 序列 |
| `0xFFFFF807C1E30B00` | `0x10C` | [壓縮] | `Zstd_HeapSiftDown` | 24-byte key 節點的最小堆 sift-down（Huffman 優先佇列）|
| `0xFFFFF807C1E30C20` | `0x30F` | [壓縮] | `Zstd_Quicksort` | Zstd 資料 block 的 introsort/quicksort（median-of-3 pivot，threshold=40）|
| `0xFFFFF807C1E31BE0` | `0x158` | [壓縮] | `Zstd_FrameHeader_Write` | 寫入 Zstd 幀 header（magic 0xFD2FB528，幀描述符）|
| `0xFFFFF807C1E31D40` | `0x1C6` | [壓縮] | `Zstd_FrameHeader_Read` | 從壓縮串流解析 Zstd 幀 header |
| `0xFFFFF807C1E31F20` | `0xA9` | [壓縮] | `Zstd_ChecksumVerify` | 驗證 Zstd xxHash64 內容 checksum |

---

## 基礎設施與工具函式

| 位址 | 大小 | 標記 | 重建名稱 | 說明 |
|---|---|---|---|---|
| `0xFFFFF807C1E1A140` | `0x1` | [基礎] | `nullsub_2` | Null subroutine — 佔位符 / 對齊 |
| `0xFFFFF807C1E1A150` | `0xD` | [基礎] | `ReturnZero` | 永遠回傳 0 — 用作預設處理器 |
| `0xFFFFF807C1E1A160` | `0xF` | [基礎] | `ReturnOne` | 永遠回傳 1 |
| `0xFFFFF807C1E1A170` | `0x1D6` | [基礎] | `Pool_Alloc` | Kernel pool 分配器包裝器（混淆的 ExAllocatePoolWithTag）|
| `0xFFFFF807C1E1A350` | `0x1F` | [基礎] | `Pool_GetTag` | 回傳 pool tag 常數 |
| `0xFFFFF807C1E1A370` | `0xA6` | [基礎] | `Pool_Free` | Kernel pool 釋放包裝器 |
| `0xFFFFF807C1E1A420` | `0x5E` | [基礎] | `Pool_AllocZeroed` | 分配 + 清零 pool 記憶體 |
| `0xFFFFF807C1E1A480` | `0x3` | [基礎] | `ReturnArg` | 原封不動回傳第一個參數 |
| `0xFFFFF807C1E196A0` | `0x14F` | [基礎] | `SafeReadMemory` | `sub_FFFFF807C1EBF800` 等效 — 帶大小+鎖定驗證的安全記憶體讀取 |
| `0xFFFFF807C1E19630` | `0x70` | [基礎] | `DereferenceObject` | 遞減參考計數（ObDereferenceObject 等效）|
| `0xFFFFF807C1E18AA0` | `0x133` | [基礎] | `UnicodeString_Init` | 從 char 陣列初始化 UNICODE_STRING |
| `0xFFFFF807C1E16630` | `0x3E` | [基礎] | `SpinLock_Acquire` | 取得 kernel spin lock |
| `0xFFFFF807C1E16670` | `0x4E` | [基礎] | `SpinLock_Release` | 釋放 kernel spin lock |
| `0xFFFFF807C1E166C0` | `0x45` | [基礎] | `FastMutex_Acquire` | 取得 FAST_MUTEX（IRQL ≤ APC_LEVEL）|
| `0xFFFFF807C1E16710` | `0x5A` | [基礎] | `FastMutex_Release` | 釋放 FAST_MUTEX |
| `0xFFFFF807C1E16770` | `0x42` | [基礎] | `ListEntry_Validate` | `FatalListEntryError` — 鏈結串列完整性檢查 |
| `0xFFFFF807C1E16820` | `0x251` | [基礎] | `WorkItem_Queue` | 向系統 worker thread pool 排隊工作項目 |
| `0xFFFFF807C1E2D180` | `0x5` | [基礎] | `Align_Stub` | 對齊/填充 stub |
| `0xFFFFF807C1E2D840` | `0x42` | [基礎] | `StringHash_FNV` | FNV-1a 或類似的快速字串 hash |
| `0xFFFFF807C1E30570` | `0x21` | [基礎] | `Memcpy_Small` | 小型最佳化 memcpy（≤ 32 bytes，非 SIMD）|
| `0xFFFFF807C1E33040` | `0x5` | [基礎] | `Pad_Stub` | 填充 |

---

## Driver 初始化、IOCTL 與生命週期管理

| 位址 | 大小 | 標記 | 重建名稱 | 說明 |
|---|---|---|---|---|
| `0xFFFFF807C1E21180` | `0x7A` | [IOCTL] | `IoCompletionRoutine` | IRP 完成 callback — 非同步 I/O 完成時呼叫 |
| `0xFFFFF807C1E211FC` | `0x74` | [IOCTL] | `IrpDispatch_Create` | IRP_MJ_CREATE 處理器 — user-mode 開啟 `\\.\EasyAntiCheat` 時呼叫 |
| `0xFFFFF807C1E30600` | ~varies | [IOCTL] | `IrpDispatch_DevCtrl` | IRP_MJ_DEVICE_CONTROL 處理器 — 主要 IOCTL 路由器 |
| `0xFFFFF807C1E308C0` | `0x23A` | [IOCTL] | `IrpDispatch_Close` | IRP_MJ_CLOSE — user-mode 關閉 device handle |
| `0xFFFFF807C1E2A4E0` | `0xCF` | [IOCTL] | `IrpDispatch_Cleanup` | IRP_MJ_CLEANUP — 最終 handle 清理 |
| `0xFFFFF807C1E50D40` | ~varies | [清理] | `DriverUnload` | Driver 卸載處理器 — 解引用物件、檢查 `0xBC44A31CA74B4AAF` canary、釋放 pool |
| `0xFFFFF807C1F16DE0` | ~varies | [清理] | `FreePoolWrapper` | DriverUnload 呼叫的 pool 釋放包裝器，用於物件解分配 |
| `0xFFFFF807C1F201E0` | ~varies | [清理] | `ObjectCleanup` | 在分配的 EAC 狀態 block 上呼叫的自訂物件解構器 |

---

## 掃描與偵測相關函式

| 位址 | 大小 | 標記 | 重建名稱 | 說明 |
|---|---|---|---|---|
| `0xFFFFF807C1E226E0` | `0x31D` | [偵測] | `ECC_ScalarMult` | 用於簽名；也用於來自伺服器的挑戰驗證 |
| `0xFFFFF807C1E3A4C0` | `0x11A` | [偵測] | `HashAlgo_Select` | 選擇用於程式碼區域驗證的 hash 演算法 |
| `0xFFFFF807C1EBF800` | ~varies | [偵測] | `SafeStructRead` | Kernel probe + 安全讀取包裝器，用於掃描 kernel 結構 |
| `0xFFFFF807C1E17CF0` | `0xF2` | [偵測] | `ModuleEnum_IterNext` | 推進模組列表迭代器（LDR_DATA_TABLE_ENTRY 遍歷）|
| `0xFFFFF807C1E17F10` | `0xF2` | [偵測] | `ModuleEnum_GetBase` | 從當前模組項目回傳基址欄位 |
| `0xFFFFF807C1E173E0` | `0xFB` | [偵測] | `ProcessEnum_IterNext` | 透過 ActiveProcessLinks 推進 process 列表迭代器 |
| `0xFFFFF807C1E16EF0` | `0xF0` | [偵測] | `DispatchTable_Check` | 檢查 MajorFunction[] 指標是否在 driver 範圍內 |
| `0xFFFFF807C1E16FE0` | `0xF7` | [偵測] | `SSDT_Validate` | 驗證 SSDT 項目指向 ntoskrnl |
| `0xFFFFF807C1E18190` | `0x4E` | [偵測] | `VAD_WalkNext` | 在 tree 遍歷中推進到下一個 VAD 節點 |

---

## 全域資料 / 關鍵位址一覽

| 位址 | 大小 | 變數名稱 | 說明 |
|---|---|---|---|
| `0xFFFFF807C2068E78` | 8 | `enc_ptr_slot_0` | 加密函式指標 — PsGetCurrentProcess 等效 |
| `0xFFFFF807C2068E88` | 8 | `enc_ptr_slot_1` | 加密函式指標 — 封包序列化器 |
| `0xFFFFF807C2068EC8` | 8 | `enc_ptr_slot_2` | 加密函式指標 — PsGetProcessSessionId |
| `0xFFFFF807C2068EE8` | 8 | `enc_ptr_slot_3` | 加密函式指標 — KeQuerySystemTime |
| `0xFFFFF807C206A820` | 1 | `g_bInitialized` | Driver 初始化旗標（byte）|
| `0xFFFFF807C206A828` | 8 | `g_pStateBlock` | 指向主要 EAC 狀態分配的指標（canary = `0xBC44A31CA74B4AAF`）|
| `0xFFFFF807C206A830` | 8 | `g_pWorkQueue` | 指向工作佇列物件的指標 |
| `0xFFFFF807C206A838` | 4 | `g_WorkItem1Active` | 工作項目 #1 排隊旗標 |
| `0xFFFFF807C206A83C` | 4 | `g_WorkItem2Active` | 工作項目 #2 排隊旗標 |
| `0xFFFFF807C206AD10` | 8 | `g_pCallback1` | Kernel callback 註冊 handle #1 |
| `0xFFFFF807C206AD18` | 4 | `g_Callback1Active` | Callback #1 啟用旗標 |
| `0xFFFFF807C206AD20` | 8 | `g_pCallback2` | Kernel callback 註冊 handle #2 |
| `0xFFFFF807C206AD28` | 4 | `g_Callback2Active` | Callback #2 啟用旗標 |
| `0xFFFFF807C206AD30` | 8 | `g_pCallback3` | Kernel callback 註冊 handle #3 |
| `0xFFFFF807C206AD38` | 4 | `g_Callback3Active` | Callback #3 啟用旗標 |
| `0xFFFFF807C1FFEE10` | ~512 | `aBin` | 二進位資料 — 編碼模組名稱簽名表 #1 |
| `0xFFFFF807C1FFEDF0` | ~512 | `aBin_0` | 二進位資料 — 編碼模組名稱簽名表 #2 |
| `0xFFFFF78000000014` | 4 | `KUSER_SHARED_DATA.TickCountLow` | 遙測組裝器直接引用 |
| `0xFFFFF807C1F8BF80` | 8 | `qword_F8BF80` | 函式指標 — memset 等效（清零函式庫函式）|
| `0xFFFFF807C1F8BCC0` | ~varies | `sub_F8BCC0` | Memcpy 等效（用於 NTT 多項式操作）|

---

## 分析統計

| 項目 | 數值 |
|---|---|
| 已識別函式總數 | 200+ |
| 加密函式 | ~22 |
| 壓縮函式 | ~18 |
| 遙測 / 資料收集 | ~20 |
| 偵測 / 掃描 | ~12 |
| IOCTL / 分派 | ~8 |
| 基礎設施 / 工具 | ~30+ |
| 反編譯失敗的函式 | ~15（SIMD 密集或填充 stub）|
| Binary 載入大小 | ~8 MB |
| 程式碼段大小 | ~7 MB |
| 資料段大小 | ~1 MB（字串表、簽名資料、全域狀態）|

---

*← [Spoofer 偵測](spoofer_detection.md) | [回到 README](README.md)*

---