# 原文封存 — Inside EAC/EOS driver: hardware identity collection, kernel telemetry and CPU probes

> **這是一個外部來源的逐字封存檔，不是本 repo 自己做的分析。**
>
> | 項目 | 內容 |
> |---|---|
> | 討論串 | *Inside EAC/EOS driver: hardware identity collection, kernel telemetry and CPU probes* |
> | 版面 | UnKnoWnCheaTs — Anti-Cheat Research（討論串編號 772181） |
> | 作者 | **lauralex**（UnKnoWnCheaTs 會員，Join Date: Sep 2011） |
> | 原始網址 | <https://www.unknowncheats.me/forum/anti-cheat-research/772181-inside-eac-eos-driver-hardware-identity-collection-kernel-telemetry-cpu-probes.html> |
> | 發文時間 | 主文 2026-09-15；更新 2026-09-17；補充章節 2026-09-22（GMT） |
> | 封存時間 | 2026-09-24 |
> | 封存範圍 | 原作者 lauralex 在本討論串中的四篇長文（其餘為社群回覆，見文末索引） |
>
> 內容著作權屬原作者所有，這裡只是研究用途的引用存檔。**本 repo 不對文中任何結論背書**，
> 原始數據是在模擬環境（KEVLAR）中產生的，閱讀時請務必搭配
> [導讀與重點整理](uc_eos_driver_writeup_zh_tw.md) 的「讀這篇前要注意的事」一節。
>
> 若原作者或版方要求移除，請直接刪除本檔案。

---

## 封存的四篇貼文

| # | 時間（GMT） | 標題／內容 | 字元數 |
|---|---|---|---|
| #1 | 2026-09-15 13:48 | 主文：第 1–21 節（Revision 1 原文 + Revision 2 changelog） | 170,604 |
| #44 | 2026-09-17 22:06 | Changelog — 17 September update | 11,469 |
| #61 | 2026-09-22 16:28 | Platform and processor probes — 第 5、12、13、14 節 | 17,397 |
| #64 | 2026-09-22 16:31 | Appendix: acquisition sites and the current picture — 第 20、18 節 | 13,205 |

主文附帶的樣本與下載資訊：

```
Image:         eos.sys (Fortnite version)
Architecture:  Windows x64
Size:          44,666,520 bytes
Entry RVA:     0x2594F8
SHA-256:       020d5da6b881408ced33be09b92dc45e12e641b8b3c91f3a327429e5027fef74
```

版務（rhaym）在第 6 篇核准了原作者上傳的 `eos.zip`，標註 SHA-256：
`4ad6071c7a35e6fa47fb03a0e612abb00bf4363f7d72dfe9c4abdb282733d26b`（zip）與上面那一組（`eos.sys`）。

> **版權與引用說明：** 以下為原文逐字內容（含原作者原有的雙倍行距與程式碼區塊格式）。
> 僅供研究引用與存檔；請勿把本檔當成可再利用的素材再散布。

---

## Post #1 — 主文（2026-09-15，Revision 2）

**Inside EAC/EOS driver: hardware identity collection, kernel telemetry and CPU probes**

Inside EAC/EOS driver: hardware identity, kernel telemetry, PCI/ACPI inspection and CPU probes (pt. 1)

I've been tracing this EOS kernel driver far enough to get past the usual DriverEntry/import-table view and into its actual steady-state behavior.

The primary image is:

~~~
Image:         eos.sys (Fortnite version)

Architecture:  Windows x64

Size:          44,666,520 bytes

Entry RVA:     0x2594F8

SHA-256:

020d5da6b881408ced33be09b92dc45e12e641b8b3c91f3a327429e5027fef74
~~~

Most aggregate counts below come from C317:

~~~
Run:

20260914T033348.817Z-6220

Validated events:       85,388,481

Paired call scopes:      2,122,595

Operation groups:              667

Complete stream SHA-256:

230f0a79e8f53761b30f5596621edbf8136a26bb6b023c552b62f82aa34856dc
~~~

This revision outgrew the forum's per-post limit, so four sections live in follow-up posts in this thread:

~~~
Sections 5, 12, 13, 14   Platform and processor probes

Sections 20 and 18       Acquisition sites and the current picture
~~~

[Platform and processor probes](https://www.unknowncheats.me/forum/4806980-post61.html) · [Acquisition sites and the current picture](https://www.unknowncheats.me/forum/4806985-post64.html)

Changelog

Revision 2, 22 September 2026.** Several of the open questions from the first version have been followed further. Section numbers below refer to this revision.**
New sections

~~~
4   From the GPU object to an encrypted record on a protected list

    Reference acquisition, the marker/UUID search at CD4h/CD5h, byte

    encoding into a CM13 record, the XOR 1Ah header update, the CMCa

    wrapper copy, XXTEA, the mutex-protected list append, plaintext

    erase and the wrapper's release during DriverUnload.

    Replaces the two-paragraph "GPU-containing object" stub.

4   A second serial source: cached storage state

    EOS walks captured kernel memory to a STORAGE_DEVICE_DESCRIPTOR and

    reads the serial characters directly, separate from the ATA response.

4   Where those delivered buffers actually go

    Delivery-to-release records for six response allocations.

4   Which interface fields EOS actually reads

    24 rows walked, 15 GUID reads, 9 flags-only reads, zero MAC reads,

    and the GUID's arithmetic consumer.

4   What the generated UUID is used for

    It is an ETW session identifier placed in WNODE_HEADER.Guid, with the

    STOP/START sequence and six field-substitution controls.

6   One IPI callback measures progress on another processor

    Arrival ticket, barrier, shared counter, and the double counter read

    that stops it being called an atomic minimum.

7   With a populated cache, EOS compares history against the loaded-module list

7   Why the populated walk stops after twenty records

7   The inventory becomes an encrypted record and goes on the same list

7   The two chains meet on the same list

    PiDDB now has a populated walk, a recovered count gate at index 19,

    a record builder, pool-tag rotation, XXTEA and the same list append

    the NVIDIA record uses.

7   What the image-load callback actually does with its metadata

    File-object selection, the 0x101 to 0x102 filename fallback, reuse of

    the callback-supplied name, the CR8 guard, the PID-keyed list and the

    creation-time-keyed process table.

7   What the verification callback reads

7   Only one import name is in plaintext

8   It's checking for one specific detour

8   The flags become a field in a process-image record

8   Bit 21 is an Administrators-group check

8   The bit-21 route checks token integrity and gives up above 0x3FFF

8   What's behind that gate: NtOpenProcess transfer inspection

8   A recovered destination leads to the module's file and its certificate

8   And then the record is cleared and freed

    The rest of the DbgUiRemoteBreakin check.

11  The consumer worker, end to end

11  The context is built from a template, and the callback pointer is encoded

11  Buffer delivery, the parser and the callback

11  A timestamp the parser reads from the wrong offset

11  The callback reads the opcode and splits on 25

11  Native network records reach payload comparisons

11  Loopback sends maintain per-process, per-port counters

11  And a cleanup path that erases all of it

12  It masks the performance-monitor interrupt around that experiment

15  The user-mode relay hypothesis, stated so it can be tested
~~~

Expanded

~~~
2   Initialization timing is now closed for the identified mechanism:

    the saved timestamp's producer, the DO_DEVICE_INITIALIZING clear,

    a selector proof over every clock pair and every flags value, the

    STATUS_DRIVER_UNABLE_TO_LOAD outcome, and the early C399 context

    where the same comparator always selects one target.

3   Worker table gains the private-context code pointer, and five workers

    are tied to the ETW consumer routine.

7   Loader backing admission counts, and the name/size/timestamp mismatch

    that would have attached the wrong backing objects.

8   RtlPcToFileHeader call volume during steady observation, and the

    CALL-preceded check that weakens the return-address reading.

12  The 666 CPUID events with none at the alternate-CR3 probe body;

    SampleVirtualTsc's enforced minimums behind the 150-versus-1 deltas.

17  Two of the eleven residual allocations identified as OS caches, the

    debug-print lead for the 40-byte one, and the consumer close contract.

21  Coverage numbers, and why the percentage moves down as coverage grows.
~~~

Corrected

~~~
Section numbering is now sequential. The old post had 5A before 6, 6A

before 6, and two sections numbered 16.

Sections 5, 12, 13, 14, 18 and 20 moved to follow-up posts in this

thread. Their numbers are unchanged, and each stub links to its post.
~~~

Unchanged

~~~
C317 lifecycle figures, worker roster, PCI/ACPI/MMIO counts, registry

and certificate-store census, notification inventory, IOCTL candidates,

the targeted driver-name searches, the process-name prefixes, the

six-string decoding and candidate K, and the trust-provider tables.
~~~

Revision 1, 15 September 2026. Original post.

1. Scope

The driver executes inside KEVLAR's modeled Windows environment.

Original EOS instructions execute as guest code. Calls into Windows can receive typed model responses, captured machine data or copied Windows behavior where enough state exists to execute it meaningfully.

The input isn't one complete snapshot from one Windows boot. It combines authorized captures, an older kernel dump and modeled process state.

Earlier focused investigations keep their original run labels rather than being silently promoted to C317.

C317 also contains admitted acceleration and semantic replay. A replayed semantic operation isn't treated as another independent execution of the instruction that originally generated it.

Three kinds of evidence appear below and shouldn't be collapsed into one:

~~~
Observed execution    An identified instruction, call or access happened

                      in a named run.

Modeled response      KEVLAR supplied the guest-visible result. The model's

                      limits are stated where they affect a conclusion.

Original-code control Original bytes executed from retained or declared

                      state. An available branch is not an executed branch.
~~~

2. Lifecycle

DriverEntry returns successfully at event 18398543**, although EOS workers continue initialization afterward.**

~~~
DriverEntry returns:

18398543

STATUS_SUCCESS

Initial runnable work drains:

20094524

Steady observation begins:

13.2266385 virtual seconds

Workload #1 completes:

20096297

Workload #2 completes:

51096881

Workload #3 completes:

73953454

Observation ends:

79695111

1800.0000337 observation seconds

DriverUnload enters:

79695124

DriverUnload returns:

85383716

Unload duration:

42.3739071 virtual seconds

Post-unload ownership snapshot:

85383750

Harness reclamation verified:

85388264

Trace closes:

85388481
~~~

The primary run therefore includes 30 virtual minutes of steady observation**. DriverUnload consumes another **42.3739071 virtual seconds while remaining worker activity finishes.

Initialization has a time-dependent branch

An older execution of this exact root image, P185, exposed a timing-sensitive protected branch.

P185 finishes FltStartFiltering and IoCreateSymbolicLink at events 18394308 and 18394311, after 94.4187147 virtual seconds of setup, then enters rollback.

A fixed-frame experiment held the remaining inputs constant and varied elapsed SystemTime:

~~~
Elapsed time       Continuation   Result

-----------------  -------------  -----------------------------------

60.9999999 sec     0x39F3B0       returns to 0x259518, RAX = 0

61.0000000 sec     0x41C1BE       reaches rollback routine 0x216CAD
~~~

The actual tail is indirect:

~~~
00AF541C  add rsp, 220h

00AF5423  pop rbp

00AF5424  jmp rsi
~~~

The threshold comes from following the computed continuation while changing one retained input. The original code doesn't contain a literal `cmp time, 61`.

Following the timing value into the continuation

Later original-code replay identifies the two inputs consumed by this decision. RVA 0xAF3D3C** reads SystemTime, while **0xAF4496** reads the saved initialization timestamp from the retained frame. The protected arithmetic reconstructs their difference and multiplies it by 100, converting the 100 ns units into nanoseconds.**

~~~
00AF3D3C  mov rdx, [rax]             ; SystemTime

; protected arithmetic / address construction omitted

00AF4496  mov r15, [r15]             ; saved initialization timestamp

; split-width subtraction omitted

00AF4559  mov rdx, r9

00AF455C  shr rdx, 15h

00AF4560  and edx, 1FFFFFh

00AF4566  imul rdx, rdx, 64h

00AF456A  mov r14d, edx

00AF456D  shr r14d, 15h

00AF4571  and r9d, 1FFFFFh

00AF4578  imul r9, r9, 64h

00AF457C  shl rdx, 15h

00AF4580  add rdx, r9                ; nanoseconds in the boundary cases
~~~

The adjacent boundary inputs produce 60,999,999,900** and **61,000,000,000** at 0xAF4583. Moving both timestamps by plus or minus one day leaves the boundary unchanged, and changing InterruptTime independently does not alter the result in the controlled cases.**
A later arithmetic proof narrows this further. The original block at 0xAF4640-0xAF46C8** implements a signed comparison against **61,000,000,000 ns. The constant is split across the protected limb arithmetic rather than appearing as one immediate: `0x0FFFFF1C` is -228 in the 28-bit middle limb, `0x0C1DDE00` contributes 203,283,968 in the low limb, and -228 x 2^28 + 203,283,968 = -61,000,000,000.

~~~
00AF4645  add edx, 0C1DDE00h

00AF464B  and edx, 0FFFFFFCh

00AF4653  cmp edx, 0C1DDE00h

00AF4659  setb dil

; carry propagation omitted

00AF4671  lea ecx, [rdi+rbx+0FFFFF1Ch]

; top-limb/sign handling omitted

00AF4690  add cl, sil

00AF4693  dec cl

00AF4695  shr cl, 7

00AF4698  shr eax, 15h

00AF469B  mov edx, ecx

00AF469D  xor dl, al

00AF469F  and dl, al

; unrelated result preparation omitted

00AF46BE  xor dl, cl

00AF46C0  movzx esi, dl

00AF46C3  mov edx, esi

00AF46C5  and edx, 1
~~~

The recovered predicate is equivalent to:

~~~
elapsed_ticks    = current_system_time - saved_start_time   (mod 2^64)

elapsed_ns_bits  = elapsed_ticks * 100                      (mod 2^64)

success          = signed64(elapsed_ns_bits) < 61000000000
~~~

The original 39-instruction block was exercised across 115 controlled cases, including threshold-adjacent inputs, negative values, carries and signed extrema. A separate SMT check found no counterexample for the lifted 64-bit comparison.

Where the saved timestamp comes from, and what the branch actually does

This one is now closed for the identified mechanism, so here is the rest of it.

The saved timestamp has a located producer. An original startup prefix reads the same shared SystemTime address and stores it at a frame slot that the later code reaches as context `+308h`:

~~~
022BF0D8  49 8B 0A    mov rcx, [r10]    ; R10 = FFFFF78000000014h

022BF0DB  48 89 0F    mov [rdi], rcx    ; RDI = context + 308h in the controls
~~~

Twelve bounded startup controls vary clocks, initial registers, vector values and stack position, and each reaches that store.

The same timing block also clears a device flag before the comparison. `AF3C67` reads the device Flags dword and `AF3CA7` writes back `flags & 0xFFFFFF7F`, clearing bit `0x80`. In the documented Windows device-object contract that bit is `DO_DEVICE_INITIALIZING`, which a driver clears once its device is ready.

~~~
00AF3C67  8B 08    mov ecx, [rax]    ; device Flags dword

; ... protected bit manipulation ...

00AF3CA7  89 30    mov [rax], esi    ; original flags with bit 80h cleared
~~~

The selector proof now covers every pair of 64-bit clock values and every 32-bit device-flags value, with the remaining retained frame inputs fixed. Ten negated obligations return UNSAT. Twelve original-code controls match 20,016 instruction-entry checkpoints, 320,256 general-register values and 1,104 consumed CF/ZF values, stopping at the final indirect jump with every memory read defined.
The failure side has a concrete outcome. P185 unregisters its filter at 18394312** and DriverEntry returns **0xC000026C** at **19738271. The local Windows SDK names that status:

~~~
STATUS_DRIVER_UNABLE_TO_LOAD
~~~

The selected result records contain a generic initialization failure. They do not contain a hypervisor-specific classification.

One more control keeps this from being over-generalized. The same comparator is shared code. C399 hits it early in initialization, produces predicate one at 33714, selects 0x382EEC at 34606 and executes it at 34607. Replaying 823 captured instruction-entry checkpoints and 13,168 register values from that frame shows the comparator computing the same predicate for every declared 64-bit operand, while the target stays `0x382EEC` on both sides of the threshold. Both equivalence checks are UNSAT.

~~~
Protected context              Below 61e9 ns   At or above

-----------------------------  --------------  --------------

Retained P185 late init        39F3B0          41C1BE

Captured C399 early invocation 382EEC          382EEC
~~~

So this is an initialization time budget in the P185 frame, with both destinations executed and an observed failure status. It still does not identify a hypervisor verdict, debugger verdict or reporting action attached to that budget, and it does not extend to every hit of the shared comparator.

3. Worker tree and recurring work

C317 instantiates 17 EOS-created system threads**. Every one enters the common protected worker entry at:**
RVA 0x1CBE5B

and eventually reaches PsTerminateSystemThread(0).

The last column is a code pointer stored at private-context offset `+0x10`. It is not a recovered task name, and a shared entry address doesn't make two workers the same task.

~~~
EOS TID  Creator   Entry event   Terminate(0)   Completion   Context +10h

-------  -------  ------------  -------------  -----------  ------------

332      328      40829         85380429       85380435     0x22505C

356      328      41809         85377486       85377492     0x75E3C

404      328      41888         85377211       85377217     0x75E3C

484      328      41965         85377625       85377631     0x75E3C

876      328      42042         85377732       85377738     0x75E3C

1108     328      18291917      85380523       85380529     0x75E3C

1116     328      18292002      85380615       85380621     0x75E3C

1124     328      18396021      79695653       79695659     0xEC6E5

1332     356      19679418      25776336       25776342     0x22569B

1424     356      19680656      25776631       25776637     0x22569B

1444     404      19731536      19731585       19731590     0x21D235

1568     404      19732196      19732244       19732249     0x21D235

1672     876      20101922      20108797       20108803     0x22569B

1732     876      29383219      31125921       31125927     0x22569B

1880     876      56080154      57824502       57824508     0x22569B

1884     404      68516418      69904232       69904238     0x75E3C

2064     404      78015802      79387949       79387955     0x75E3C
~~~

Worker 404 handles all **21 TPM submissions** in C317, all four captured storage responses, firmware-variable work, WMI and PCI activity.
Worker 484** obtains and later frees the network interface table.**
The five workers sharing context pointer 0x22569B** show process attachment, multi-object waits and event-based synchronization. A later capture, C460, records EOS storing exactly `eos.sys+0x22569B` into a worker context at `+0x10h` while setting up an **ETW real-time consumer**, then creating a thread at `0x1CBE5B` with that context. C317 has five trace sessions, five consumers, and five workers carrying this context pointer. The correspondence is consistent; the C317 bodies themselves were not instruction-traced.**
TID 2064** begins at observation offset **1791.7957331 seconds, only a few seconds before the thirty-minute deadline.

Approximately one-second module refresh

A focused run contains:

~~~
Allocations:             791

Allocation size:         60,988 bytes

Response size:           60,984 bytes

Allocation return RVA:   0x10801D

Corresponding frees:     791

Median replacement:

1.0008451 virtual seconds
~~~

After the first allocation, each freed pointer is the previous module snapshot.

EOS handles STATUS_INFO_LENGTH_MISMATCH, resizes, retries, publishes the new snapshot and retires the old one.

4. Hardware, boot policy and machine identity

Boot security policy and OS state

EOS queries more than identity. It also asks Windows about the trust and virtualization context of the current boot.

C317 contains:

~~~
Boot-environment queries, class 90:

2

Secure Boot queries:

2

Code Integrity queries:

3

Build-version queries, class 222:

42

DMA-guard policy queries, class 202:

1

Isolated-user-mode queries, class 165:

1

Enlightenment-information queries, class 91:

1

Speculation-control queries, class 201:

1

Custom-kernel-signer licensing query:

1
~~~

The delivered state includes:

~~~
Firmware type:

2

Boot flags:

0

Secure Boot enabled:

1

Secure Boot capable:

1

Code Integrity options:

0x5

Windows build:

22631

QFE:

7517

Edition marker:

DesktopEditions

DMA guard:

disabled in the modeled response

Isolated user-mode flags:

0

Connected hypervisor / enlightenment fields:

absent in the modeled response

Custom configurable kernel signers:

DWORD 0
~~~

The boot-environment query also returns a captured boot GUID. I've omitted the host-specific value here.

The licensing value is:

~~~
CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners
~~~

This is Windows signing policy, not an EOS account-license check.

Relevant original EOS call sites:

~~~
00099230  call qword ptr [r14]

; boot-environment query

0042928C  call qword ptr [rsp+8]

; NtQueryLicenseValue

003FEB24  call qword ptr [rsp+8]

; Secure Boot query

003C68AB  call qword ptr [rsp+8]

; DMA-guard policy

00432EE8  call qword ptr [rsp+8]

; isolated user mode

003776CE  call qword ptr [rsp+8]

; enlightenment information
~~~

The zero virtualization-related fields are KEVLAR's modeled results. They don't establish that EOS failed to detect a hypervisor on the physical host.

Registry identity inventory

The registry catalog contains:

~~~
153 attempts

88 distinct key/value groups

21 distinct value names

65 exact captured payload deliveries
~~~

Names:

~~~
AttestationKey

BIOSReleaseDate

BIOSVendor

Blob

ComputerHardwareId

DeviceDesc

DriverDesc

EacQuoteKey

LocationInformation

MachineGuid

MachineId

ProcessorNameString

QuoteKeyStatus

QuoteKeyStatusCode

SMBiosData

Service

SusClientId

SystemManufacturer

SystemProductName

TaskReadyForAttestation

WindowsAIKHash
~~~

MachineGuid and ComputerHardwareId

These two have direct named-request evidence.

~~~
MachineGuid

Query:       19740440

Completion:  19740468

Payload:     74 string bytes

ComputerHardwareId

Query:       19729598

Completion:  19729626

Payload:     78 string bytes
~~~

Acquisition bridge:

~~~
003D16D6  mov rsp, r12

003D16D9  call 0x36217F

003D16DE  lea rsp, [rsp+1C0h]

003D16E6  call qword ptr [rsp+8]

003D16EA  lea rsp, [rsp-1C0h]

003D16F2  call 0x362060
~~~

The trace resolves the call to NtQueryValueKey and binds the requested value name.

EOS explicitly selects and receives both values.

Where those delivered buffers actually go

A later pass followed the response allocations to their release instead of stopping at delivery. Six of them now have a bounded delivery-to-release record: both registry identifiers, registry SMBIOS, Boot0000, the monitor WMI response and the TPM ReadPublic response.

~~~
Response buffer            Delivered   ExFreePoolWithTag   Modeled unmap

-------------------------  ----------  ------------------  -------------

ComputerHardwareId, 90 B   19729626    19729689            19729691

MachineGuid, 86 B          19740468    19740532            19740534

Registry SMBIOS, 4,753 B    8602194     8602206             8602208

Boot0000, 300 B             8570305     8570322             8570324

Monitor WMI, 608 B         19734291    19734300            19734302

TPM ReadPublic, 398 B      19734344    19734349            19734351
~~~

The value data in the two registry results follows the 12-byte `KEY_VALUE_PARTIAL_INFORMATION` header. Some outputs are stack destinations instead: `BootCurrent` writes two bytes and `OfflineUniqueIDRandomSeed` writes 32 bytes straight onto the caller's stack.

That rules out treating those response addresses as persistent containers past the free. A copy, hash or encoded record could have been produced before release, and that reader is the next target for each of them. The destination index preserves 183 retained completions and 236 reported output destinations across the registry, TPM, storage and firmware/WMI groups.

SMBIOS

EOS obtains SMBIOS through two separate paths.

~~~
Registry source:

SMBiosData

Events:

8602193 -> 8602194

Payload:

4,741 bytes
~~~

Firmware source:

~~~
NtQuerySystemInformation class:

0x4C

Provider:

RSMB

Table:

0

API:

19734421 -> 19734423

Decoded delivery:

19734422

Payload:

4,741 bytes
~~~

The acquired tables contain system, board, chassis, BIOS, memory and processor identity fields.

The registry SMBIOS source contains an all-zero system UUID, while the separately captured firmware-table source contains a nonzero UUID. They remain separate evidence sources.

UEFI variables

EOS requests:

~~~
BootCurrent

8570275 -> 8570278

2 bytes

Boot0000

8570303 -> 8570305

300 bytes

OfflineUniqueIDRandomSeed

19734310 -> 19734313

32 bytes
~~~

Boot0000 contains:

~~~
\EFI\MICROSOFT\BOOT\BOOTMGFW.EFI
~~~

and a GPT partition GUID at load-option offset +0x48.

OfflineUniqueIDRandomSeed is selected under:

~~~
eaec226f-c9a3-477a-a826-ddc716cdc0e3
~~~

ATA disk identity

EOS sends ATA IDENTIFY DEVICE, command 0xEC, using:

~~~
SMART_RCV_DRIVE_DATA       0x7C088

ATA_PASS_THROUGH_DIRECT    0x4D030
~~~

SMART path:

~~~
Request build:

19730854 -> 19730858

Dispatch:

19730861 -> 19730867

Captured response:

19730862

IRP completion:

19730863
~~~

Direct path:

~~~
Request build:

19731563 -> 19731568

Dispatch:

19731571 -> 19731578

Data copy:

19731573
~~~

IDENTIFY DEVICE fields:

~~~
Serial:    byte 20

Firmware:  byte 46

Model:     byte 54
~~~

With the SMART response header:

~~~
Serial:    36

Firmware:  62

Model:     70
~~~

EOS receives ATA data containing the drive serial, firmware revision and model.

A second serial source: cached storage state

The pass-through response isn't the only place the disk serial comes from. EOS also walks captured kernel memory to a cached storage descriptor and reads the serial characters out of it directly.

In C317 it follows the device object at `FFFF918F9F3D10A0` through a pointer at `+40h`, then another pointer at `FFFF918F9F3D13F8`, to a record at `FFFF918F9BCF9390`. The two fields it reads there match the documented `STORAGE_DEVICE_DESCRIPTOR` layout:

~~~
record +4    0x18C    Size

record +18h  0x5A     SerialNumberOffset
~~~

The offset points at twelve spaces followed by the eight serial characters and a NUL. Events 19731646-19731654 record EOS reading those nine bytes one at a time.

~~~
013FC197  mov   ecx, [r10]                ; #19731631: record+4

02A2D97F  mov   r11d, [rax]               ; #19731632: record+18h

0262957E  movzx eax, byte ptr [rax]       ; #19731646-54: serial bytes and NUL

00259029  movups xmm1, xmmword ptr [rdx+r8-10h]

                                          ; #19731658 includes the eight serial bytes
~~~

The direct ATA response is released at 19731623 and unmapped at 19731624, so the pass-through buffer is already gone when the cached record is read. Two successful multibyte-to-Unicode conversions occur around this interval, at 19731621 and 19731664, and a case-insensitive Unicode comparison at 19731666 returns equal at 19731667.

A consistency check between the pass-through data and cached storage state is the obvious reading, and it's the reason I want this one resolved. The comparison's operand contents aren't retained in that older trace, so equality alone doesn't establish which two strings were compared.

Monitor identity

EOS queries WmiMonitorID:

~~~
GUID:

671a8285-4edb-4cae-99fe-69a15c48c0bc

API:

19734289 -> 19734291

Decoded delivery:

19734290

Size:

608 bytes
~~~

The two returned WNODE records contain manufacturer, product, serial, display-name and production fields.

TPM public material

C317 contains 21 TPM submissions.

~~~
ReadPublic(0x81010001)

19734342 -> 19734344

Area A

CreatePrimary(0x4000000B)

19741871 -> 19741874

Area A

ReadPublic(0x810EAC00)

19742126 -> 19742128

Area B
~~~

The target is Tbsip_Submit_Command.

~~~
0006E393  mov [rsp+30h], r13

0006E398  mov [rsp+28h], rbx

0006E39D  mov [rsp+20h], r14d

0006E3A2  mov rcx, r15

0006E3A5  xor edx, edx

0006E3A7  mov r9, [rsp+40h]

0006E3AC  call r10

0006E3AF  test eax, eax

0006E3B1  je 0x6E3F8
~~~

The returned packets expose two distinct RSA public areas and their TPM Names. Area A has restricted-decryption attributes, area B restricted-signing attributes, and both Names verify as SHA-256 over the returned public bytes.

The wrapper tests the TBS transport status in EAX. The TPM response code is a separate field inside the response buffer, so a successful transport doesn't mean the TPM command succeeded or that an attestation decision passed.

Network interfaces

GetIfTable2:

~~~
API:

58594 -> 58598

Allocation / delivery:

58597

Free:

68818

Rows:

24
~~~

Important MIB_IF_ROW2 offsets:

~~~
LUID                     +0x000

Interface index          +0x008

Interface GUID           +0x00C

Physical-address length  +0x420

Current MAC              +0x424

Permanent MAC            +0x444
~~~

The returned table carries both current and permanent MAC addresses.

Which interface fields EOS actually reads

Delivery of the table isn't the same as consumption of its MAC fields, so this one got followed instruction by instruction. C425's actual `GetIfTable2` events 61418-61422 on worker 484 lead into a retained 32,768-entry instruction window, and a declared continuation walks the whole table.

~~~
All 24 rows inspected:               781,389 original instructions

Rows with an interface-GUID read:    15

Rows with flags/state reads only:      9

Current MAC read in that interval:     0

Permanent MAC read in that interval:   0
~~~

The GUID does have a consumer. At sequence 64779 RDX points at row zero's `InterfaceGuid`, at row offset `Ch`; two read witnesses supply all sixteen bytes; EOS copies the vector to a local stack slot.

~~~
009B5DBB  F3 0F 6F 02       movdqu xmm0, xmmword ptr [rdx] ; InterfaceGuid

009B5E41  F3 41 0F 7F 03    movdqu xmmword ptr [r11], xmm0
~~~

The GUID then reaches arithmetic directly. The first invocation splits it into two qwords and combines them with local accumulator fields:

~~~
009B66B2  66 0F 70 C8 EE            pshufd xmm1, xmm0, 0xee

009B66B7  66 48 0F 7E C1            movq rcx, xmm0

009B66BC  48 8B BC 24 08 01 00 00   mov rdi, qword ptr [rsp + 0x108]

009B66C7  48 F7 E1                  mul rcx

009B66CA  66 48 0F 7E CE            movq rsi, xmm1

009B66CF  48 0F AF FE               imul rdi, rsi

009B66D3  48 09 D7                  or rdi, rdx

009B66F1  48 31 CA                  xor rdx, rcx

009B66F4  48 31 C2                  xor rdx, rax

009B66F7  48 89 94 24 D0 00 00 00   mov qword ptr [rsp + 0xd0], rdx

009B66FF  48 31 F7                  xor rdi, rsi

009B6702  4C 31 CF                  xor rdi, r9

009B6705  48 89 BC 24 C8 00 00 00   mov qword ptr [rsp + 0xc8], rdi
~~~

In the captured state the multiplier and previous accumulators are zero, so those two stores just retain the GUID halves. Six controls then run the collector to its native return at 785,379 instructions: baseline, both MAC substitutions swapped in each direction, single GUID bit changes in rows 1 and 14, and the complement of all fifteen read GUIDs. All six agree on path, 18 scalar registers, 16 YMM registers, 1,432 defined caller-stack bytes and 18,763 non-stack stores.

So in this interval the transient GUID arithmetic leaves no surviving difference in the compared return state, and neither MAC field is read at all. The table is released through `FreeMibTable`; C434 records the actual call and the 32 KiB release at events 108847-108850.

ExUuidCreate and the MAC-related node

C317 events 19679279-19679280 record a successful ExUuidCreate call on worker 356.

The returned 16-byte value is a version-1 UUID, so its last six bytes contain a node.

~~~
003FB4D5  mov rsp, r12

003FB4D8  call 0x36217F

003FB4DD  lea rsp, [rsp+1C0h]

003FB4E5  call qword ptr [rsp+8]

003FB4E9  lea rsp, [rsp-1C0h]
~~~

The node correlates with the current MAC of one captured adapter and associated filter rows; that adapter's permanent MAC differs.

This UUID is separate from the SMBIOS UUID and NVIDIA UUID.

UUID node stability across later profiles

Later retained profiles separate the UUID's node from its clock sequence. C317, C386 and a retained C388 profile snapshot use the same six-byte node while the fourteen-bit clock sequence changes.

~~~
Seed component              C317                    C386 / retained C388

--------------------------  ----------------------  ----------------------

Node                        2C-F0-5D-D7-3E-34       2C-F0-5D-D7-3E-34

Clock sequence              0x0A1F                  0x0A23

Local-only node             false                   false
~~~

A changed sequential-UUID seed hash therefore does not, by itself, mean the MAC-related node changed. Version-3 hardware profiles now retain the complete nine-byte seed. Qualification covers exact replay bytes, both return statuses, legacy behavior and malformed-input rejection across 69 validated run bundles.

What the generated UUID is used for

This is the part I couldn't answer in the first post. The UUID is an ETW session identifier.

EOS places the sixteen bytes directly into `WNODE_HEADER.Guid`, at request offset `18h`. In C425 the request is 252 bytes starting at `FFFFB00044DCC010`, so the UUID sits at `FFFFB00044DCC028`. The logger name in that request is a separate value and is not a formatted copy of the generated UUID.

~~~
ExUuidCreate

   -> UUID at request +18h

   -> NtTraceControl function 2   (stop the named session)

   -> NtTraceControl function 1   (start it, same request, same UUID)
~~~

Function 2 is the stop request; the native target is `EtwpStopTrace`. Function 3, which the host capture helper uses to ask whether a logger exists, reaches `EtwpQueryTrace`. Getting those two backwards would change the reading of this sequence entirely.

~~~
0038C7B5  48 8D A4 24 C0 01 00 00  lea rsp, [rsp+1C0h]

0038C7BD  FF 54 24 08              call qword ptr [rsp+8] ; function 2, stop

; ... 4,624 original instructions in the admitted continuation ...

003C9F95  48 8D A4 24 C0 01 00 00  lea rsp, [rsp+1C0h]

003C9F9D  FF 54 24 08              call qword ptr [rsp+8] ; function 1, start
~~~

Six controls separate the UUID fields from the creation status. Each substitutes one input and follows the original caller to the start request:

~~~
Input changed                              Result at the start boundary

-----------------------------------------  --------------------------------

Nothing (captured UUID, success)            Same 252-byte request

Node -> the adapter's permanent MAC         Changed UUID submitted, same path

Node -> 02:00:00:00:00:01                   Changed UUID submitted, same path

Clock sequence 0A1Fh -> 0A23h               Changed UUID submitted, same path

Timestamp + 1 tick                          Changed UUID submitted, same path

Status -> RPC_NT_UUID_LOCAL_ONLY            Frame values differ, then converge
~~~

No original read or write intersects the sixteen UUID bytes in these caller intervals. After the declared stop response all six cases execute the same 632 reads and 554 stores, values included. EOS passes the whole UUID through the request instead of extracting its node.

The failure route erases it. On a name collision or access-denied START, EOS clears four temporary allocations and releases two process references; two vector stores overlap the UUID at `DCC028h` and `DCC030h` before the containing request is freed.

~~~
; Nonnegative START path: RAX points to request +30h.

015AAE18  8B 38           mov edi, dword ptr [rax]       ; returned BufferSize

; Failure cleanup. XMM0 is zero in these controls.

00259324  0F 29 41 10     movaps xmmword ptr [rcx+10h], xmm0

0025932F  0F 29 41 E0     movaps xmmword ptr [rcx-20h], xmm0
~~~

This improves the input model and answers the local consumer question. It doesn't add evidence that EOS extracts the node separately or places it in a final HWID.

GPU-containing object

Focused run C205:

~~~
Events:

19729319 -> 19729323

Source:

0xFFFF918FA4AA3000

Length:

0x2000

Copy type:

virtual
~~~

The copied 8 KB object contains an NVIDIA UUID at:

~~~
+0xCD5
~~~

In the first version of this post that was where the trail ended. It doesn't end there any more.

From the GPU object to an encrypted record on a protected list

This is the longest new chain in the report, so here it is in order. Every stage is either an actual captured event or an original-code continuation from retained state, and I've labeled which.

1. EOS fetches a 16-byte reference value first. C460 events 19904085-19904088 are an actual `MmCopyMemory` of 16 bytes from `FFFF918FA4CE2DB5` into the stack slot `FFFFB00000ABB750`. Events 19904093-19904097 then copy the 8,192-byte object from `FFFF918FA4AA3000` to `FFFFB0005CE69010`. Both are observed; the payload SHA-256 is authenticated.

~~~
; Shared MmCopyMemory wrapper. C460 #19904085 binds the arguments:

; RCX=FFFFB00000ABB750, RDX=FFFF918FA4CE2DB5, R8=10h, R9D=2.

0000DA69  48895C2420      mov qword ptr [rsp + 0x20], rbx

0000DA6E  4C89F1          mov rcx, r14

0000DA71  4889FA          mov rdx, rdi

0000DA74  4989F0          mov r8, rsi

0000DA77  4189E9          mov r9d, ebp

0000DA7A  41FFD2          call r10
~~~

2. It scans the copy for that value. Original instruction `EC8568` reads bytes at offsets 0 through 6 of the copy, `D0 4E D3 A6 00 F8 FF`, with 10,362 original instructions between byte loads. A retained continuation runs the scan out: 3,284 nonmatching byte positions, then a different route at offset `CD4h`.

~~~
00EC8568  440FB611        movzx r10d, byte ptr [rcx]   ; candidate byte

; ... on the matching route ...

00EC86FD  F3410F6F02      movdqu xmm0, xmmword ptr [r10] ; candidate at marker+1

00EC8730  F30F6F0F        movdqu xmm1, xmmword ptr [rdi] ; stack reference

00EC88D6  660F70D0EE      pshufd xmm2, xmm0, 0xee

00EC88DB  660F70D9EE      pshufd xmm3, xmm1, 0xee

00EC88E0  66490F7EC5      movq r13, xmm0

00EC88F1  66490F7ECE      movq r14, xmm1

00EC8904  66480F7ED5      movq rbp, xmm2

00EC8926  66490F7EDB      movq r11, xmm3
~~~

The match condition is a marker byte `01h` at `CD4h` followed by the 16-byte reference at `CD5h`. Two control sets pin that down:

~~~
Control                                         Cases   Result

----------------------------------------------  ------  -------------------------

Candidate equals reference, marker = all values   256    only 01h leaves the loop

Marker = 01h, flip each of 128 candidate bits     128    every flip returns to loop
~~~

So the field location at `+0xCD5` isn't assumed from a hexdump. EOS discovers it by searching the copied object for a value it already holds.

3. It erases and frees the copy. A declared continuation zeroes all 8,192 payload bytes and transfers to `ExFreePoolWithTag`; the actual free is C460 event 19980930, tag `ClfC`. The final memory check confirms every payload byte is zero.

~~~
00259435  F3AA        rep stosb byte ptr [rdi], al

0020F7C4  49FFE0      jmp r8       ; ExFreePoolWithTag(base, ClfC)
~~~

The stack reference is a separate location, which is why the value survives.

4. The reference is encoded into a private record. The next continuation reads all sixteen reference bytes at RVA `2325F46` and writes an encoded sequence at `2325FAA` into a `CM13` record at `FFFFB00055B83010`, offset `26h`.

~~~
02325F46  450FB620     movzx r12d, byte ptr [r8]   ; reference byte

; byte combiner, intervening upper-bit arithmetic omitted

02325F76  4420E1       and cl, r12b

02325F79  428D1420     lea edx, [rax + r12]

02325F7F  8D3C09       lea edi, [rcx + rcx]

02325F82  4028FA       sub dl, dil

02325FAA  8803         mov byte ptr [rbx], al      ; encoded output byte
~~~

Executing the original block for all 65,536 input-byte/mask-byte pairs agrees with `output = input XOR mask`. The mask-state generator is still unreconstructed, so this is the local operation only.

~~~
Record offset   Contents

--------------  ------------------------------------------------

+20h            header dword, updated as old_value XOR 1Ah

+26h..+35h      sixteen encoded UUID bytes

+36h..+3Dh      eight further output bytes

+3Eh..+3Fh      two later stores: 23 F6

+1Ch            changed from A269BAC7h to 75B0726Eh in C484
~~~

The `+20h` update is worth a note. The protected arithmetic looks at first like `old_value + 1` assembled from 15-bit limbs, but the complete stored expression reduces to `old_value XOR 1Ah`. A bit-vector solver finds no 32-bit input where the lifted expression differs, and a separate execution of the original machine code agrees for 4,191 values including limb boundaries and wraparound. `1Ah` is 26, which is the number of bytes just written: two initial bytes, sixteen encoded UUID bytes and eight following bytes. That's a record-accounting lead, not a decoded length field.

~~~
00B63DF5  8B5500                 mov edx, dword ptr [rbp]   ; record +20h

00B63F22  31F9                   xor ecx, edi

00B63F24  31C1                   xor ecx, eax

00B63F26  894C2434               mov dword ptr [rsp + 0x34], ecx

00B643C9  488B542450             mov rdx, qword ptr [rsp + 0x50]

00B643CE  8B5C2434               mov ebx, dword ptr [rsp + 0x34]

00B643D2  891A                   mov dword ptr [rdx], ebx   ; stored back
~~~

5. The record is copied into a wrapper allocation.** C484 reaches `1416EE3` on worker 404 with the same record address, changes `+1Ch`, allocates `70h` bytes with tag `61434D43h` (`CMCa`) at events 19854096-19854099, and copies all 64 bytes into it. The local replay matches all 16,384 captured scalar checkpoints.**

~~~
Object              Address / size        Role

------------------  --------------------  ----------------------------------

Source record       FFFFB00055B83010 40h  encoded UUID and updated header

Raw CMCa            FFFFB0005CE6C000 70h  allocation, tag CMCa

Usable wrapper      FFFFB0005CE6C010      wrapper fields precede the record

Copied record       FFFFB0005CE6C030 40h  exact copy of the updated source
~~~

6. The copy is encrypted in place, and it's XXTEA.** All **144 successive dword updates match corrected Block TEA over sixteen words and nine rounds. The four key words were stored into the wrapper header during the captured prefix, so they're per-record values observed in this run:

~~~
Key word   Allocation offset   Captured value   Original store / event

K[0]       +1Ch                3DA7B79Ah        RVA 1816C86, #19858288

K[1]       +20h                D3CA47F0h        RVA 83443A,  #19859884

K[2]       +24h                4657CF65h        RVA 83443A,  #19861413

K[3]       +28h                DC3C0140h        RVA 68C7FD,  #19863669
~~~

~~~
01816C86  45 89 32       mov dword ptr [r10],r14d ; captured K[0]

0083443A  89 30          mov dword ptr [rax],esi  ; captured K[1], then K[2]

0068C7FD  89 10          mov dword ptr [rax],edx  ; K[3], then body words

0068F45B  44 89 01       mov dword ptr [rcx],r8d  ; final word of each round

0038AF14  FF 54 24 08    call qword ptr [rsp+8]   ; ExAcquireFastMutex
~~~

Changing one key bit, or reversing the input word byte order, changes the output. The identification holds for this captured record; it says nothing about how the key is generated.

7. The wrapper is appended to a protected list. The continuation reaches `ExAcquireFastMutex` with the mutex at **`image+30A830h`** and the wrapper still in RSI; C484 events 19865007-19865009 confirm the target, arguments and successful acquisition. The next instructions read the list head at **`image+30A900h`**.
C500 captures the actual append. At event 19872239, `EOS+232C4F5` writes the wrapper `FFFFB0005CE6C010` into the previously null next-pointer slot at `FFFFB00055B82010`.

~~~
0232C4F5  4C 89 11       mov qword ptr [rcx],r10 ; tail slot = new wrapper
~~~

An endpoint check ties the two halves together: the first 64 plaintext bytes captured at #19885756 encrypt exactly to the wrapper's ciphertext under the qualified XXTEA recurrence and those four captured key words. A one-bit key change and reversed word byte order both break the equality.

8. The plaintext is erased and released. The cleanup reads each allocation's tag at raw offset zero and payload length at `+8`, subtracts the length from a byte counter at `image+30D630h`, decrements an allocation counter at `image+30D628h`, clears the payload plus its 16-byte header and calls `ExFreePoolWithTag`.

~~~
Allocation        Raw address       Payload   Cleared   Free / unmap

CM27 temporary    FFFFB00055BAE000     296       312     19883064-19883067

CM13 plaintext    FFFFB00055B83000  44,204    44,220     19887418-19887421
~~~

~~~
Byte counter       19,522,606 -> 19,522,310 -> 19,478,106

Allocation counter      1,256 ->      1,255 ->      1,254
~~~

The CM13 clear includes 44,156 byte stores through `REP STOSB` after the initial 64 bytes, and original-code replay confirms every byte is zero at the cleanup boundary.

9. The wrapper itself is freed during DriverUnload. C500 records `ExFreePoolWithTag(FFFFB0005CE6C000, 61434D43h)` at event **20255930**, followed by the modeled unmap at 20255932, inside DriverUnload scope 588465.

~~~
DriverUnload begins        20253274   EOS+CE846

Previous tail released     20255926   tag Dcdd

NVIDIA wrapper released    20255930   tag CMCa

DriverUnload returns       20259577

Harness reclamation        20259598
~~~

That free site serves a broader cleanup: across the whole C500 DriverUnload interval the same caller appears in 79 frees with 34 distinct tag values, `CMCa` three times and `Dcdd` twice. So the adjacency identifies a useful capture sequence without identifying the structure that selected those nodes.

What this establishes, and what it doesn't. EOS acquires a GPU-derived reference, locates it inside a copied private object by search, encodes it into a record, encrypts that record with XXTEA using per-record keys stored beside it, queues it on a mutex-protected list, erases the plaintext, and frees the queued object at unload. That is a complete producer-to-teardown path.

The payload reader is still missing. No instruction has been observed reading that ciphertext back, and the release at unload is equally compatible with an earlier delivery or with a record that sat queued and was discarded. The list is the single most useful next target in the whole report.

5. PCI, ACPI and physical access

Moved to a follow-up post in this thread so the main post fits the forum's length limit: [Platform and processor probes](https://www.unknowncheats.me/forum/4806980-post61.html).

It covers the 512 `HalGetBusDataByOffset` calls and 272 `HalpPCIConfig` calls, the C388 all-ones predicate over the eight bytes returned from configuration offset `0x04`, the twelve requested ACPI tables, the single HPET and local-APIC register reads, and the physical-alias and physical-copy counts.

6. Persistent state and cross-processor work

KeCapturePersistentThreadState

EOS requests a persistent-thread-state buffer during initialization.

C317:

~~~
Call:

41610 -> 41612

EOS call RVA:

0x3F8993

Returned buffer:

256 KiB

Guest address:

0xFFFFB00000988010
~~~

Original EOS call:

~~~
003F8993  call qword ptr [rsp+8]
~~~

The runtime target is:

KeCapturePersistentThreadState

EOS supplies a guest context, a null thread argument and zero bugcheck parameters.

The returned buffer begins with the expected dump signatures:

~~~
PAGE

DU64
~~~

KEVLAR builds the buffer from its modeled context and kernel metadata. The response contains fields such as CR3, kernel list-head addresses, processor information and build metadata.

Some native fields are absent or zero in the model, including the default PFN-database address.

This is a real EOS acquisition call, but the returned 256 KiB structure is synthetic provider output rather than a host crash dump.

Bugcheck secondary-data callback

EOS separately registers a bugcheck-reason callback:

~~~
EOS callback RVA:

0xA1120

Reason:

2

Registration:

18397159
~~~

The three workload invocations return:

~~~
OutBuffer:

0

OutBufferLength:

0

MaximumAllowed:

65536
~~~

Events:

~~~
20095099

51095609

73952247
~~~

The exercised fixture therefore produces no secondary-dump payload.

KeIpiGenericCall

EOS makes 2,265 KeIpiGenericCall calls**:**

~~~
Initial runnable work:

2,264

Steady observation:

1
~~~

The model records 27,180 IPI-worker entries, corresponding to twelve modeled processor participants per broadcast.

Most broadcasts target:

~~~
EOS RVA 0xEA80C:

2,258 broadcasts

EOS RVA 0xA106C:

5 broadcasts

EOS RVA 0x8BEF9:

2 broadcasts
~~~

First broadcast scope:

~~~
19744422 -> 19744563
~~~

Original call bridge:

~~~
00429527  call qword ptr [rsp+8]
~~~

The emulator serializes the participants while retaining processor identity and callback results. These records shouldn't be read as simultaneous execution on twelve physical host cores.

One IPI callback measures progress on another processor

C317 event 19744422 passes RVA 0xA106C to KeIpiGenericCall, and that body turned out to be readable. It assigns roles by arrival order, waits for at least two participants, and lets the second arrival increment a shared counter while the first arrival runs supplied callbacks and samples that counter.

~~~
Context offset  Access in the original worker                  Role

+0x00           atomic fetch-and-increment, wait for > 1        arrival ticket / barrier

+0x04           polled by waiters, set to 1 by first arrival    completion flag

+0x08           tested by second arrival; address passed on     gate for increments

+0x0C           atomically incremented; sampled and reset       shared progress counter

+0x10           initialized to all ones, conditionally replaced retained sample

+0x18           called with gate address and [+0x20]            per-round callback

+0x20           passed to both supplied callbacks               shared callback argument

+0x28           optional call; zero byte skips the round loop   admission callback

+0x30           tested for zero, compared with the loop index   requested round count
~~~

The observer loop is short and contains no timestamp instruction at all:

~~~
000A1098  mov eax, dword ptr [rsi+4]   ; completion

000A109B  test eax, eax

000A109D  jne 0A1118h                 ; return when complete

000A109F  mov al, byte ptr [rsi+8]    ; gate

000A10A2  test al, al

000A10A4  je 0A1098h

000A10A6  lock inc dword ptr [rsi+0Ch]

000A10AA  jmp 0A1098h
~~~

Twenty controlled original-code cases cover participant admission, callback preparation and sample selection. With zero callbacks and zero rounds, two, three and twelve synthetic participants complete; a single participant stays at the barrier for its whole instruction budget.

One detail stops this from being called an atomic minimum. The sample update reads the counter twice: it sign-extends the first dword for an unsigned qword comparison, then performs a separate load when storing.

~~~
000A10ED  mov eax, dword ptr [rsi+0Ch] ; comparison sample

000A10F0  cdqe

000A10F2  mov rcx, qword ptr [rsi+10h]

000A10F6  cmp rcx, rax

000A10F9  jbe 0A1104h

000A10FB  mov eax, dword ptr [rsi+0Ch] ; separate storage sample

000A10FE  cdqe

000A1100  mov qword ptr [rsi+10h], rax
~~~

A declared interleaving that starts from a retained value of ten, compares against three, then changes the counter to twelve before the second load makes the original code store twelve. So this is a cross-processor progress measurement around a supplied operation, and describing it as a global minimum needs stability or callback gating established first. The round callbacks, the final threshold and any hypervisor use of the result are all unresolved. Nothing here generates or delivers an NMI.

Support-call volume

The complete operation catalog also contains some very high-volume support routines:

~~~
_vsnprintf:

150,922

RtlTimeFieldsToTime:

8,567

RtlRandomEx:

10
~~~

These are part of the observed execution rather than separate detection mechanisms. In particular, RtlRandomEx calls don't establish a cryptographic construction.

7. Kernel-driver discovery and historical traces

EOS has several independent views of kernel drivers:

~~~
System module catalog

\Driver object namespace

PsLoadedModuleResource / loader entries

PiDDB synchronization

Image-load notifications

Image-verification callbacks

Big-pool inventory

Pool-tag information

Code-integrity state

Hotpatch state

Address-to-image attribution
~~~

PiDDBLock, PiDDBCacheTable and PiDDBCacheList

For the matching kernel:

~~~
PiDDBLock RVA:

0xC5C8C0

PiDDBCacheTable RVA:

0xD55320

PiDDBCacheList RVA:

0xD54F30

C317 kernel base:

0xFFFFF80072E00000

Runtime PiDDBLock:

0xFFFFF80073A5C8C0
~~~

EOS passes that exact lock address to ExAcquireResourceExclusiveLite with `Wait=FALSE`.

~~~
Acquire call:

165429

Acquisition / return:

165430 -> 165431

Return:

1

Release:

165712 -> 165714
~~~

Original EOS bridges:

~~~
003B31DE  lea rsp, [rsp+1C0h]

003B31E6  call qword ptr [rsp+8]

003B31EA  lea rsp, [rsp-1C0h]

; protected body omitted

003A30BD  lea rsp, [rsp+1C0h]

003A30C5  call qword ptr [rsp+8]

003A30C9  lea rsp, [rsp-1C0h]
~~~

PiDDB layout in the matching Windows kernel

The corresponding Windows code initializes an AVL table and circular list.

Entry payload:

~~~
Offset  Meaning

------  ---------------------------------------------

0x00    list links

0x10    UNICODE_STRING image basename

0x20    PE TimeDateStamp

0x24    cached result

0x28    16 bytes of additional cached result data
~~~

The update routine caps this kernel's cache at:

256 entries

Lookup compares image names case-insensitively and, in ordinary lookup mode, includes the PE timestamp.

Windows initialization:

~~~
00B5EC58  lea rdx, [PiCompareDDBCacheEntries]

00B5EC5F  lea rcx, [PiDDBCacheTable]

00B5EC66  call RtlInitializeGenericTableAvl

00B5EC6B  lea rax, [PiDDBCacheList]

00B5EC72  mov [PiDDBCacheList+8], rax

00B5EC79  mov [PiDDBCacheList], rax
~~~

C317 uses an empty PiDDB input

C317 event 23034 records:

~~~
state=empty_boot_initialized_cache
~~~

The model creates:

~~~
AVL elements:

0

List:

self-linked / empty
~~~

So C317 demonstrates EOS acquiring PiDDBLock while the cache is empty. That was the input limitation in the first version of this post, and it has since been removed.

With a populated cache, EOS compares history against the loaded-module list

C401 restores all 169 PiDDB records from the matching historical dump: every counted name, each full `0x38`-byte payload, the linked-list closure and an AVL graph of height nine. The import validates the complete bounded list and tree before publishing globals, and rejects a conflicting kernel identity rather than falling back to an empty cache.

C401c then captures what EOS does with it. Run `20260919T033517.008Z-12564`, 1,096,043 validated events, 57,644 paired call scopes.

~~~
Step                        Events            Result

--------------------------  ----------------  ------------------------------

Query loaded modules        168126-168128     205 profile modules plus EOS

Take the cache tail         168864-168866     PiDDBCacheList.Blink -> a node

Validate the counted name   170300-170312     UNICODE_STRING, length 30h

Convert the name            170846-170849     RtlUnicodeToUTF8N, 24 bytes

Search loaded modules       170874-175882     indices 0-205, 224 byte compares

                                              206 mismatch exits, returns 0

Read the cache timestamp    176239-176242     node+20h

Build a text record         178012-178014     _vsnwprintf: name, LF, hex, LF
~~~

Each module record has stride `128h`, with a word at `+26h` locating the basename inside path bytes at `+28h`. The name comparison is the same byte predicate used elsewhere in this driver: XOR the two bytes and test with mask `DFh`, which ignores bit `20h`.

~~~
; Original basename loop. R8B = DFh, R15 = byte index.

00132E71  42 8A 6C 3C 30    mov  bpl, [rsp+r15+30h] ; converted cache name

00132E76  46 8A 14 3B       mov  r10b, [rbx+r15]    ; module basename

00132E7A  45 89 D5          mov  r13d, r10d

00132E7D  41 30 ED          xor  r13b, bpl

00132E80  45 84 C5          test r13b, r8b

00132E83  75 13             jne  132E98h            ; try next module

00132E85  41 08 EA          or   r10b, bpl

00132E88  74 1D             je   132EA7h            ; both bytes are NUL
~~~

Across the protected interval there are 20 successful name conversions, exactly the last 20 supplied list entries in reverse order, and **six formatted name-and-timestamp records**. Every conversion is bound to its historical name address and output hash, and all six formatted outputs match the reconstructed UTF-16LE text including LF delimiters and the final NUL.

~~~
Formatted cache name        Timestamp   Formatter call

--------------------------  ----------  --------------

nohv-safe-testsigned.sys    6A90317E    178012-178014

Dbgv.sys                    6A3174E7    178055-178057

signed-pt-xss-probe.sys     6A94D1BF    178374-178376

mshidkmdf.sys               5213A61F    178839-178841

MSKSSRV.sys                 BCF7A2E8    180179-180181

magdrvamd64.sys             66C053DD    180271-180273
~~~

Those names come from the historical dump's boot, and they include local research drivers. Their presence proves nothing about an embedded EOS allowlist or blocklist. What the sequence does establish is a check for cache names that are absent from the current loaded-module snapshot, with the name and its PE timestamp reaching a formatter. An unloaded driver is one explanation for that difference.

Note also the capture-time mismatch: the cache comes from the historical dump while the module array comes from the selected profile, so the six strings can't be reported as native same-boot anomalies.

Why the populated walk stops after twenty records

The twenty is EOS's own bound, not the end of the list. C402 reaches the twentieth name with a zero-based traversal counter of 19, selects a count-dependent exit, and releases the PiDDB resource while another node is still available. The next historical record would have been `xvdd.sys`.

The count test is arithmetic rather than a literal compare. At the comparison, `RAX = P - R13` and `R9 = -R13` modulo 2^64, so equality tests whether the combined mixed difference `P` is zero.

~~~
012975FD  48 8B 84 24 80 00 00 00  mov rax, [rsp+80h] ; saved counter = 19

01297608  48 31 D7                 xor rdi, rdx

0129760B  48 0F AF FA              imul rdi, rdx

01297612  48 C1 E9 3C              shr rcx, 3Ch

01297619  48 C1 EE 20              shr rsi, 20h

0129761D  48 D3 EE                 shr rsi, cl

; further original mixes combine three differences into RAX

012976E1  48 09 F0                 or rax, rsi

012976E4  4C 29 E8                 sub rax, r13

012976E7  4C 39 C8                 cmp rax, r9

012976F2  40 0F 94 C7              sete dil
~~~

The unchanged fragment reproduces all eighteen captured register, RIP and flags values at each of its 2,627 instruction entries. Nine counter cases, and an exhaustive evaluation of the lifted predicate over indices 0-168, select only 19.

~~~
/* Simplified predicate only: captured state, indices 0..168. */

count_gate = (index == 19);

selected_node = count_gate ? current_node : current_node->Blink;
~~~

The lookup result also changes what happens next. With a nonzero module match, EOS reads through stack scratch and proceeds to the next-record handler. With zero, that same read is redirected to the cache record's timestamp at `node+20h`, which is the path C401c completes through formatting.

Afterwards EOS clears the temporary module buffer before returning it: it reads the allocation header, subtracts `1DC70h` from a byte counter at `30D630` and one from the count at `30D628`, zero-fills `1DC80h` bytes (121,984 including the header, which is allocation capacity, not the 60,984-byte query result), and frees with the saved tag `SmBf`.

The inventory becomes an encrypted record and goes on the same list

The six formatted records don't just sit on the stack. C408b, C413 and C415 follow them into the same record machinery the NVIDIA UUID uses.

Byte transform. C408b reads a descriptor whose length is **167 bytes**, resolves its payload pointer, and transforms input bytes into a separate stack buffer. The 65,536-instruction capture observes 18 of the 167 bytes: prefix `01` followed by the ASCII text `nohv-safe-testsig`.

~~~
; First captured input byte: 01. DL at entry: 9B.

25F1ADC     0F B6 08             movzx ecx, byte ptr [rax]

25F1ADF     41 89 D0             mov   r8d, edx

25F1AE2     41 20 C8             and   r8b, cl

25F1AE5     44 8D 1C 0A          lea   r11d, [rdx+rcx]

25F1AE9     44 89 DB             mov   ebx, r11d

25F1AEC     43 8D 04 00          lea   eax, [r8+r8]

25F1AF0     41 28 C3             sub   r11b, al

; r11b = (dl + cl - 2*(dl & cl)) mod 256 = dl XOR cl

25F1E2F     88 19                mov   byte ptr [rcx], bl
~~~

For all 18 observed byte pairs the output equals the input XOR the low byte of RDX, and an independent execution of the six arithmetic instructions verifies that identity for all 65,536 byte pairs. First outputs `9A 9F 2B E0` from inputs `01 6E 6F 68`.

Allocation with a rotating pool tag. The record allocator picks its tag from an original 45-entry table at RVA `2E9B20`, driven by a mutable DWORD at `EOS+305160`. The state update is a plain LCG followed by shifts, XORs and a remainder:

~~~
20F06D  85 C0                       test eax, eax

20F06F  75 02                       jne  20F073h

20F071  0F 31                       rdtsc                ; zero-state seed path

20F080  41 69 CA 24 C0 F3 B8        imul ecx, r10d, 0B8F3C024h

20F087  81 F1 01 47 CF 0D           xor  ecx, 0DCF4701h   ; 214013 in this state

20F08D  0F AF C8                    imul ecx, eax

20F090  41 69 D2 3D 35 D0 A6        imul edx, r10d, 0A6D0353Dh

20F097  81 F2 68 A7 FD 5B           xor  edx, 5BFDA768h   ; 2531011 in this state

20F09D  01 CA                       add  edx, ecx

20F0D5  89 14 37                    mov  dword ptr [rdi+rsi], edx

20F0E9  F7 F1                       div  ecx              ; EDX = remainder, divisor 45

20F103  8B 0C 91                    mov  ecx, [rcx+rdx*4] ; table entry
~~~

`state = (214013 * state + 2531011) mod 2^32`, with `RDTSC` seeding the zero state. The table includes `ClfC`, `ClfI`, `ClfO`, `Clfs`, `CM11`, `CM13`, `CM16`, `CM17`, `CM20`, `CM25`, `CM26`, `CM27`, `CM28`, `CM29`, `CM31`, `CM32`, `CMAl`, `CMCa`, `CMSb`, `CMSc`, `Cont`, `Dcdd`, `Devi`, `EtwB`, `UdMI`, `Uref`, `UsbC`, `WDIs`, `Wdog`, `WfpC`, `WfpS`, `ViMm`, `Nhfs`, `Ntf0`, `NtFB`, `NtFf`, `NtFL`, `Obtb`, `PcSi`, `Uswd`, `Plcl`, `ScCB`, `SmBf`, `SmMm` and `SmMs`.

That is the reason pool tags are useless as record-type identifiers here. `CM13`, `CM20`, `CMCa` and `Ntf0` label particular observed objects in particular runs, and two objects with the same tag need not be the same kind of thing.
Record build and XXTEA.** C413 captures the full aggregate and its copy:**

~~~
Inventory descriptor  length 0xA7, data at FFFFB0000110D010   #172057

Full inventory bytes  prefix 01 plus six name/timestamp pairs #172089

Allocation            ExAllocatePoolWithTag(200h, 130h, CM28) #180074

                      returns FFFFB0000111A000

Full record copy      256 bytes -> FFFFB0000111A030, 16 stores #181816-181918
~~~

~~~
+00  4 bytes   38324D43h   allocator tag

+08  8 bytes   120h        size recorded by the allocator wrapper

+18  4 bytes   1104A635h   wrapper field, purpose unresolved

+1C 16 bytes   four key words

+2C  4 bytes   100h        copied record length

+30 256 bytes  the record body
~~~

The transform over that body matches XXTEA again, this time 64 words over 6 rounds, 384 updates, with the reference recurrence from Wheeler and Needham's 1998 correction note. Keys `54B56A8F 980429F9 8254C792 A6F9E56D`.

~~~
rounds = 6 + floor(52 / 64) = 6

sum += 0x9E3779B9

e = (sum >> 2) & 3

mix = ((z >> 5 XOR y << 2) + (y >> 3 XOR z << 4))

      XOR ((sum XOR y) + (K[(p & 3) XOR e] XOR z))

word[p] += mix
~~~

That is lifted notation, not a function that appears unobfuscated in the binary. A one-bit key change and a different input word byte order both change the output.

The four key words sit beside the transformed record in the same allocation, so whoever holds the complete allocation also holds the key that reverses this layer. An independent reverse recurrence recovers all 256 copied bytes.
List insertion and plaintext release. C415 observes the append itself:

~~~
Prepare the new node      181382         next pointer zeroed at 0111A010

Acquire the fast mutex    270559-270561  image+30A830h

Read the head             270699-270700  image+30A900h -> FFFFB00000731010

Traverse                  271915-282710  eleven next-pointer reads to the tail

Append                    283718         [FFFFB00000FF5010] = FFFFB0000111A010

Release                   290345-290347  outer mutex

Clear the plaintext       300875-334612  167 bytes, 90 stores captured

Free the plaintext        334783-334786  ExFreePoolWithTag(...0110D000, Wdog)
~~~

~~~
; Initialize the new node.

232C10B  49 89 32       mov qword ptr [r10], rsi ; r10 = new node, rsi = 0

; Read the list head.

235112B  4C 8B 18       mov r11, qword ptr [rax] ; rax = image + 30A900h

; Executed eleven times while following next pointers.

18166F1  48 8B 39       mov rdi, qword ptr [rcx]

; Publish the new tail.

232C4F5  4C 89 11       mov qword ptr [rcx], r10

; Clear each plaintext byte.

1C66B7D  41 88 0B       mov byte ptr [r11], cl   ; cl = 0
~~~

Starting after the final captured mutex return, the cleanup replay matches all 40,973 available instruction-entry checkpoints and writes zero to every address from `FFFFB0000110D010` through `FFFFB0000110D0B6`, exactly 167 bytes.

The two chains meet on the same list

Worth stating on its own, because it took two separate investigations to see it:

~~~
                 PiDDB inventory              NVIDIA UUID reference

                       |                               |

              byte-wise XOR stage             byte-wise XOR stage

                       |                               |

           256-byte record, CM28 pool       64-byte record, CMCa pool

                       |                               |

         XXTEA, 64 words / 6 rounds       XXTEA, 16 words / 9 rounds

                       |                               |

                       +-------------+-----------------+

                                     |

                       ExAcquireFastMutex image+30A830h

                                     |

                       list head at  image+30A900h

                                     |

                       append store at EOS+232C4F5

                                     |

                       reader / drain / transport: unresolved
~~~

Two unrelated collection paths converge on one mutex, one list head and one append instruction. That is good evidence for a shared staging list of encoded records. It is not evidence of what drains it, and C415's walk found eleven records already on the list whose contents remain unexamined.

Repeated system-module inventory

C317 contains 1,964 system-module catalog refreshes:

~~~
Initialization:           50

Initial worker work:      14

Steady observation:    1,859

Unload:                   41

----------------------------

Total:                 1,964
~~~

The modeled catalog reports 205 captured modules plus EOS.

\Driver enumeration

EOS performs five passes over:

~~~
\Driver
~~~

Each pass returns the same ordered:

143 driver-object names

for:

~~~
715 delivered entries
~~~

Examples include:

~~~
nvlddmkm

fvevol

Wdf01000
~~~

PsLoadedModuleResource and backing objects

C317 records:

207 matched acquire/release pairs

around PsLoadedModuleResource.

The first begins at:

~~~
20169800
~~~

Original EOS routine 0x6F7BA walks loader entries and contains a path toward the backing FILE_OBJECT:

~~~
0006FDCD  mov r14, qword ptr [r14]

0006FE11  mov rax, qword ptr [r14+70h]

0006FE15  test rax, rax

0006FE18  jne 0006FE2F

0006FE1F  lea r8, [r14+58h]

0006FE2D  jmp 0006FDCD

0006FE36  mov rcx, qword ptr [rsp+0B0h]

0006FE3E  cmp qword ptr [r14+30h], rcx

0006FE42  jne 0006FDCD

0006FE44  mov rax, qword ptr [rax+28h]

; protected pointer-mask arithmetic omitted

0006FE71  and rbx, qword ptr [rax+40h]

0006FE7B  cmp word ptr [rbx+58h], 0

0006FE86  cmp qword ptr [rbx+60h], 0
~~~

The matching Windows types fit:

~~~
KLDR_DATA_TABLE_ENTRY

        |

        v

SectionPointer

        |

        v

SECTION / CONTROL_AREA

        |

        v

FILE_OBJECT

        |

        v

FileName
~~~

C317 event 20171486 reads a zero SectionPointer, so the non-null backing-file branch isn't dynamically covered in this run.

Later live kernel inputs and the non-null backing-file branch

A later read-only kernel capture supplies real examples for several inputs that are empty or null in C317. This is a later Windows boot, so it is retained as separate input evidence rather than rewritten into C317.

~~~
Loaded modules:                  204

Non-null SectionPointer:         140

Null SectionPointer:              64

Sampled non-null backing chains:  16 / 16 with readable file names

PiDDB entries:                   168

Readable PiDDB names:            167

Unloaded-driver records:          18
~~~

The 16 sampled loader entries cover normal loaded images and all lead through SECTION / CONTROL_AREA state to a readable FILE_OBJECT name. Original EOS instructions at 0x6FE11-0x6FE8B were then executed against those captured object graphs. Every one reaches the next protected resolver stage at 0x6FE91.

Controlled alternatives produce distinct exits: a null section can continue the walk, a null control area reaches 0x7022A, while a null file pointer, zero name length or null name buffer reaches 0x70218. Tests over all sixteen low-nibble fast-reference tag values confirm that EOS masks the tag before consuming the file pointer.

Feeding those captured graphs into the production loader is now qualified separately. Exact backing admission retains the historical entry bytes, verifies the selected image and kernel layout, reads the whole backing graph and preserves it before publishing fresh guest loader links:

~~~
Admitted non-null graph   132   exact image match plus a readable section,

                                control area, file object and counted name

Admitted native null       61   the matching historical entry is null

Unavailable field          12   missing identity evidence or a differing image

Selected catalog total    205
~~~

Comparing every chain also exposed differences that the initial 16-chain sample missed. Of 205 entries there are 137 basename matches but only 136 timestamp-and-size matches, and 134 that pass both the image and namespace checks. One module matches by name and size while its timestamps differ, so name and size alone would have attached historical backing objects to a different image.

The next protected call at 0x6FF2A is strongly attributable to `IoQueryFileDosDeviceName` from the original resolver arithmetic and an independently observed call to the same API elsewhere in EOS.

~~~
0006FF1F  lea rdx, [rsp+0A8h]       ; output pointer slot

0006FF27  mov rcx, rbx              ; admitted FILE_OBJECT

0006FF2A  call r8                    ; strongly attributed name-query API

0006FF2D  mov [rsp+08Ch], eax       ; retain NTSTATUS

0006FF34  imul ecx, esi, 2AF116D0h

0006FF3A  xor ecx, 0F222A5Fh

0006FF40  cmp eax, ecx

0006FF42  jle 703F6h                ; signed negative status

0006FF48  mov rdx, [rsp+0A8h]       ; consume returned pointer
~~~

Six controlled status cases show zero and positive NTSTATUS values reaching 0x6FF48, while `0x80000000`, `STATUS_OBJECT_NAME_NOT_FOUND` and `0xFFFFFFFF` reach the error path. These tests establish backing-object admission and signed status handling. They stop before the returned filename is processed into a final policy decision.

Loader-order diagnostics

The null-section branch also depends on where the entry appears in the loader walk. Once EOS has seen a non-null entry, a subsequent null SectionPointer causes it to prepare diagnostic code 3 with the loader entry's BaseDllName. Two other missing-backing conditions prepare codes 4 and 5.

~~~
Condition                                                     Diagnostic

------------------------------------------------------------  ----------

Null section, prior-entry flag clear                          none here

Null section, prior-entry flag set                            3

Matching image, section present, control area null            4

Matching image, control area present, file/name unavailable   5
~~~

Original null-section path:

~~~
0006FE1A  test dil, dil

0006FE1D  je 6FDCBh

0006FE1F  lea r8, [r14+58h]         ; BaseDllName descriptor

0006FE23  mov rcx, [rsp+50h]

0006FE28  mov edx, r12d             ; derived diagnostic code 3

0006FE2B  call rbx                  ; helper RVA 0x21AD4E

0006FE2D  jmp 6FDCDh

0006FE2F  mov edi, [rsp+88h]        ; non-null entry sets retained flag
~~~

Helper 0x21AD4E preserves a valid counted Unicode name. Null, zero-length, null-buffer or odd-length descriptors instead select the decrypted UTF-16 fallback:

~~~
<INVALID STRING>
~~~

The helper eventually reaches protected routine 0x3AC1FA. Its behavior is still unresolved, so codes 3/4/5 should be described as prepared diagnostics rather than bans or blocking results. The live capture is at least consistent with the distinction the code makes: its catalog has exactly 64 null entries followed by 140 non-null entries, with no later nulls.

Backing-image path normalization and temporary buffers

The successful file-name path optionally normalizes DOS/Win32 spellings before later processing. Under the constrained loader seed, helper 0x12F5E9** converts the following forms:**

~~~
Input                                   Tested result

--------------------------------------  --------------------------------------

C:\Windows\driver.sys                   \??\C:\Windows\driver.sys

C:/Windows/driver.sys                   \??\C:\Windows\driver.sys

\\?\C:\Windows\driver.sys               \??\C:\Windows\driver.sys

\\.\C:\Windows\driver.sys               \??\C:\Windows\driver.sys

\\server\share\driver.sys                \??\UNC\server\share\driver.sys

//server/share/driver.sys               \??\UNC\server\share\driver.sys

C:\                                     \??\C:\
~~~

Already NT-style names, device paths, bare basenames and several unsupported spellings take the temporary-copy cleanup path. The caller retains the original name when this optional conversion returns zero, so failure of this helper is not** a rejected-driver result.**
The copy helper at 0xD1B26** validates the source buffer, nonzero length, nonzero maximum length and requested capacity before allocating a writable counted-string copy. It zeroes the requested capacity and then copies exactly the counted source bytes. Cleanup releases the temporary buffer and clears its 16-byte descriptor.**

~~~
000D1B77  cmp word ptr [rdi+2], 0

000D1B7C  sete dl

000D1B7F  cmp si, cx

000D1B82  setb cl

000D1B85  or cl, dl

000D1B87  jne D1C10h

; allocation / zeroing / counted copy omitted

0012F9D2  call r8                  ; free temporary buffer

0012F9F0  xor edi, edi

0012F9F2  mov rcx, rsi

0012F9F5  xor edx, edx

0012F9F7  call 2592C0h            ; clear 16-byte descriptor
~~~

Fourteen bounded cases cover the guard inputs, five copy/allocation outcomes and the cleanup continuation. A few of them are worth naming because they are checks this helper omits: an embedded NUL in the counted source is copied through, an odd byte length is accepted as counted bytes, and a nonzero source maximum smaller than the source length is admitted. That's a description of the local contract, not a reachable malformed input from Windows.

Pool, CI and hotpatch inputs

C317 also contains:

~~~
Big-pool queries:

20

Pool-tag queries:

1

Code Integrity queries:

3

Hotpatch queries:

2
~~~

The model reports:

~~~
Code Integrity options:

0x5

Active hotpatch entries:

none
~~~

These inputs are useful for driver/environment inventory. The current evidence doesn't reconstruct a manual-map verdict or traversal of a private CI hash cache.

Image-load and image-verification callbacks

Normal image-load callback:

~~~
EOS RVA:

0x684C6

Registration:

18396055
~~~

C317's three normal image notifications are user-mode workload images with nonzero process IDs.

The separate image-verification callback is:

~~~
EOS RVA:

0x68CAD

Registration:

18397161 -> 18397162
~~~

It runs three times with a driver-image fixture:

~~~
20095386

51095969

73952545
~~~

The fixture carries driver/service paths, publisher text and synthetic hash/thumbprint data with an initial KnownGood classification.

Classification remains:

~~~
1
~~~

with flags zero.

Registration instructions:

~~~
00403801  call qword ptr [rsp+8]

; PsSetLoadImageNotifyRoutine

00107AD6  call r10

; SeRegisterImageVerificationCallback
~~~

What the image-load callback actually does with its metadata

C399 gives a concrete view. The workload loads `KevlarLifecycle0.exe` into process 1576 at `0xAF150000` and invokes the registered callback at `0x684C6`.

~~~
; R11 = IMAGE_INFO*, R10 = IMAGE_INFO+1, RBX = IMAGE_INFO+28h.

00177E75  movzx r14d, byte ptr [r10]  ; captured byte 04h

00177E7D  test  r14b, 4               ; ExtendedInfoPresent

00177E81  cmove rbx, r9               ; absent: use temporary storage

00177E85  mov   r10, qword ptr [rbx]  ; captured FileObject

00177E88  test  r10, r10

00177EE2  cmove rsi, r10

00177EE6  mov   [r12+40h], rsi        ; pass the selected FileObject onward
~~~

The flag and pointer reads are events 20224854 and 20224859; the selected object reaches `FltGetFileNameInformationUnsafe` at 20225553. EOS copies the returned path, scans the UTF-16 characters for `:` and `\`, stores a pointer to the basename at `0xC2B3C`, and writes length and maximum length `0x28` at `0xC2B50` and `0xC2B53`.

It then compares the notified image base against the current process's section base. Both are `0xAF150000` in this workload, and equality controls the continuation, which is how the callback distinguishes a main process image from other load notifications.

~~~
001DB6B5  cmp   rsi, qword ptr [r8+8] ; IMAGE_INFO.ImageBase

001DB6B9  mov   rsi, rsp

001DB6BC  cmove rsi, r10

001DB6C0  mov   qword ptr [rsi], r11

001DB6F4  cmovne rax, r15             ; equality retains 0043B5ACh

001DB6F8  pop   rcx

001DB6F9  jmp   rax                   ; captured destination: 0043B5ACh
~~~

There is a filename fallback. The first query uses options `0x101`, which Microsoft defines as `FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT`. On a negative status EOS prepares a second call to the same function with `0x102`, the opened name.

~~~
0012F4A0  41 69 CC 5B C0 2A 7D  imul ecx, r12d, 7D2AC05Bh

0012F4A7  81 F1 B3 44 88 55     xor  ecx, 558844B3h ; ECX = FFFFFFFFh

0012F4AD  39 C8                 cmp  eax, ecx       ; returned NTSTATUS

0012F4AF  7F 55                 jg   12F506h        ; signed status > -1

0012F4E1  45 69 C4 E8 46 86 1A  imul r8d, r12d, 1A8646E8h

0012F4E8  41 81 F0 A2 A5 0A AE  xor  r8d, AE0AA5A2h ; R8d = 102h

0012F4F2  4C 8D 4C 24 20        lea  r9, [rsp+20h]  ; same output slot

0012F4F7  4C 89 F1              mov  rcx, r14       ; same file object

0012F4FA  31 D2                 xor  edx, edx

0012F4FC  FF D6                 call rsi            ; second query
~~~

If the second query also fails, the helper returns zero through a thirteen-instruction exit with no third query and no name-information release. Three declared failure pairs, using `C000009Ah` and `C01C0005h` in each order, all take that route. The caller then tests only `AL`, selects RVA `37E865` and jumps to `CC72E`.

And EOS falls back to the name it was handed. With both queries failed, it selects the `UNICODE_STRING` supplied with the image notification, copies the 16-byte descriptor, and passes it to the same component-selector helper the successful path uses. The selector scans each UTF-16 unit for colon and backslash: a backslash before the final character makes the following unit a candidate, a colon clears the candidate.

~~~
C2AEF   0F B7 6F FE              movzx ebp, word ptr [rdi-2]

C2AF3   83 FD 3A                 cmp ebp, 3Ah          ; colon

C2AF6   74 1A                    je C2B12

C2AF8   83 FD 5C                 cmp ebp, 5Ch          ; backslash

C2AFB   74 06                    je C2B03

C2B03   4D 39 DE                 cmp r14, r11          ; before final character?

C2B0C   4C 0F 42 D7              cmovb r10, rdi        ; char after separator

C2B12   45 31 D2                 xor r10d, r10d        ; colon clears candidate

C2B3C   4C 89 52 08              mov [rdx+8], r10      ; borrowed Buffer

C2B50   66 89 02                 mov [rdx], ax         ; component byte length
~~~

352 finite controls cover every string of up to four units over ordinary character, backslash, colon and NUL. A few results are more specific than "take the basename": `a:b\c` selects `c`; `a\b:c` or a trailing backslash rejects the candidate entirely; `a/b` keeps the whole input, since forward slash has no role here; and scanning stops at an embedded NUL while the returned view keeps the original counted length rather than recomputing it.

Then a PID gate and an IRQL guard. EOS obtains the current process, its PID, and calls helper `DFCE7`. That helper requires a nonzero PID and a nonzero dword at `image+302B38`, then reads CR8. Under the reproduced frame its obfuscated mask evaluates to `FEh`, so the test is `(CR8 & FEh) == 0`: only IRQL 0 and 1 continue toward the mutex, which matches the documented requirement that `ExAcquireFastMutex` callers run at or below `APC_LEVEL`. All sixteen architectural CR8 values were checked.

~~~
DFD3B   8B 04 01                 mov eax, [rcx+rax]     ; image+302B38, observed 1

DFD40   48 85 D2                 test rdx, rdx          ; PID

DFD43   0F 84 E9 01 00 00        je DFF32

DFD49   85 C0                    test eax, eax

DFD4B   0F 84 E1 01 00 00        je DFF32

DFD54   44 0F 20 C0              mov rax, cr8

DFD70   48 31 CA                 xor rdx, rcx           ; RDX = FEh in this frame

DFD73   48 85 D0                 test rax, rdx

DFD76   74 07                    je DFD7F               ; admit CR8 = 0 or 1

DFE47   41 FF D0                 call r8                ; ExAcquireFastMutex
~~~

Inside the mutex is a forward-linked collection keyed by PID at `image+302B78h`. The captured head is self-linked, so EOS skips the body and returns zero. The unvisited body is still readable: it compares the qword at `link-2C8h` with the PID, rejects a match whose byte at `link-4` is nonzero, otherwise increments a dword at `link-8` by one and returns `link-670h` as the enclosing record.

~~~
DFE6B   48 8B 00                 mov rax, [rax]           ; next forward link

DFE6E   48 39 C8                 cmp rax, rcx             ; head reached?

DFE71   74 2E                    je DFEA1

DFE73   48 39 B8 38 FD FF FF     cmp [rax-2C8h], rdi      ; PID

DFE7A   75 EF                    jne DFE6B

DFE7C   8A 48 FC                 mov cl, [rax-4]          ; state byte

DFE7F   84 C9                    test cl, cl

DFE81   74 04                    je DFE87

DFE83   31 DB                    xor ebx, ebx             ; reject this match

DFE94   F0 01 48 F8              lock add [rax-8], ecx    ; increment by one

DFE98   48 05 90 F9 FF FF        add rax, -670h           ; enclosing record
~~~

265 finite controls cover an empty list, a missing PID, every state-byte value, five counter values including wraparound, a second-node match and a duplicate PID whose first match is rejected. The increment-before-return pattern reads like a reference count; its release sites are unidentified.

The callback keys per-process state on process creation time. After `PsLookupProcessByProcessId` succeeds, EOS calls `PsGetProcessCreateTimeQuadPart`, stores the timestamp, acquires `image+30A868h` and requests 36 bytes with tag `Ntf0`.

C508 captures the insertion itself:

~~~
Table manager     FFFFB000006E3010   flags +38h/+39h = 1/0

Bucket array      manager +40h       count +3Ch = 4096

Selected head     index 672h         initially null

Raw allocation    FFFFB00135105000   24h bytes, tag ClfC

Usable node       FFFFB00135105010   next +00h, key +08h, payload +10h

Saved payload     FFFFB00135105020   four zero bytes

Entry count       manager +48h       204 -> 205
~~~

~~~
001B137A  48897808          mov [rax+8], rdi       ; creation-time key

001B137E  48C70000000000    mov qword ptr [rax], 0 ; next = NULL

001B1483  488B5640          mov rdx, [rsi+40h]     ; bucket array

001B1487  488B0CDA          mov rcx, [rdx+rbx*8]   ; RBX = 672h, head = NULL

001B14C3  488904DA          mov [rdx+rbx*8], rax   ; publish the new node

001B1535  014648            add dword ptr [rsi+48h], eax
~~~

Independent replay matches all 17,446 scalar checkpoints. Using creation time rather than PID distinguishes separate process instances that reuse a PID, which is a reasonable purpose and still an interpretation. The four-byte payload starts at zero and its later reader is unknown.

The callback also releases what it took: `ObfDereferenceObject` on the same process object at events 20280331-20280332, inside the same callback scope, with callback return at 20280347.

There is a failure route too. Before the filename lookup, EOS allocates `88h` bytes tagged `CM11`, stores the notification thread at `+28h`, initializes two events, and links the body into a doubly linked list headed by `eos.sys+30CB90h` under the mutex at `+30CBA0h`. If the process lookup returns `STATUS_INVALID_CID`, original code restores the two links, releases the mutex, restores the byte and allocation counters, erases all 136 bytes and frees the allocation, then executes 238 further instructions back through the callback epilogue.

What the verification callback reads

C399 also supplies the initialized state that had blocked the earlier verification probes. At sequence 20235988 EOS reads `0xCD195B82` from image RVA `0x305160`, takes the nonzero branch and skips the adjacent `RDTSC`.

The callback's first captured payload access is offset `+4`, the `ImageFlags` field:

~~~
026880AF  8B 00                    mov eax, dword ptr [rax]

026880B1  89 C1                    mov ecx, eax

026880B3  81 E1 FF 07 00 00        and ecx, 7FFh

026880B9  8D 50 01                 lea edx, [rax+1]

026880BC  81 E2 FF 07 00 00        and edx, 7FFh

; carries propagated through 11/11/10-bit slices

02688133  41 09 C7                 or r15d, eax

02688136  4C 89 BC 24 90 00 00 00  mov qword ptr [rsp+90h], r15
~~~

The whole contiguous range simplifies to `temporary = ImageFlags + 1`. The captured zero input produces one, and a control that changes only that dword to one produces two at the same stack destination. Both reach the first indirect jump at `40259E` with identical registers and flags, and both later reach the same `9618h`-byte `ViMm` allocation request. At the capture edge, eleven stack bytes still differ between the two cases, so the input-dependent data is still live when the window ends. The callback's return and any classification consumer are outside it.

In the selected 16,384-entry window the flags dword is the only witnessed access to the 1,024-byte payload.

Driver-history boundaries

The matching Windows symbols include:

~~~
MmUnloadedDrivers

MmLastUnloadedDriver
~~~

but no root-EOS traversal of either structure has been established.

The same applies to private Code Integrity hash buckets commonly discussed as `g_KernelHashBucketList`.

The user-mode DLL unload ring described later uses ntdll!RtlGetUnloadEventTrace and is a different mechanism.

Targeted driver-name searches

The 17 September C399 diagnostic records thirteen specific driver basenames** being searched against the loaded-module catalog. The comparison operands, case flag and results are preserved. Each target is checked against the same **206 module names**, comprising 205 profile modules plus EOS itself.**

~~~
Target             Comparisons    First / last C399 operand event

-----------------  -------------  --------------------------------

VBoxGuest.sys      206            39011 / 39626

VBoxVideo.sys      206            39629 / 40245

vm3dmp.sys         206            40248 / 40863

prl_kmdd.sys       206            40866 / 41481

HyperVideo.sys     206            41484 / 42099

vrd.sys            206            42102 / 42717

viostor.sys        206            42720 / 43335

vioscsi.sys        206            43338 / 43953

xen.sys            206            43956 / 44571

xenfilt.sys        206            44574 / 45190

Dbgv.sys           206            50417 / 52263

PROCMON23.sys      206            50420 / 52266

dbk64.sys          206            50423 / 52269
~~~

The first ten are searched target-first across the complete catalog. The final three are checked for each module before EOS advances to the next module. Both paths use RtlCompareString with case-insensitive comparison enabled**. The class-0xB module queries preceding the two passes return identical buffer hashes and module order.**
Across these passes, all 2,678 comparisons are nonmatches in C399. The source therefore proves targeted presence searches for virtualization-related and inspection/debugging-related driver names. It does not contain an observed positive match followed by an allow, deny, block or report action.

Comparison wrapper:

~~~
000D14F5  imul r8d, ebx, 45h

000D14F9  xor r8b, 0F8h

000D14FD  mov rcx, rsi              ; first counted descriptor

000D1500  mov rdx, rdi              ; second counted descriptor

000D1503  call r9                   ; observed RtlCompareString

000D1506  nop                       ; provider return site
~~~

The three names in the second pass are also recovered from encrypted literals in the original image:

~~~
Literal          Ciphertext RVA    Plaintext bytes including NUL

---------------  ----------------  ------------------------------------------

Dbgv.sys         0x2D78BA           44 62 67 76 2E 73 79 73 00

PROCMON23.sys    0x2D78C3           50 52 4F 43 4D 4F 4E 32 33 2E 73 79 73 00

dbk64.sys        0x2D78D1           64 62 6B 36 34 2E 73 79 73 00
~~~

Three local predicates distinguish an equal comparison from a nonzero result:

~~~
0013078F  call qword ptr [rsp+128h]

00130796  test eax, eax

00130798  je 130B5Bh

001308DA  call qword ptr [rsp+100h]

001308E1  test eax, eax

; MOV/LEA instructions preserve ZF

001308FF  je 130B3Fh

001309F8  call qword ptr [rsp+1C8h]

001309FF  mov r13d, eax

; temporary-buffer clearing calls occur here

00130A37  test r13d, r13d

00130A42  je 130B6Ah
~~~

Fifteen original-byte tests cover zero, positive and negative comparison values. Under the candidate mixed key, the shown equal-result paths prepare EAX = 0xF01, AL = 1. The tests stop before cleanup/result preparation and do not show a caller turning this value into enforcement.

C399 is a one-second diagnostic that has since completed initialization, one steady second and guest unload. Its whole stream validates: 20,263,668 events, 590,116 paired call scopes, no open scopes, no dropped events, no trace-sink failure. Lifecycle acceptance is 19/20, with nine allocations totaling 720 bytes, four handles and four referenced objects unexplained after guest unload. It does not replace the matching 30-minute replay.

Process-name prefix predicates in the same inspection routine

The earlier part of the three-driver inspection routine contains encrypted process-name prefixes:

~~~
dbgview    7 compared bytes

devenv.    7 compared bytes

tv_        3 compared bytes
~~~

The terminating NUL is outside each comparison width, so longer names can match the prefix. Local original-byte tests confirm exact and uppercase forms, longer suffixes, shorter names, mismatches at each position and the bit-0x20 aliases produced by the mask.

~~~
0012FFD0  mov dl, [rsp+rax+1A0h]

0012FFD7  mov r8b, [rsp+rax+50h]

0012FFDC  mov r9d, r8d

0012FFDF  xor r9b, dl

0012FFE2  test r9b, sil             ; SIL = 0xDF in tested candidate state

0012FFE5  jne 130001h

0012FFE7  or r8b, dl

0012FFEA  je 130A96h

0012FFF0  inc rax

0012FFF3  cmp rcx, r11

0012FFF6  lea rcx, [rcx+r15]

0012FFFA  jb 12FFD0h

0012FFFC  jmp 130A96h
~~~

The byte predicate is `(actual XOR expected) AND 0xDF`. It folds ASCII letter case and also aliases some punctuation, for example `.` with byte 0x0E and `_` with byte 0x7F. It is a byte mask rather than a Unicode case-insensitive comparison.

Forty-nine prefix cases and the fifteen driver-result cases exercise 2,951 instruction entries across 58 distinct sites. They explain the local matching logic, not the caller's policy. The short `tv_` prefix is not enough to identify a specific product by itself.

How the six inspection strings are decoded

The recovered Dbgv.sys**, **PROCMON23.sys** and **dbk64.sys** literals, and the **dbgview**, **devenv.** and **tv_** process prefixes, use XOR masks derived from a mixed 64-bit value, **K. The decoder also uses K to reconstruct ciphertext pointers and loop constants. Once those expressions are evaluated, the string operations reduce to a small set of 32-bit multiply/add/rotate or XOR/shift steps.

This reconstruction covers these six strings. The decoding paths for the other ten driver names observed in the catalog search have not been reconstructed here.

Recovering the candidate key

In the original three-driver routine, RBX contains the mixed value. The following instructions reconstruct a pointer from the qword at image RVA 0x2EDD60. Subtracting the product with `0xFE93B797063588CF` is equivalent, modulo 64 bits, to adding a product with `0x016C4868F9CA7731`.

~~~
; Original EOS instructions. RBX is the mixed value K at this point.

00130350  48 B8 CF 88 35 06 97 B7 93 FE  mov rax, 0FE93B797063588CFh

0013035A  48 0F AF C3                    imul rax, rbx

0013035E  48 8B 0D FB D9 1B 00           mov rcx, [rip+1BD9FBh] ; image RVA 2EDD60h

00130365  48 29 C1                       sub rcx, rax

00130368  48 89 8C 24 28 01 00 00        mov [rsp+128h], rcx
~~~

Constraining that pointer to the identified comparison wrapper gives the equation below. Here B is the preferred image base and S is the original qword stored in the pointer slot. All arithmetic wraps modulo `2^64`. The multiplier is odd, so it has a multiplicative inverse in this ring.

~~~
B = 0x0000000140000000

S = 0x84605495DB43F33B

M = 0x016C4868F9CA7731

S + M*K = B + 0xD13C2                 (mod 2^64)

K = (B + 0xD13C2 - S) * inverse(M)    (mod 2^64)

K = 0x4692EF1D2B0A9537
~~~

This is a conditional static key reconstruction. The comparison-wrapper identity constrains K. The resulting ciphertext addresses, lengths and decoded driver names independently agree with the retained C399 operands. The relevant pointer slots have `DIR64` relocations, so the load-base adjustment preserves the equation.

The original entry argument in RCX and its producer remain unresolved. K is constrained here from the wrapper target rather than recovered from captured entry state. The local RCX-to-RBX mixing instructions are preserved, but they don't provide the missing input.

Decoding the driver names

Treat each body as little-endian 32-bit words. XOR each ciphertext word with the current state, then update the state. The simplified functions below use unsigned 32-bit arithmetic: every multiply, add and left shift is truncated to 32 bits. `ROL32` rotates a 32-bit value left.

These are readable expressions of the reviewed instruction semantics under the candidate K, not original EOS source code.

~~~
uint32_t affine_step(uint32_t state, unsigned rotation)

{

    return ROL32(0x000343FDu * state + 0x00269EC3u, rotation);

}

uint32_t shift_step(uint32_t state)

{

    state ^= state >> 7;

    state ^= state << 9;

    state ^= state >> 13;

    return ROL32(state, 3);

}

/* For each complete driver-name word: */

plaintext_word = ciphertext_word ^ state;

state = selected_step(state);
~~~

~~~
String           Initial state    Complete-word body                      Remaining byte masks

---------------  ---------------  --------------------------------------  --------------------

Dbgv.sys         0xD3593260       Two words; affine_step(state, 2)        5B

PROCMON23.sys    0x1A43E043       Three words; shift_step(state)          2B A9

dbk64.sys        0x02B2FEE1       Two words; affine_step(state, 1)        01 FC
~~~

The final masks decode the remaining bytes, including the terminator. For the two-byte tails, the original routine takes the low byte of a separate seed and shifts that seed right by eight bits before the next byte. The seeds reduce to:

~~~
PROCMON23.sys tail seed: 0x5B71A92B

dbk64.sys tail seed:     0x71A0FC01

Dbgv.sys final mask:     0x5B
~~~

The first word loop shows the XOR, state update and plaintext write directly. EDX holds the current state, R15D and R14D the multiplier and addend, and EBP the rotation count. The saved plaintext word in R9D is written after the next mask state has been computed.

~~~
; Original first driver-name loop, contiguous through its back edge.

00130713  48 8B 4C 24 68        mov rcx, [rsp+68h]

00130718  46 8B 0C 81           mov r9d, [rcx+r8*4]

0013071C  41 31 D1              xor r9d, edx

0013071F  4C 8B 54 24 50        mov r10, [rsp+50h]

00130724  41 0F AF D7           imul edx, r15d

00130728  44 01 F2              add edx, r14d

0013072B  89 E9                 mov ecx, ebp

0013072D  D3 C2                 rol edx, cl

0013072F  47 89 0C 82           mov [r10+r8*4], r9d

00130733  49 89 F0              mov r8, rsi

00130736  A8 01                 test al, 1

00130738  B8 00 00 00 00        mov eax, 0

0013073D  75 D4                 jne 130713h
~~~

For a worked example, the original nine ciphertext bytes at RVA 0x2D78BA are:

~~~
24 50 3E A5 A1 6D 0B 49 5B
~~~

The two word masks, in memory byte order, are:

~~~
60 32 59 D3

8F 1E 72 3A
~~~

and the final-byte mask is:

~~~
5B
~~~

XORing those bytes produces:

~~~
44 62 67 76 2E 73 79 73 00
~~~

which is `Dbgv.sys` followed by NUL. C399 event 50417 independently records the eight counted name bytes. The terminator is reconstructed from the original ciphertext outside that counted operand.

Decoding the process prefixes

The same K simplifies the process-prefix expressions, although their mask schedules differ. In particular, dbgview updates its state before each word is XORed, while the three driver-name loops above use the current state first.

~~~
Prefix     Simplified masks under candidate K

---------  -----------------------------------------------------------------------------

dbgview    Start at 0x089E2856. Before each of two words:

           state = ROL32(0x43FD43FD * state + 0x00C39EC3, 4)

           then XOR the ciphertext word with that state.

devenv.    XOR its two words with 0xE05C3ACE and 0x78431F33, in that order.

tv_        XOR its one word with 0x3CDA9FBF.
~~~

All six results have been recomputed from the identified original image and checked against the preserved proofs. The reproduction retains the key equation, ciphertext bytes, word masks and exact instruction bytes.

This is a static reconstruction. It performs no new EOS execution and doesn't establish that these routines explain every encrypted string or protected pointer in the image.

Only one import name is in plaintext

Worth recording next to the string decoders. The root image's ordinary PE import directory contains exactly one named import, in readable ASCII, and the delay-import directory is empty.

~~~
Import directory        0x2F4D58, 40 bytes   one descriptor plus the null one

Import lookup table     0x2F4D80             one named thunk plus a null thunk

Import address table    0x2F4D90             slot bound for FltRegisterFilter

Import name             0x2F4DA2             FltRegisterFilter

Module name             0x2F4DB4             FLTMGR.SYS
~~~

Every other kernel call in the catalog goes through the protected indirect bridges. So the observed call inventory cannot be read off the import table at all, and the thirteen driver basenames and three process prefixes above are inspection targets rather than EOS's own imported API names. A complete account of runtime API discovery would need each resolver's producer and consumer, which is outside this post.

Driver trust tables and current blacklist boundary

The root image also contains two adjacent Windows trust-provider stage tables whose GUIDs and function names match the Windows SDK `SoftPub.h` definitions:

~~~
Table RVA   Action                                   Recovered stage names

----------  ---------------------------------------  -----------------------------------------------

0x2C5880    Generic Authenticode verification        SoftpubInitialize

                                                     SoftpubAuthenticode

                                                     SoftpubCleanup

0x2C58F8    Driver verification                      DriverInitializePolicy

                                                     DriverFinalPolicy

                                                     DriverCleanupPolicy
~~~

The tables also contain certificate, message and signature stages. They contain no driver basenames. Their presence doesn't make them a driver whitelist, and the EOS consumer of those tables remains unresolved.

The current evidence therefore supports targeted driver presence searches, a populated-history walk with a twenty-record bound and a formatted record, separate trust inputs, loader-consistency diagnostics and image-verification callbacks. It does not yet establish the final allowlist/blocklist policy or what happens after a positive driver-name match.

8. Process and image inspection

PEB and loader traversal

Routine 0x86BF8 reads PEB.ProcessParameters and copies a selected Unicode field.

P110L takes the image-path branch.

Routine 0x1F3C61 traverses a native loader list and compares BaseDllName values.
P110L selects winsrv.dll on its sixth comparison.

~~~
001F4216  mov rax, [rax+18h]

001F42C4  mov r8, [rax+60h]

001F4304  call rax

001F4306  test eax, eax

001F4312  mov rax, [rax]
~~~

PE structure validation

Routine 0x1F2FFC checks:

~~~
MZ

e_lfanew bounds

PE signature

PE32 / PE32+

section-table extent
~~~

~~~
001F3181  mov rax, [rbp-20h]

001F3185  movzx eax, word ptr [rax]

001F3188  cmp ax, [rbp-12h]

001F318C  jne 0x1F3280
~~~

For the tested seed the comparison operand is 0x5A4D.

Current and unloaded modules

Routine 0x4064D** constructs current module records containing base, size, timestamp and owned full-path text.**
The decoded native path has a 512-module maximum with 32-byte records.

The unload-history path concerns user-mode DLL history, not `MmUnloadedDrivers`.

EOS reaches:

ntdll!RtlGetUnloadEventTrace

Consumer RVA:

0x41717

~~~
00041772  cmp qword ptr [r8], 0

00041776  je 0x41791

00041778  add r8, 68h

000418B4  mov [rdx+rax], rcx

000418B8  mov ecx, [r8+8]

000418BC  mov [rdx+rax+8], ecx

000418C0  mov ecx, [r8+14h]

000418C4  mov [rdx+rax+0Ch], ecx

000418C8  lea rdi, [r8+1Ch]
~~~

The EOS loop has a recovered 65-record ceiling under the tested seed.

Import-name inventory

Root routine:

0xE8008

parses IMAGE_IMPORT_DESCRIPTOR entries.

P121:

~~~
Image:

um.exe

Named imports:

143

Formatter outputs:

429

Passes:

3
~~~

P124:

~~~
Image:

conhost.exe

Named imports:

321

Formatter outputs:

963

Passes:

3
~~~

Names are formatted as:

~~~
dllstem.FunctionName
~~~

Bulk process and handle snapshots

C317 adds system-wide views on top of the per-process enumeration.

Process-information queries:

~~~
Total:

68
~~~

One sizing request:

~~~
Event:

33926
~~~

followed by delivery at:

~~~
33937

Processes:

215

Threads:

3,777
~~~

The final delivered snapshot at:

~~~
84724885
~~~

still reports:

~~~
Processes:

215

Threads:

3,784
~~~

C317 also contains:

~~~
Handle-information queries:

41

During steady observation:

38
~~~

The handle provider exposes KEVLAR's sandbox handle table, so this is not a complete native-host handle snapshot.

Working sets and process security

C317:

~~~
Working-set responses:                23

Region-property responses:             6

Mapped-file responses:                 6

ProcessBreakOnTermination:            228

PsIsProtectedProcess:                  43

PsIsProtectedProcessLight:              4

Token integrity:                      439

Token groups:                         626

Token privileges:                     242
~~~

The token queries total 1,307 SeQueryInformationToken calls.

Working-set bridge:

~~~
00386D40  mov rsp, r12

00386D43  call 0x36217F

00386D48  lea rsp, [rsp+1C0h]

00386D50  call qword ptr [rsp+8]

00386D54  lea rsp, [rsp-1C0h]
~~~

DbgUiRemoteBreakin

P195 event 20084640** targets the first byte of:**
ntdll!DbgUiRemoteBreakin

at:

~~~
0x7FF9EAFA7E10

NTDLL RVA 0xD7E10
~~~

EOS:

~~~
00374FED  mov rax, [r12+28h]

00374FF2  mov al, [rax]

00374FF4  mov [r12+190h], al
~~~

The first-byte predicate

EOS explicitly tests whether the inspected entry begins with byte 0xE9, the opcode for a near relative jump.

The continuation saved by P195 reaches the block below. The byte read at RVA 0x374FF2 is zero-extended, a VM transport status is checked, and the byte is compared with 0xE9 before EOS selects one of two indirect continuations.

~~~
00146352  movzx edx, byte ptr [r12+190h]

0014636E  cmp qword ptr [r12+199h], 1

00146387  mov r8d, 440C2Fh

0014638D  mov r9d, 43DA82h

00146393  cmove r9, r8

00146397  cmp rdx, 0E9h

; VM result/frame stores omitted

001463B3  cmovne r9, r8

001463B7  add r9, rcx

001463BA  jmp r9
~~~

For successful-load status, an exhaustive 256-byte sweep shows that E9 alone reaches RVA 0x436472. The other 255 byte values reach **0x43961F**. The clean NTDLL input starts with `48`, so it takes the common path. `EB`, `FF`, `CC` and `C3` do as well.

A synthetic transport status of 1 forces the common route even when the byte is E9. Other tested non-1 statuses preserve the E9 split. The status test is therefore equality with 1 rather than a generic nonzero failure test.

It's checking for one specific detour

The E9 route reads a 32-bit field at `frame+0x40`, multiplies it by eight and uses it as an index into a qword table. That much was in the first version of this post. C508 and C511 now identify the table, the index and the comparison, and the answer is more specific than "looks for a patch".

The index comes from the process bitness. The captured `PsGetProcessWow64Process` call at events 20275762-20275764 returns null. Original code tests that result, selects `40h`, and a later compare against `20h` with `setne bl` turns it into an index.

~~~
; Captured state before 84B65h: ECX=20h, EDX=40h, RAX=getter result.

00084B65  4885C0            test rax, rax

00084B68  0F44CA            cmove ecx, edx       ; null -> 40h; nonzero -> 20h

0017A4E4  4983F820          cmp r8, 20h

0017A4E8  0F95C3            setne bl             ; 32 -> 0; 64 -> 1

0017A525  8918              mov [rax], ebx
~~~

So the captured native case selects index 1; declared nonzero getter results select index 0, the WoW64 branch.

There are two parallel tables. The address table starts at `image+30CCE0h` and the DWORD table at `image+30CCD4h`. At index 1:

~~~
image+30CCE8h   7FF9EAFA7E10   the inspected DbgUiRemoteBreakin entry

image+30CCD8h   FFF7968Bh      the reference DWORD for that entry
~~~

Snapshot 20257957 supplies both, and later original reads at 20276046 and 20276661 confirm the selected entry address.

On the E9 route EOS compares the four bytes after the E9 with that reference.

~~~
00384790  8B00              mov eax, [rax]         ; DWORD at entry+1

004221DB  8B00              mov eax, [rax]         ; DWORD at image+30CCD8h

01DF2D13  39D1              cmp ecx, edx           ; returned operand vs reference

01DF2D62  39D1              cmp ecx, edx

01DF2D71  490F45C1          cmovne rax, r9         ; mismatch -> common path

003DB46A  8818              mov [rax], bl          ; equality: frame+47h = 1
~~~

Now interpret the reference as a signed `E9 rel32` displacement:

~~~
D7E10h + 5 - 86975h = 514A0h
~~~

In the identified NTDLL image, RVA `514A0h` is the exported LdrShutdownProcess.

That is an exact export and arithmetic correspondence, and it changes the reading of this whole check. EOS is not testing for "any jump". It is testing whether `DbgUiRemoteBreakin` has been redirected to a process-shutdown export, which is a well known way to make an attaching debugger kill the target instead of breaking into it. The qualified fragment compares the saved DWORD; it hasn't been observed calculating or executing that destination, and the reference table's writer is unidentified.

A match sets a bit in the caller's saved flags.

~~~
Declared input                                     Local result

-------------------------------------------------  ------------------------------

E9, displacement FFF7968Bh, saved result 00h       frame+47h = 01h, AL = 1,

                                                   caller does flags |= 20h

E9, displacement FFF7968Ah (one bit off)           store skipped, AL = 0

E9, displacement zero                              unequal, common result reader

Actual C508 byte 48h                               reads initialized zero, AL = 0
~~~

~~~
01B3EBB3  418B942490010000  mov edx, [r12+190h] ; saved flags value

01B3EBC3  4883C104          add rcx, 4          ; caller frame + 4

01B3EBCF  83CA20            or edx, 20h

01B3EBD2  418994249C010000  mov [r12+19Ch], edx

00387D1A  498B842494010000  mov rax, [r12+194h] ; destination

00387D22  418B9C249C010000  mov ebx, [r12+19Ch] ; updated flags

00387D2A  8918              mov [rax], ebx      ; DWORD store
~~~

Three flags controls show the update rule preserves everything else: `00000000h` becomes `00000020h`, `000000A5h` stays `000000A5h`, `FFFFFFFFh` stays `FFFFFFFFh`.

The actual captured run reads first byte `48h` and takes the zero route, so none of this is an observed patched process. What's established is the predicate, the reference it compares against, and the flag update it performs.

One detail that would be easy to get wrong: on the common route EOS restores RAX as `00007FF9EAFA7E00`, whose upper bits are leftover pointer bits, and the caller tests only the low byte at `2289B43h`. Treating the whole nonzero RAX as a Boolean would invert the result.

The flags become a field in a process-image record

C514 follows that DWORD onward. In that run it holds `00208001h`. Original `1579780h` loads it, protected-frame transport carries it out to an outer caller field, and a record constructor writes it into an allocation.

~~~
01579780  8B7104                 mov esi, dword ptr [rcx + 4]

015797A7  4989742428             mov qword ptr [r12 + 0x28], rsi

01043467  4189842498010000       mov dword ptr [r12 + 0x198], eax

003E5B0B  8918                   mov dword ptr [rax], ebx

001D0CF4  448BA580020000         mov r12d, dword ptr [rbp + 0x280]

001D0D36  4489631A               mov dword ptr [rbx + 0x1a], r12d
~~~

~~~
Usable record offset   C514 value    Source

---------------------  ------------  -----------------------------------

+00h                   0000000Ah     record discriminator

+04h                   5045496Dh     magic DWORD from the original code

+08h                   0002h         two-byte header field

+0Eh                   AF150000h     modeled lifecycle image base

+16h                   00001000h     image size from this fixture

+1Ah                   00208001h     the saved flags
~~~

The working record is then copied, in plaintext, into a second allocation tagged `CM20`: 616 usable bytes, so the flags land at that record's `+1Ah` as well. The working buffer's 4,704 bytes are cleared and its allocation released. Later reads refer to the retained copy.

Two different selectors read that field:

~~~
01201834  488B0A                 mov rcx, qword ptr [rdx]

01201837  8B491A                 mov ecx, dword ptr [rcx + 0x1a]

01201858  0FBAE109               bt ecx, 9                ; mask 00000200h

0120185C  480F43C2               cmovae rax, rdx

01201860  FFE0                   jmp rax

0021FD72  41F6431C20             test byte ptr [r11 + 0x1c], 0x20 ; mask 00200000h

0021FD7A  4D0F45F9               cmovne r15, r9

0021FDA6  FFE0                   jmp rax
~~~

~~~
Selector                 Clear -> target   Set -> target   Actual C514 route

-----------------------  ----------------  --------------  -----------------

Bit 9,  mask 00000200h   389679h           41BFB8h         clear

Bit 21, mask 00200000h   42E465h           3A00B0h         set
~~~

Adding the E9 mask `20h` changes neither selection, so bit 5 is read by something else again.

Bit 21 is an Administrators-group check

The `00200000h` bit has an identified producer, and it is a security-context test rather than an integrity one.

EOS reads the kernel export `SeExports` at event 20282487, then its `+110h` field. In the exact kernel image `SeExports` is at RVA `D54A08h` and `+110h` is `SeAliasAdminsSid`. That pointer becomes the first argument to `RtlEqualSid` at event 20282991, against the first SID in the process token's group buffer, and the provider returns true. The frozen serializer supplies S-1-5-32-544, built-in Administrators, in that entry.

~~~
01322374  48BAA1679E18F2310067     movabs rdx, 0x670031f2189e67a1

0132237E  490FAF542428             imul rdx, qword ptr [r12 + 0x28]

0132238C  4933542468               xor rdx, qword ptr [r12 + 0x68]

01322391  488B12                   mov rdx, qword ptr [rdx]

01322394  488BBA10010000           mov rdi, qword ptr [rdx + 0x110]
~~~

Equality alone isn't enough. After it, `7B672h` tests attribute bit `02h`**, whose Windows name is `SE_GROUP_ENABLED_BY_DEFAULT`, and it does **not use the separate `04h` `SE_GROUP_ENABLED` bit. The actual first entry has attributes `0Eh`.

~~~
0007B664  4084F6                   test sil, sil    ; RtlEqualSid result

0007B667  410F94C6                 sete r14b

0007B66E  4D0F44DA                 cmove r11, r10

0007B672  41F60302                 test byte ptr [r11], 2

0007B676  410F94C7                 sete r15b

0007B67A  4508F7                   or r15b, r14b

0007B6EE  4D899C24D8000000         mov qword ptr [r12 + 0xd8], r11
~~~

Ten controls combine equal/unequal SID results with attributes `00h`, `02h`, `04h`, `06h` and `0Eh`. Equality plus bit `02h` selects the matched-group path; `04h` alone doesn't. The true result survives four intervening OS calls through the unchanged nonvolatile RBX, is tested at event 20285791, and selects `flags |= 200000h`, producing the `00208001h` written back.

The token contents here are modeled inputs, so a different faithful token could produce a different result. The comparisons and the flag store are original EOS execution.

The bit-21 route checks token integrity and gives up above 0x3FFF

On the set-bit route EOS references the process's primary token, calls `SeQueryInformationToken` with class 25** at event 20317827, and receives integrity RID **`4000h`. It then compares that DWORD with `3FFFh`, computed under the captured key by an `imul`/`xor` pair:

~~~
0001A801  84C0                     test al, al

0001A803  7419                     je 0x1a81e

0001A805  4169C45DDA625A           imul eax, r12d, 0x5a62da5d

0001A80C  35CB07C2C6               xor eax, 0xc6c207cb      ; EAX = 3FFFh

0001A811  39442464                 cmp dword ptr [rsp + 0x64], eax

0001A815  7607                     jbe 0x1a81e

0001A817  31ED                     xor ebp, ebp

0001A819  E9A3030000               jmp 0x1abc1

0001ABC1  89E8                     mov eax, ebp
~~~

`4000h` is System integrity, so the unsigned `jbe` is not taken and the routine returns zero. Six controls cover success/failure, the `3FFFh`/`4000h` boundary and lower and higher values.

Practically: the modeled SYSTEM-integrity process is excluded from whatever the rest of this routine does.

What's behind that gate: NtOpenProcess transfer inspection

The body the integrity check skips is worth describing, because it explains why the gate is there.

It decodes two strings with the captured caller key `130FA81D1D489DC4h`. The first decoder runs five DWORDs through xorshift, negation and XOR to produce UTF-16 `ntdll.dll` from ciphertext at `EOS+2BB180h`; the second uses a multiply/add sequence and a byte tail to produce ASCII `NtOpenProcess` from `EOS+2BB194h`. It then resolves the module, the export, a range/alignment probe and a byte consumer, and hands the export's address to that consumer.

~~~
; UTF-16 name decoder, register moves between lines omitted.

0001A8E1  D3E7                     shl edi, cl

0001A8EA  D3EB                     shr ebx, cl

0001A8F4  41D3E1                   shl r9d, cl

0001A8FA  41F7D9                   neg r9d

0001A902  8B0CB1                   mov ecx, dword ptr [rcx + rsi*4]

0001A905  4431C9                   xor ecx, r9d

0001A90D  890CB7                   mov dword ptr [rdi + rsi*4], ecx
~~~

The consumer is a transfer-destination extractor:

~~~
First bytes at the export                    Result

-------------------------------------------  ------------------------------------

4C 8B D1 B8 26 00 00 00 (identified stub)    output stays zero, low byte 0

E8 rel32 or E9 rel32                         entry + 5 + signed displacement

EB rel8                                      entry + 2 + signed displacement

FF 25 disp32                                 routes the slot through a guarded copy

All 256 first-byte values, rest fixed        only E8, E9 and EB give a nonzero result
~~~

~~~
01922DD7  49C70000000000           mov qword ptr [r8], 0   ; clear output

01922DDE  410FB611                 movzx edx, byte ptr [r9]

01922EC5  4D0FBE1B                 movsx r11, byte ptr [r11]

01922F58  486331                   movsxd rsi, dword ptr [rcx]

019230C5  498939                   mov qword ptr [r9], rdi ; store destination

01F9ADA0  48833A00                 cmp qword ptr [rdx], 0

01F9ADA4  400F95C6                 setne sil
~~~

The `FF 25` path is guarded: the indirect slot address must be strictly above `MmSystemRangeStart` (the frozen value `FFFF800000000000h`), and a slot exactly equal to it is rejected. A kernel-range slot reaches an eight-byte `MmCopyMemory` with virtual-memory flag 2. That has a consequence worth stating, since the final predicate only tests the output qword for zero:

~~~
Declared copy response              Output qword          Final low byte

----------------------------------  --------------------  --------------

Success, 8 bytes copied             full pointer          1

Partial 8000000Dh, 4 bytes copied   low 4 bytes, high 0   1 if nonzero

Access violation, 0 bytes copied    zero                  0

8-byte copy of a null pointer       zero                  0
~~~

A partial copy with a failing status can still produce true. Windows documents the status and the transferred byte count separately, and the caller here inspects the value rather than the count.

A recovered destination leads to the module's file and its certificate

A nonzero destination isn't the end. EOS passes it and the process object to a helper at `4026Ah`, checks the user-address limit, and walks that process's loader list looking for the module containing the destination.

~~~
000400AA  488B4018                 mov rax, qword ptr [rax + 0x18]  ; PEB+18h

000400F1  488B4010                 mov rax, qword ptr [rax + 0x10]  ; Ldr+10h

0004015B  4883783000               cmp qword ptr [rax + 0x30], 0

0004016E  83784000                 cmp dword ptr [rax + 0x40], 0

000401F8  FFD0                     call rax
~~~

On a match it copies the module's full path, prepends `\??\`, saves and clears the thread's previous-mode byte, and calls `NtCreateFile`:

~~~
Desired access     00120089h   read data / attributes / EA, standard read, sync

Object attributes  240h        kernel handle, case-insensitive lookup

Name               \??\ + the containing module's full path

Share access       7           read, write, delete

Create disposition 1           open existing

Create options     24h         sequential access, synchronous non-alertable
~~~

~~~
000C2F62  654C8B342588010000       mov r14, qword ptr gs:[0x188]   ; current thread

000C2FA9  418A0C06                 mov cl, byte ptr [r14 + rax]    ; previous mode

000C2FAD  884E08                   mov byte ptr [rsi + 8], cl      ; save it

000C2FD3  41C6040600               mov byte ptr [r14 + rax], 0     ; KernelMode

000C3851  41FF1424                 call qword ptr [r12]            ; NtCreateFile
~~~

Eight controls complete the file helper. Every successful open has one matching close and every completed case restores the saved mode. Failures at each stage (open denied, information query failed, a file size of `100000000h`, allocation failure, a short read) erase and release what was taken.

On the successful path EOS queries `FileStandardInformation`, allocates, reads the whole file, and parses its PE certificate table. In the declared `ntdll.dll` control it stores:

~~~
Issuer common name    Microsoft Windows Production PCA 2011

Subject common name   Microsoft Windows

Leaf certificate      505F1F9FECEA37A97FCAB8F061CDFD324CF38DBD
~~~

An independent parse of the retained file's PKCS#7 certificate table identifies the same issuer and leaf subject, and hashing the leaf certificate's DER bytes with SHA-1 gives exactly the twenty bytes EOS wrote. So the stored hash is a certificate fingerprint, not a hash of the DLL and not a hardware identifier.

Two changed-input controls keep this from being overread. Clearing the PE certificate-directory entry at file offset `198h` takes the parser's absent-directory route. Changing one byte of the leaf subject, `Microsoft Windows` to `Nicrosoft Windows`, preserves the entire 71,746-instruction path and simply produces the changed name and a different fingerprint, with the embedded signature bytes left untouched. EOS extracts this material; it has not been observed validating it.

When the file path fails, a different branch scans the mapped image for strings. Its classifier accepts printable ASCII lanes plus tab, LF and CR:

~~~
0006B95A  F30F6F0438               movdqu xmm0, xmmword ptr [rax + rdi]

0006B963  660FFCCE                 paddb xmm1, xmm6

0006B96B  660FDAD7                 pminub xmm2, xmm7

0006B96F  660F74D1                 pcmpeqb xmm2, xmm1

0006B977  66410F74C8               pcmpeqb xmm1, xmm8

0006B996  660FEBE2                 por xmm4, xmm2

0006B99A  66440FD7E4               pmovmskb r12d, xmm4
~~~

A collector callback copies each 24-byte descriptor into a temporary array and returns true once the count equals capacity, which the scanner tests to stop early. In the declared `ntdll.dll` case the array fills at 512 entries: 216 narrow and 296 wide. The caller then makes 72 `RtlUnicodeToUTF8N` requests producing 1,905 bytes into a `ClfI` allocation. The first conversion's source is an embedded string naming a registry path; that's data inside the inspected PE, not a registry operation.

And then the record is cleared and freed

The `CM20` record has an owner and an end. At event 20296064 EOS stores its usable pointer into the first qword of a `Uref` object. The destructor loads that pointer, calls the release helper, decrements the payload-byte and allocation counters, and clears all 632 bytes from the raw allocation, header included, before the free.

~~~
0002A896  488B0F                   mov rcx, qword ptr [rdi]

0002A899  4885C9                   test rcx, rcx

0002A89C  7424                     je 0x2a8c2

0002A8BF  41FFD0                   call r8

0020F675  488B540108               mov rdx, qword ptr [rcx + rax + 8]

0020F6D9  8B1C01                   mov ebx, dword ptr [rcx + rax]

0020F701  E8BA9B0400               call 0x2592c0

0020F7C4  49FFE0                   jmp r8
~~~

The semantic trace records `ExFreePoolWithTag` on the raw CM20 allocation at 20335960 and on the `Uref` owner at 20335964, both inside image callback scope 587999, with the callback completing at 20336000.

So the record cannot survive in that allocation past the callback. That doesn't exclude an earlier copy somewhere else, and the final consumer of either flag bit is still unresolved.

Address ownership and memory work

At 888.0840104 seconds into observation, EOS asks which image contains:

~~~
eos.sys + 0x37B50C
~~~

using RtlPcToFileHeader.

~~~
000FEC23  lea rdx, [rsp+38h]

000FEC43  mov rcx, rdi

000FEC46  mov rbx, rax

000FEC49  xchg [rsp+18h], rbx

000FEC4E  call qword ptr [rsp+18h]

000FEC52  push rax
~~~

That call isn't rare: C317 records 384,420 RtlPcToFileHeader calls during steady observation, paired with `MmIsAddressValid` on other EOS addresses.

Across C317:

~~~
NtReadFile:              4,907

NtCreateSection:           206

Section mappings:          205

Section unmaps:            205

MmCopyMemory:           25,667

MDL allocate:            3,420

MDL lock:                3,420

MDL unlock:              3,420

MDL free:                3,420
~~~

NtReadFile phase distribution:

~~~
Initialization:           222

Initial worker work:       72

Steady observation:     3,656

Unload:                   957
~~~

When an inspected address belongs to no loaded image

The RtlPcToFileHeader path has a recovered fallback when the API returns no containing image. EOS aligns the inspected address down to a 4 KiB page, calls helper 0x1B1B92 with selector 4, and can increment the first DWORD of the returned record.

~~~
0010D081  and rdi, -1000h            ; page-align inspected address

0010D088  mov rax, [r14+28h]         ; fifth helper argument

; protected dispatch omitted

0035B746  mov [rsp+20h], rax

0035B74B  lea r9, [rsp+34h]          ; output slot

; decode second argument omitted

0035B75D  mov rcx, rdi               ; aligned page

0035B760  mov r8d, 4                 ; selector

0035B777  mov rdx, rsi

0035B77A  call qword ptr [rsp+18h]   ; helper 0x1B1B92

; non-null result path

0035A541  pop rax

0035A542  inc dword ptr [rax]
~~~

Four controlled cases cover image-found / image-not-found and helper-record present / absent. In the record-present test, a declared counter changes from 7 to 8. That record has not been identified as a violation counter.

Helper 0x1B1B92 is itself a resolve, prepare, retry wrapper. It calls an unresolved routine A first. If A returns null, it calls routine B; only B's low return byte controls whether EOS tail-calls A again.

~~~
001B1C1E  call rax                    ; A

001B1C20  test rax, rax

001B1C23  je 1B1C36h

001B1C35  ret

; construct B arguments

001B1C7C  call r10                    ; B

001B1C7F  test al, al

001B1C81  je 1B1CA9h

; recompute A and restore caller frame

001B1CA6  jmp rax                     ; tail-call A

001B1CA9  xor eax, eax

001B1CAB  jmp 1B1C25h
~~~

The wrapper itself never dereferences the candidate page in the recovered 83 instructions. A lookup/create/lookup interpretation is plausible, but the callees remain unresolved.

One more check narrows the "these are stack return addresses" reading. The first five inspected EOS addresses in the selected interval are not immediately preceded by an instruction that decodes as CALL and ends at that address in the original bytes. That weakens a simple return-address list interpretation without proving the absence of a separate stack walker.

9. Windows notifications

Registered routines include:

~~~
Process notify           0x6787C

Thread notify            0x67F68

Image load               0x684C6

Object pre               0xEA9B9

Object post              0xEBD81

Registry                 0x225088

Filesystem pre           0x22563B

Filesystem pre           0x22566F

Filter unload            0x22560D

PnP                      0x19FE4B

Image verification       0x68CAD

Bugcheck reason          0xA1120

TDI address              0x13E1C6

CREATE / CLOSE            0xCCA29

DEVICE_CONTROL            0xCCAAF
~~~

C317 guest callback counts:

~~~
Process:                    6

Thread:                    16

Image:                      3

Object handles:         2,116

Registry:               1,262

Filesystem family:         10

PnP:                        6

Image verification:         3

Bugcheck reason:            3

TDI address:                4

Device create/close:        6

Device control:             0
~~~

Within the registration families this catalog recognizes, the only registered routine never invoked is the device-control handler `0xCCAAF`. Filter unload `0x22560D` and DriverUnload `0xCE846` both execute. Every listed invocation is guest-executed; the catalog records zero replayed callback invocations.

Debug-print callback ABI issue

At event 19745941, EOS calls DbgSetDebugPrintCallback with:

~~~
Callback RVA:

0x8BFF3

Raw RDX:

0xA8F07168EFA201
~~~

Windows consumes only DL:

~~~
005A8030  cmp dl, 1

005A8033  jne remove_callback

005A8035  call DbgpInsertDebugPrintCallback
~~~

DL is 1.

The old executor compared full RDX and incorrectly chose removal. The original C317 STATUS_NOT_FOUND is therefore a model bug.

10. Object-manager namespace, registry and trust inputs

Object-manager namespace

C317 contains:

~~~
NtQueryDirectoryObject:

11,730 calls

Delivered object entries:

11,560

Initialization:

7,044

Steady observation:

4,516
~~~

First delivery:

~~~
Name:

PendingRenameMutex

Type:

Mutant

Directory:

\
~~~

Registry reads

C317:

~~~
NtOpenKey:               385

NtQueryValueKey:         561

NtEnumerateKey:          536

NtEnumerateValueKey:      12
~~~

Local catalog/trust work:

~~~
ICatDBSvc_v2 enumerations:

315

During unload:

61
~~~

The model returns success with zero catalog names, which is an explicit modeling limit rather than an empty host catalog.

CI DebugFlags and EOS registry state

The registry is also an output surface.

EOS writes:

~~~
HKLM\System\CurrentControlSet\Control\CI\DebugFlags

DWORD 0x10
~~~

during initialization:

~~~
Event:

40942
~~~

and again during unload:

~~~
85380475
~~~

Both return through EOS RVA:

~~~
0x419FDC
~~~

Original shared write bridge:

~~~
00419FD8  call qword ptr [rsp+8]
~~~

Microsoft documents `DebugFlags = 0x10` as retaining unsigned-driver blocking while kernel debugging is enabled. The observed write therefore doesn't disable Code Integrity.

The trace records two earlier queries at 40910 and 40917, but those records don't preserve the prior DWORD payload. The unload write shouldn't be called a proven restoration of an independently observed old value.

EOS diagnostic and filter state

EOS writes several diagnostic/configuration values:

~~~
ErrRpt_ServiceState

DWORD 0

event 23122

ErrRpt_LastInitTime

QWORD payload

event 23125

ErrRpt_LastInitInfo1

EOS image base

event 23128

ErrRpt_LastInitInfo2

image extent

event 23131

Registry flush:

23138
~~~

Minifilter instance configuration:

~~~
DefaultInstance:

EasyAntiCheat_EOSSys

Altitude:

327530

Flags:

0
~~~

Events:

~~~
18397536

18397990

18398188
~~~

During unload EOS writes:

~~~
ErrRpt_LastUnloadDuration

DWORD 42364

event 85383702
~~~

The unit represented by that DWORD hasn't been independently reconstructed.

There are 22 total set-value observations:

~~~
EOS caller:

10

Environment setup:

9

Injected workload:

3
~~~

There is also one EOS delete-value observation at 85383714, whose stored path uses an encoded value filename; the logical value name isn't established by that event alone.

Keeping the caller attribution prevents setup/workload mutations from being counted as EOS behavior.

Certificate stores and AuthRoot CTL

The full registry census contains:

388 value-query attempts under SystemCertificates

split as:

~~~
Blob:

385

EncodedCtl:

3
~~~

By store:

~~~
CA:

188

AuthRoot:

131

ROOT:

65

FlightRoot:

4
~~~

These are query attempts, including sizing/overflow sequences, not 388 unique certificates.

At event 481078, EOS receives:

~~~
ROOT certificate-store Blob

2,001 bytes
~~~

At 18097377, after sizing/overflow calls, it receives:

~~~
AuthRoot\AutoUpdate\EncodedCtl

206,702 bytes
~~~

Both use the same NtQueryValueKey delivery bridge at RVA:

~~~
0x3D16E6
~~~

These inputs give EOS Windows trust-store material alongside the catalog RPC and image-verification callback. The current trace doesn't recover complete certificate-chain validation or a final signature decision.

Device-interface discovery

EOS calls IoGetDeviceInterfaces for:

~~~
Monitor interface:

1 request

Network-device interface:

4 requests
~~~

Requested standard GUIDs:

~~~
Monitor:

{E6F07B5F-EE97-4A90-B076-33F57BF4EAA7}

Network device:

{CAC88484-7515-4C03-82E6-71A87ABAC361}
~~~

Result events:

~~~
Monitor:

19728544

Network:

19734261

20113876

68464727

73849565
~~~

All five calls succeed but return an empty MULTI_SZ.

The provider only enumerates its registered ActiveInterfaces and doesn't contain a captured host interface inventory. The empty response therefore can't be used to claim that the host had no monitor or network devices.

GetIfTable2 and WmiMonitorID succeed through separate interfaces, but those successes don't populate this symbolic-link enumeration path.

Storage IRP construction and copied driver stack

EOS constructs 12 device-control IRPs during initial runnable work:

~~~
SMART_RCV_DRIVE_DATA:

2 requests

IOCTL_STORAGE_QUERY_PROPERTY:

8 requests

ATA_PASS_THROUGH_DIRECT:

2 requests
~~~

SMART requests:

~~~
IOCTL:

0x7C088

Input:

33 bytes

Output:

529 bytes
~~~

Storage-property queries:

~~~
IOCTL:

0x2D1400

Input:

12 bytes

Output capacities:

8 / 40 / 396 bytes
~~~

ATA pass-through:

~~~
IOCTL:

0x4D030

Request:

48 bytes

Indirect data buffer:

512 bytes
~~~

IRP-building observations span:

~~~
19730857 -> 19732368
~~~

Original construction site:

~~~
00020648  call r10

0002064B  test rax, rax
~~~

The guest device stack reaches copied code from:

~~~
disk

CLASSPNP

ACPI

storport
~~~

For example, eight KseGetIoCallbacks calls originate from:

~~~
storport.sys RVA 0xFED2
~~~

Those are support calls inside the guest storage stack, not eight direct EOS detector calls.

The 12 built IRPs and **four captured storage-response events** refer to different boundaries and shouldn't be treated as a one-to-one completion count.

WMI acquisition

WMI work totals:

~~~
Opens:

8

Queries:

16
~~~

The opens cover:

~~~
Raw SMBIOS:

6

System information:

1

Monitor data:

1
~~~

This is another route into firmware/device information alongside the registry SMBIOS source, RSMB firmware query and monitor WNODE response.

11. ETW telemetry

C317 contains:

~~~
Trace sessions:             5

Real-time consumers:        5

Delivered buffers:          7

USB UCX records queued:

2,601
~~~

Threat Intelligence provider:

~~~
GUID:

f4e1897c-bb5d-5668-f1d8-040f4d8dd344

MatchAnyKeyword:

0x03FFF0FF

Level:

0
~~~

The copied publisher manifest decodes 22 selected bits, covering activity around allocation, protection changes, remote APCs, thread context, memory reads/writes and process/thread suspend/resume/freeze/thaw.

Queued records, delivered buffers and records actually interpreted by EOS are three different measurements, which is why the rest of this section exists.

The consumer worker, end to end

C460 follows a successful session START into consumer setup. EOS requests a `21000h`-byte user allocation, initializes a 32-bit bitmap, creates two events, and calls `NtTraceControl` with function `0Bh` and 96-byte input/output records.

~~~
User allocation       00000000AD9F0000, size 21000h   #19777959

Bitmap                header AD9F0020, bits ADA10030  #19791917

Consumer data area    AD9F0030, size 20000h           #19810488, session 32

Notification objects  FFFFB00044E5F000 / ...44E60000  #19810488

Worker context        FFFFB00044E62010                #19820035

Context +10h          eos.sys+22569Bh                 store #19820610

Context +18h          parent FFFFB00044DC8010         store #19820634

Thread entry          eos.sys+1CBE5Bh, guest TID 1332 #19828001

Persistent reference  eos.sys+30CB90h holds the ctx   store #19834582
~~~

~~~
01017DB3  4C8918        mov qword ptr [rax], r11   ; [context+10h] = 22569Bh

01017E11  4C8927        mov qword ptr [rdi], r12   ; [context+18h] = parent

01D3C7E4  48891A        mov qword ptr [rdx], rbx   ; image+30CB90h = context
~~~

That is the same context code pointer carried by five of the seventeen C317 workers.

The context is built from a template, and the callback pointer is encoded

The original binary contains a 304-byte default-value block at `eos.sys+2EAA40h`. Eight of its fields decode to zero even though the stored qwords are nonzero, and the early C484 context matches 32 of its 38 qwords. The instruction that copies the template hasn't been found.

~~~
Context  Encoded default     Early snapshot  Parser-entry snapshot

+20h     21C61AEFE00E7A19    0               1004h    first handle

+48h     148032C22B53437D    0               1000h    second handle

+60h     4CEE739EEC8B0F2A    0               FFFFF8010008B88A   callback

+78h     3A896BC0F8ED35DD    0               FFFF918FA696F140   process

+A8h     4515B64B560E04D7    0               0        callback argument

+B8h     291073C9A885D713    0               AD9F0000 buffer header

+118h    689DD3D603F541A7    44DC9010        same     scratch destination

+128h    72D1AB4B64762B5E    1000h           1000h    scratch capacity
~~~

Pointers in this context are stored additively. C522 recovers the writer: at the return from `ExUuidCreate`, R13 already holds `FFFFF8010008B88A`, and EOS installs the callback at RVA `BB7941` and the process value at `BB7DB1`, before either `NtTraceControl` STOP or START.

~~~
; Entry: R10 = target; R14 = (1<<42)-1; R11 = target & R14; RBP = R9 = 0.

00BB7912  48BB2A0F8BEC9E030000     movabs rbx, 0x39eec8b0f2a

00BB791C  4C01D3                   add rbx, r10

00BB791F  4C21F3                   and rbx, r14

00BB7922  49C1EA2A                 shr r10, 0x2a

00BB7926  4C39DB                   cmp rbx, r11

00BB7929  4181D29C3B1300           adc r10d, 0x133b9c

00BB7930  49C1E22A                 shl r10, 0x2a

00BB7934  4909DA                   or r10, rbx

00BB7937  4D31D1                   xor r9, r10

00BB793A  4C0FAFD5                 imul r10, rbp

00BB793E  4D31CA                   xor r10, r9

00BB7941  4D8910                   mov qword ptr [r8], r10
~~~

The split arithmetic implements `stored = target + 4CEE739EEC8B0F2Ah (mod 2^64)`, proved for every 64-bit target by bit-vector check, and the decoder adds the inverse constant `B3118C611374F0D6h`. The template's default is therefore the encoding of a null pointer, replaced during setup by the encoding of `eos.sys+8B88Ah`. This is pointer storage protection; it says nothing about encrypted event payloads.

The selected process value gates setup too. After START, EOS decodes `context+78h` and tests it at `843D3h`. With the initialized value it continues to the current-process call; substituting the earlier encoded null takes the other branch and eventually issues another STOP. Reverting only the callback field, or only the `+Ch` DWORD, keeps the initialized route.

The reconstruction retires 19,351 original instructions to the captured START return, matching all 18 scalar and 16 YMM registers. Of 339,600 overlapping memory bytes, twelve differ, and they're recorded explicitly rather than smoothed over.

Buffer delivery, the parser and the callback

C484 binds the wait, parser and callback on guest thread 1332.

~~~
Satisfied data wait   #19871872   RAX = 1, worker continues

Parser entry          #19873223   context FFFFB00044DC8010

First callback        #19876841   CALL at 21A0CEh, target 8B88Ah, opcode 20h

Next two records      #19896352, #19905138   opcodes 05h and 08h

Recorded returns      #19904566, #19912003   both RAX = 1

Next wait             #19912323-#19912326    worker blocks again
~~~

The parser takes a linked list from the consumer header, reverses the links, subtracts `20h` from each to recover the buffer base, validates the recorded length against capacity and a decoded minimum, selects a record format from the type byte at record `+2`, copies the record into scratch and builds an `EVENT_RECORD`-compatible descriptor on the stack.

~~~
EventHeader.Size       34h              the 52-byte source record

EventHeader.Flags      0300h            classic header, processor index

Version / opcode       2 / 20h

UserDataLength (+56h)  24h              36 payload bytes

UserData (+60h)        FFFFB00044DC9020 scratch + 10h

EventHeader.TimeStamp  zero
~~~

Then it decodes the callback and its argument out of the context and calls it:

~~~
0021A0A6  488B4C2460              mov rcx, [rsp+60h]

0021A0AB  488B4160                mov rax, [rcx+60h]       ; encoded callback

0021A0AF  4803842460010000        add rax, [rsp+160h]      ; decode target

0021A0B7  488B89A8000000          mov rcx, [rcx+A8h]       ; encoded argument

0021A0BE  48038C2458010000        add rcx, [rsp+158h]      ; decode argument

0021A0C6  488D9424A0010000        lea rdx, [rsp+1A0h]      ; stack descriptor

0021A0CE  FFD0                    call rax
~~~

A timestamp the parser reads from the wrong offset

Small but concrete. Native Windows classic buffers put the record timestamp at source record +8**. EOS initializes a frame slot to `10h` and uses it as the source offset, so it reads source **+10h instead.

~~~
; 2195F9: RCX = 10h. R15 later points at the classic source record.

; EVENT_RECORD begins at RSP+1A0h; its timestamp is at +10h.

002195F9  48898C24D0000000       mov qword ptr [rsp + 0xd0], rcx

00219AFF  410FB65F02             movzx ebx, byte ptr [r15 + 2]

00219FD0  418A07                 mov al, byte ptr [r15]

00219FEA  488B8424D0000000       mov rax, qword ptr [rsp + 0xd0]

00219FF2  498B0407               mov rax, qword ptr [r15 + rax]   ; source + 10h

00219FF6  48898424B0010000       mov qword ptr [rsp + 0x1b0], rax ; descriptor + 10h
~~~

The actual worker executes this at #19876797, reads eight zero payload bytes and stores them, which is why the first captured descriptor has timestamp zero. Controls confirm the offset directly: changing only source `+8` leaves the descriptor timestamp zero, while changing only source `+10h` puts the supplied qword there exactly. Two retained native Windows buffers independently place all three of their metadata timestamps at `+8`.

I'd rather not overstate this. It explains the selected descriptors on this input; it doesn't show a later consumer acting on a wrong time, and it doesn't extend to every ETW header format.

The callback reads the opcode and splits on 25

The callback's first payload access is the descriptor's opcode byte at `+2Dh`. Four original instructions set a local byte to whether the opcode is below 25:

~~~
00048A03  440FB627               movzx r12d, byte ptr [rdi]     ; EVENT_RECORD+2Dh

00048A3C  418D8424E7FF0100       lea eax, [r12 + 0x1ffe7]

00048A44  25FFFF0100             and eax, 0x1ffff

00048A49  3DE7FF0100             cmp eax, 0x1ffe7

00048A4E  400F93C5               setae bpl
~~~

Running the original 382-instruction transfer for all 256 opcode values, twice with different backing, gives a clean split:

~~~
Opcode byte   Earlier BPL   Later AL   Target of JMP RDI at 49097h

00h..18h      1             1          3D3985h

19h           0             0          3D3985h

1Ah..FFh      0             1          3D47D1h
~~~

Eight full-callback controls then run both routes. The short route retires 6,167 instructions and the long route 19,510; all eight return RAX = 1 and none of them reads the 36-byte scratch payload.

A second predicate in the same frame traces back to R9 at callback entry, which is zero after the parser's copy loop decrements its counter. It applies four 64-bit keyed transforms of the form `t = (x XOR k) * k`, `Hk(x) = (t XOR ((t >> 32) >> (t >> 60))) * k`, ORs three XOR comparisons together, and tests whether the combined mismatch is nonzero. 1,266 original-code checks over 633 declared values agree with that lifted formula. An unrestricted 64-bit search for the zero case timed out, and a separate solver attempt also returned unresolved after its 300-second limit, so reachability of that case is open.

Native network records reach payload comparisons

Changing the opcode byte alone only exercises routing. C524 instead passes five complete records from a retained native Windows network capture through the same parser and callback. The record bytes keep their native identity; placing each one in the retained EOS buffer is the declared part.

~~~
Native record type        Record / payload   Payload read by the callback

------------------------  -----------------  ----------------------------

060Ah, IPv4 send          52 / 36 bytes      source address at +0Ch

060Bh, IPv4 receive       44 / 28 bytes      PID at +0

060Ch, IPv4 connect       60 / 44 bytes      none

060Dh, IPv4 disconnect    44 / 28 bytes      none

0610h, IPv4 reconnect     44 / 28 bytes      none
~~~

All five callbacks retire the same 6,167 instructions. The equal instruction paths hide different data accesses: protected arithmetic selects a payload address in the first two cases and a local stack address in the others. Instruction and branch counts alone would have missed that entirely.

The comparison blocks recognize two concrete values, `0100007Fh` (bytes `7F 00 00 01`, IPv4 loopback) and **`4`**, using the same keyed multiply/XOR/shift construction with different embedded keys.

~~~
Declared field change              Effect inside EOS

---------------------------------  --------------------------------------------

Send source = 127.0.0.1            reads the destination address at payload +8

Send source = 126.0.0.1            does not read that field

Receive PID = 4                    reads the source address at payload +0Ch

Receive PID = 5                    does not read that field

Send source and destination        reads further fields and follows the object

  both = 127.0.0.1                 pointer in image global +3004F8h
~~~

~~~
; 1665D49: selected send-source / receive-PID read. 1665FF8: second address.

; 16668FB reads image+3004F8h; 16668FE copies its object pointer into the frame.

01665C8F  4C8B3A                 mov r15, qword ptr [rdx]

01665D49  8B3E                   mov edi, dword ptr [rsi]

01665E4C  4839F1                 cmp rcx, rsi

01665E4F  0F95C0                 setne al

01665F9D  4839EE                 cmp rsi, rbp

016660F1  4839EA                 cmp rdx, rbp

016660F4  400F94C6               sete sil

01666196  448B17                 mov r10d, dword ptr [rdi]

016668FB  488B00                 mov rax, qword ptr [rax]

016668FE  49890424               mov qword ptr [r12], rax
~~~

These tests establish the two matches. They don't prove the keyed arithmetic has no other collision across all 32-bit inputs.

Loopback sends maintain per-process, per-port counters

Following the double-loopback case through the complete callback is where this gets interesting.

The object behind `image+3004F8h` is a hash table. C526 captures it for real: root `FFFFB00044CCB010`, bucket pointer `FFFFB00044CCC010`, 4,096 buckets, both selected flag bytes cleared and entry count zero, summarized at events 19841954, 19850037 and 19880416. Every traversal visits all 4,096 buckets and finds no nodes, because C526 receives only one modeled 200-byte ETW metadata buffer and no traffic.
Feed it a loopback send and it populates. C525 runs the complete callback under an explicit empty-table control: one uninterrupted execution retires 50,158 instructions and matches the staged continuation exactly. EOS keys the outer table by the event PID and builds a two-level structure:

~~~
image+3004F8h

   -> process table, 4,096 buckets

      -> PID node, key +8 = 7B3Ch (PID 31548)

         -> 24-byte payload

              +00h  UNICODE_STRING (executable path)

              +10h  pointer to a port table

                      -> 4,096 buckets

                         -> port node, key +8 = BB01h

                            -> 12-byte payload

                                 +0  01 BB   the port bytes

                                 +4  32-bit event count

                                 +8  32-bit accumulated byte count
~~~

Port 443 arrives as the network-order bytes `01 BB`, and the key is the unconverted little-endian scalar `BB01h`.

~~~
001B137A  48897808                 mov qword ptr [rax + 8], rdi

001B137E  48C70000000000           mov qword ptr [rax], 0

001B14C3  488904DA                 mov qword ptr [rdx + rbx*8], rax

001B1535  014648                   add dword ptr [rsi + 0x48], eax

001B104C  89473C                   mov dword ptr [rdi + 0x3c], eax

001B1080  48894740                 mov qword ptr [rdi + 0x40], rax

0255885D  6641893F                 mov word ptr [r15], di

02558A20  895500                   mov dword ptr [rbp], edx

02558ACA  418911                   mov dword ptr [r9], edx
~~~

Repeat controls show the counters behaving as counters:

~~~
Input after the first 206-byte event   Port 443 record      Extra storage

-------------------------------------  -------------------  -----------------

Same PID, port 443, 206 more bytes     2 events, 412 bytes  none

Same PID, port 443, 17 more bytes      2 events, 223 bytes  none

Same PID, port 444, 206 bytes          unchanged at 1/206   a port-444 record
~~~

And the PID entry keeps the executable path. A control that sets the event PID to the retained current process follows the callback for 52,470 instructions. EOS calls `NtQueryInformationProcess(-1, 27, NULL, 0, &length)`, gets `C0000004h` and a required 118 bytes, repeats the query with a real buffer, allocates 102 text bytes, copies the name and publishes `Length`/`MaximumLength`/`Buffer` into the PID payload beside the port table pointer.

~~~
00085369  FF17                    call qword ptr [rdi]     ; sizing query

0008551B  FF5500                  call qword ptr [rbp]     ; real query

00085C05  418A0C06                mov cl, byte ptr [r14 + rax]

00085CCD  881C06                  mov byte ptr [rsi + rax], bl

000D136D  48894708                mov qword ptr [rdi + 8], rax   ; Buffer

000D1383  66895F02                mov word ptr [rdi + 2], bx     ; MaximumLength

000D1395  668907                  mov word ptr [rdi], ax         ; Length
~~~

The helper reads the thread's previous-mode byte, writes zero around each query and restores it afterwards. The temporary query buffer is cleared in full, allocator prefix included, and freed; the name allocation stays live and reachable from the PID node.

Two things this control does not show. The process lookup for PID 31548 returns `STATUS_INVALID_CID` and a null process pointer, because that PID isn't in the retained 215-process catalog, and EOS records the event anyway. And all four completed counter controls return `AL = 1` with pointer bits still in the upper RAX bytes, so the Boolean result doesn't encode the byte count.
C526 plus C528 tie this back to an observed table. Replaying the unchanged callback against the actual captured table matches 19,511 scalar checkpoints. Replacing only the descriptor and payload with the native-derived loopback input then retires 48,115 instructions, follows the same accounting path, and stores one 206-byte event for PID 31548 / port 443, with the captured table bytes unchanged at entry.

Afterwards the immediate caller tests `AL`, advances the aligned record pointer and prepares the next callback. Those 531 instructions perform no read or write of the four new allocations, and the port record still holds one event and 206 bytes at the next dispatch boundary `EOS+21A0C6`.

~~~
; Contiguous original caller instructions after the callback returns.

0021A0D0  84C0                    test al, al

0021A0D2  488B9424E8000000        mov rdx, qword ptr [rsp + 0xe8]

0021A0DA  0F844CF9FFFF            je 0xfffff80100219a2c

0021A0E0  03AC24C0000000          add ebp, dword ptr [rsp + 0xc0]

0021A0E7  23AC24BC000000          and ebp, dword ptr [rsp + 0xbc]

0021A0EE  4901EF                  add r15, rbp

0021A0F1  01F5                    add ebp, esi

0021A0F3  89EE                    mov esi, ebp

0021A0F5  39D5                    cmp ebp, edx

0021A0F7  0F8202FAFFFF            jb 0xfffff80100219aff
~~~

Callback and caller together match 20,042 original scalar checkpoints including every selected read.

And a cleanup path that erases all of it

The cleanup selected by the earlier UUID/session-failure route reaches this same table. Its visitor calls `EOS+224D70` for each entry, passing the PID as key and the 24-byte payload as value. Running that original consumer over the table produced by the accounting control gives a complete disposal:

~~~
#  Owned object                          Action before the modeled free

1  executable-name allocation, 118 B     every byte zeroed; the 16-byte

                                         UNICODE_STRING in the payload cleared

2  port-node allocation, 44 B            every byte zeroed, counters included

3  port-bucket allocation, 32,784 B      buckets cleared, allocation erased

4  port-table allocation, 96 B           table and allocator prefix erased

5  PID-node allocation, 56 B             caller erases and frees after return

6  root PID table                        all 4,096 bucket slots zeroed, count 0
~~~

~~~
; RSI = table, RDI = node during iteration; RDI = payload in the last two lines.

001B1756  8B4E3C                  mov ecx, dword ptr [rsi + 0x3c]

001B17A2  488B5640                mov rdx, qword ptr [rsi + 0x40]

001B17AF  498D143E                lea rdx, [r14 + rdi]

001B17B3  488B4F08                mov rcx, qword ptr [rdi + 8]

001B17BA  41FFD4                  call r12

0008BC7A  488B4F08                mov rcx, qword ptr [rdi + 8]

0008BCE1  488B5710                mov rdx, qword ptr [rdi + 0x10]
~~~

The visitor completes after 113,268 instructions and the caller runs another 38,192 through node removal and bucket clearing. Five allocations totaling 33,098 bytes are released, and qualification checks the last original write to every byte before each free, so an initially zero buffer can't stand in for an observed erasure.
The visitor reads the name and table pointers and never reads the 12-byte port counters**. This consumer disposes of the record without interpreting it.**

What the network accounting does and doesn't show

Established: EOS subscribes to classic TCP/IP records, reads the source address on sends and the PID on receives, recognizes loopback and PID 4, and for a matching loopback send maintains a per-process, per-destination-port record holding an event count, an accumulated byte count and the process's full executable path. A separate cleanup path erases and frees all of it.

Not established: any normal-operation reader of those counters, any comparison against a MAC address or UUID, any serialization, any user-mode transfer and any transmission. The table observed in a real run is empty, because that run received only metadata; the populated cases are declared-traffic experiments over original code. That distinction is the whole reason the next experiment on my list is a discriminating traffic delivery through the existing logger transport rather than another metadata run.

12. Anti-virtualization and hypervisor checks

Full section in a follow-up post in this thread: [Platform and processor probes](https://www.unknowncheats.me/forum/4806980-post61.html).

A dedicated pass reselected 22,527 CPU and exception records from C317 and checked every selected record against the source stream and original image bytes. The mechanisms it covers:

~~~
Hypervisor CPUID leaves 40000000h and 40000100h

Windows hypervisor-information query, class 197

100x timed CPUID loop against a 100x timestamp-only baseline

TF and BTF probes, with and without a MOV SS reload

256 synthetic MSR reads, 40000000h through 400000FFh

VMREAD status/fault probe

Debug-register reads and writes

RTM read/execute and physical-alias return probes

PMU minimum sampling, XGETBV / XSETBV, RDTSC

Intel Processor Trace, IA32_RTIT_CTL = 0x2105

CR3 read/reload blocks

Alternate page-table-root experiment

APIC performance-interrupt masking around that experiment
~~~

Two results are worth pulling forward here. The alternate page-table-root path saves CR3, substitutes paging entries, switches to a constructed root and executes `CPUID`, `SIDT` and `SGDT` under it before restoring. C317's CPU selection contains 666 CPUID events and none at that probe body, so the body is original-code reconstruction rather than observed execution.

That same routine masks the local APIC performance-monitor interrupt before the probe and restores the mask afterwards, using either xAPIC offset `0x340` or x2APIC MSR `0x834`. It is the closest thing to the NMI-storm idea anywhere in the recovered code, and it does not set NMI delivery mode, program a counter overflow or contain a repeated generation loop.

13. Stack-walking claim: current evidence

Full section in the same follow-up post. The EOS kernel-call catalog contains zero recorded calls named `RtlVirtualUnwind`, `RtlWalkFrameChain`, `RtlCaptureStackBackTrace`, `RtlLookupFunctionEntry` or `RtlCaptureContext`, and C317's five unwind records come from KEVLAR's exception dispatcher. A custom inline walker remains possible; the retained evidence doesn't establish one.

14. Temporary win32k callback slot

Full section in the same follow-up post. EOS writes `eos.sys+0x237A00` into `win32kbase.sys+0x28E058`, and the previous zero value returns roughly 0.5000021 virtual seconds later.

15. Device interface and IOCTL candidates

EOS creates:

~~~
\Device\EasyAntiCheat_EOS
~~~

Dispatch:

~~~
CREATE / CLOSE:

0xCCA29

DEVICE_CONTROL:

0xCCAAF
~~~

Control-code load:

~~~
01D722B2  mov r15d, dword ptr [rdi]
~~~

where:

~~~
RDI = CurrentStackLocation + 0x18
~~~

An isolated set of 131 command probes distinguishes fifteen values that reach request or initialized-state reads. All fifteen encode METHOD_NEITHER.

~~~
Reaches Type3InputBuffer and input length

0x22E017

0x22E01B

0x22E023

0x22E043

Needs initialized driver data first

0x22E007

0x22E00F

0x22E01F

0x22E04B

0x22E06B

Needs encoded table state at EOS data RVA 0x2F09C8

0x22E047

0x22E04F

0x22E053

0x22E05B

0x22E063

0x22E067
~~~

These are candidates for protocol reconstruction, not fifteen accepted commands.

The user-mode relay hypothesis, stated so it can be tested

Since two collection paths now demonstrably end on one protected record list, the obvious explanation is that a user-mode component drains it and later sends the contents somewhere. I'd rather write that down as a hypothesis with testable steps than let it drift into the narrative as fact.

~~~
EOS collects and encodes records

        |

        v

protected kernel record list           <- producer and append observed

        |

        |  transfer reader unlocated

        v

kernel-to-user transfer

        |

        |  recipient unlocated

        v

user-mode component

        |

        |  upload unobserved

        v

backend
~~~

~~~
Proposed step                What would establish it

---------------------------  ----------------------------------------------

A record leaves the list     an original consumer reading the identified node

                             or payload, then copying it across a boundary

A named component gets it    destination process and buffer identity, matching

                             bytes, and a receiver instruction consuming them

That recipient is manually   evidence of its loading path and memory layout,

mapped                       tied to the receiving process

The data reaches a backend   receiver-side dataflow into an identified request

All identifiers are sent     a traced path per identifier, including the

                             conditions that retain or discard it
~~~

None of those is established here. Driver-side local checks, selective reporting, and records left queued until unload all remain possible, and the C500 free during DriverUnload is compatible with both an earlier delivery and an undelivered record. A shared container does not establish universal transmission.

16. Network collection vs transmission

EOS collects local network identity through GetIfTable2, generated UUID state and TDI address notification, and it now demonstrably accounts for loopback traffic per process and destination port.

The validated kernel-side network inventory still contains no packet-send operation. TDI registration obtains an existing captured address; workload address and transport changes are injected local notifications whose records explicitly identify no transmission. Local ETW delivery and the catalog RPC are not an Internet connection or an EOS-service exchange.

The normal EOS user-mode service isn't present in the run, so this statement applies to the observed driver inventory rather than the complete product.

17. DriverUnload and residue

DriverUnload:

~~~
RVA:

0xCE846

Entry:

79695124

Return:

85383716
~~~

Shutdown helper:

~~~
001CCA39  mov rcx, rbx

001CCA3C  xor edx, edx

001CCA3E  xor r8d, r8d

001CCA41  call r9

001CCA44  cmp byte ptr [rsi+60h], 0

001CCA48  jnz return_path

001CCA4E  mov rsi, [rsi+28h]

001CCA52  test rsi, rsi

001CCA55  jz return_path

001CCADF  mov qword ptr [rsp+20h], 0

001CCAE8  mov rcx, rsi

001CCAEB  xor edx, edx

001CCAED  xor r8d, r8d

001CCAF0  xor r9d, r9d

001CCAF3  call r10
~~~

Post-unload snapshot:

~~~
Tracked guest-pool allocations:

11 / 1,132 bytes

OS-owned caches:

2 / 412 bytes

Direct EOS allocations:

9 / 720 bytes

Kernel handles:

10

Referenced objects:

10

File / registry handles:

0

Guest IRPs:

0

Devices:

0

Filters:

0

Runnable / waiting contexts:

0
~~~

Two of those eleven aren't EOS allocations at all. The 356-byte and 56-byte APIC and HPET tables arise inside modeled `HalAcpiGetTableEx` calls at events 33141 and 890728, so they are borrowed OS cache entries that the old provider wrongly charged to the guest ledger.

The other nine come from EOS allocator calls: one 40-byte allocation at 28512 returning to RVA `0x23823B`, and eight totaling 680 bytes at 19699251-19699280 returning to RVA `0x20F2A5` on worker 404. The 40-byte one has a lead: the rundown initialization and acquire/release calls that follow it use the same kernel-global lock as native `DbgpInsertDebugPrintCallback`, and events 28510-28519 match that insertion pattern.

All five real-time consumers disconnect and EOS closes both event handles for each. The first connection at 19679383 disconnects at 25776306 with handle closes at 25776361-25776366. The model still retains consumer handles and event references until harness reclamation, because the copied kernel separates disconnection from object destruction and the model conflates them. That is the open question there, not whether EOS signaled disconnection.

Lifecycle acceptance remains:

~~~
19 / 20
~~~

18. Current picture

The full inventory, grouped into machine and boot identity, platform characterization, kernel-driver discovery, record construction and retention, process and software inspection, telemetry and event handling, trust and policy state, and execution-environment probes, is in the appendix post: [Current picture and acquisition sites](https://www.unknowncheats.me/forum/4806985-post64.html).

19. Evidence boundaries

C317's virtualization, DMA, Secure Boot and signing-policy values come from the declared modeled platform. The original EOS query sites are real; the returned values aren't native measurements of the host.

The CPUID timing loop is real. The 150-versus-1 deltas come from KEVLAR's virtual clock, which enforces those minimums by policy.

The CR3 same-value reload blocks are real. A repeated timed CR3-thrashing workload and its decision consumer haven't been established.

EOS acquires the exact PiDDBLock. C317 initializes the cache empty; the populated walk, its twenty-record gate and its six formatted records come from C401c/C402 with a restored historical cache, whose boot differs from the module profile's. Those six names are not native same-boot anomalies.

The backing FILE_OBJECT path exists in original EOS code, and the live capture supplies real graphs for it, while C317 supplies a null SectionPointer at the observed site.

The three ordinary image-load stimuli are user images. They don't exercise the kernel-image branch of the image-load callback.

The five IoGetDeviceInterfaces requests return empty lists because of the modeled ActiveInterfaces input. They don't show that the physical host lacks those devices.

The 256 KiB persistent-thread-state buffer is provider-built triage data, not a host crash dump.

Certificate-store and CTL delivery establishes trust-data acquisition, not a recovered certificate-validation algorithm.

The GPU chain is complete from reference acquisition through XXTEA, list append and release at unload. No instruction has been observed reading that ciphertext back, and the unload free is equally compatible with an earlier delivery or with a discarded record.

The PiDDB record follows the same path onto the same list. C415's walk found eleven records already queued whose contents were not examined.

XXTEA is identified for the two captured records, against the reference recurrence and with negative controls on the key and word order. That is not a claim about every input or about the surrounding protocol's security.

The four key words sit in the same allocation as the ciphertext, so anyone holding the allocation holds the key to that layer. Whether a further transport layer exists is unknown.

The recorded unwind events belong to exception delivery in the harness and don't establish an EOS stack-spoofing detector.

C388 establishes an exact all-ones predicate over one eight-byte PCI response, but the downstream PCI/DMA policy remains unresolved.

The later live kernel capture supplies populated PiDDB, unloaded-driver and backing-file inputs from another Windows boot. Those inputs don't retroactively prove that C317 traversed them.

C399 searches thirteen driver basenames and contains local equal-result branches, but all 2,678 observed comparisons are nonmatches and the positive-match policy consumer remains unresolved.

The dbgview, devenv. and tv_ process-name predicates are recovered local byte-prefix checks. No matching live process followed by a policy action is captured.

The decode paths for Dbgv.sys, PROCMON23.sys, dbk64.sys, dbgview, devenv. and tv_ are reconstructed under candidate K = 0x4692EF1D2B0A9537. K is constrained statically from the comparison-wrapper identity rather than recovered from a captured runtime entry state, and the decode paths for the other ten targeted driver names remain unreconstructed.

The DbgUiRemoteBreakin displacement reference decodes to LdrShutdownProcess by exact export and signed-arithmetic correspondence. The actual captured run reads byte 48h and takes the common route, so the matching case and its flag update are declared controls. The reference table's writer is unidentified.

The Administrators-SID predicate uses modeled token contents. The comparisons and flag stores are original execution; a different faithful token could give a different result.

The certificate issuer, subject and SHA-1 fingerprint are extracted from a declared file fixture under a declared loader entry. A changed-subject control produces a changed fingerprint on the same 71,746-instruction path, so this is extraction rather than a validated trust verdict.

The ETW network accounting is populated by declared traffic records placed in a retained buffer. The table observed in a completed run is empty, because that run received only metadata.

The classic timestamp offset finding explains the selected descriptors. It doesn't show a later consumer acting on a wrong time or extend to every ETW header format.

The alternate page-table-root probe exists in original EOS code, but its central CPUID/SIDT/SGDT body is not observed in the completed C317 CPU-event selection.

The APIC mask/restore fragments are original code under sixteen bounded controls. NMI delivery mode, counter overflow programming and any repeated generation loop remain unobserved.

20. Acquisition-site reference with original instructions

Moved to a follow-up post in this thread so the main post fits the forum's length limit: [Appendix: acquisition sites with original instructions](https://www.unknowncheats.me/forum/4806985-post64.html).

It collects the original bytes for the registry, policy, firmware, storage, TPM, network, `MmCopyMemory`, record-encryption and list-append, CPUID, PCI, HPET/APIC, `ExUuidCreate`, ETW callback, persistent-state, IPI, PiDDB, loader, CI DebugFlags and inspection-string sites in one place.

21. Status

The primary C317 execution reaches successful DriverEntry, all three workload rounds, 1,800.0000337 seconds** of steady observation, all **17 observed EOS worker completions and the actual DriverUnload return.

~~~
Validated events:

85,388,481

Paired call scopes:

2,122,595

Operation groups:

667

Catalog categories:

52

Kernel-call groups:

218

Lifecycle checks passed:

19 / 20
~~~

Measured coverage, which needs its own caveats because these numbers answer different questions and must not be added together:

~~~
Selected runtime/fragment union sites:        231,540

Known direct conditional outcomes witnessed:  937 / 1,456   (64.35%)

Alternatives absent from both datasets:       519

Research families closed:                     1 / 17

Whole-driver instruction or branch coverage:  unavailable
~~~

That percentage moves in an unintuitive direction, and it's worth saying why: reaching new code exposes new branch sites, so the denominator grows along with the numerator. One recent pass added 1,226 sites and 22 witnessed outcomes while exposing 38 further possible outcomes, which lowered the percentage even though observed coverage grew. No previously recorded site or outcome was lost. There is no validated complete CFG for the protected code, so a whole-driver denominator doesn't exist.

The one closed research family is initialization timing, closed for the identified mechanism and its known protected contexts.

The changelog at the top lists what this revision added.

The main open areas are still the final HWID reduction path, the consumer of the processor measurements, the reader and transport of the shared record list, kernel-image notification coverage, certificate/trust decision logic, the normal user-mode IOCTL protocol and the post-unload ownership residue.

Downloads

[eos dump](https://www.unknowncheats.me/forum/downloads.php?do=file&id=57683)

Credits

     @[lolz5465az](https://www.unknowncheats.me/forum/members/2687046.html) (for KEVLAR emulator)

Note: btw, this took days of continuous KEVLAR refinement and iterative OS behavior mirroring and emulation and over 1 TB of logs which I have NTFS-compressed. If you have any kind of suggestions or tips either regarding the writeup (AI-written) and/or AC reversing workflow, it'd be super-cool.

---

## Post #44 — Changelog: 17 September update（2026-09-17）

**Changelog - 17 September update**

This update keeps the previous writeup intact and adds the findings recovered in the newer investigations.

Initialization timing

Followed the initialization timing value further through the original protected code.

Confirmed that EOS reads SystemTime and the saved initialization timestamp, computes the elapsed interval and converts it from 100 ns units to nanoseconds.

Recovered the actual signed comparison implemented by the protected arithmetic:

~~~
signed_nanoseconds < 61,000,000,000
~~~

The previous version only had the experimentally observed boundary:

~~~
60.9999999 seconds -> success path

61.0000000 seconds -> rollback path
~~~

The new analysis derives the same 61-second threshold directly from the original instructions, including the split-limb constant used by the protected code.

Generated UUID / MAC-related identity

The sequential UUID investigation now separates two independent pieces of its seed:

~~~
Node:

2C-F0-5D-D7-3E-34

C317 clock sequence:

0x0A1F

C386 / retained C388 clock sequence:

0x0A23
~~~

The six-byte node remains identical while the clock sequence changes.

This is useful because a changed UUID seed or UUID output does not necessarily mean the underlying MAC-related node changed.

PCI configuration consumer recovered

The earlier version showed that EOS retrieves PCI configuration data. The update now contains a concrete consumer of those returned bytes.

In C388, EOS reads eight bytes from PCI configuration offset 0x04:

~~~
00 00 00 00 05 00 00 06
~~~

and later executes:

~~~
021E4450  mov r13, qword ptr [rbx+48h]

; ...

021E4496  cmp r13, -1
~~~

The entire qword is compared against:

~~~
FFFFFFFFFFFFFFFF
~~~

The actual captured value selects continuation:

~~~
0x3E65AF
~~~

while an exact all-ones result selects:

~~~
0x39EE09
~~~

Controlled tests covered the captured value, zero, individual bit changes and the all-ones sentinel.

This establishes an exact all-ones PCI-response predicate. The later PCI/DMA policy decision is still unresolved.

Native kernel-driver inputs

A later read-only native kernel capture adds real populated examples for structures that were empty or incomplete in C317.

~~~
Loaded modules:

204

PiDDB entries:

168

Readable PiDDB names:

167

PiDDB AVL height:

9

MmUnloadedDrivers records:

18

Loader entries with non-null SectionPointer:

140

Loader entries with null SectionPointer:

64
~~~

A sample of 16 non-null loader entries was followed through:

~~~
KLDR_DATA_TABLE_ENTRY

|

v

SECTION

|

v

CONTROL_AREA

|

v

FILE_OBJECT

|

v

FileName
~~~

All 16 sampled chains reached readable backing filenames.

These are later native inputs and are kept separate from the completed C317 lifecycle.

Backing-file inspection expanded

The previously unexercised non-null backing-file branch now has controlled execution coverage.

The recovered path:

reads the loader entry's SectionPointer;

compares DllBase with the requested image;

follows the section/control-area chain;

removes the low fast-reference tag bits from the file pointer;

checks FILE_OBJECT.FileName;

reaches a protected call strongly attributed to IoQueryFileDosDeviceName.

The returned NTSTATUS is treated as signed:

~~~
0006FF40  cmp eax, ecx

0006FF42  jle 703F6h
~~~

Controlled status tests confirm that zero and positive values use the success continuation, while negative NTSTATUS values use the error path.

Loader diagnostics: codes 3, 4 and 5

The loader walk now has three recovered diagnostic conditions:

~~~
Code 3:

Null SectionPointer after EOS has already encountered a non-null loader entry.

Code 4:

Matching image with a valid SectionPointer but missing control-area state.

Code 5:

Matching image with unavailable FILE_OBJECT or filename state.
~~~

The original null-section branch includes:

~~~
0006FE1A  test dil, dil

0006FE1D  je 6FDCBh

0006FE1F  lea r8, [r14+58h]

0006FE23  mov rcx, [rsp+50h]

0006FE28  mov edx, r12d

0006FE2B  call rbx
~~~

The helper also handles malformed counted strings. Invalid descriptors are replaced with:

~~~
 <INVALID STRING>
~~~

The final consumer after this diagnostic preparation remains protected and unresolved.

Backing-image path normalization

A filename-normalization helper at 0x12F5E9 was reconstructed.

Examples:

~~~
C:\Windows\driver.sys

-> ??\C:\Windows\driver.sys

C:/Windows/driver.sys

-> ??\C:\Windows\driver.sys

$$?\C:\Windows\driver.sys

    -> \??\C:\Windows\driver.sys

\\.\C:\Windows\driver.sys

    -> \??\C:\Windows\driver.sys

\\server\share\driver.sys

    -> \??\UNC\server\share\driver.sys
~~~

The helper also converts forward slashes to backslashes.

Unsupported spellings do not imply a rejected driver. The caller retains the original name when this optional conversion fails.

The temporary counted-string copy helper and its allocation/failure cleanup were also reconstructed.

Targeted driver-name searches

This is one of the larger additions.

C399 records EOS explicitly searching the loaded-module catalog for 13 driver basenames:

~~~
VBoxGuest.sys

VBoxVideo.sys

vm3dmp.sys

prl_kmdd.sys

HyperVideo.sys

vrd.sys

viostor.sys

vioscsi.sys

xen.sys

xenfilt.sys

Dbgv.sys

PROCMON23.sys

dbk64.sys
~~~

Every target is compared against the same 206 module names.

~~~
10-name pass:

2,060 comparisons

3-name pass:

618 comparisons

Total:

2,678 comparisons
~~~

All 2,678 observed comparisons are nonmatches.

Both passes use `RtlCompareString` with case-insensitive comparison enabled.

Original comparison wrapper:

~~~
000D14F5  imul r8d, ebx, 45h

000D14F9  xor  r8b, 0F8h

000D14FD  mov  rcx, rsi

000D1500  mov  rdx, rdi

000D1503  call r9

000D1506  nop
~~~

The names strongly suggest searches for virtualization software and debugging/inspection tools.

The current evidence establishes targeted presence searches. It does not yet establish what EOS does after a real positive match, so I am not treating these names as a proven ban list.

Positive driver-name comparison branches

The three-driver routine also has recovered equal-result predicates for:

~~~
Dbgv.sys

PROCMON23.sys

dbk64.sys
~~~

Original predicates:

~~~
0013078F  call qword ptr [rsp+128h]

00130796  test eax, eax

00130798  je   130B5Bh

001308DA  call qword ptr [rsp+100h]

001308E1  test eax, eax

001308FF  je   130B3Fh

001309F8  call qword ptr [rsp+1C8h]

001309FF  mov  r13d, eax

; temporary-buffer clearing occurs here

00130A37  test r13d, r13d

00130A42  je   130B6Ah
~~~

Controlled zero/nonzero comparison results confirm the branch destinations.

Under the reconstructed candidate key, the matched-path arithmetic prepares:

~~~
EAX = 0xF01

AL  = 1
~~~

The tests stop before the surrounding cleanup and caller policy logic.

There is still no observed allow, deny, report or enforcement action attached to this return value.

Process-name prefix predicates

The same inspection routine contains encrypted process-name prefixes:

~~~
dbgview

devenv.

tv_
~~~

Comparison widths:

~~~
dbgview    7 bytes

devenv.    7 bytes

tv_        3 bytes
~~~

The NUL terminator is outside the comparison width, so longer process names beginning with those prefixes can match.

The byte predicate is:

~~~
(actual XOR expected) AND 0xDF
~~~

This folds ASCII case, but also produces some punctuation aliases because bit `0x20` is ignored.

The first loop is visible directly:

~~~
0012FFD0  mov  dl, [rsp+rax+1A0h]

0012FFD7  mov  r8b, [rsp+rax+50h]

0012FFDC  mov  r9d, r8d

0012FFDF  xor  r9b, dl

0012FFE2  test r9b, sil

0012FFE5  jne  130001h

0012FFE7  or   r8b, dl

0012FFEA  je   130A96h

0012FFF0  inc  rax

0012FFF3  cmp  rcx, r11

0012FFF6  lea  rcx, [rcx+r15]

0012FFFA  jb   12FFD0h

0012FFFC  jmp  130A96h
~~~

Forty-nine controlled cases cover exact, uppercase, longer, shorter and mismatching inputs.

No live matching process followed by an enforcement action is currently captured.

DbgUiRemoteBreakin: exact E9 predicate

The old writeup established that EOS reads the first byte of:

~~~
ntdll!DbgUiRemoteBreakin
~~~

The new analysis recovers what happens to that byte.

EOS explicitly compares it with:

~~~
0xE9
~~~

which is the x86 near-relative-jump opcode.

Original code:

~~~
00146352  movzx edx, byte ptr [r12+190h]

; ...

0014636E  cmp   qword ptr [r12+199h], 1

00146387  mov   r8d, 440C2Fh

0014638D  mov   r9d, 43DA82h

00146393  cmove r9, r8

00146397  cmp   rdx, 0E9h

; ...

001463B3  cmovne r9, r8

001463B7  add   r9, rcx

001463BA  jmp   r9
~~~

A complete 256-byte input sweep gives:

~~~
E9:

0x436472

Every other byte:

0x43961F
~~~

for the successful-load state.

The clean retained NTDLL begins with `0x48` and takes the common path.

The E9 route then reads a 32-bit frame field, multiplies it by eight and uses it to select an eight-byte entry from a table.

This makes the runtime-integrity check considerably more specific than the previous "reads DbgUiRemoteBreakin" description.

The later policy result still hasn't been recovered.

Unknown-image address fallback

The `RtlPcToFileHeader` path now has a recovered fallback for addresses that don't belong to a known loaded image.

When image attribution returns zero, EOS:

aligns the inspected address down to a 4 KiB page;

calls helper `0x1B1B92` with selector `4`;

checks the returned record pointer;

increments the first DWORD when a record exists.

Relevant original code:

~~~
0010D081  and rdi, -1000h

; ...

0035B75D  mov rcx, rdi

0035B760  mov r8d, 4

; ...

0035B77A  call qword ptr [rsp+18h]

; returned record path

0035A541  pop rax

0035A542  inc dword ptr [rax]
~~~

The helper itself was narrowed further to a resolve / prepare / retry wrapper:

~~~
001B1C1E  call rax

001B1C20  test rax, rax

001B1C23  je   1B1C36h

; ...

001B1C7C  call r10

001B1C7F  test al, al

001B1C81  je   1B1CA9h

; ...

001B1CA6  jmp  rax

001B1CA9  xor eax, eax

001B1CAB  jmp 1B1C25h
~~~

The incremented record has not been identified as a violation counter.

The candidate addresses also haven't been proven to be stack return addresses.

Alternate page-table-root experiment

The hypervisor section now contains a more substantial paging experiment than the previously known same-value CR3 reloads.

Original EOS code:

saves the current CR3;

copies and modifies paging entries;

redirects selected page-table entries;

executes `INVLPG`;

constructs and loads an alternate CR3;

executes `RDTSC`, `CPUID`, `SIDT` and `SGDT` while the altered mappings are active;

contains code to restore the modified table state and original CR3.

Selected entry substitution:

~~~
0035D144  mov rcx, [rsi+20h]

0035D148  mov rdx, [rsi+48h]

0035D14C  shl rdx, 0Ch

0035D150  and rdx, r14

0035D153  mov r8, [rcx+rax*8]

0035D157  and r8, rbx

0035D15A  or r8, rdx

0035D15D  mov [rcx+rax*8], r8

; ...

0035D17F  invlpg [rax]
~~~

Probe sequence:

~~~
0035FB5F  rdtsc

0035FB61  xchg rbx, r8

0035FB64  xor eax, eax

0035FB66  mov r9, [rsi+10h]

0035FB6A  xor ecx, ecx

0035FB6C  cpuid

0035FB6E  xchg rbx, r8

0035FB71  sidt [r9]

0035FB75  mov r9, [rsi+30h]

0035FB79  mov [r9], eax

0035FB7C  mov [r9+4], r8d

0035FB80  mov [r9+8], ecx

0035FB84  mov [r9+0Ch], edx

0035FB88  mov rax, [rsi+10h]

0035FB8C  sgdt [rax]

0035FB8F  rdtsc
~~~

This supports a translation/execution-consistency interpretation.

C317 does not contain execution of the central probe body at `0x35FB6C`, so this stays separate from the completed lifecycle evidence.

---

## Post #61 — Platform and processor probes（2026-09-22）

**Platform and processor probes (follow-up to the main post)**

Continuation of [the main post](https://www.unknowncheats.me/forum/4800149-post1.html), which ran into the forum's length limit. Section numbers match that post.

Same subject throughout: root `eos.sys`, SHA-256 `020d5da6b881408ced33be09b92dc45e12e641b8b3c91f3a327429e5027fef74`, with C317 supplying the aggregate counts unless another run is named.

5. PCI, ACPI and physical access

PCI enumeration

C317 contains 512 HalGetBusDataByOffset calls:

~~~
256 from TID 328

256 from TID 404

32 return 4 bytes

480 return no match
~~~

First successful response:

~~~
86 80 53 9B
~~~

which decodes to:

~~~
Vendor: 8086

Device: 9B53
~~~

Call bridge:

~~~
0038F630  mov rsp, r12

0038F633  call 0x36217F

0038F638  lea rsp, [rsp+1C0h]

0038F640  call qword ptr [rsp+8]

0038F644  lea rsp, [rsp-1C0h]
~~~

PCI configuration space

Worker 404 makes another 272 HalpPCIConfig calls.

Requests include:

~~~
2 full 256-byte headers

header type at 0x0E

capability-list pointer at 0x34

reads around 0x04

extended configuration attempts at 0x100+
~~~

Modeled identities:

~~~
8086:9B53

8086:1901
~~~

Outcomes:

~~~
260 absent virtual functions

8 reads from configured headers

4 unmodeled extended-tail accesses
~~~

All selected operations are reads.

What EOS does with one returned PCI field

A later one-second diagnostic, C388**, captures a concrete consumer of an eight-byte PCI configuration read. Events 19735199-19735202 read configuration offset **0x04** for segment 0, bus 0, slot 0. The modeled header returns:**

~~~
00 00 00 00 05 00 00 06
~~~

EOS loads the entire qword at RVA 0x21E4450** and compares it with `FFFFFFFFFFFFFFFF`.**

~~~
021E4450  mov r13, qword ptr [rbx+48h]

; continuation / VM-frame preparation omitted

021E4496  cmp r13, -1

021E449A  lea r13, [rsp+28h]

021E449F  cmove rbp, r13

; the same flags select later field accesses

021E44CB  cmovne r11, qword ptr [r15]

021E4505  cmovne rax, qword ptr [rsp+8]

021E450B  add rsp, 30h

021E450F  pop rbp

021E4510  jmp rax
~~~

The actual captured bytes select continuation 0x3E65AF**. Supplying eight FF bytes selects **0x39EE09**. Controlled tests cover the captured qword, zero, every single-bit difference from all-ones, and every single-bit flip in the captured value. Only the exact all-ones qword selects the alternate continuation in that tested frame.**
This is an all-ones validity/sentinel predicate over the bytes returned from PCI offset 0x04. It is not a vendor/device comparison and it does not yet establish a DMA or IOMMU detection result. The C388 source run completed its one-second diagnostic lifecycle, but it does not replace C317's 30-minute reference.

ACPI selection

EOS requests 12 ACPI tables:

~~~
DMAR  x3

IVRS  x2

APIC  x3

WAET  x2

HPET  x1

DSDT  x1
~~~

The captured snapshot supplies APIC and HPET. The rest are absent from that selected firmware snapshot.

DMAR and IVRS give EOS a path to inspect DMA-remapping/IOMMU configuration, although no final IOMMU or DMA-device verdict has been recovered.

HPET and local APIC

HPET:

~~~
Physical:

0xFED00000

Event:

890738

EOS RVA:

0x26F1926

Value:

0x0429B17F8086A201
~~~

~~~
026F1926  48 8B 00    mov rax, qword ptr [rax]
~~~

Local APIC:

~~~
Physical:

0xFEE000F0

Event:

8570269

EOS RVA:

0x730208

Value:

0x1FF
~~~

~~~
00730208  41 8B 0C 24    mov ecx, dword ptr [r12]
~~~

Physical aliases

C317 contains:

~~~
MMIO observations:       6,118

fixture=none:            6,116

I/O-space mappings:      2,298

I/O-space unmaps:        2,298

Physical-copy ops:       9,056
~~~

Most MMIO-classified records are ordinary bytes reached through coherent physical aliases, not hardware registers.

12. Anti-virtualization and hypervisor checks

A dedicated pass reselected 22,527 CPU and exception records from C317 and checked the selected records against the source stream and original image bytes.

The main mechanisms are:

~~~
Hypervisor CPUID leaves

Windows hypervisor-information query

100x timed CPUID loop

100x timestamp-only baseline loop

TF + CPUID probe

TF + MOV SS + CPUID probe

BTF + CPUID probe

BTF + MOV SS + CPUID probe

256 synthetic MSR reads

VMREAD status/fault probe

Debug-register reads and writes

RTM read/execute tests

Physical-alias return tests

PMU minimum-sample logic

XGETBV / XSETBV

RDTSC sampling

Intel Processor Trace

CR3 read/reload blocks

Alternate page-table-root experiment

APIC performance-interrupt masking
~~~

Hypervisor CPUID leaves

C317:

~~~
Event 892191

EOS RVA 0x3D590A

EAX input = 0x40000000

Event 19699243

EOS RVA 0x3E0190

EAX input = 0x40000000

Event 19699248

EOS RVA 0x3FD702

EAX input = 0x40000100
~~~

Original sites:

~~~
003D590A  cpuid

003E0190  cpuid

003FD702  cpuid
~~~

The profile returns:

~~~
EAX = 0x1004

EBX = 0x1324

ECX = 0x64

EDX = 0
~~~

Leaf 1 in the timing loop returns ECX `0x7FFAFBFF`, with hypervisor-present bit 31 clear.

EOS continues probing anyway.

Windows hypervisor query

C317 event:

~~~
42622
~~~

~~~
SystemHypervisorSharedPageInformation

class 197
~~~

Returned model state:

~~~
user_va = 0

virtual_hypervisor_present = 0
~~~

CPUID timing against a baseline

Timing function:

RVA 0x179CDC

~~~
00179D8E  rdtsc

00179D90  mov r10, rdx

00179D93  mov r11, rax

00179D9E  cpuid

00179DBA  rdtsc

00179DBC  shl rdx, 20h

00179DC0  or rdx, rax

00179DC3  sub rdx, r10

00179DC6  add r12, rdx

00179DD5  jne 0x179D8E

00179DD7  mov [rsp+38h], r12
~~~

Baseline:

~~~
00179DE2  rdtsc

00179DE4  mov rcx, rdx

00179DE7  shl rcx, 20h

00179DEB  or rcx, rax

00179DEE  rdtsc

00179DF0  shl rdx, 20h

00179DF4  or rdx, rax

00179DF7  sub rdx, rcx

00179DFA  add r9, rdx

00179E09  jne 0x179DE2

00179E0B  lea rcx, [rsp+20h]

00179E10  mov [rcx+20h], r9
~~~

Observed C317:

~~~
CPUID samples:

100

Virtual delta / sample:

150

Accumulated:

15,000

Baseline samples:

100

Virtual delta / sample:

1

Accumulated:

100
~~~

The code really performs the comparison experiment. The numerical deltas come from KEVLAR's virtual clock: `SampleVirtualTsc` enforces a 150-tick minimum after CPUID and a one-tick minimum advance between reads, so those are clock-model policy rather than a measured 150x slowdown.

TF, BTF and MOV SS probes

Ordinary variant:

~~~
00237BF7  mov r8, rdx

00237C00  pushfq

00237C01  or qword ptr [rsp], rcx

00237C05  popfq

00237C06  cpuid

00237C08  inc qword ptr [r8]

00237C10  int3
~~~

SS-reload variant:

~~~
00237BCA  mov ax, ss

00237BCD  pushfq

00237BCE  or qword ptr [rsp], rcx

00237BD2  popfq

00237BD3  mov ss, ax

00237BD6  cpuid

00237BD8  inc qword ptr [r8]

00237BE1  int3
~~~

C317 supplies TF mask `0x100` and tests each path with IA32_DEBUGCTL values 0 and 2.

~~~
TF + CPUID:

STATUS_SINGLE_STEP at 0x237C08

TF + MOV SS + CPUID:

STATUS_SINGLE_STEP at 0x237BD8

BTF + CPUID:

STATUS_SINGLE_STEP at 0x237C10

BTF + MOV SS + CPUID:

STATUS_SINGLE_STEP at 0x237BE1
~~~

All four find EOS handler:

~~~
0x439280
~~~

The last two are single-step exceptions at an `INT3` address, not evidence that `INT3` executed and produced a breakpoint exception.

Synthetic MSR sweep

EOS probes:

~~~
0x40000000

through

0x400000FF
~~~

All 256 indices reach:

~~~
0038BEF9  mov rbp, [r12+194h]

0038BF01  mov ecx, [r12+190h]

0038BF09  rdmsr

0038BF0B  mov [r12+190h], eax

0038BF13  mov [r12+194h], edx

0038BF1B  xor rbx, rbx

0038BF1E  mov [r12+1A0h], rbx

0038BF26  mov [r12+198h], rax

0038BF2E  jmp rbp

0038BF30  mov rbx, 1

0038BF37  jmp 0x38BF1E
~~~

Fault and success converge on the same result path, so RAX after a fault must not be read as valid MSR data.

VMREAD probe

~~~
00237C26  vmread qword ptr [rdx], rcx

00237C29  sete al

00237C2C  setb cl

00237C2F  adc al, cl

00237C31  ret
~~~

Normal completion would encode:

~~~
0 = success

1 = VMfailValid

2 = VMfailInvalid
~~~

C317 instead records VMX inactive, no current VMCS and architectural #UD before reaching the EOS handler.

CR3 access

~~~
0035CFF3  mov rax, cr3

0035CFF6  mov cr3, rax
~~~

and:

~~~
0035D1EE  mov rax, cr3

0035D1F1  mov cr3, rax

0035D1F4  mov rax, [rsi+0F8h]

0035D1FB  cmp rax, [rip-5D85Ah]
~~~

These same-value reloads are present in the image. The recovered local flow doesn't show a repeated timed CR3 loop.

Alternate page-table-root experiment

Separate original code implements a much more active translation experiment than the same-value CR3 reloads above. EOS saves the current CR3, copies and modifies paging entries, switches to a constructed page-table root, executes processor and descriptor-table instructions around deliberately changed mappings, then reaches restoration code.

The recovered path begins at trampoline 0x1B8EE1 and reaches 0x35AA30. The first participant saves CR3 in RDI. EOS uses these masks:

~~~
Address bits 12-47:      0x0000FFFFFFFFF000

Complement / other bits: 0xFFFF000000000FFF
~~~

Those are implementation constants in this EOS build, not a general physical-address-width rule.

The selected entry substitution is visible in the original instructions:

~~~
0035D144  mov rcx, [rsi+20h]          ; copied table

0035D148  mov rdx, [rsi+48h]          ; replacement PFN value

0035D14C  shl rdx, 0Ch

0035D150  and rdx, r14                 ; retain address bits 12-47

0035D153  mov r8, [rcx+rax*8]

0035D157  and r8, rbx                  ; retain other entry bits

0035D15A  or r8, rdx

0035D15D  mov [rcx+rax*8], r8

; second entry receives saved original address bits

0035D175  or r8, rdx

0035D178  mov [rax], r8

0035D17B  mov rax, [rsi+30h]

0035D17F  invlpg [rax]
~~~

At 0x14CBAD, EOS constructs and writes an alternate CR3 from the PFN in `context+0x28`, combined with the preserved bits from the original root.

The central probe body fills two 4 KiB buffers with FF bytes and executes:

~~~
0035FB5F  rdtsc

0035FB61  xchg rbx, r8

0035FB64  xor eax, eax

0035FB66  mov r9, [rsi+10h]

0035FB6A  xor ecx, ecx

0035FB6C  cpuid

0035FB6E  xchg rbx, r8

0035FB71  sidt [r9]

0035FB75  mov r9, [rsi+30h]

0035FB79  mov [r9], eax

0035FB7C  mov [r9+4], r8d

0035FB80  mov [r9+8], ecx

0035FB84  mov [r9+0Ch], edx

0035FB88  mov rax, [rsi+10h]

0035FB8C  sgdt [rax]

0035FB8F  rdtsc
~~~

Restoration copies the backup page back, restores the selected entry's original address bits, synchronizes the participants and eventually writes the saved RDI value back to CR3 at 0x58FCA.

The recovered local flow therefore demonstrates that EOS can construct a controlled translation inconsistency and execute `CPUID`, `SIDT` and `SGDT` under that alternate root. This is compatible with testing whether the execution environment handles translation-sensitive state consistently.

C317 does not contain the central probe body's CPUID at 0x35FB6C or its two RDTSC sites. Its complete CPU-event selection has 666 CPUID events and none at that address. The completed lifecycle therefore doesn't establish execution of this body. The current evidence comes from original-code reconstruction and bounded synthetic fragment tests, not a live page-table modification on the host. No final hypervisor verdict or timing comparison has been recovered from this path.

It masks the performance-monitor interrupt around that experiment

The APIC-dependent edge in that control flow is now filled in, and it does something specific: it masks the local APIC performance-monitor interrupt before the probe and restores the mask state afterwards.

Both access forms are supported. In xAPIC mode the entry is at offset `0x340`; in x2APIC mode it's MSR `0x834`, which the architecture assigns to `IA32_X2APIC_LVT_PMI`. Bit 16 is the LVT mask and bits 10-8 select delivery mode.

~~~
Phase              xAPIC                      x2APIC

-----------------  -------------------------  --------------------------

Select access      descriptor byte +1 != 1    == 1, compare at 1B8E10

Inspect mask       load [base+340h], 14D242   RDMSR ECX=834h, 35D2CB

Mask if clear      OR with 10000h, 35B587     OR EAX, then WRMSR, 3612AF

Run probe          continue to 14CB97 (alternate CR3 construction)

Restore CR3        MOV CR3,RDI at 58FCA

Restore mask       clear bit 16, 8BF73        clear bit 16, WRMSR 35F935
~~~

~~~
; x2APIC preparation: inspect the performance-counter LVT mask.

0035D2C6  B9 34 08 00 00        mov ecx, 834h

0035D2CB  0F 32                 rdmsr

0035D2CD  41 B5 01              mov r13b, 1

0035D2E8  0F BA E0 10           bt eax, 10h

0035D2EC  4D 0F 43 C4           cmovae r8, r12

003612AA  0D 00 00 01 00        or eax, 10000h

003612AF  0F 30                 wrmsr

0035F930  25 FF FF FE FF        and eax, 0FFFEFFFFh

0035F935  0F 30                 wrmsr
~~~

~~~
; xAPIC form and the restore decision after the experiment.

0014D242  8B 88 40 03 00 00              mov ecx, dword ptr [rax+340h]

0014D254  0F BA E1 10                    bt ecx, 10h

0035B587  81 88 40 03 00 00 00 00 01 00  or dword ptr [rax+340h], 10000h

00058FCA  0F 22 DF                       mov cr3, rdi

00058FE3  45 84 ED                       test r13b, r13b

00058FE6  4C 0F 45 C3                    cmovne r8, rbx

0008BF73  81 A0 40 03 00 00 FF FF FE FF  and dword ptr [rax+340h], 0FFFEFFFFh
~~~

An entry that was already masked is left masked; only a path that masked an initially unmasked entry clears the bit afterwards. Sixteen bounded controls cover both initial mask states and two supplied delivery modes, fixed and NMI, across four mask/restore fragments, executing 58 distinct original instruction sites. The delivery mode is unchanged in every case.

The NMI-storm idea stays a hypothesis. This path does not set NMI delivery mode, program a counter overflow, write an interrupt-command register or contain a repeated generation loop. The retained C317 CPU selection has 574 MSR events with no access to MSR `0x830` or `0x834`, and neither its operation catalog nor the C388/C399 catalogs contain an NMI-named operation group. Those are bounded observations and can't exclude a generator elsewhere in the protected code.

Debug registers

C317:

~~~
Debug-register reads:

2,252

Debug-register writes:

243

Steady-state reads:

2,181

Steady-state writes:

228
~~~

Representative instructions:

~~~
00404652  mov rax, dr7

00366D09  mov dr0, rax
~~~

C317 also contains 310 exception raises and 310 handler observations across initialization, initial work and steady state.

RTM probes

~~~
00237B90  xbegin 0x237B99

00237B96  xend

00237B99  ret
~~~

Read/execute path:

~~~
00237B9A  xbegin 0x237BAA

00237BA0  mov al, [rcx]

00237BA2  call rcx

00237BA4  xend

00237BA7  mov al, 1

00237BA9  ret

00237BAA  xor al, al

00237BAC  ret
~~~

C317:

~~~
XBEGIN:

4,520

XEND:

4,520

Single-return target probes:

4,516

Mapped-return observations:

2,258
~~~

PMU minimum sampling

EOS programs:

~~~
IA32_PERFEVTSEL0 = 0x4200C0
~~~

and retains a smaller sample:

~~~
00224757  xor ecx, ecx

00224759  rdpmc

0022476C  cmp qword ptr [r8+10h], rdx

00224770  jbe 0x224776

00224772  mov qword ptr [r8+10h], rdx

00224776  ret
~~~

A related block places an `IA32_FEATURE_CONTROL` read between the reset and the `RDPMC`, but the MSR result is overwritten by the counter read before the store, so the retained value is the counter sample. The same applies to an FS-base read inside another sampling block: the value stored is the counter, not the segment base.

XCR and RDTSC

C317:

~~~
XGETBV:

5

XSETBV:

4

XCR0:

0x7

RDTSC:

4,545
~~~

~~~
00224645  xor ecx, ecx

00224647  xgetbv

0022464A  shl rdx, 20h

0022464E  or rdx, rax

00224661  xsetbv
~~~

Intel Processor Trace

EOS requests:

~~~
IA32_RTIT_CTL = 0x2105
~~~

Decoded, that requests tracing with OS, ToPA and BranchEn enabled; user-mode tracing is not selected by that value.

Original bridge:

~~~
004110C8  mov rbp, [r12+19Ch]

004110D0  mov eax, [r12+190h]

004110D8  mov ecx, [r12+194h]

004110E0  mov edx, [r12+198h]

004110E8  wrmsr

004110EA  xor rbx, rbx

004110ED  mov [r12+198h], rbx

004110F5  mov [r12+190h], rax

004110FD  jmp rbp
~~~

13. Stack-walking claim: current evidence

C317 has:

~~~
unwind_step:

5

cross_frame_unwind:

5
~~~

Those records come from KEVLAR's exception dispatcher.

The EOS kernel-call catalog has zero recorded calls named:

~~~
RtlVirtualUnwind

RtlWalkFrameChain

RtlCaptureStackBackTrace

RtlLookupFunctionEntry

RtlCaptureContext
~~~

A custom inline walker remains possible, but the retained evidence doesn't establish one. The `RtlVirtualUnwind` name appears in the `um.exe`/`conhost.exe` import inventories EOS parses, which is EOS reading another image's import table rather than calling the function.

14. Temporary win32k callback slot

EOS temporarily writes:

~~~
eos.sys + 0x237A00
~~~

into:

~~~
win32kbase.sys + 0x28E058
~~~

Original store:

~~~
0294984A  mov qword ptr [r10], r11
~~~

with:

~~~
r10 = win32kbase.sys + 0x28E058

r11 = eos.sys + 0x237A00
~~~

The previous zero value returns roughly 0.5000021 virtual seconds later.

The matching Windows image's `LeaveCrit` routine loads that slot, checks for null and dispatches through it using the Control Flow Guard helper when populated, which explains how a data pointer there becomes an execution hook. The recorded workload has not been shown invoking `LeaveCrit` through the installed pointer, and the half-second lifetime argues against calling it a permanently installed hook.

---

## Post #64 — Appendix: acquisition sites and the current picture（2026-09-22）

**Appendix: acquisition sites and the current picture (follow-up to the main post)**

Continuation of [the main post](https://www.unknowncheats.me/forum/4800149-post1.html), which ran into the forum's length limit. These are sections 20 and 18 of that post, in that order.

All addresses are RVAs in root `eos.sys`, SHA-256 `020d5da6b881408ced33be09b92dc45e12e641b8b3c91f3a327429e5027fef74`. Resolved API identities come from the runtime records, not from the indirect instructions themselves.

R1: NtQueryValueKey delivery

~~~
003D16D6  4C 89 E4                mov rsp, r12

003D16D9  E8 A1 0A F9 FF          call 0x36217f

003D16DE  48 8D A4 24 C0 01 00 00 lea rsp, [rsp + 0x1c0]

003D16E6  FF 54 24 08             call qword ptr [rsp + 8]

003D16EA  48 8D A4 24 40 FE FF FF lea rsp, [rsp - 0x1c0]

003D16F2  E8 69 09 F9 FF          call 0x362060
~~~

R2: NtQueryValueKey sizing

~~~
003E0B16  48 8D A4 24 C0 01 00 00 lea rsp, [rsp + 0x1c0]

003E0B1E  FF 54 24 08             call qword ptr [rsp + 8]

003E0B22  48 8D A4 24 40 FE FF FF lea rsp, [rsp - 0x1c0]
~~~

R3: partial registry path

~~~
0019BB64  mov qword ptr [rsp+28h], rbp

0019BB69  mov dword ptr [rsp+20h], eax

0019BB6D  lea rdx, [rsp+48h]

0019BB72  lea r9, [rsp+88h]

0019BB7A  mov rcx, r15

0019BB7D  call qword ptr [r12]

0019BB81  mov ebp, eax
~~~

POL1-POL6: boot, licensing and policy queries

~~~
00099230  call qword ptr [r14]     ; boot environment

0042928C  call qword ptr [rsp+8]   ; NtQueryLicenseValue

003FEB24  call qword ptr [rsp+8]   ; Secure Boot

003C68AB  call qword ptr [rsp+8]   ; DMA guard

00432EE8  call qword ptr [rsp+8]   ; isolated user mode

003776CE  call qword ptr [rsp+8]   ; enlightenment information
~~~

F1-F4: firmware tables and variables

~~~
; F1 SMBIOS firmware table

003B3462  lea rsp, [rsp+1C0h]

003B346A  call qword ptr [rsp+8]

003B346E  lea rsp, [rsp-1C0h]

003B3476  call 0x362060

; F2 BootCurrent

003849EA  lea rsp, [rsp+1C0h]

003849F2  call qword ptr [rsp+8]

003849F6  lea rsp, [rsp-1C0h]

003849FE  call 0x362060

; F3 Boot0000

00406428  lea rsp, [rsp+1C0h]

00406430  call qword ptr [rsp+8]

00406434  lea rsp, [rsp-1C0h]

0040643C  call 0x362060

; F4 OfflineUniqueIDRandomSeed

00380D56  lea rsp, [rsp+1C0h]

00380D5E  call qword ptr [rsp+8]

00380D62  lea rsp, [rsp-1C0h]

00380D6A  call 0x362060
~~~

D1: WmiMonitorID

~~~
003AECD7  lea rsp, [rsp+1C0h]

003AECDF  call qword ptr [rsp+8]

003AECE3  lea rsp, [rsp-1C0h]

003AECEB  call 0x362060
~~~

S1/S2: storage request construction and dispatch

~~~
0002062E  mov qword ptr [rsp+20h], r15

00020633  mov byte ptr [rsp+30h], 0

00020638  mov ecx, ebx

0002063A  mov rdx, rbp

0002063D  mov r8, rdi

00020640  mov r9d, dword ptr [rsp+0F8h]

00020648  call r10

0002064B  test rax, rax

00020733  mov r8, qword ptr [rbp+8]

00020737  movzx eax, byte ptr [rax-48h]

0002073B  mov rcx, rbp

0002073E  mov rdx, rdi

00020741  call qword ptr [r8+rax*8+70h]

00020746  mov ebp, eax
~~~

S3: cached storage-descriptor serial read

~~~
013FC197  mov   ecx, [r10]                ; descriptor Size

02A2D97F  mov   r11d, [rax]               ; SerialNumberOffset

0262957E  movzx eax, byte ptr [rax]       ; serial characters and NUL
~~~

T1/T2: TPM bridge and submission

~~~
0042B730  lea rsp, [rsp+1C0h]

0042B738  call qword ptr [rsp+8]

0042B73C  lea rsp, [rsp-1C0h]

0042B744  call 0x362060

0006E393  mov [rsp+30h], r13

0006E398  mov [rsp+28h], rbx

0006E39D  mov [rsp+20h], r14d

0006E3A2  mov rcx, r15

0006E3A5  xor edx, edx

0006E3A7  mov r9, [rsp+40h]

0006E3AC  call r10
~~~

N1: GetIfTable2

~~~
003D5B06  lea rsp, [rsp+1C0h]

003D5B0E  call qword ptr [rsp+8]

003D5B12  lea rsp, [rsp-1C0h]

003D5B1A  call 0x362060
~~~

G1: shared MmCopyMemory wrapper

Used for both the GPU object copy and the 16-byte reference acquisition.

~~~
0000DA69  mov qword ptr [rsp+20h], rbx

0000DA6E  mov rcx, r14

0000DA71  mov rdx, rdi

0000DA74  mov r8, rsi

0000DA77  mov r9d, ebp

0000DA7A  call r10
~~~

G2: record encryption and list append

The same two sites serve the NVIDIA record and the PiDDB inventory record.

~~~
0068C7FD  89 10          mov dword ptr [rax],edx  ; cipher body words

0068F45B  44 89 01       mov dword ptr [rcx],r8d  ; final word of each round

0038AF14  FF 54 24 08    call qword ptr [rsp+8]   ; ExAcquireFastMutex 30A830h

0235112B  4C 8B 18       mov r11, qword ptr [rax] ; list head image+30A900h

018166F1  48 8B 39       mov rdi, qword ptr [rcx] ; follow next pointer

0232C4F5  4C 89 11       mov qword ptr [rcx], r10 ; append the new node
~~~

C1: CPUID vendor and signature

~~~
0024F0DA  cpuid

0024F0DC  mov r9d, eax

0024F0DF  xor ecx, ecx

0024F0E1  mov eax, 1

0024F0E6  xor r8b, r8b

0024F0E9  cpuid

0024F0EB  mov [rsp], eax

0024F0EE  mov [rsp+4], ebx
~~~

P1/P2: PCI queries

~~~
0038F630  mov rsp, r12

0038F633  call 0x36217F

0038F638  lea rsp, [rsp+1C0h]

0038F640  call qword ptr [rsp+8]

0038F644  lea rsp, [rsp-1C0h]

0041DC7E  mov rsp, r12

0041DC81  call 0x36217F

0041DC86  lea rsp, [rsp+1C0h]

0041DC8E  call qword ptr [rsp+8]

0041DC92  lea rsp, [rsp-1C0h]
~~~

H1/A1: HPET and local APIC reads

~~~
026F1926  mov rax, qword ptr [rax]

00730208  mov ecx, dword ptr [r12]
~~~

U1: ExUuidCreate

~~~
003FB4D5  mov rsp, r12

003FB4D8  call 0x36217F

003FB4DD  lea rsp, [rsp+1C0h]

003FB4E5  call qword ptr [rsp+8]

003FB4E9  lea rsp, [rsp-1C0h]
~~~

ETW1: consumer callback dispatch

~~~
0021A0AB  488B4160                mov rax, [rcx+60h]       ; encoded callback

0021A0AF  4803842460010000        add rax, [rsp+160h]      ; decode target

0021A0C6  488D9424A0010000        lea rdx, [rsp+1A0h]      ; stack descriptor

0021A0CE  FFD0                    call rax                 ; EOS+8B88Ah
~~~

PST1/IPI1: persistent state and cross-processor dispatch

~~~
003F8993  call qword ptr [rsp+8]   ; KeCapturePersistentThreadState

00429527  call qword ptr [rsp+8]   ; KeIpiGenericCall
~~~

DDB1/DDB2: PiDDBLock acquisition and release

~~~
003B31DE  lea rsp, [rsp+1C0h]

003B31E6  call qword ptr [rsp+8]

003B31EA  lea rsp, [rsp-1C0h]

003A30BD  lea rsp, [rsp+1C0h]

003A30C5  call qword ptr [rsp+8]

003A30C9  lea rsp, [rsp-1C0h]
~~~

DRV1-DRV3: loader inspection and callback registration

~~~
0006FDCD  mov r14, qword ptr [r14]

0006FE11  mov rax, qword ptr [r14+70h]

0006FE15  test rax, rax

0006FE18  jne 0006FE2F

0006FE1F  lea r8, [r14+58h]

0006FE2D  jmp 0006FDCD

0006FE36  mov rcx, qword ptr [rsp+0B0h]

0006FE3E  cmp qword ptr [r14+30h], rcx

0006FE42  jne 0006FDCD

0006FE44  mov rax, qword ptr [rax+28h]

0006FE71  and rbx, qword ptr [rax+40h]

0006FE7B  cmp word ptr [rbx+58h], 0

0006FE86  cmp qword ptr [rbx+60h], 0

00403801  call qword ptr [rsp+8]   ; PsSetLoadImageNotifyRoutine

00107AD6  call r10                 ; SeRegisterImageVerificationCallback
~~~

CIW1: Code Integrity DebugFlags write

~~~
00419FD8  call qword ptr [rsp+8]
~~~

C317 binds this shared registry-write bridge to `CI\DebugFlags = 0x10` at events 40942 and 85380475.

STR1-STR4: inspection-string decoding and comparison

~~~
; STR1 candidate key reconstruction

00130350  48 B8 CF 88 35 06 97 B7 93 FE  mov rax, 0FE93B797063588CFh

0013035A  48 0F AF C3                    imul rax, rbx

0013035E  48 8B 0D FB D9 1B 00           mov rcx, [rip+1BD9FBh]

00130365  48 29 C1                       sub rcx, rax

00130368  48 89 8C 24 28 01 00 00        mov [rsp+128h], rcx

; STR2 driver-name word decoder

00130713  48 8B 4C 24 68        mov rcx, [rsp+68h]

00130718  46 8B 0C 81           mov r9d, [rcx+r8*4]

0013071C  41 31 D1              xor r9d, edx

0013071F  4C 8B 54 24 50        mov r10, [rsp+50h]

00130724  41 0F AF D7           imul edx, r15d

00130728  44 01 F2              add edx, r14d

0013072B  89 E9                 mov ecx, ebp

0013072D  D3 C2                 rol edx, cl

0013072F  47 89 0C 82           mov [r10+r8*4], r9d

00130733  49 89 F0              mov r8, rsi

00130736  A8 01                 test al, 1

00130738  B8 00 00 00 00        mov eax, 0

0013073D  75 D4                 jne 130713h

; STR3 comparison wrapper, resolved to RtlCompareString

000D14F5  44 6B C3 45        imul r8d, ebx, 45h

000D14F9  41 80 F0 F8        xor  r8b, 0F8h

000D14FD  48 89 F1           mov  rcx, rsi

000D1500  48 89 FA           mov  rdx, rdi

000D1503  41 FF D1           call r9

000D1506  90                 nop

; STR4 process-prefix byte predicate, SIL = 0xDF

0012FFD0  8A 94 04 A0 01 00 00  mov dl, [rsp+rax+1A0h]

0012FFD7  44 8A 44 04 50        mov r8b, [rsp+rax+50h]

0012FFDC  45 89 C1              mov r9d, r8d

0012FFDF  41 30 D1              xor r9b, dl

0012FFE2  41 84 F1              test r9b, sil

0012FFE5  75 1A                 jne 130001h

0012FFE7  41 08 D0              or r8b, dl

0012FFEA  0F 84 A6 0A 00 00     je 130A96h

0012FFF0  48 FF C0              inc rax

0012FFF3  4C 39 D9              cmp rcx, r11

0012FFF6  4A 8D 0C 39           lea rcx, [rcx+r15]

0012FFFA  72 D4                 jb 12FFD0h

0012FFFC  E9 95 0A 00 00        jmp 130A96h
~~~

18. Current picture

Machine and boot identity:

~~~
MachineGuid

ComputerHardwareId

SMBIOS, registry and firmware sources

Boot environment / firmware type

Secure Boot state

Code Integrity state

Windows build / QFE

Custom-kernel-signer policy

Boot variables

OfflineUniqueIDRandomSeed

ATA identity via SMART and pass-through

Cached STORAGE_DEVICE_DESCRIPTOR serial read

Monitor identity

TPM public material

MAC / interface identity

Version-1 UUID node, used as an ETW session ID

GPU-containing object and its 16-byte reference

CPU vendor / signature
~~~

Platform characterization:

~~~
PCI vendor/device enumeration

PCI configuration-space reads

PCI qword all-ones predicate

DMAR / IVRS / APIC / WAET / HPET / DSDT

HPET capability

Local APIC state

DMA-guard state

Isolated-user-mode state

Enlightenment information

Physical aliases and physical-copy paths
~~~

Kernel-driver discovery:

~~~
System-module refreshes

\Driver namespace enumeration

PsLoadedModuleResource

PiDDBLock acquisition

Populated PiDDB walk, name conversion and module comparison

Twenty-record count gate

Name-and-timestamp formatting

Loader SectionPointer inspection

Backing FILE_OBJECT path, name query and normalization

Loader diagnostic codes 3 / 4 / 5

Big-pool inventory

Pool-tag information

Code-integrity state

Hotpatch state

Image-load callbacks and their filename fallback

Creation-time-keyed process table

Image-verification callbacks and their ImageFlags consumer

RtlPcToFileHeader attribution

Targeted driver-name searches

Process-name prefix predicates

Six-string encrypted-literal decoding / candidate K reconstruction
~~~

Record construction and retention:

~~~
Byte-wise XOR encoding stage

Pool-tag rotation over a 45-entry table

XXTEA over the PiDDB inventory record, 64 words / 6 rounds

XXTEA over the NVIDIA UUID record, 16 words / 9 rounds

Per-record key words stored beside the ciphertext

Mutex-protected append to one shared record list

Plaintext erase and release

Wrapper release during DriverUnload
~~~

Process/software inspection:

~~~
Bulk process/thread snapshots

Bulk handle snapshots

PEB / process parameters

Native and WoW64 loader traversal

PE-header validation

Current module inventory

User DLL unload history

Import-name inventory

Working-set queries

Mapped-file attribution

Protected-process state

Token integrity / groups / privileges

DbgUiRemoteBreakin E9 first-byte predicate

E9 displacement compared against an LdrShutdownProcess detour

Signature bit 20h in a saved flags DWORD

Process-image record with that flags field

Administrators-SID predicate producing bit 21

Token-integrity gate at 3FFFh

NtOpenProcess transfer-byte inspection

Module lookup, file open and certificate-name / SHA-1 extraction

Mapped-image string collection

Unknown-image page fallback / record update
~~~

Telemetry and event handling:

~~~
Five trace sessions and five real-time consumers

Threat Intelligence subscription, 22 decoded keywords

Consumer worker, context template and encoded callback pointer

Classic record parser and EVENT_RECORD construction

Opcode routing split at 25

Classic timestamp read from record +10h

IPv4 send / receive payload readers

Loopback and PID 4 comparisons

PID and destination-port counter tables

Executable-path retention per PID

Failure-path erase of the whole table
~~~

Trust and policy state:

~~~
CI DebugFlags write

EOS initialization/unload diagnostic values

Minifilter instance configuration

SystemCertificates Blob queries

AuthRoot EncodedCtl retrieval

Catalog RPC

Image-verification callback

Windows trust-provider stage tables
~~~

Execution-environment probes:

~~~
Hypervisor CPUID leaves

Windows hypervisor query

CPUID timing with baseline

TF/BTF exception placement

MOV SS interaction

Synthetic MSR sweep

VMREAD

Debug-register access

Architectural exception probes

RTM execution probes

Mapped-return probes

PMU sampling

XCR access

RDTSC

Processor Trace

CR3 read/reload blocks

Alternate page-table-root experiment

APIC performance-interrupt masking

Cross-processor IPI execution and progress measurement

Persistent-thread-state acquisition
~~~

---

## 附錄：討論串完整索引（72 篇）

僅列出貼文編號、作者、時間與開頭摘要，方便回頭定位原始討論。

| # | 作者 | 時間 | 開頭 |
|---|---|---|---|
| #1 | lauralex **(封存)** | 15th September 2026 01:48 PM | **Inside EAC/EOS driver: hardware identity collection, kernel telemetry and CPU probes** Inside EAC/EOS driver |
| #2 | SecretPaster | 15th September 2026 02:24 PM | Missed quite a bit, but this is actually useful compared to what was released here the past year. Good job |
| #3 | lauralex | 15th September 2026 02:28 PM | Originally Posted by **SecretPaster** (Post 4800176) Missed quite a bit, but this is actually useful compared  |
| #4 | FUSEdev | 15th September 2026 02:33 PM | Originally Posted by **lauralex** (Post 4800179) Yeah, this is only pt.1, also I [removed]ed up the writeup. I |
| #5 | lauralex | 15th September 2026 03:37 PM | Originally Posted by **FUSEdev** (Post 4800184) could you perchance upload some of the logs? Unfortunately the |
| #6 | rhaym | 15th September 2026 05:01 PM | Moderator note ([rhaym](https://www.unknowncheats.me/forum/members/6262081.html)) ![img](images/icons/mod_excl |
| #7 | lolz5465az | 15th September 2026 06:49 PM | Originally Posted by **lauralex** (Post 4800149) ... very beautiful post, nice job using the tool like it was  |
| #8 | FUSEdev | 15th September 2026 07:04 PM | Originally Posted by **lauralex** (Post 4800235) Unfortunately the log file of each run is approximately 50 GB |
| #9 | jaydipm | 15th September 2026 07:13 PM | ur so cool and it's actually formatted nicely even though its massive. see, if you use ai, please use it like  |
| #10 | lauralex | 15th September 2026 07:33 PM | Originally Posted by **lolz5465az** (Post 4800386) very beautiful post, nice job using the tool like it was in |
| #11 | Heashey | 15th September 2026 07:58 PM | felt like i was scrolling for a year, but anyway there is some good information |
| #12 | lauralex | 15th September 2026 08:04 PM | Originally Posted by **jaydipm** (Post 4800417) ur so cool and it's actually formatted nicely even though its  |
| #13 | ecco271k | 15th September 2026 08:19 PM | this is a goldmine and saved me a whole bunch of time, thank you! |
| #14 | xSquad | 15th September 2026 09:56 PM | The **TPM public material** is similar to what I posted before btw if you capture it at runtime. |
| #15 | lauralex | 16th September 2026 12:30 AM | Originally Posted by **xSquad** (Post 4800583) The **TPM public material** is similar to what I posted before  |
| #16 | xSquad | 16th September 2026 12:34 AM | Originally Posted by **lauralex** (Post 4800707) Yeah, I read it. I might do some runtime inspection in pt. 2, |
| #17 | lauralex | 16th September 2026 09:26 AM | Originally Posted by **xSquad** (Post 4800709) Seems like they are doing the same for Rust (the game) and Fort |
| #18 | rqhz | 16th September 2026 09:38 AM | Originally Posted by **lauralex** (Post 4800988) Yep. Also, next writeup update will be focused on the unreach |
| #19 | xSquad | 16th September 2026 11:09 AM | Originally Posted by **rqhz** (Post 4800997) What I also think is funny is that these posts are also good for  |
| #20 | rqhz | 16th September 2026 11:39 AM | Originally Posted by **xSquad** (Post 4801028) If the **OP/threadstarter** digs deeper, especially focusing on |
| #21 | xSquad | 16th September 2026 11:47 AM | Originally Posted by **rqhz** (Post 4801048) Yep I dont wanna know how many anticheats reverse their competito |
| #22 | rqhz | 16th September 2026 11:49 AM | Originally Posted by **xSquad** (Post 4801054) Hahaha, anyway I really like this thread. This is how UC used t |
| #23 | xSquad | 16th September 2026 11:51 AM | Originally Posted by **rqhz** (Post 4801055) Waiting for the day one of the popular anticheat sources get leak |
| #24 | ApexCV | 16th September 2026 12:19 PM | Originally Posted by **rqhz** (Post 4800997) What I also think is funny is that these posts are also good for  |
| #25 | xSquad | 16th September 2026 12:37 PM | Originally Posted by **ApexCV** (Post 4801078) They don't need UC to draw ideas. EAC already implements some s |
| #26 | alexanderyy | 16th September 2026 01:02 PM | EAC uses RtlVirtualUnwind and RtlLookupFunctionEntry, KEVLAR might not be picking it up. But in a real envirom |
| #27 | lauralex | 16th September 2026 01:35 PM | Originally Posted by **alexanderyy** (Post 4801107) EAC uses RtlVirtualUnwind and RtlLookupFunctionEntry, KEVL |
| #28 | alexanderyy | 16th September 2026 01:40 PM | Originally Posted by **lauralex** (Post 4801129) Yeah, trying to figure out why they're not called. Maybe they |
| #29 | lauralex | 16th September 2026 01:50 PM | Originally Posted by **alexanderyy** (Post 4801132) Here are the RVA's for them on the latest EAC rust version |
| #30 | WhiteByte | 16th September 2026 08:26 PM | Tbsip_Submit_Command is related to HWID-locking (in EAC's case, HWID‑based game bans) and TPM attestation (det |
| #31 | xSquad | 16th September 2026 10:04 PM | Originally Posted by **WhiteByte** (Post 4801482) Tbsip_Submit_Command is related to HWID-locking (in EAC's ca |
| #32 | Volopaz | 17th September 2026 03:21 AM | Really solid work on that thread - the fixed-frame timing experiment around the 61s branch (P185 rollback vs 0 |
| #33 | SDSyntax | 17th September 2026 04:52 AM | i got lost in this post too, felt like a year like someone said. +rep |
| #34 | shakro | 17th September 2026 04:59 AM | Ok I just finished scrolling... I was doing that since yesterday. let's see how deep the usermode side goes in |
| #35 | lolz5465az | 17th September 2026 05:00 AM | Originally Posted by **rqhz** (Post 4801055) Waiting for the day one of the popular anticheat sources get leak |
| #36 | xSquad | 17th September 2026 08:02 AM | Originally Posted by **lolz5465az** (Post 4801809) soon.. :hump: EAC got updated today btw, maybe they changed |
| #37 | rqhz | 17th September 2026 08:15 AM | Originally Posted by **xSquad** (Post 4801916) EAC got updated today btw, maybe they changed something. sha-25 |
| #38 | xSquad | 17th September 2026 08:34 AM | Originally Posted by **rqhz** (Post 4801918) EAC getting scared i was hoping they would fix the performance is |
| #39 | rqhz | 17th September 2026 11:12 AM | Originally Posted by **xSquad** (Post 4801926) i was hoping they would fix the performance issues but nvm its  |
| #40 | xSquad | 17th September 2026 11:25 AM | Originally Posted by **rqhz** (Post 4802030) Trust me if u play [removed] Like EFT u will not complain about B |
| #41 | Swiftik | 17th September 2026 11:45 AM | Originally Posted by **xSquad** (Post 4802041) i havent looked into eft yet but seems like it must be somethin |
| #42 | xSquad | 17th September 2026 11:59 AM | Originally Posted by **Swiftik** (Post 4802064) it's about a 20-30fps difference on facepunch servers with and |
| #43 | darkmqn121 | 17th September 2026 09:22 PM | good job thx for information +rep |
| #44 | lauralex **(封存)** | 17th September 2026 10:06 PM | **Changelog - 17 September update** This update keeps the previous writeup intact and adds the findings recove |
| #45 | ApexCV | 18th September 2026 12:31 AM | Originally Posted by **lauralex** (Post 4802603) Original EOS code: saves the current CR3; copies and modifies |
| #46 | xSquad | 18th September 2026 09:30 AM | Originally Posted by **lauralex** (Post 4802603) ... i see, looks like they improved the **chain** |
| #47 | mohameds00a6 | 18th September 2026 11:23 AM | they gonna send bomb to your home lol |
| #48 | NovaHF | 18th September 2026 01:02 PM | Amazing post, thank you |
| #49 | FUSEdev | 18th September 2026 01:21 PM | Originally Posted by **lauralex** (Post 4802603) **Changelog - 17 September update** This update keeps the pre |
| #50 | lauralex | 18th September 2026 02:49 PM | Originally Posted by **FUSEdev** (Post 4803114) Have you also thought about doing this analysis on their userm |
| #51 | FUSEdev | 18th September 2026 03:54 PM | Originally Posted by **lauralex** (Post 4803166) yes, usermode part will be in pt. 2, it will focus on the use |
| #52 | lauralex | 18th September 2026 06:48 PM | Originally Posted by **FUSEdev** (Post 4803228) the usermode service isnt as interesting as the manual mapped  |
| #53 | FUSEdev | 18th September 2026 07:03 PM | Originally Posted by **lauralex** (Post 4803390) yes, I'll talk briefly about the usermode service and EOS boo |
| #54 | Ketaminess | 18th September 2026 11:56 PM | Good job ! |
| #55 | jessajoy | 19th September 2026 01:53 PM | hope you can make also for EAC Steam KATHANA bypass |
| #56 | SoftcoreEXE | 19th September 2026 05:52 PM | man this is the good stuff, first time i have seen anyone actually map what eos queries instead of just guessi |
| #57 | lauralex | 19th September 2026 06:23 PM | Originally Posted by **SoftcoreEXE** (Post 4804244) man this is the good stuff, first time i have seen anyone  |
| #58 | xxuser | 20th September 2026 04:21 PM | this is actual gold mine, thanks a lot |
| #59 | vmnotaware | 20th September 2026 05:06 PM | Great post and great use of Ai at least, well done |
| #60 | ExFreePool | 20th September 2026 05:15 PM | great post. well done. All times are GMT. The time now is 01:10 PM . Page 3 of 4 [<](printthread.php?t=772181& |
| #61 | lauralex **(封存)** | 22nd September 2026 04:28 PM | **Platform and processor probes (follow-up to the main post)** Continuation of [the main post](https://www.unk |
| #62 | Daloggz12 | 22nd September 2026 04:31 PM | Originally Posted by **lauralex** (Post 4806980) **Platform and processor probes (follow-up to the main post)* |
| #63 | xSquad | 22nd September 2026 04:31 PM | Thanks for keeping it up. :You_Rock_Emoticon: |
| #64 | lauralex **(封存)** | 22nd September 2026 04:31 PM | **Appendix: acquisition sites and the current picture (follow-up to the main post)** Continuation of [the main |
| #65 | FUSEdev | 22nd September 2026 07:28 PM | Originally Posted by **lauralex** (Post 4806985) **Appendix: acquisition sites and the current picture (follow |
| #66 | lauralex | 23rd September 2026 01:54 PM | usermode part is coming |
| #67 | ExFreePool | 23rd September 2026 05:25 PM | hey do u have discord ive done alot of changes to my hypervisor from ur posts and now its very seemless and pe |
| #68 | lauralex | 23rd September 2026 05:51 PM | Originally Posted by **ExFreePool** (Post 4808207) hey do u have discord ive done alot of changes to my hyperv |
| #69 | xSquad | 23rd September 2026 07:26 PM | @[lauralex](https://www.unknowncheats.me/forum/members/214675.html) you should try using [KernelMul](https://w |
| #70 | 1koohs | 23rd September 2026 10:51 PM | nice job all the way around, especially for how organized and professional the write-ups are, impressive. |
| #71 | reveriee | 24th September 2026 12:31 AM | generational |
| #72 | lauralex | 24th September 2026 12:42 AM | Not only usermode EOS runtime module. The emulation system must run EOS driver, EOS runtime, EOS SDK, mock gam |

---

*本檔由社群公開頁面擷取後機械化轉換而成；格式（標題、表格、程式碼區塊）已依 Markdown 重排，文字內容未經改寫。*
