# RE note: sample_08

| Field | Value |
|---|---|
| SHA-256 | `8485df8a54d5d666128acd015be589e6b6d6bc93d3f3fbeede2fe87eadce6051` |
| Label / family | benign / benign: IMEWDBLD.EXE |
| Why chosen | typical benign: Ordinary Microsoft system program for contrast |
| Source and date obtained | Clean Windows 11 install (benign_manifest.csv) |
| Analysed on (date, VM snapshot) | 2026-10-20; benign file, so structure and call sites were extracted with a pefile/capstone helper on Windows; to be confirmed in Ghidra (VM snapshot `dataset-ready`) |
| Tools | Ghidra 12.1.4; pefile + capstone (x64) helper; pemd run `20261020-024822_raw` |

## 1. Static pipeline view (auto-filled)

- **p(malware) = 0.0014**, route **benign** (gate: benign < 0.34, malware >= 0.5), model `xgboost`
- Explanation method: TreeSHAP (xgboost pred_contribs)

| Feature | Value | Contribution |
|---|---|---|
| `hdr:checksum_zero` | 0 | -2.066 |
| `meta:has_debug` | 1 | -0.861 |
| `meta:overlay_ratio` | 0 | +0.591 |
| `op_h:170` (nop mov, movups mov) | 0.0217 | -0.548 |
| `hdr:is_dll` | 0 | +0.505 |
| `hdr:subsystem_gui` | 1 | +0.490 |
| `hdr:dllchar_guard_cf` | 1 | -0.469 |
| `imp_fn_h:347` (api-ms-win-crt-runtime-l1-1-0.dll:_initterm, kernel32.dll:getnativesysteminfo) | 1 | -0.440 |
| `byte_hist:89` | 0.000901 | -0.399 |
| `meta:has_version_info` | 1 | -0.363 |

## 2. Structure (auto-filled, then checked in Ghidra)

- Machine: x64 (64-bit); type: EXE; **native code**
- File size 438272 bytes, overall entropy 5.80; overlay 0 bytes
- TLS callbacks directory: yes; Authenticode signature: no; resources: yes

| Section | Raw size | Virtual size | Entropy | Flags | Entry point |
|---|---|---|---|---|---|
| `.text` | 192512 | 189058 | 6.11 | R-X | yes |
| `fothk` | 4096 | 4096 | 0.02 | R-X |  |
| `.rdata` | 73728 | 72440 | 4.79 | R-- |  |
| `.data` | 12288 | 13248 | 4.32 | RW- |  |
| `.pdata` | 12288 | 8532 | 4.20 | R-- |  |
| `.didat` | 4096 | 48 | 0.05 | RW- |  |
| `.rsrc` | 131072 | 129592 | 4.92 | R-- |  |
| `.reloc` | 4096 | 1932 | 3.39 | R-- |  |

- Packed? **No.** No W+X section, maximum section entropy 6.11 (`.text`), a rich import table (269 functions, plus 2 delay-loaded DLLs) and the entry point at the start of `.text` (RVA 0x1b90). The unusual `fothk` section (R-X, 4 KB) contains only one 5-byte `jmp` instruction followed by `int3` padding: a Microsoft build-time thunk, not a packer stub.
- Entry point: `entry` calls FUN_1400022c4 (the usual MSVC security-cookie initialiser) and then jumps to the C runtime start-up (FUN_140001910). This is standard MSVC CRT start-up with no allocation or decryption loop.

### Imports

- **ADVAPI32.dll** (15): OpenThreadToken, OpenProcessToken, GetTokenInformation, ConvertSidToStringSidW, RegOpenKeyExW, EventUnregister, EventRegister, EventWriteTransfer, RegQueryValueExW, RegCloseKey, EncryptFileW, RegCreateKeyExW, RegSetValueExW, RegEnumKeyExW, RegDeleteTreeW
- **KERNEL32.dll** (71): GetModuleHandleW, WideCharToMultiByte, DebugBreak, IsDebuggerPresent, RaiseException, LeaveCriticalSection, ReleaseSRWLockShared, ReleaseSRWLockExclusive, InitializeCriticalSectionEx, DeleteCriticalSection, EnterCriticalSection, AcquireSRWLockExclusive, AcquireSRWLockShared, LocalFree, GetCurrentThread, GetCurrentProcess, CreateSemaphoreExW, CreateThreadpoolTimer, FreeLibrary, LoadLibraryW, DeleteFileW, CopyFileW, SetFileAttributesW, Sleep, GetProcessHeap, ... (+46)
- **GDI32.dll** (3): SelectObject, CreateFontIndirectW, DeleteObject
- **USER32.dll** (29): GetDesktopWindow, GetParent, MessageBoxW, GetWindowRect, CopyRect, OffsetRect, SetWindowPos, ReleaseDC, GetTabbedTextExtentW, GetDC, DialogBoxIndirectParamW, EndDialog, SetWindowTextW, PostMessageW, GetDlgItem, EnableWindow, EnableMenuItem, GetSystemMenu, ShowWindow, SendDlgItemMessageW, LoadIconW, GetSystemMetrics, LoadImageW, DestroyIcon, SetDlgItemTextW, ... (+4)
- **msvcrt.dll** (70): _write, _wcsicmp, _XcptFilter, _wcstoui64, _read, _close, _lseek, _wopen, _wtoi, _fmode, memmove_s, _commode, _lock, _unlock, ??1type_info@@UEAA@XZ, __C_specific_handler, __dllonexit, _amsg_exit, _wcmdln, ??_V@YAXPEAX@Z, wcsncpy_s, _vsnwprintf_s, ??0exception@@QEAA@AEBV0@@Z, ??0exception@@QEAA@XZ, _onexit, ... (+45)
- **api-ms-win-core-winrt-l1-1-0.dll** (1): RoGetActivationFactory
- **api-ms-win-core-winrt-string-l1-1-0.dll** (2): WindowsDeleteString, WindowsCreateStringReference
- **api-ms-win-core-com-l1-1-0.dll** (7): CoCreateInstance, CoWaitForMultipleHandles, IIDFromString, StringFromGUID2, CoCreateGuid, CoCreateFreeThreadedMarshaler, CoUninitialize
- **api-ms-win-core-winrt-error-l1-1-1.dll** (1): RoGetMatchingRestrictedErrorInfo
- **api-ms-win-core-winrt-error-l1-1-0.dll** (1): SetRestrictedErrorInfo
- **OLEAUT32.dll** (12): SysFreeString, VariantInit, VariantClear, VariantCopy, VariantChangeType, SysStringLen, SysStringByteLen, SysAllocStringByteLen, SysAllocString, GetErrorInfo, VarBstrFromDate, SystemTimeToVariantTime
- **api-ms-win-core-shlwapi-legacy-l1-1-0.dll** (5): PathRemoveBackslashW, PathFindExtensionW, PathFindFileNameW, PathFileExistsW, PathRemoveExtensionW
- **api-ms-win-shell-shdirectory-l1-1-0.dll** (1): ord292
- **api-ms-win-shcore-obsolete-l1-1-0.dll** (1): CommandLineToArgvW
- **WINTRUST.dll** (1): WinVerifyTrust
- **CRYPT32.dll** (8): CertGetNameStringW, CryptMsgGetParam, CertFindCertificateInStore, CertFreeCertificateContext, CertCloseStore, CryptDecodeObject, CryptQueryObject, CryptMsgClose
- **Cabinet.dll** (4): ord21, ord22, ord23, ord20
- **api-ms-win-core-heap-l1-1-0.dll** (3): HeapSize, HeapReAlloc, HeapDestroy
- **api-ms-win-core-synch-l1-1-0.dll** (1): InitializeCriticalSection
- **api-ms-win-core-string-l1-1-0.dll** (1): CompareStringW
- **api-ms-win-core-processenvironment-l1-1-0.dll** (1): ExpandEnvironmentStringsW
- **api-ms-win-core-processthreads-l1-1-0.dll** (3): CreateProcessW, TerminateProcess, GetStartupInfoW
- **api-ms-win-core-synch-l1-2-0.dll** (2): WakeAllConditionVariable, SleepConditionVariableSRW
- **api-ms-win-core-rtlsupport-l1-1-0.dll** (3): RtlVirtualUnwind, RtlLookupFunctionEntry, RtlCaptureContext
- **api-ms-win-core-errorhandling-l1-1-0.dll** (3): SetUnhandledExceptionFilter, UnhandledExceptionFilter, SetErrorMode
- **api-ms-win-core-profile-l1-1-0.dll** (1): QueryPerformanceCounter
- **api-ms-win-core-sysinfo-l1-1-0.dll** (3): GetVersionExW, GetTickCount, GetSystemTimeAsFileTime
- **ole32.dll** (2): OleRun, CoInitialize
- **SHELL32.dll** (2): ShellExecuteW, ord680
- **COMCTL32.dll** (1): InitCommonControlsEx
- **UxTheme.dll** (1): GetThemeSysFont
- **api-ms-win-security-base-l1-1-0.dll** (3): IsValidSid, GetSidSubAuthorityCount, GetSidSubAuthority
- **api-ms-win-core-file-l1-1-0.dll** (2): GetFileAttributesW, GetTempFileNameW
- **ntdll.dll** (1): RtlIsMultiUsersInSessionSku
- **api-ms-win-core-file-l2-1-0.dll** (1): MoveFileExW
- **profapi.dll** (2): ord104, ord103
- **api-ms-win-core-apiquery-l1-1-0.dll** (1): ApiSetQueryApiSetPresence

### API capability groups found (api_cat features)

- `privilege`: OpenProcessToken
- `registry`: RegOpenKeyExW, RegCreateKeyExW, RegSetValueExW, RegEnumKeyExW
- `dynamic_resolution`: GetModuleHandleW, LoadLibraryW, GetProcAddress, GetModuleHandleExW
- `anti_debug`: IsDebuggerPresent, OutputDebugStringW, QueryPerformanceCounter, GetTickCount
- `file_enumeration`: DeleteFileW, MoveFileExW
- `screen_capture`: GetDC
- `process_execution`: CreateProcessW, ShellExecuteW

### Notable strings (defanged)

- **IP address:** `1[.]3[.]6[.]1`; `5[.]5[.]7[.]3`; `6[.]0[.]0[.]0`
- **Registry:** `HKEY__@@P6AJPEAU1@@Z$1?RegCloseKey@@YAJ0@ZU?$integral_constant@_K$0A@@wistd@@PEAU1@PEAU1@$0A@$$T@details@wil@@@details@wil@@@w`

## 3. Behaviour indicated by code (Ghidra)

| Capability | Evidence (function address, API, string) | Visible in static features? (which) |
|---|---|---|
| Debugger check | `IsDebuggerPresent` is called from 4 functions (FUN_14000290c, FUN_140002ba0, FUN_14000480c, FUN_140006ffc). Each also calls `OutputDebugStringW`/`GetCurrentThreadId`: Windows Implementation Library (WIL) error-logging helpers (`result_macros.h` strings), which print diagnostics only when a debugger is attached | `api_cat:anti_debug` = 1, but **benign context**: logging, not evasion |
| File encryption | `EncryptFileW` in FUN_140009944, together with `CopyFileW`, `DeleteFileW`, `SetFileAttributesW` and strings `.dic`, `%s\%s_%s.dctr`, `PlugInGUID:%s`: copies an IME user dictionary and protects the copy with Windows EFS | Not in any `api_cat` group; ransomware-like API set but a **benign purpose** |
| Registry access | `RegOpenKeyExW` in FUN_14000a8e4 / FUN_14000ca1c; strings `Software\Microsoft\IME\PlugInDict`, `Software\Policies\Microsoft\IME\Shared` | `api_cat:registry` (reads IME settings and policy) |
| Process termination | `TerminateProcess` in FUN_140001e50 with `SetUnhandledExceptionFilter`/`UnhandledExceptionFilter`: the CRT fail-fast handler | Not in `api_cat`; runtime boilerplate |
| Signature check | `WinVerifyTrust` and `CryptQueryObject` imported; strings "This dictionary is not signed" and "Failed to verify the digital signature of this dictionary": verifies downloaded dictionaries | Not in `api_cat`; defensive behaviour |

## 4. Feature decisions

| Feature / pattern | Decision (retain / prioritise / discard) | Reason |
|---|---|---|
| `api_cat:anti_debug` | **retain, but weak alone** | Imported by ordinary Microsoft code for logging (WIL), so presence alone is not evidence of evasion |
| `sec:n_wx`, `sec:entropy_max` | **prioritise** | This benign file has no W+X section and moderate entropy, the opposite of the packed malware (sample_04) |
| `hdr:checksum_zero`, `meta:has_debug`, `hdr:dllchar_guard_cf` | **discard** (in the artefact-free configuration) | They are the top SHAP contributions pushing this file to benign (-2.07, -0.86, -0.47), but they describe Microsoft's build process, not behaviour |
| API combination features (e.g. EncryptFileW + DeleteFileW) | retain, with context | The same APIs as ransomware serve a benign purpose here: capability needs context |

## 5. Mutation resistance

- **Build artefacts** (checksum, debug directory, CFG flag): any author can set a valid checksum and enable CFG and debug info with a linker switch at **zero cost**, which is why the model must not rely on them.
- **`api_cat:anti_debug`**: malware can drop the import and use `PEB.BeingDebugged` directly at low cost, so the feature is weak in both directions.
- **W+X / entropy**: a packed sample must decrypt itself into executable memory; avoiding W+X costs the packer either a `VirtualProtect` call (visible as `memory_protection`) or no packing at all, so this is **more robust**.

## 6. Notes for the dissertation

A typical Microsoft program is classified benign (p = 0.0014) mainly through **build-environment artefacts** (valid checksum, debug directory, CFG), not through what it does. Its behaviour includes APIs often linked to malware (`IsDebuggerPresent`, `EncryptFileW`, `TerminateProcess`), but the code shows benign purposes: logging, EFS protection of dictionaries, and crash handling. This supports (1) discarding toolchain artefacts for a fair model (run `raw_no_artifacts`) and (2) treating single API capabilities as context-dependent evidence rather than proof (RQ2).
