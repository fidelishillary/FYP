# RE note: sample_06

| Field | Value |
|---|---|
| SHA-256 | `234d8d99629d1dcf9d74b0f9911af86548ff8a2a1bfcaf07a73d80491e53fdd5` |
| Label / family | malware / (no family label) |
| Why chosen | missed by the model: Malware scored p=0.05 (cleared as benign) in run raw_no_artifacts: why? |
| Source and date obtained | MalwareBazaar (see data/raw/malwarebazaar_metadata.csv) |
| Analysed on (date, VM snapshot) | 2026-10-20, **static triage only**: automatic structure/import/string extraction (`scripts/case_study_prep.py`) in the isolated VM; not decompiled in Ghidra |
| Tools | pefile-based pre-fill (scripts/case_study_prep.py), pemd run `20261020-024822_raw` |

## 1. Static pipeline view (auto-filled)

- In run `raw_no_artifacts`: p(malware) = 0.05, so **cleared as benign** (a false negative; the reason this file was chosen). With all features (below) it is caught narrowly.
- **p(malware) = 0.7346**, route **malware** (gate: benign < 0.34, malware >= 0.5), model `xgboost`
- Explanation method: TreeSHAP (xgboost pred_contribs)

| Feature | Value | Contribution |
|---|---|---|
| `meta:has_debug` | 0 | +2.657 |
| `hdr:checksum_zero` | 0 | -1.383 |
| `hdr:is_dll` | 0 | +0.729 |
| `imp_fn_h:347` (api-ms-win-crt-runtime-l1-1-0.dll:_initterm, kernel32.dll:getnativesysteminfo) | 1 | -0.543 |
| `hdr:subsystem_gui` | 1 | +0.532 |
| `meta:overlay_ratio` | 0.00113 | +0.435 |
| `byte_hist:89` | 0.00115 | -0.398 |
| `sec:virtual_size_mean` | 1.74e+06 | +0.374 |
| `meta:has_version_info` | 1 | -0.333 |
| `op_h:151` (mov mov, movdqa mov) | 0.121 | +0.307 |

## 2. Structure (auto-filled, then checked in Ghidra)

- Machine: x64 (64-bit); type: EXE; **native code**
- File size 13911344 bytes, overall entropy 6.49; overlay 15664 bytes
- TLS callbacks directory: yes; Authenticode signature: yes; resources: yes

| Section | Raw size | Virtual size | Entropy | Flags | Entry point |
|---|---|---|---|---|---|
| `.text` | 8701952 | 8701798 | 6.43 | R-X | yes |
| `.rdata` | 4990976 | 4990548 | 6.01 | R-- |  |
| `.data` | 69120 | 69736 | 0.08 | RW- |  |
| `.pdata` | 86528 | 86424 | 6.15 | R-- |  |
| `.tls` | 1024 | 545 | 0.02 | RW- |  |
| `_RDATA` | 1536 | 1092 | 2.97 | R-- |  |
| `.rsrc` | 18432 | 18384 | 4.36 | R-- |  |
| `.reloc` | 25088 | 24776 | 5.43 | R-- |  |

- Packed? **No** (from the automatic structure): no W+X section, max entropy 6.43, rich import table, entry point in .text. 13.9 MB, **Authenticode-signed**, 64-bit, TLS directory present.

### Imports

- **bcrypt.dll** (1): BCryptGenRandom
- **uxtheme.dll** (1): SetWindowTheme
- **shlwapi.dll** (1): AssocQueryStringW
- **advapi32.dll** (12): ConvertSidToStringSidW, CopySid, GetLengthSid, GetTokenInformation, ImpersonateAnonymousToken, IsValidSid, OpenProcessToken, RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RevertToSelf, SystemFunction036
- **user32.dll** (88): AdjustWindowRectEx, ChangeDisplaySettingsExW, ClientToScreen, ClipCursor, CloseClipboard, CloseTouchInputHandle, CreateIcon, CreateIconFromResourceEx, CreateWindowExA, CreateWindowExW, DefWindowProcA, DefWindowProcW, DestroyCursor, DestroyIcon, DestroyWindow, DispatchMessageW, EmptyClipboard, EnableMenuItem, EnumDisplayMonitors, FlashWindowEx, GetActiveWindow, GetAsyncKeyState, GetClassInfoExW, GetClassNameW, GetClientRect, ... (+63)
- **api-ms-win-crt-math-l1-1-0.dll** (50): __setusermatherr, _hypotf, acos, acosf, acosh, acoshf, asin, asinf, asinh, asinhf, atan, atan2f, atanf, cbrtf, ceil, ceilf, cos, cosf, cosh, coshf, exp, exp2, exp2f, expf, floor, ... (+25)
- **gdi32.dll** (13): BitBlt, ChoosePixelFormat, CreateCompatibleDC, CreateDIBSection, CreateRectRgn, DeleteDC, DeleteObject, DescribePixelFormat, GetDeviceCaps, GetPixelFormat, SelectObject, SetPixelFormat, SwapBuffers
- **api-ms-win-crt-string-l1-1-0.dll** (3): strcpy_s, strlen, wcslen
- **ntdll.dll** (11): NtCancelIoFileEx, NtCreateFile, NtCreateNamedPipeFile, NtDeviceIoControlFile, NtOpenFile, NtQueryInformationProcess, NtQuerySystemInformation, NtReadFile, NtWriteFile, RtlGetVersion, RtlNtStatusToDosError
- **api-ms-win-crt-runtime-l1-1-0.dll** (19): __p___argc, __p___argv, _c_exit, _cexit, _configure_narrow_argv, _crt_atexit, _exit, _get_initial_narrow_environment, _initialize_narrow_environment, _initialize_onexit_table, _initterm, _initterm_e, _register_onexit_function, _register_thread_local_exe_atexit_callback, _seh_filter_exe, _set_app_type, abort, exit, terminate
- **kernel32.dll** (117): AddVectoredExceptionHandler, CancelIo, CancelIoEx, CloseHandle, CompareStringOrdinal, CopyFileExW, CreateDirectoryW, CreateEventA, CreateEventW, CreateFileW, CreateIoCompletionPort, CreateMutexA, CreateProcessW, CreateThread, CreateWaitableTimerExW, DeleteCriticalSection, DeleteFileW, DuplicateHandle, EncodePointer, ExitProcess, FindClose, FindFirstFileExW, FindNextFileW, FlsAlloc, FlsFree, ... (+92)
- **bcryptprimitives.dll** (1): ProcessPrng
- **powrprof.dll** (1): CallNtPowerInformation
- **crypt32.dll** (11): CertAddCertificateContextToStore, CertCloseStore, CertDuplicateCertificateChain, CertDuplicateCertificateContext, CertDuplicateStore, CertEnumCertificatesInStore, CertFreeCertificateChain, CertFreeCertificateContext, CertGetCertificateChain, CertOpenStore, CertVerifyCertificateChainPolicy
- **secur32.dll** (10): AcceptSecurityContext, AcquireCredentialsHandleA, ApplyControlToken, DecryptMessage, DeleteSecurityContext, EncryptMessage, FreeContextBuffer, FreeCredentialsHandle, InitializeSecurityContextW, QueryContextAttributesW
- **psapi.dll** (1): GetModuleFileNameExW
- **dwmapi.dll** (2): DwmEnableBlurBehindWindow, DwmSetWindowAttribute
- **api-ms-win-crt-locale-l1-1-0.dll** (1): _configthreadlocale
- **api-ms-win-crt-stdio-l1-1-0.dll** (2): __p__commode, _set_fmode
- **d3dcompiler_47.dll** (1): D3DCompile
- **ole32.dll** (7): CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, OleInitialize, RegisterDragDrop, RevokeDragDrop
- **shell32.dll** (4): CommandLineToArgvW, DragFinish, DragQueryFileW, SHGetKnownFolderPath
- **api-ms-win-core-synch-l1-2-0.dll** (3): WaitOnAddress, WakeByAddressAll, WakeByAddressSingle
- **pdh.dll** (6): PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue, PdhOpenQueryA, PdhRemoveCounter
- **imm32.dll** (6): ImmAssociateContextEx, ImmGetCompositionStringW, ImmGetContext, ImmReleaseContext, ImmSetCandidateWindow, ImmSetCompositionWindow
- **ws2_32.dll** (19): WSACleanup, WSAGetLastError, WSAIoctl, WSASend, WSASocketW, WSAStartup, bind, closesocket, connect, freeaddrinfo, getaddrinfo, getpeername, getsockname, getsockopt, ioctlsocket, recv, send, setsockopt, shutdown
- **oleaut32.dll** (3): GetErrorInfo, SysFreeString, SysStringLen
- **api-ms-win-crt-heap-l1-1-0.dll** (4): _set_new_mode, calloc, free, malloc
- **OPENGL32.dll** (7): wglCreateContext, wglDeleteContext, wglGetCurrentContext, wglGetCurrentDC, wglGetProcAddress, wglMakeCurrent, wglShareLists

### API capability groups found (api_cat features)

- `privilege`: OpenProcessToken
- `registry`: RegOpenKeyExW
- `keylogging_hooks`: GetAsyncKeyState, GetForegroundWindow, GetKeyState, GetKeyboardState, GetRawInputData, RegisterRawInputDevices
- `screen_capture`: GetDC, BitBlt
- `anti_debug`: NtQueryInformationProcess, QueryPerformanceCounter
- `process_execution`: CreateProcessW
- `file_enumeration`: DeleteFileW, FindFirstFileExW, FindNextFileW
- `dynamic_resolution`: GetModuleHandleA, GetModuleHandleW, GetProcAddress, LoadLibraryA, LoadLibraryExA, LoadLibraryExW, LoadLibraryW
- `process_injection`: OpenProcess
- `network`: WSAStartup, connect, getaddrinfo, recv, send

### Notable strings (defanged)

- **URL:** `hxxp://ns.adobe.iso:ts:21496:-1`; `hxxps://registry.khronos.org/vulkan/specs/1.3-extensions/html/vkspec.html#devsandqueues-lost-device>Mapping`; `hxxps://docs.rs/egui/latest/egui/load/index.htmlImage`; `hxxps://www.shadertoy.com/view/llVGzG`; `hxxps://blog.demofox.org/2022/01/01/interleaved-gradient-noise-a-different-kind-of-low-discrepancy-sequence/`; `hxxps://github.com/rerun-io/rerun/`
- **IP address:** `1[.]3[.]6[.]1`; `5[.]5[.]7[.]3`; `4[.]1[.]311[.]10`; `2[.]16[.]840[.]1`; `127[.]0[.]0[.]1`
- **Registry:** `SOFTWARE\Microsoft\Windows NT\CurrentVersionCurrentBuildNumberCurrentMajorVersionNumber\Processor(_Total)\% Idle Time`
- **Shell / LOLBin:** `cmd.exe /e:ON /v:OFF /d /c "batch file arguments are invalid`; `cmd.exe/2ustc/52b6e2c208b73276ccb36ec0b68456913a801c96/library\std\src\sys\thread_local\destructors\list.rs`
- **Crypto / ransom:** `encryptedInvalid password`
- **File path:** `C:\Users\runneradmin\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\egui-0.29.1\src\containers\wi`; `C:\r\src\g\e.rs`; `C:\r\src\g\register.rs`; `C:\Users\runneradmin\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\aes-0.8.4\src\soft\fixslice64`; `C:\Users\runneradmin\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\anyhow-1.0.102\src\fmt.rs`; `C:\Users\runneradmin\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\anyhow-1.0.102\src\error.rs`

## 3. Behaviour indicated by code (Ghidra)

| Capability | Evidence (function address, API, string) | Visible in static features? (which) |
|---|---|---|
| Rust-style program with a GUI stack | Imports typical of the Rust standard library (`ProcessPrng`, `WaitOnAddress`, `NtCreateNamedPipeFile`, `NtDeviceIoControlFile`, UCRT `api-ms-win-crt-*`) plus graphics/UI (`D3DCompile`, DWM, OpenGL pixel formats, clipboard, drag and drop) | Only generic api_cat hits; nothing specific |
| Security/identity APIs | `ImpersonateAnonymousToken`, `GetTokenInformation`, `secur32` (TLS: `InitializeSecurityContextW`, `EncryptMessage`), `crypt32` certificate store | api_cat:privilege; plausible for a networked desktop application |

## 4. Feature decisions

| Feature / pattern | Decision (retain / prioritise / discard) | Reason |
|---|---|---|
| Build artefacts (`meta:has_debug`=0 pushes towards malware, `hdr:checksum_zero`) | **discard** | Decide this file's score in both directions without describing behaviour |
| Generic imports of modern toolchains (Rust/UCRT) | **retain** | Shared by benign and malicious programs built with the same toolchain |

## 5. Mutation resistance

- A malicious program built with a mainstream toolchain and GUI framework, and signed, has almost no static feature that distinguishes it from benign software: a fundamental limit of static analysis that motivates the dynamic fallback.

## 6. Notes for the dissertation

Static triage only. This unlabelled sample was missed by the model without build artefacts (p = 0.05) and caught only narrowly with them (p = 0.73). Its structure looks like an ordinary signed Rust desktop application with a graphics stack and TLS networking; nothing in its imports or sections is specific to malware. It is either a mislabelled or grey-ware sample (label noise, a threat to validity) or malware whose behaviour is only observable at run time. Either way, it is exactly the kind of file the hybrid design should escalate to dynamic analysis rather than clear statically.
