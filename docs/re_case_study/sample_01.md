# RE note: sample_01

| Field | Value |
|---|---|
| SHA-256 | `076b561bddf88c1482feefb2cbbc11a82b7829528988fd246a6e4a245eb48e73` |
| Label / family | malware / Amadey |
| Why chosen | native, rich import table: Most API-capability hits in its family: tests whether api_cat reflects real behaviour |
| Source and date obtained | MalwareBazaar (see data/raw/malwarebazaar_metadata.csv) |
| Analysed on (date, VM snapshot) | 2026-10-20, **static triage only**: automatic structure/import/string extraction (`scripts/case_study_prep.py`) in the isolated VM; not decompiled in Ghidra |
| Tools | pefile-based pre-fill (scripts/case_study_prep.py), pemd run `20261020-024822_raw` |

## 1. Static pipeline view (auto-filled)

- **p(malware) = 0.9923**, route **malware** (gate: benign < 0.34, malware >= 0.5), model `xgboost`
- Explanation method: TreeSHAP (xgboost pred_contribs)

| Feature | Value | Contribution |
|---|---|---|
| `hdr:checksum_zero` | 0 | -1.295 |
| `meta:overlay_ratio` | 0.00074 | +0.955 |
| `op_h:64` (add xor, je push) | 0.00669 | +0.797 |
| `op_h:55` (ret call, dec add) | 0.0153 | +0.656 |
| `hdr:is_dll` | 0 | +0.551 |
| `imp_fn_h:347` (api-ms-win-crt-runtime-l1-1-0.dll:_initterm, kernel32.dll:getnativesysteminfo) | 2 | -0.527 |
| `meta:has_debug` | 1 | -0.503 |
| `hdr:subsystem_gui` | 1 | +0.448 |
| `sec:entropy_max` | 6.71 | +0.431 |
| `op_h:151` (mov mov, movdqa mov) | 0.0825 | +0.359 |

## 2. Structure (auto-filled, then checked in Ghidra)

- Machine: x86 (32-bit); type: EXE; **native code**
- File size 17708840 bytes, overall entropy 6.82; overlay 13096 bytes
- TLS callbacks directory: yes; Authenticode signature: yes; resources: yes

| Section | Raw size | Virtual size | Entropy | Flags | Entry point |
|---|---|---|---|---|---|
| `.text` | 11561472 | 11561184 | 6.60 | R-X | yes |
| `.rdata` | 4964864 | 4964684 | 6.71 | R-- |  |
| `.data` | 177664 | 224736 | 5.31 | RW- |  |
| `_RDATA` | 512 | 292 | 3.52 | R-- |  |
| `.rsrc` | 374272 | 373952 | 3.01 | R-- |  |
| `.reloc` | 615936 | 615504 | 6.53 | R-- |  |

- Packed? **No** (from the automatic structure): no W+X section, max entropy 6.71, about 600 ordinary imports, entry point in .text. Very large (17.7 MB), **Authenticode-signed**, TLS directory present.

### Imports

- **WSOCK32.dll** (32): sendto, recvfrom, listen, bind, WSAGetLastError, inet_ntoa, getpeername, WSAAsyncSelect, recv, send, shutdown, WSASetLastError, __WSAFDIsSet, accept, ntohl, htonl, setsockopt, inet_addr, htons, getsockname, connect, closesocket, ioctlsocket, WSACleanup, WSAStartup, ... (+7)
- **USER32.dll** (124): GetWindowPlacement, SetWindowPlacement, IsWindowVisible, IsIconic, IsZoomed, SetCapture, ReleaseCapture, UpdateWindow, SetForegroundWindow, SetWindowRgn, InvalidateRect, ValidateRgn, ScrollWindowEx, SetWindowTextW, GetWindowRect, AdjustWindowRectEx, SetCursor, ClientToScreen, ScreenToClient, GetDesktopWindow, SetParent, SetWindowsHookExW, UnhookWindowsHookEx, CallNextHookEx, DestroyIcon, ... (+99)
- **ADVAPI32.dll** (50): DuplicateTokenEx, CreateProcessWithLogonW, LookupAccountNameW, SystemFunction036, CryptAcquireContextW, CryptReleaseContext, CryptGenRandom, CryptSignHashA, CryptDestroyHash, CryptCreateHash, CryptDecrypt, CryptSetHashParam, CryptDestroyKey, RegisterEventSourceA, DeregisterEventSource, RegQueryInfoKeyW, RegFlushKey, RegEnumValueW, RegEnumKeyExW, RegDeleteKeyW, RegCreateKeyExW, GetLengthSid, CopySid, GetUserNameW, RegQueryValueExW, ... (+25)
- **OLEAUT32.dll** (24): VariantTimeToSystemTime, SystemTimeToVariantTime, SysAllocStringLen, SafeArrayDestroy, SafeArrayGetDim, SafeArrayGetUBound, SafeArrayGetLBound, SafeArrayAccessData, SafeArrayUnaccessData, SafeArrayGetElement, SafeArrayPutElement, SafeArrayGetVartype, SafeArrayCreateVector, OleTranslateColor, OleCreateFontIndirect, OleCreatePictureIndirect, LoadTypeLib, GetActiveObject, SysAllocString, SysStringLen, VariantClear, SysFreeString, VariantInit, SafeArrayCreate
- **ole32.dll** (27): OleSetClipboard, OleUninitialize, OleInitialize, RevokeDragDrop, OleFlushClipboard, OleIsCurrentClipboard, RegisterDragDrop, DoDragDrop, CoCreateGuid, StringFromGUID2, OleCreateFromFile, CreateILockBytesOnHGlobal, StgCreateDocfileOnILockBytes, CLSIDFromProgID, CoFreeUnusedLibraries, CoGetClassObject, CoTaskMemFree, CoUninitialize, CoInitializeEx, OleGetClipboard, CoSetProxyBlanket, ReleaseStgMedium, CoInitialize, CoGetMalloc, CoInitializeSecurity, ... (+2)
- **SHELL32.dll** (4): ShellExecuteW, Shell_NotifyIconW, SHGetFileInfoW, ShellExecuteExW
- **USERENV.dll** (2): DestroyEnvironmentBlock, CreateEnvironmentBlock
- **WTSAPI32.dll** (4): WTSQuerySessionInformationW, WTSQueryUserToken, WTSFreeMemory, WTSEnumerateSessionsW
- **CRYPT32.dll** (4): CertGetCertificateChain, CertFreeCertificateContext, CertFreeCertificateChain, CertCreateCertificateContext
- **IPHLPAPI.DLL** (5): IcmpCloseHandle, IcmpSendEcho2, IcmpCreateFile, GetIpNetTable, IcmpParseReplies
- **pdh.dll** (11): PdhCollectQueryData, PdhGetFormattedCounterValue, PdhGetRawCounterValue, PdhEnumObjectsW, PdhRemoveCounter, PdhGetCounterInfoW, PdhExpandWildCardPathW, PdhParseCounterPathW, PdhAddCounterW, PdhOpenQueryW, PdhCloseQuery
- **dbghelp.dll** (1): MiniDumpWriteDump
- **ODBC32.dll** (30): ord165, ord138, ord24, ord26, ord9, ord29, ord12, ord13, ord30, ord31, ord43, ord44, ord18, ord20, ord75, ord61, ord72, ord127, ord108, ord111, ord136, ord119, ord139, ord140, ord145, ... (+5)
- **KERNEL32.dll** (209): LoadLibraryW, ReadProcessMemory, ProcessIdToSessionId, GetCurrentProcessId, GetProcAddress, LoadLibraryExW, GetCurrentThreadId, CreateFileW, SetUnhandledExceptionFilter, CreateDirectoryA, GetTickCount, FindClose, FindFirstFileA, FindNextFileA, SetHandleInformation, GetModuleFileNameW, GetProcessTimes, QueryPerformanceFrequency, QueryPerformanceCounter, MulDiv, GetVolumeInformationW, EnterCriticalSection, LeaveCriticalSection, InitializeCriticalSection, VirtualFree, ... (+184)
- **GDI32.dll** (41): GetCharABCWidthsI, GdiFlush, SelectClipRgn, ExtTextOutW, SetWorldTransform, SetTextAlign, SetTextColor, SetGraphicsMode, SetBkMode, GetTextExtentPoint32W, GetOutlineTextMetricsW, GetGlyphOutlineW, GetCharABCWidthsFloatW, GetCharABCWidthsW, GetTextFaceW, GetTextMetricsW, GetFontData, EnumFontFamiliesExW, CreateFontIndirectW, CreateDIBSection, CreateBitmap, GetPaletteEntries, CreatePalette, GetRegionData, CreateRectRgn, ... (+16)
- **IMM32.dll** (9): ImmGetContext, ImmReleaseContext, ImmAssociateContext, ImmGetCompositionStringW, ImmSetCompositionFontW, ImmNotifyIME, ImmSetCompositionWindow, ImmSetCandidateWindow, ImmGetDefaultIMEWnd
- **WINMM.dll** (3): timeBeginPeriod, timeEndPeriod, PlaySoundW
- **d3d9.dll** (1): Direct3DCreate9
- **WS2_32.dll** (12): WSASocketW, WSASendTo, WSASend, WSARecvFrom, WSAAccept, WSAConnect, WSAHtonl, WSAHtons, WSANtohl, WSANtohs, WSAIoctl, WSARecv

### API capability groups found (api_cat features)

- `network`: recv, send, connect, WSAStartup, gethostbyname, socket
- `keylogging_hooks`: SetWindowsHookExW, GetAsyncKeyState, GetKeyboardState, GetKeyState
- `screen_capture`: GetDC, BitBlt, CreateCompatibleBitmap
- `privilege`: DuplicateTokenEx, OpenProcessToken, LookupPrivilegeValueW, AdjustTokenPrivileges
- `crypto`: CryptAcquireContextW, CryptGenRandom, CryptDecrypt
- `registry`: RegEnumKeyExW, RegDeleteKeyW, RegCreateKeyExW, RegOpenKeyExW, RegSetValueExW, RegDeleteValueW, RegOpenKeyExA
- `process_execution`: CreateProcessAsUserW, ShellExecuteW, ShellExecuteExW, CreateProcessW
- `dynamic_resolution`: LoadLibraryW, GetProcAddress, LoadLibraryExW, GetModuleHandleW, GetModuleHandleExW, GetModuleHandleA, LoadLibraryA
- `anti_debug`: GetTickCount, QueryPerformanceCounter, CheckRemoteDebuggerPresent, OutputDebugStringW, IsDebuggerPresent
- `file_enumeration`: FindFirstFileA, FindNextFileA, DeleteFileA, DeleteFileW, GetDriveTypeW, GetLogicalDrives, FindFirstFileW, MoveFileW
- `memory_protection`: VirtualAlloc
- `process_injection`: OpenProcess

### Notable strings (defanged)

- **URL:** `hxxp://www.w3.org/XML/1998/namespace`; `hxxp://www.w3.org/2000/xmlns/`; `hxxp://www.w3.org/2005/xpath-functions`; `hxxp://www.w3.org/1999/XSL/Transform`; `hxxp://www.w3.org/2005/xqt-errors`; `hxxp://www.w3.org/2005/xquery-local-functions`
- **IP address:** `255[.]255[.]255[.]255`; `3[.]7[.]7[.]1`; `127[.]0[.]0[.]1`; `1[.]3[.]5[.]7`; `0[.]0[.]0[.]0`; `1[.]3[.]6[.]1`
- **Registry:** `SOFTWARE\Net-SNMP`; `HKEY_LOCAL_MACHINE\Software\Classes\`; `HKEY_LOCAL_MACHINE\Software\Classes`; `HKEY_LOCAL_MACHINE\Software`; `HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\`; `HKEY_CURRENT_USER\`
- **Shell / LOLBin:** `wscript "%1"`; `powershell.exe`; `cmd.exe`
- **Crypto / ransom:** `encryption error`; `decryption error`; `encryption error.`; `encryption length error.`; `encrypted PDU`; `encrypted sPDU`
- **File path:** `c:\actions-runner2\_work\rgsupv-agent\rgsupv-agent\winpty-0.4.3\src\libwinpty\winpty.cc`; `c:\actions-runner2\_work\rgsupv-agent\rgsupv-agent\winpty-0.4.3\src\shared\backgrounddesktop.cc`; `c:\actions-runner2\_work\rgsupv-agent\rgsupv-agent\winpty-0.4.3\src\shared\buffer.cc`; `c:\actions-runner2\_work\rgsupv-agent\rgsupv-agent\winpty-0.4.3\src\shared\osmodule.h`; `c:\actions-runner2\_work\rgsupv-agent\rgsupv-agent\winpty-0.4.3\src\shared\stringutil.cc`; `c:\actions-runner2\_work\rgsupv-agent\rgsupv-agent\winpty-0.4.3\src\shared\windowssecurity.cc`

## 3. Behaviour indicated by code (Ghidra)

| Capability | Evidence (function address, API, string) | Visible in static features? (which) |
|---|---|---|
| Broad, application-like import set | Imports from WSOCK32/WS2_32 (sockets), USER32 (124), GDI32, ODBC32, d3d9, WTSAPI32, IPHLPAPI (ICMP ping), pdh (performance counters), dbghelp (MiniDumpWriteDump), CRYPT32 | api_cat groups: network, keylogging_hooks, screen_capture, privilege, crypto |
| Capabilities typical of remote-administration tools | `SetWindowsHookExW`/`GetAsyncKeyState` (input), `BitBlt`/`GetDC` (screen), `DuplicateTokenEx`/`CreateProcessWithLogonW`/`WTSQueryUserToken` (sessions/privileges), sockets | Visible in api_cat, **but not decompiled**: whether they serve a GUI framework or malicious logic was not established |

## 4. Feature decisions

| Feature / pattern | Decision (retain / prioritise / discard) | Reason |
|---|---|---|
| `api_cat:*` presence | **retain with context** | A large signed application imports many "suspicious" API groups; presence alone cannot separate it from a legitimate remote-administration tool (compare sample_07) |
| file size / import count | **retain** | Very large, signed, application-like binaries are a known disguise (trojanised or bundled software) |

## 5. Mutation resistance

- Importing many ordinary UI and network APIs dilutes capability features at no cost: a large, signed, application-like carrier gives malware camouflage.

## 6. Notes for the dissertation

Static triage only. The sample labelled Amadey is a 17.7 MB signed binary with ~600 imports spanning GUI, database, Direct3D, networking and session APIs, and it triggers five api_cat groups. Without decompilation it is not possible to tell whether these capabilities belong to a legitimate framework or to malicious logic, which is itself the point: capability counts from imports need context and do not by themselves establish malice. Decompiling the callers of SetWindowsHookExW and WSAConnect is left as future work.
