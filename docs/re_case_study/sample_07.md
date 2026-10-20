# RE note: sample_07

| Field | Value |
|---|---|
| SHA-256 | `3eb01639b7313743e14084dba0fe99e20e34769edb8dbae2072ec6502df0b4bf` |
| Label / family | benign / benign: PhotoAcq.dll |
| Why chosen | benign but escalated: Benign file scored p=0.67: what looks suspicious about it? |
| Source and date obtained | Clean Windows 11 install (benign_manifest.csv) |
| Analysed on (date, VM snapshot) | 2026-10-20; benign file, so resources and call sites were extracted with a pefile/capstone helper on Windows; to be confirmed in Ghidra (VM snapshot `dataset-ready`) |
| Tools | Ghidra 12.1.4; pefile + capstone (x86) helper; pemd run `20261020-024822_raw` |

## 1. Static pipeline view (auto-filled)

- In run `raw_no_artifacts`: p(malware) = 0.67, so **escalated** (the reason this file was chosen). With all features (below) the artefacts pull it back to benign.
- **p(malware) = 0.2362**, route **benign** (gate: benign < 0.34, malware >= 0.5), model `xgboost`
- Explanation method: TreeSHAP (xgboost pred_contribs)

| Feature | Value | Contribution |
|---|---|---|
| `hdr:checksum_zero` | 0 | -1.678 |
| `meta:has_debug` | 1 | -0.715 |
| `meta:overlay_ratio` | 0 | +0.711 |
| `hdr:subsystem_gui` | 1 | +0.489 |
| `hdr:dllchar_guard_cf` | 1 | -0.474 |
| `op_h:64` (add xor, je push) | 0.00109 | +0.469 |
| `op_h:151` (mov mov, movdqa mov) | 0.00837 | -0.467 |
| `hdr:major_subsystem_version` | 10 | -0.352 |
| `imp_fn_h:347` (api-ms-win-crt-runtime-l1-1-0.dll:_initterm, kernel32.dll:getnativesysteminfo) | 1 | -0.347 |
| `sec:virtual_size_mean` | 3.36e+05 | +0.343 |

## 2. Structure (auto-filled, then checked in Ghidra)

- Machine: x86 (32-bit); type: DLL; **native code**
- File size 1680384 bytes, overall entropy 6.94; overlay 0 bytes
- TLS callbacks directory: yes; Authenticode signature: no; resources: yes

| Section | Raw size | Virtual size | Entropy | Flags | Entry point |
|---|---|---|---|---|---|
| `.text` | 667648 | 667154 | 6.38 | R-X | yes |
| `.data` | 3072 | 6400 | 2.79 | RW- |  |
| `.idata` | 20480 | 20078 | 5.74 | R-- |  |
| `.rsrc` | 949760 | 949344 | 7.00 | R-- |  |
| `.reloc` | 38400 | 37896 | 6.70 | R-- |  |

- Packed? **No.** No W+X section, 704 imports, entry point in `.text`. The high `.rsrc` entropy (7.00, 949 KB) is **compressed image data**: 73 icons (662 KB) and 13 PNG images (193 KB) for the photo-import UI, plus a type library (75 KB) and 7 COM registration scripts (REGISTRY resources). It is not an encrypted payload.

### Imports

- **api-ms-win-crt-string-l1-1-0.dll** (4): wcspbrk, memset, wcscspn, wcsspn
- **api-ms-win-crt-runtime-l1-1-0.dll** (2): _initterm_e, _initterm
- **api-ms-win-crt-private-l1-1-0.dll** (54): _o__purecall, _o__recalloc, _o__register_onexit_function, _o__seh_filter_dll, _o__wcsicmp, _o_bsearch, _o_calloc, _o_ceil, _o_floor, _o_free, memmove, _o_iswgraph, _o_iswprint, _o_iswspace, _o_malloc, _o_qsort, _o_terminate, _o_towlower, _o_towupper, _o_wcscat_s, _o_wcscpy_s, _o_wcsncpy_s, _o_wcstok, _o_wcstol, _o_wcstoul, ... (+29)
- **ADVAPI32.dll** (20): RegCloseKey, RegQueryInfoKeyW, RegEnumKeyExW, RegOpenKeyExW, RegSetValueExW, RegEnumValueW, RegCreateKeyExW, RegDeleteValueW, TraceEvent, GetTraceLoggerHandle, GetTraceEnableLevel, GetTraceEnableFlags, RegisterTraceGuidsW, UnregisterTraceGuids, EventWriteTransfer, EventRegister, EventUnregister, RegQueryValueExW, InitializeAcl, TreeResetNamedSecurityInfoW
- **GDI32.dll** (45): DeleteObject, SetBkMode, SetDIBitsToDevice, SetBkColor, CreateSolidBrush, GetObjectW, CreateFontIndirectW, SelectObject, DeleteDC, GetDeviceCaps, CombineRgn, CreateRectRgnIndirect, GetLayout, SetLayout, SaveDC, RestoreDC, CreateDIBSection, CreateCompatibleDC, CreateHalftonePalette, SelectPalette, RealizePalette, SetBrushOrgEx, SetStretchBltMode, StretchBlt, CreatePen, ... (+20)
- **gdiplus.dll** (115): GdipCreateLineBrushFromRect, GdiplusStartup, GdiplusShutdown, GdipSetStringFormatHotkeyPrefix, GdipSetStringFormatFlags, GdipGetStringFormatFlags, GdipSetStringFormatTrimming, GdipDisposeImage, GdipFree, GdipAlloc, GdipCloneImage, GdipGetSmoothingMode, GdipSetSmoothingMode, GdipDeleteGraphics, GdipCreateBitmapFromScan0, GdipCreatePath, GdipAddPathArcI, GdipAddPathLineI, GdipClosePathFigure, GdipCreateBitmapFromStream, GdipCreateFont, GdipCreateFontFamilyFromName, GdipDeleteFontFamily, GdipGetGenericFontFamilySansSerif, GdipStringFormatGetGenericTypographic, ... (+90)
- **KERNEL32.dll** (132): GetLocalTime, ExpandEnvironmentStringsW, IsWow64Process, CreateProcessW, FindResourceW, SetFilePointer, GetFileSize, ReadFile, SetEndOfFile, QueryPerformanceFrequency, GlobalAddAtomW, GlobalDeleteAtom, lstrlenW, GetSystemDirectoryW, GetFileAttributesExW, GetProcessMitigationPolicy, GetModuleHandleExW, GetLastError, SizeofResource, IsDebuggerPresent, InitializeSListHead, QueryPerformanceCounter, WaitForSingleObjectEx, InitializeCriticalSectionAndSpinCount, TerminateProcess, ... (+107)
- **ole32.dll** (57): HICON_UserUnmarshal, HBITMAP_UserSize, HWND_UserUnmarshal, HWND_UserFree, HICON_UserMarshal, HBITMAP_UserMarshal, HWND_UserSize, HICON_UserFree, HBITMAP_UserUnmarshal, HICON_UserSize, HWND_UserMarshal, HBITMAP_UserFree, NdrProxyForwardingFunction18, NdrProxyForwardingFunction17, ObjectStublessClient12, NdrProxyForwardingFunction14, NdrProxyForwardingFunction15, NdrProxyForwardingFunction20, ObjectStublessClient11, NdrProxyForwardingFunction8, ObjectStublessClient22, ObjectStublessClient18, NdrProxyForwardingFunction16, ObjectStublessClient23, NdrProxyForwardingFunction19, ... (+32)
- **OLEAUT32.dll** (23): SysStringByteLen, SysAllocStringByteLen, VariantCopy, LoadRegTypeLib, VariantTimeToSystemTime, SysStringLen, SysFreeString, BSTR_UserSize, BSTR_UserFree, LPSAFEARRAY_UserSize, LPSAFEARRAY_UserFree, LPSAFEARRAY_UserUnmarshal, BSTR_UserUnmarshal, BSTR_UserMarshal, LPSAFEARRAY_UserMarshal, VarUI4FromStr, SysAllocString, SysAllocStringLen, VariantInit, VariantClear, UnRegisterTypeLib, LoadTypeLib, RegisterTypeLib
- **OLEACC.dll** (3): CreateStdAccessibleProxyW, LresultFromObject, AccessibleObjectFromWindow
- **PROPSYS.dll** (5): PSFormatForDisplayAlloc, InitVariantFromBuffer, VariantToPropVariant, PSGetPropertyKeyFromName, PropVariantChangeType
- **RPCRT4.dll** (11): NdrDllCanUnloadNow, NdrDllGetClassObject, NdrDllRegisterProxy, IUnknown_AddRef_Proxy, NdrOleFree, NdrOleAllocate, NdrStubForwardingFunction, NdrStubCall2, IUnknown_Release_Proxy, IUnknown_QueryInterface_Proxy, NdrDllUnregisterProxy
- **SETUPAPI.dll** (5): SetupDiOpenDeviceInterfaceW, SetupDiGetDeviceInterfaceDetailW, SetupDiOpenDevRegKey, SetupDiDestroyDeviceInfoList, SetupDiCreateDeviceInfoList
- **SHELL32.dll** (22): ord747, ord18, SHGetFileInfoW, SHGetPropertyStoreForWindow, ord68, SHGetSpecialFolderPathW, SHBindToParent, ord4, SHParseDisplayName, ord2, ord644, ord645, ShellExecuteExW, SHGetPathFromIDListW, CommandLineToArgvW, DragQueryFileW, SHGetDesktopFolder, SHCreateItemWithParent, SHChangeNotify, ord152, ord155, SHBrowseForFolderW
- **SHLWAPI.dll** (32): SHRegGetValueW, PathIsRootW, StrCSpnW, PathIsDirectoryW, PathAppendW, PathAddBackslashW, PathFileExistsW, StrRetToBSTR, StrCmpNIW, ord158, StrRetToBufW, PathFindExtensionW, SHStrDupW, StrStrW, PathFindFileNameW, PathRemoveExtensionW, PathParseIconLocationW, PathStripToRootW, PathSkipRootW, PathFindNextComponentW, PathRemoveBackslashW, SHCreateStreamOnFileEx, StrToInt64ExW, PathRemoveFileSpecW, StrCmpW, ... (+7)
- **STI.dll** (1): StiCreateInstanceW
- **USER32.dll** (144): IsWindowEnabled, GetParent, RemovePropW, SetWindowTextW, SetPropW, EnumWindows, SetForegroundWindow, GetPropW, GetDlgItem, GetCursor, SetCursor, LoadCursorW, OffsetRect, GetClientRect, GetSysColorBrush, IntersectRect, MapWindowPoints, GetWindowRect, GetSysColor, EndDialog, MapDialogRect, GetWindowTextW, UnregisterDeviceNotification, RegisterDeviceNotificationW, GetActiveWindow, ... (+119)
- **WINMM.dll** (1): PlaySoundW
- **PhotoBase.dll** (16): ??0Exception@Base@@QAE@ABV01@@Z, ??0Exception@Base@@IAE@J@Z, ?GdiplusStatusToHresult@Base@@YGJH@Z, ?AddToStream@Sqm@@YGXKK@Z, ?AddToStream@Sqm@@YGXKKK@Z, ?Delete@BasePrivate@@YAXPAX@Z, ?New@BasePrivate@@YAPAXI_N@Z, ?BaseAtlThrow@ATL@@YGXJ@Z, ?Throw@Base@@YGXJ@Z, ??1Exception@Base@@UAE@XZ, ??BException@Base@@QBEJXZ, ?GetBaseStringManager@String@Base@@SGAAVCAtlStringMgr@ATL@@XZ, ?ThrowLastError@Base@@YGXXZ, ?IsEnabled@Sqm@@YG_NXZ, ?AddToStream@Sqm@@YGXKPBG@Z, ?Initialize@Base@@YGXXZ
- **dwmapi.dll** (1): DwmIsCompositionEnabled
- **UxTheme.dll** (8): GetThemeFont, CloseThemeData, OpenThemeData, GetThemeMargins, GetThemePartSize, DrawThemeBackground, GetThemeColor, SetWindowTheme
- **VERSION.dll** (3): GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW

### API capability groups found (api_cat features)

- `registry`: RegEnumKeyExW, RegOpenKeyExW, RegSetValueExW, RegCreateKeyExW, RegDeleteValueW
- `screen_capture`: CreateCompatibleBitmap, BitBlt, GetDC
- `process_execution`: CreateProcessW, ShellExecuteExW
- `dynamic_resolution`: GetModuleHandleExW, LoadLibraryExA, LoadLibraryA, LoadLibraryW, LoadLibraryExW, GetModuleHandleW, GetModuleHandleA, GetProcAddress
- `anti_debug`: IsDebuggerPresent, QueryPerformanceCounter, GetTickCount, OutputDebugStringA
- `memory_protection`: VirtualAlloc
- `file_enumeration`: MoveFileW, FindNextFileW, FindFirstFileW, DeleteFileW, MoveFileExW, GetDriveTypeW
- `keylogging_hooks`: GetForegroundWindow, GetKeyState

### Notable strings (defanged)

- **IP address:** `5[.]1[.]0[.]0`; `6[.]0[.]0[.]0`
- **Shell / LOLBin:** `rundll32.exe "%MODULE%",AutoplayComServerW {00f2b433-44e4-4d88-b2b0-2698a0a91dba}'`
- **File path:** `X:\:`:d:h:l:p:t:x:/:`; `T:\:h:p:`

## 3. Behaviour indicated by code (Ghidra)

| Capability | Evidence (function address, API, string) | Visible in static features? (which) |
|---|---|---|
| Registry writes | `RegSetValueExW` in 11 functions, e.g. FUN_10062db0 (`Software\Microsoft\Windows\CurrentVersion\Photo Acquisition`: `FilenameTemplate`, `AcquisitionFlags`), FUN_10048cc4 (window size `PhotoPickerCustSelectWindowWidth`), FUN_1003f900 (`DestinationMru`, `MruEntry%d`); FUN_100134fa handles ATL COM registration (`ForceRemove`, `NoRemove`) | `api_cat:registry` = 5, but it **stores user settings and recent-folder lists**, not persistence |
| Screen / bitmap APIs | `BitBlt`, `GetDC`, `CreateCompatibleBitmap` in UI drawing code (FUN_10061dc0 with GDI+ and halftone palettes; FUN_1006e2f6 drawing themed `BUTTON`s; GetDC callers set dialog fonts for `SysLink`, `msctls_progress32`, `tooltips_class32`) | `api_cat:screen_capture` = 3, but it **draws thumbnails and dialogs**, not screen capture |
| Elevated relaunch | FUN_100683d8: `ShellExecuteExW` with verb `runas` + `CreateProcessW` + `AllowSetForegroundWindow` (shows the UAC prompt to restart with admin rights) | `api_cat:process_execution`; a **dual-use** pattern malware also uses for privilege escalation |
| Device properties | FUN_10020352: `ShellExecuteExW` with verb `properties` on the shell path `::{20D04FE0…}\::{35786D3C…}` (This PC → Portable Devices) and `PortableDeviceIsMassStorage` | `api_cat:process_execution`; opens a camera's Properties dialog |

## 4. Feature decisions

| Feature / pattern | Decision (retain / prioritise / discard) | Reason |
|---|---|---|
| `api_cat:registry`, `api_cat:screen_capture`, `api_cat:process_execution` | **retain, never use alone** | All three are present in this benign file for ordinary UI and settings reasons; their *combination* with other evidence (packing, few imports) matters, not their presence |
| `sec:entropy_max` / `.rsrc` entropy | **retain with context** | 7.0 here comes from PNG and icon resources; entropy should be read per *code* section, not resources |
| `meta:n_resources`, resource size | **retain** | Large, structured resource trees (icons, typelib, version info) are typical of genuine applications; contrast with sample_03 where one huge opaque resource is the payload |
| Build artefacts (`hdr:checksum_zero`, `meta:has_debug`, `hdr:dllchar_guard_cf`) | **discard** | They push this file to benign (−1.68, −0.72, −0.47); without them it is escalated, so the model's confidence came from *who built it* |

## 5. Mutation resistance

- **API capability groups:** these APIs are so common in benign software that malware gains camouflage by importing many ordinary UI APIs (as sample_01 appears to). Cost: near zero, so presence-based features are easy to dilute.
- **Resource entropy:** malware can hide an encrypted payload among legitimate-looking images. Separating *code-section* entropy from *resource* entropy makes this harder to exploit.
- **Build artefacts:** trivially copied (valid checksum, debug directory), which is why a model that depends on them is fragile.

## 6. Notes for the dissertation

This benign Microsoft component triggers three API-capability groups (registry, screen capture, process execution) and has a high-entropy resource section. Yet code inspection shows ordinary purposes: saving photo-import settings, drawing the UI, relaunching elevated via UAC, and opening device properties. Without build-artefact features it is escalated (p = 0.67), which is the correct gate behaviour for an ambiguous file and exactly the case the hybrid design sends to dynamic analysis. Lesson for RQ2: capability features carry evidence only in context, and entropy must be measured on code, not on resources.
