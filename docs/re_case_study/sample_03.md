# RE note: sample_03

| Field | Value |
|---|---|
| SHA-256 | `67903b4fd435e1acb4a1f5f1320ccaf3a69bd6db9b6d0c8ccd59344362a286d1` |
| Label / family | malware / WannaCry |
| Why chosen | native ransomware: Well-documented behaviour (crypto, file enumeration): checks crypto/file api_cat |
| Source and date obtained | MalwareBazaar (see data/raw/malwarebazaar_metadata.csv) |
| Analysed on (date, VM snapshot) | 2026-10-20, Ghidra session in the isolated VM (snapshot `dataset-ready`) |
| Tools | Ghidra 12.1.4 (CodeBrowser: Memory Map, Symbol Tree, references, decompiler), pemd run `20261020-024822_raw` |

## 1. Static pipeline view (auto-filled)

- **p(malware) = 0.9934**, route **malware** (gate: benign < 0.34, malware >= 0.5), model `xgboost`
- Explanation method: TreeSHAP (xgboost pred_contribs)

| Feature | Value | Contribution |
|---|---|---|
| `meta:has_debug` | 0 | +2.659 |
| `hdr:checksum_zero` | 0 | -1.205 |
| `meta:has_version_info` | 0 | +1.138 |
| `meta:overlay_ratio` | 0 | +0.841 |
| `hdr:subsystem_gui` | 0 | -0.629 |
| `hdr:is_dll` | 1 | -0.515 |
| `op_h:64` (add xor, je push) | 0.00118 | +0.427 |
| `sec:virtual_size_mean` | 8.84e+05 | +0.380 |
| `op_h:151` (mov mov, movdqa mov) | 0.0949 | +0.308 |
| `byte_hist:204` | 0.00215 | +0.304 |

## 2. Structure (auto-filled, then checked in Ghidra)

- Machine: x64 (64-bit); type: DLL; **native code**
- File size 5298176 bytes, overall entropy 5.56; overlay 0 bytes
- TLS callbacks directory: no; Authenticode signature: no; resources: yes

| Section | Raw size | Virtual size | Entropy | Flags | Entry point |
|---|---|---|---|---|---|
| `.text` | 31744 | 31608 | 6.32 | R-X | yes |
| `.rdata` | 11264 | 11208 | 4.70 | R-- |  |
| `.data` | 5120 | 13920 | 1.82 | RW- |  |
| `.pdata` | 2048 | 1932 | 4.25 | R-- |  |
| `.rsrc` | 5243392 | 5243392 | 5.55 | R-- |  |
| `.reloc` | 3584 | 3240 | 0.00 | R-- |  |

- Packed? **No.** .text entropy 6.32, no W+X section, 71 ordinary imports. The DLL's own code is small (31 KB); 5.2 MB of the 5.3 MB file is a single resource (entropy 5.55) that contains the real payload.

### Imports

- **KERNEL32.dll** (71): CloseHandle, WriteFile, CreateFileA, SizeofResource, LockResource, LoadResource, FindResourceA, CreateProcessA, GetCurrentThreadId, FlsSetValue, GetCommandLineA, DecodePointer, UnhandledExceptionFilter, SetUnhandledExceptionFilter, IsDebuggerPresent, RtlVirtualUnwind, RtlLookupFunctionEntry, RtlCaptureContext, EncodePointer, TerminateProcess, GetCurrentProcess, RtlUnwindEx, FlsGetValue, FlsFree, SetLastError, ... (+46)

### API capability groups found (api_cat features)

- `process_execution`: CreateProcessA
- `anti_debug`: IsDebuggerPresent, QueryPerformanceCounter, GetTickCount
- `dynamic_resolution`: GetProcAddress, GetModuleHandleW, LoadLibraryW

### Notable strings (defanged)

- **Shell / LOLBin:** `cmd.exe /c "%s"`
- **File path:** `C:\%s\%s`; `C:\%s\qeriuwjhrf`

## 3. Behaviour indicated by code (Ghidra)

| Capability | Evidence (function address, API, string) | Visible in static features? (which) |
|---|---|---|
| Payload dropping | `FUN_180001014`: FindResourceA -> LoadResource -> LockResource -> SizeofResource; the first DWORD of the resource is the payload length; `CreateFileA(&DAT_18000d2a0)` + `WriteFile(hFile, resource+4, length)` writes the payload to disk. `DAT_18000d2a0` is an empty .data buffer filled at run time (path format `C:\%s\qeriuwjhrf`) | Partly: meta:has_resources=1, very large .rsrc; no api_cat group covers FindResource/LoadResource |
| Hidden execution | `FUN_1800010f8`: STARTUPINFO cleared (FUN_1800011f0, 0x60 bytes), `wShowWindow=0` (SW_HIDE), `dwFlags=0x81`; `CreateProcessA(NULL, &DAT_18000d2a0, ..., 0x08000000 CREATE_NO_WINDOW, ...)` runs the dropped file invisibly (call at 0x180001178), then closes both handles | api_cat:process_execution=1, but benign files use it too (sample_07) |
| Encryption (ransomware) | Not in this DLL: no crypto imports and no crypto code; encryption happens in the dropped payload | No: api_cat:crypto=0 for a ransomware component |

## 4. Feature decisions

| Feature / pattern | Decision (retain / prioritise / discard) | Reason |
|---|---|---|
| `api_cat:crypto` | **retain, but not sufficient** | A ransomware component with zero crypto imports: behaviour sits in the embedded payload |
| Resource size vs file size (~99% here) | **prioritise (proposed new feature)** | A single huge opaque resource is the payload container; genuine applications have many small resources (sample_07: icons and PNGs) |
| FindResource+LoadResource+SizeofResource **with** CreateFile/WriteFile + CreateProcess | **prioritise (proposed capability group "drop & execute")** | The chain *is* the dropper behaviour; each API alone is common |
| `api_cat:process_execution` | **retain with context** | Needed to launch the payload, but also used by benign software |

## 5. Mutation resistance

- Moving the payload from a resource into the overlay or .data, or encrypting it, defeats resource-size features cheaply, but size and entropy anomalies remain.
- Dropping and executing needs file-writing and process-creation APIs. Hiding them requires runtime API resolution, which then appears as `api_cat:dynamic_resolution` (see sample_04), so the chain is costly to remove completely.

## 6. Notes for the dissertation

This WannaCry component contains no encryption code: Ghidra shows it extracting a 5.2 MB resource to disk (`FUN_180001014`) and running it hidden with SW_HIDE and CREATE_NO_WINDOW (`FUN_1800010f8`), consistent with the WannaCry launcher DLL described in public analyses. Import-based capability features therefore miss the ransomware behaviour (api_cat:crypto = 0), while structural features (one dominant resource, ~99% of the file) and the drop-and-execute API chain capture it. The RE study motivates two new features: a resource-to-file size ratio and a drop-and-execute capability group.
