# RE note: sample_02

| Field | Value |
|---|---|
| SHA-256 | `c5b47b6fb38693695b05ccabc05abb68ca5a620590eaf068c93da0f7f03bd66a` |
| Label / family | malware / LummaStealer |
| Why chosen | native, packed/encrypted: Highest section entropy in its family: packing and runtime API resolution |
| Source and date obtained | MalwareBazaar (see data/raw/malwarebazaar_metadata.csv) |
| Analysed on (date, VM snapshot) | 2026-10-20, Ghidra session in the isolated VM (snapshot `dataset-ready`) |
| Tools | Ghidra 12.1.4 (CodeBrowser: Memory Map, Symbol Tree, references, decompiler), pemd run `20261020-024822_raw` |

## 1. Static pipeline view (auto-filled)

- **p(malware) = 0.9997**, route **malware** (gate: benign < 0.34, malware >= 0.5), model `xgboost`
- Explanation method: TreeSHAP (xgboost pred_contribs)

| Feature | Value | Contribution |
|---|---|---|
| `hdr:checksum_zero` | 1 | +2.116 |
| `meta:has_debug` | 0 | +1.190 |
| `meta:overlay_ratio` | 0 | +0.880 |
| `hdr:is_dll` | 0 | +0.754 |
| `meta:has_version_info` | 0 | +0.720 |
| `hdr:subsystem_gui` | 0 | -0.585 |
| `sec:virtual_size_mean` | 8.18e+05 | +0.304 |
| `op_h:151` (mov mov, movdqa mov) | 0.218 | +0.299 |
| `byte_hist:89` | 0.00152 | -0.257 |
| `byte_hist:125` | 0.00177 | +0.250 |

## 2. Structure (auto-filled, then checked in Ghidra)

- Machine: x86 (32-bit); type: EXE; **native code**
- File size 10416128 bytes, overall entropy 7.03; overlay 0 bytes
- TLS callbacks directory: no; Authenticode signature: no; resources: no

| Section | Raw size | Virtual size | Entropy | Flags | Entry point |
|---|---|---|---|---|---|
| `.text` | 3359744 | 3359250 | 6.07 | R-X | yes |
| `.rdata` | 3248128 | 3247664 | 5.92 | R-- |  |
| `.data` | 430592 | 649068 | 6.82 | RW- |  |
| `/4` | 512 | 331 | 5.58 | R-- |  |
| `/19` | 572416 | 572267 | 8.00 | R-- |  |
| `/32` | 99840 | 99420 | 7.98 | R-- |  |
| `/46` | 512 | 94 | 1.52 | R-- |  |
| `/65` | 1006592 | 1006517 | 8.00 | R-- |  |
| `/78` | 781312 | 781223 | 8.00 | R-- |  |
| `/90` | 226816 | 226400 | 7.94 | R-- |  |
| `.idata` | 1536 | 1100 | 3.87 | RW- |  |
| `.reloc` | 159744 | 159436 | 6.63 | R-- |  |
| `.symtab` | 527360 | 527347 | 5.39 | R-- |  |

- Packed? **No, despite entropy 8.0.** Ghidra's Memory Map resolves the long section names: `/4`=.zdebug_abbrev, `/19`=.zdebug_line (entropy 8.00), `/32`=.zdebug_frame (7.98), `/46`=.debug_gdb_scripts, `/65`=.zdebug_info (8.00), `/78`=.zdebug_loc (8.00), `/90`=.zdebug_ranges (7.94). These are **zlib-compressed DWARF debug sections** produced by the Go toolchain. Only .text is executable (entropy 6.07); .data/.idata are RW; no W+X section. The program is a 32-bit **Go** binary (strings `go.dev`, `crypto/tls`, `net/http`; Go packages in the Symbol Tree, incl. a non-standard package `apex2/Methods`).

### Imports

- **kernel32.dll** (44): WriteFile, WriteConsoleW, WerSetFlags, WerGetFlags, WaitForMultipleObjects, WaitForSingleObject, VirtualQuery, VirtualFree, VirtualAlloc, TlsAlloc, SwitchToThread, SuspendThread, SetWaitableTimer, SetUnhandledExceptionFilter, SetProcessPriorityBoost, SetEvent, SetErrorMode, SetConsoleCtrlHandler, ResumeThread, RaiseFailFastException, PostQueuedCompletionStatus, LoadLibraryW, LoadLibraryExW, SetThreadContext, GetThreadContext, ... (+19)

### API capability groups found (api_cat features)

- `memory_protection`: VirtualAlloc
- `dynamic_resolution`: LoadLibraryW, LoadLibraryExW, GetProcAddress
- `process_injection`: SetThreadContext

### Notable strings (defanged)

- **URL:** `hxxps://netedns0[::1]:53continue_gatewayshutdowninvalid`; `hxxps://go.dev/issue/66821):`; `hxxp://www.semrush.com/bot.html)Mozilla/4.0`; `hxxps://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)Mozilla/4.0`; `hxxp://www.google.com/bot.html)Mozilla/5.0`; `hxxp://dictionaryperceptionrevolutionfoundationpx;height:successfulsupportersmillenniumhis`
- **IP address:** `5[.]4[.]62[.]5`; `4[.]32[.]5[.]4`; `52[.]5[.]4[.]72`; `5[.]4[.]82[.]5`; `2[.]5[.]4[.]102`; `5[.]4[.]112[.]5`
- **Registry:** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zonestls: internal error: handshake should have had a resultnet/http: request c`
- **Crypto / ransom:** `decrypt`; `encrypt`; `decryptTicket`; `encryptTicket`; `encryptionKey`; `decryptionKey`
- **File path:** `n:\"identity\""; ObfuscatedTicketAge uint32 "json:\"obfuscated_ticket_age\"" }]`; `M:\:e:t:}:`; `T:\:w:`; `J:\:d:`; `P:\:n:`; `T:\:`:`

## 3. Behaviour indicated by code (Ghidra)

| Capability | Evidence (function address, API, string) | Visible in static features? (which) |
|---|---|---|
| Go program with own package | Symbol Tree lists standard Go packages (`encoding/json`, `bytes`, runtime `_rt0_386`) and a non-standard package `apex2/Methods` (author code); `main.main` at 0x733ad0 (not decompiled in this session) | Indirectly: byte_hist / op_h n-grams of Go code |
| Networking / TLS client | Strings `net/http`, `crypto/tls`, TLS session-ticket fields, `Mozilla/4.0` user agents | api_cat:network only partly: Go resolves most Windows APIs itself (44 imports, incl. LoadLibraryW/GetProcAddress) |
| Malware family | Labelled LummaStealer on MalwareBazaar, but Lumma itself is written in C; a Go binary with this label is most likely a **loader/crypter carrying Lumma**, not Lumma itself | Label noise is a threat to validity (family labels describe the final payload) |

## 4. Feature decisions

| Feature / pattern | Decision (retain / prioritise / discard) | Reason |
|---|---|---|
| `sec:entropy_max` alone | **retain, never alone** | Here 8.0 comes from compressed debug sections, a **false packing signal**; only W+X (absent here) or entropy of *executable* sections indicates packing |
| entropy of executable sections only (proposed) | **prioritise (proposed refinement)** | .text entropy 6.07 correctly shows this file is not packed |
| `api_cat:*` for Go programs | **weak** | Go's runtime loads most system functions dynamically, so the import table is small for benign and malicious Go programs alike |
| non-standard section names (`sec:n_nonstandard_names`) | **retain (weak)** | Go/MinGW tools produce `/NN` names legitimately |

## 5. Mutation resistance

- Entropy-based packing features are easily fooled in both directions: compressed debug data raises entropy without packing, and padding lowers it with packing. Restricting entropy to executable sections makes the feature harder to game.
- Rebuilding without debug sections (`-ldflags="-s -w"`) changes these features at zero cost to the author: a reminder that build options alone can shift static features.

## 6. Notes for the dissertation

This "LummaStealer" sample is a Go program whose highest-entropy sections (8.0) turned out, in Ghidra, to be zlib-compressed DWARF debug information, not a packed payload. Its executable code has ordinary entropy (6.07) and there is no W+X section. A feature that reads maximum section entropy as "packed" is therefore misled. The RE study motivates measuring entropy only over executable sections. The family label also illustrates label noise: Lumma is a C program, so this file is most likely a Go loader delivering it.
