# RE note: sample_04

| Field | Value |
|---|---|
| SHA-256 | `975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2` |
| Label / family | malware / Vidar |
| Why chosen | native infostealer: W+X sections / high entropy: unpacking stub evidence for sec:n_wx |
| Source and date obtained | MalwareBazaar (see data/raw/malwarebazaar_metadata.csv) |
| Analysed on (date, VM snapshot) | 2026-10-20, Ghidra session in the isolated VM (snapshot `dataset-ready`) |
| Tools | Ghidra 12.1.4 (CodeBrowser: Memory Map, Symbol Tree, references, decompiler), pemd run `20261020-024822_raw` |

## 1. Static pipeline view (auto-filled)

- **p(malware) = 0.9998**, route **malware** (gate: benign < 0.34, malware >= 0.5), model `xgboost`
- Explanation method: TreeSHAP (xgboost pred_contribs)

| Feature | Value | Contribution |
|---|---|---|
| `hdr:checksum_zero` | 1 | +2.256 |
| `meta:has_debug` | 0 | +1.080 |
| `meta:overlay_ratio` | 9.91e-05 | +0.844 |
| `hdr:is_dll` | 0 | +0.793 |
| `hdr:subsystem_gui` | 1 | +0.544 |
| `meta:has_version_info` | 0 | +0.542 |
| `op_h:151` (mov mov, movdqa mov) | 0.0181 | -0.374 |
| `sec:virtual_size_mean` | 9.02e+05 | +0.337 |
| `meta:overlay_size` | 37 | +0.215 |
| `meta:has_signature` | 0 | +0.214 |

## 2. Structure (auto-filled, then checked in Ghidra)

- Machine: x64 (64-bit); type: EXE; **native code**
- File size 373285 bytes, overall entropy 7.86; overlay 37 bytes
- TLS callbacks directory: no; Authenticode signature: no; resources: no

| Section | Raw size | Virtual size | Entropy | Flags | Entry point |
|---|---|---|---|---|---|
| `UPX0` | 0 | 2330624 | 0.00 | RWX |  |
| `UPX1` | 371712 | 372736 | 7.87 | RWX | yes |
| `UPX2` | 512 | 4096 | 1.35 | RW- |  |

- Packed? **Yes, UPX** (confirmed in Ghidra). Memory Map: `UPX0` 0x5e0001000-0x5e0239fff (2.3 MB, **RWX**, *uninitialised*: empty on disk), `UPX1` 0x5e023a000-0x5e0294fff (**RWX**, entropy 7.87, contains the entry point), `UPX2` (RW). Only 4 imports (LoadLibraryA, GetProcAddress, VirtualProtect, ExitProcess); no readable strings.

### Imports

- **KERNEL32.DLL** (4): LoadLibraryA, ExitProcess, GetProcAddress, VirtualProtect

### API capability groups found (api_cat features)

- `dynamic_resolution`: LoadLibraryA, GetProcAddress
- `memory_protection`: VirtualProtect

### Notable strings (defanged)

- (no notable strings in plain text; may be encrypted or packed)

## 3. Behaviour indicated by code (Ghidra)

| Capability | Evidence (function address, API, string) | Visible in static features? (which) |
|---|---|---|
| Packing / self-unpacking | `entry` (0x5e0294880, in UPX1): `LEA RSI,[DAT_5e023a025]` (compressed data in UPX1) and `LEA RDI,[RSI-0x239025]` = 0x5e0001000 (start of the empty UPX0) | Yes: sec:packer_name=1, sec:n_wx=2, sec:entropy_max=7.87, sec:n_zero_raw=1 |
| Decompression (UPX NRV) | `FUN_5e02948f0` (called from entry): loop 0x5e02948f5-0x5e0294909 reads compressed bytes from RSI and writes them with `MOV byte ptr [RDI],DL` into UPX0; `ADD EBX,EBX` / `ADC EBX,EBX` bit-reader = NRV decoder | Indirectly: the target section must be writable and executable (sec:n_wx) |
| Restore and transfer to original program (OEP) | 0x5e0294a7b `CALL VirtualProtect` (restore permissions) -> `POP RBP/RDI/RSI/RBX` -> stack-wipe loop 0x5e0294a8a-0x5e0294a91 -> **0x5e0294a95 `JMP 0x5e000a2e0`** = OEP inside UPX0 (bytes undefined statically) | api_cat:memory_protection=1; the real program is invisible statically |
| Runtime API resolution | Only LoadLibraryA/GetProcAddress imported; the stealer's real imports are rebuilt after unpacking | Partly: api_cat:dynamic_resolution=2 |

## 4. Feature decisions

| Feature / pattern | Decision (retain / prioritise / discard) | Reason |
|---|---|---|
| `sec:n_wx`, `sec:n_zero_raw` | **prioritise** | Unpacking requires writable+executable memory and an empty target section, directly tied to the observed behaviour |
| `sec:entropy_max` | **prioritise, with care** | 7.87 is real compression here, but sample_02 shows compressed *debug* data also reaches 8.0, so combine it with W+X |
| `sec:packer_name` | **retain (weak)** | Section names are free to change |
| `api_cat:dynamic_resolution` + very few imports | **prioritise** | 4 imports incl. LoadLibrary/GetProcAddress = the real API set is hidden |
| other `api_cat:*` groups | **cannot help for packed samples** | Capabilities appear only after unpacking |

## 5. Mutation resistance

- Section names: renaming UPX0/UPX1 costs nothing, so the feature is weak.
- W+X: avoiding it means unpacking into RW memory and then calling `VirtualProtect` (visible as `memory_protection`), or not packing at all. Costly to evade.
- Section entropy: padding can dilute *file* entropy, but the compressed section stays near 8. Fairly robust per section.

## 6. Notes for the dissertation

Static analysis sees only the UPX wrapper. The complete unpacking chain was traced in Ghidra: entry sets source (UPX1) and destination (the empty, RWX UPX0); the NRV loop decompresses the program into it; `VirtualProtect` restores permissions; and `JMP 0x5e000a2e0` transfers control to the original entry point. The stealer's behaviour is invisible until run time. The features that survive are structural (W+X, empty-on-disk section, high section entropy, minimal imports), which supports prioritising `sec:n_wx` and section entropy, and explains why import-based capability features cannot detect packed malware.
