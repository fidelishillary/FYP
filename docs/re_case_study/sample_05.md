# RE note: sample_05

| Field | Value |
|---|---|
| SHA-256 | `3db1e114a5585f371b675171657d6d4fcb7c0fe78ee1ce7e8af8819b34516dcd` |
| Label / family | malware / AgentTesla |
| Why chosen | .NET malware: Import table is only mscoree!_CorExeMain: explains why api_cat is empty for 56% of malware |
| Source and date obtained | MalwareBazaar (see data/raw/malwarebazaar_metadata.csv) |
| Analysed on (date, VM snapshot) | 2026-10-20, Ghidra session in the isolated VM (snapshot `dataset-ready`) |
| Tools | Ghidra 12.1.4 (CodeBrowser: Memory Map, Symbol Tree, references, decompiler), pemd run `20261020-024822_raw` |

## 1. Static pipeline view (auto-filled)

- **p(malware) = 0.9998**, route **malware** (gate: benign < 0.34, malware >= 0.5), model `xgboost`
- Explanation method: TreeSHAP (xgboost pred_contribs)

| Feature | Value | Contribution |
|---|---|---|
| `hdr:checksum_zero` | 1 | +2.436 |
| `meta:has_debug` | 0 | +1.000 |
| `meta:overlay_ratio` | 0 | +0.898 |
| `hdr:is_dll` | 0 | +0.736 |
| `hdr:subsystem_gui` | 1 | +0.560 |
| `byte_hist:89` | 0.00344 | +0.510 |
| `byte_hist:125` | 0.00388 | -0.409 |
| `sec:virtual_size_mean` | 3.56e+05 | +0.387 |
| `op_h:151` (mov mov, movdqa mov) | 0 | -0.373 |
| `meta:has_signature` | 0 | +0.257 |

## 2. Structure (auto-filled, then checked in Ghidra)

- Machine: x86 (32-bit); type: EXE; **.NET assembly (CLR header present)**
- File size 1070592 bytes, overall entropy 7.75; overlay 0 bytes
- TLS callbacks directory: no; Authenticode signature: no; resources: yes

| Section | Raw size | Virtual size | Entropy | Flags | Entry point |
|---|---|---|---|---|---|
| `.text` | 999936 | 999936 | 7.90 | R-X | yes |
| `.rsrc` | 69632 | 69272 | 2.80 | R-- |  |
| `.reloc` | 512 | 12 | 0.10 | R-- |  |

- Packed? **Obfuscated .NET** (confirmed in Ghidra). The only native code is the 6-byte entry thunk `JMP dword ptr [MSCOREE.DLL::_CorExeMain]` at 0x4f6156; Memory Map shows Headers, `.text` (R-X, 0xf4200 bytes), `.rsrc`, `.reloc`, with no W+X. The 1 MB .text holds .NET metadata and CIL bytecode with entropy 7.90, consistent with an obfuscated or encrypted .NET payload.

### Imports

- **mscoree.dll** (1): _CorExeMain

### API capability groups found (api_cat features)

- none in the import table (normal for small benign files; in malware this points to runtime API resolution, packing or .NET - check in Ghidra)

### Notable strings (defanged)

- **IP address:** `16[.]0[.]0[.]0`; `4[.]0[.]0[.]0`; `1[.]0[.]0[.]0`

## 3. Behaviour indicated by code (Ghidra)

| Capability | Evidence (function address, API, string) | Visible in static features? (which) |
|---|---|---|
| Hand-off to the .NET runtime | `entry` (0x4f6156): `JMP [MSCOREE.DLL::_CorExeMain]`; decompiles to `_CorExeMain(); return;`, the only native code in the file | Only as imp:n_functions=1 and imp_dll_h(mscoree.dll) |
| Actual stealer behaviour (credential theft, exfiltration) | Not visible at PE level: implemented in CIL bytecode, which Ghidra's PE analysis does not decompile; plain-text strings are scarce (entropy 7.9) | No: every api_cat group = 0; byte histogram and entropy are the only content signals |

## 4. Feature decisions

| Feature / pattern | Decision (retain / prioritise / discard) | Reason |
|---|---|---|
| `api_cat:*` | **cannot help for .NET** | All zero for 56% of my malware (.NET); a limit of what native imports can show, not of the groups themselves |
| `imp:n_functions = 1` + `mscoree.dll` | **retain** (.NET indicator) | Identifies the file type; benign .NET programs share it (15% of benign files), so it is not malicious by itself |
| `.text` entropy (`sec:entropy_max` = 7.9) | **prioritise for .NET** | Plain .NET assemblies have moderate .text entropy; ~8 indicates obfuscation or encryption |
| .NET metadata features (referenced namespaces/methods, e.g. System.Net.Mail, System.Security.Cryptography) | **proposed future work** | The .NET equivalent of api_cat; needs a CLR metadata parser |

## 5. Mutation resistance

- Import features cannot be evaded further: there is nothing left to change.
- Entropy can be lowered by padding or lighter obfuscation, but then the bytecode becomes readable to .NET-aware analysis: a trade-off for the attacker.

## 6. Notes for the dissertation

For .NET malware the PE import table contains a single entry (mscoree.dll!_CorExeMain) and the only native code is a 6-byte thunk, as confirmed in Ghidra. All RE-guided API capability features are therefore zero, which explains their near-zero importance on the raw track, where 56% of the malware is .NET. Detection of these samples relies on byte-level and entropy features. A .NET-aware feature extractor (CLR metadata) is proposed as future work.
