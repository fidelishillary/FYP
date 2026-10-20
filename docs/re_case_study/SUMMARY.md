# Reverse engineering case study: summary (FR-05, RQ2)

Eight files were chosen from the raw-file dataset by explicit criteria (`samples.csv`): native malware with rich imports, a packed sample, a ransomware component, a .NET sample, a Go sample, a false negative, an escalated benign file and a typical benign file. Samples 02–05 were analysed in Ghidra 12.1.4 inside the isolated VM; the two benign files (07, 08) were analysed with a pefile/capstone helper, and 08 was spot-checked in Ghidra (Memory Map, FUN_14000290c, FUN_140009944); 01 and 06 received static triage only. Each note records the model's view (SHAP), the structure, the evidence from code, feature decisions and mutation resistance.

| Note | File | Key finding | Lesson for the feature set |
|---|---|---|---|
| [sample_04](sample_04.md) | Vidar, UPX-packed | Full unpacking chain traced: entry sets RSI (compressed data, UPX1) and RDI (empty RWX UPX0); NRV loop decompresses; `VirtualProtect`; `JMP 0x5e000a2e0` to the OEP | **Prioritise W+X, empty-on-disk sections and section entropy**; import features cannot see packed behaviour |
| [sample_03](sample_03.md) | WannaCry launcher DLL | Extracts a 5.2 MB resource to disk (`FUN_180001014`) and runs it hidden with SW_HIDE + CREATE_NO_WINDOW (`FUN_1800010f8`); **no crypto code at all** | `api_cat:crypto` misses ransomware components; **propose a resource-to-file ratio feature and a "drop & execute" API-chain group** |
| [sample_05](sample_05.md) | AgentTesla (.NET) | Only native code is a 6-byte `JMP [_CorExeMain]` thunk; behaviour is in CIL bytecode; `.text` entropy 7.9 | **Explains why api_cat is empty for 56% of malware**; propose .NET metadata features (future work) |
| [sample_02](sample_02.md) | "LummaStealer", actually a Go program | Its 8.0-entropy sections are **zlib-compressed DWARF debug data**, not packing; no W+X; likely a Go loader for Lumma (label noise) | `sec:entropy_max` gives **false packing signals**; **measure entropy over executable sections only** |
| [sample_07](sample_07.md) | Benign `PhotoAcq.dll` (escalated without artefacts) | Registry writes = photo settings; BitBlt/GetDC = UI drawing; `runas` = UAC relaunch; high `.rsrc` entropy = 73 icons + 13 PNGs | Capability groups are **evidence only in context**; resource entropy is not code entropy |
| [sample_08](sample_08.md) | Benign `IMEWDBLD.EXE` | `IsDebuggerPresent` sits in WIL logging helpers; `EncryptFileW` protects dictionary copies; classified benign mainly via build artefacts | `api_cat:anti_debug` is weak; **discard toolchain artefacts** |
| [sample_01](sample_01.md) | "Amadey", 17.7 MB signed binary (triage) | ~600 imports across GUI, sockets, sessions; five api_cat groups | Capability presence cannot separate malicious from legitimate remote-admin software without code context |
| [sample_06](sample_06.md) | Unlabelled false negative (triage) | Looks like a signed Rust desktop application; nothing malware-specific statically | Fundamental static limit: such files should be **escalated, not cleared** (motivates the hybrid gate) |

## Decisions recorded in the RE review files

| Decision | Features | Evidence |
|---|---|---|
| Prioritise | `sec:n_wx`, section entropy (with W+X), `api_cat:dynamic_resolution` with few imports | sample_04 |
| Retain, interpret in context | `api_cat:*` groups | sample_03, 04 (support); 05, 07, 08 (limits) |
| Discard | build artefacts: `hdr:checksum*`, linker/OS versions, `hdr:dllchar_*`, `meta:has_debug`, `meta:has_signature`, … | sample_07, 08; run `raw_no_artifacts` |
| Proposed new features (future work) | resource-to-file size ratio; "drop & execute" API chain; entropy of executable sections only; .NET metadata features | sample_03, 02, 05 |

## Answer to RQ2 (draft)

Reverse engineering identifies which static features reflect behaviour that is costly to change: write+execute memory, empty-on-disk sections and section entropy follow directly from the unpacking mechanism. It also shows where popular features mislead: compressed debug data inflates entropy, benign software imports "suspicious" APIs for ordinary reasons, and toolchain artefacts separate publishers rather than intent. Combined with the measurements (EMBER: RE-guided selection recovered about half of the accuracy lost by statistical top-300 selection; raw track: removing artefacts costs ~2 points but removes the shortcut), the case study supports an RE-guided feature set that prioritises structural evidence, treats capability features as contextual, and discards build artefacts.
