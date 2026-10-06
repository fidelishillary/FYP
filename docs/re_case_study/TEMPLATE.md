# RE note: sample_XX

| Field | Value |
|---|---|
| SHA-256 | |
| Label / family | |
| Source and date obtained | |
| Analysed on (date, VM snapshot) | |
| Tools | Ghidra x.y, pemd commit `...` |

## 1. Static pipeline view

Paste the output of `pemd scan` here: p(malware), route, and the top influential features with their tokens.

## 2. Structure

- Sections (name, entropy, permissions), entry point location:
- Packed? Packer or stub identified? How was it recognised?
- Overlay / embedded PE / resources of note:

## 3. Behaviour indicated by code

| Capability | Evidence (function address, API, string) | Visible in static features? (which) |
|---|---|---|
| e.g. process injection | `FUN_00401a20` calls VirtualAllocEx → WriteProcessMemory → CreateRemoteThread | yes: `api_cat:process_injection` |
| e.g. runtime API resolution | API-hash loop at `0x...` | partly: only `GetProcAddress` imported |

## 4. Feature decisions

| Feature / pattern | Decision (retain / prioritise / discard) | Reason |
|---|---|---|
| | | |

## 5. Mutation resistance

How would an attacker change this sample to evade each feature above, and what would that cost them in behaviour?

## 6. Notes for the dissertation
