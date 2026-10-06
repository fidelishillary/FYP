# Safety and lab setup

This covers NFR-01 (isolation), NFR-02 (prefer feature datasets), NFR-03 (snapshots) and NFR-08 (legal and ethical use), following report Sections 1.9 and 3.9.

## Ground rules

1. **No execution outside the sandbox.** `pemd` only parses and disassembles files. Live samples are executed only by the CAPE guest, and only when `dynamic.enabled: true`.
2. **Features before binaries.** Use EMBER and SOREL-20M feature vectors wherever they are enough. Download raw samples only for the reverse engineering case study and the end-to-end demonstration.
3. **No samples in git.** `.gitignore` blocks `data/raw`, `data/external`, executables and archives. Never force-add them. Never push samples, unpacked payloads, memory dumps or PCAPs anywhere.
4. **No creation or modification of malware.** Out of scope (PRD 4.2). Robustness checks use existing labelled variants only.

## Analysis VM

| Item | Setting |
|---|---|
| Hypervisor | VirtualBox on the Windows 11 host |
| Guest | Ubuntu 22.04, Python 3.11, this repository |
| Network | **Host-only adapter only** (e.g. `vboxnet0`, 192.168.56.0/24). No NAT and no bridged adapter while samples are present |
| Shared folders | Disabled. Clipboard and drag-and-drop disabled |
| Disk | Samples are kept in password-protected archives (the `infected` convention) and extracted only inside the VM |

To get dependencies in, install them **before** copying any samples, then switch the VM to host-only and take a snapshot. If you need to update later, revert to the clean snapshot, attach NAT, update, detach NAT, and snapshot again.

## Snapshots (NFR-03)

| Snapshot | When |
|---|---|
| `clean-base` | OS + Python environment installed, no samples, before host-only switch |
| `clean-isolated` | Host-only network set, tools verified, still no samples |
| `analysis-<date>` | Optional, after an analysis session, **only** if you need to keep state; otherwise revert to `clean-isolated` |

Revert to `clean-isolated` after every reverse engineering or dynamic session.

## CAPE sandbox (FR-14, optional)

- Run the CAPE host and its Windows guest on the same host-only network. The guest must not be able to reach the internet. If CAPE's routing is used, set it to `none` / drop.
- Set `dynamic.cape_url` to the CAPE host-only address. `pemd.dynamic.cape.assert_isolated` refuses URLs that resolve to a public IP.
- Export measured verdicts to `sha256,verdict,seconds` CSV and point `evaluation.dynamic_verdicts` at it so the hybrid evaluation uses measured, not assumed, results.

## Ghidra (FR-05)

Run Ghidra inside the analysis VM. Static analysis only. Do not attach the debugger to live samples outside the sandbox guest.

## Sample sources and licensing

| Source | Use | Notes |
|---|---|---|
| EMBER 2018 (feature vectors) | Main training/evaluation data | No binaries |
| SOREL-20M (feature vectors) | Optional extra data | Binaries are disarmed; still treat them as live |
| MalwareBazaar / VirusShare | A few recent raw samples for the RE case study | Requires an account; follow the terms of use; record SHA-256 only in the dissertation |
| Benign software | Clean installs of trusted, freely distributed software | Record name, version and source |

Record the SHA-256 hashes of all raw samples used, never the files themselves, so that examiners can obtain them independently.
