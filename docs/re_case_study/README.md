# Reverse engineering case study (FR-05, RQ2)

**Goal:** use reverse engineering on a small, representative subset of samples to decide which static features reflect real, mutation-resistant behaviour (keep or prioritise) and which are superficial or easy to forge (discard). Then measure how those decisions affect detection.

## Workflow

1. **Choose samples.** Pick about 5 to 10 malware samples across the planned families (trojan, ransomware, worm, spyware, other), including at least one packed sample, plus 2 or 3 benign programs for contrast. Record each SHA-256 and its source.
2. **Get static facts from the pipeline first.** Inside the VM, run `pemd scan <file> --run-dir <run>` on each sample. This shows which features the model relies on.
3. **Analyse in Ghidra** (inside the VM). For each sample:
   - entry point and section layout: packed? unpacking stub? W+X sections?
   - imported APIs and how they are used: injection, persistence, crypto, network, anti-debugging
   - runtime-resolved APIs (`GetProcAddress` loops, hashed API names), which are invisible to the import table
   - strings: config, URLs, ransom notes; encrypted or plain?
4. **Decide for each feature or group:** retain, prioritise or discard, with a reason. Write the note using [TEMPLATE.md](TEMPLATE.md) as `sample_XX.md` in this folder. Use hashes only; never include binaries or dumps.
5. **Encode the decision** in `configs/re_feature_review.yaml`. Use a pattern, a rationale, and evidence that links the note.
6. **Measure the effect (RQ2).** Run the pipeline with and without the review and compare the metrics:
   ```bash
   pemd run --name with_re
   echo "selection: {re_review: null}" > /tmp/no_re.yaml
   pemd --config /tmp/no_re.yaml run --name without_re
   ```
   To test robustness, also compare on samples from families held out of training (FR-17).

## Starting hypotheses

These are the hypotheses currently in `re_feature_review.yaml`. Each one needs to be confirmed or rejected with evidence:

| Feature(s) | Hypothesis | Decision |
|---|---|---|
| `api_cat:*` | Capability groups survive repacking and re-compilation | prioritise |
| `sec:entropy_max`, `sec:n_wx` | Packed/self-modifying code is visible in section layout | prioritise |
| `hdr:timedatestamp` | Forgeable, and a source of temporal leakage | discard |
| `hdr:checksum` | Rarely set, no behavioural meaning | discard |
