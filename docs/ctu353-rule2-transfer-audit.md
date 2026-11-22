# Rule 2 transfer check on CTU-353

**Date:** 2026-11-15 (Europe/Moscow)  
**Purpose:** diagnostic transfer check of the small-payload, no-response UDP heuristic visible in the in-progress model experiment. This is not a release evaluation and does not authorize blocking.

## Frozen inputs and rule

- Capture: MCFP `CTU-Malware-Capture-Botnet-353-1`, `2018-05-07_capture.binetflow`.
- Capture SHA-256: `d52ca24afd42f8b12fc4f5fa6b563c3e789143dbedd509bd4cf483521c07f617`.
- Source labels: publisher's `ralabel-filters.conf` (SHA-256 `5b865794418c7b63eabb81de901168a89d33432dd2ecf07fc498f1a0ee6b7c36`).
- Rule 1: UDP, duration at least 1 second, and more than 4 packets.
- Rule 2: UDP, duration below 0.001 seconds, one-way byte asymmetry, and `log1p(total_bytes) < 5.501258373260498 - 0.5 * 1.4713478088378906`, equivalent to total bytes below approximately 116.4.
- The byte cutoff and behavior conditions are the values shown in the current experiment; they were motivated by inspection of CTU-53/54 and are therefore development-derived, not independently selected.

## Observed result

The capture has 53,372 rows: 34,041 publisher-labeled malware flows (`Malware-UDP-DNS` 25,657; `Malware-TCP` 8,384), one explicitly named Microsoft established-flow reference, and 19,330 background/ambiguous or unassigned rows. Background labels are excluded; they are not treated as benign.

- Rule 1 matched 0 of the 34,041 malware-labeled flows.
- Rule 2 matched 1,328 of 34,041 malware-labeled flows (3.90%).
- Rule 2 did not match the single labeled Microsoft reference flow.
- A false-positive rate cannot be estimated from one normal reference flow. The large background set cannot be used as a benign denominator.

## Interpretation

The heuristic's low recall on this additional real capture indicates that it describes a narrow CTU-53 behavior, not a general UDP threat rule. The published labels are rule-derived and this capture is a controlled malware lab, not the user's target network. The CTU-53/54 experiments also selected features and thresholds after looking at those captures; later use of the same captures for scoring is not an independent test. Keep this heuristic advisory/research-only. Do not enable blocking or claim release-gate success from this result.

Source directory: <https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-353-1/>  
Published label rules: <https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-353-1/ralabel-filters.conf>
