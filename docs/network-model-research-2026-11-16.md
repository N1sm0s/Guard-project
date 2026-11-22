# Network classifier research — 2026-11-16

Status: research only. No candidate in this note is approved for enforcement.

## Fixed rules

- Label only publisher `From-Botnet-*` as attack and `From-Normal-*` as benign.
- Exclude `Background`, `To-Background`, unknown labels, and invalid rows from both classes.
- Fit normalization on training captures only.
- Select model/threshold on validation only; do not inspect test labels during training or selection.
- Require the release gate on every independent test capture, then separately require target-network evidence.

## Weight experiment

`tools/train_v9.py` was rewritten to use whole capture groups 42–44 for training and capture 45 for validation. The script never opens capture 46 or later. It writes research-only checkpoints and a full validation threshold curve.

| Scheme | Validation recall | Validation FPR | 95% Wilson upper FPR | TP / FP |
|---|---:|---:|---:|---:|
| Natural | 45.58% | 0.0595% | 0.0982% | 1176 / 15 |
| Class balanced | 62.83% | 0.0357% | 0.0679% | 1621 / 9 |
| Class balanced, UDP attack multiplier 2 | 62.71% | 0% | 0.0152% | 1618 / 0 |

Artifacts: `outputs/network-eval/train-v9-validation-only/validation_weight_experiment.json` and `validation_curves.csv`.

The validation recall is below the 80% target.

## Model-family check

On the same 42–44 / 45 split at Wilson upper-FPR <= 0.1%, HistGradientBoosting with balanced weights reached 47.48% recall, a weighted HistGradientBoosting variant reached 45.81%, and balanced RandomForest reached 45.74%. None improved on the class-balanced MLP.

Artifact: `outputs/network-eval/train-v9-validation-only/model_family_comparison.json`.

## Expanded capture training

`tools/train_ctu13_expanded_groups.py` trained on complete captures 42–44 and 46–54; capture 45 remained a whole-group validation set. Unknown/background labels were excluded. The validation-selected point was recall 94.61%, FPR 0.0516%, and Wilson upper FPR 0.0883% (TP=2441, FP=13, FN=139, TN=25182). This is a promising validation result, not release evidence: capture 45 has participated in development and is not an independent test for this candidate.

Artifacts: `outputs/network-eval/train-ctu13-expanded-groups/validation_summary.json` and `validation_curve.csv`.

Per-label validation analysis for this expanded candidate showed 100% detection of the 812 labeled ICMP attack flows and 98.0% of UDP-Attempt flows, but 0% of `V45-TCP-CC73-Not-Encrypted` and 11.4% of UDP-DNS. This remaining class gap calls for broader real training data or better flow features.

## External transfer diagnostic

The expanded candidate was scored at its frozen CTU-45 threshold on available IoT-23 v2 files, excluding CTU Honeypot 7-1. Only flows with complete required fields were scored. Of 23,145 labeled rows in the malware capture, 17,824 with missing duration were excluded; therefore the evaluation has incomplete coverage and cannot close the release gate.

Among the 6,975 scored flows (4,318 attack and 2,657 benign), recall was 85.22% (95% CI 84.13–86.25%) and FPR 10.05% (95% CI 8.96–11.25%). This is far above the 0.1% FPR limit. The candidate fails transfer evaluation. IoT-23 has now been used for development diagnostics and is not a pristine final holdout for future iterations.

Artifact: `outputs/network-eval/train-ctu13-expanded-groups/iot23_transfer_diagnostic.json`.

## Next research actions

1. Resolve the feature-coverage issue explicitly: quantify missing duration by label/source and define a versioned missingness representation; do not silently impute or treat missing fields as benign.
2. Add more diverse, publisher-labeled real capture families to training and evaluate by whole-capture groups. Retain a new untouched source family for final transfer testing.
3. Inspect whether all training and runtime sensor features have the same definitions and directionality.
4. Keep enforcement disabled until each independent test capture meets recall/FPR confidence bounds and the target-network, sensor-loss, latency, and rollback gates are evidenced.

## Cross-capture IoT-23 follow-up (2026-11-16)

The v9 duration-missing feature retained all labeled rows, but it did not solve transfer between IoT-23 captures. All these are research/development results, not release evidence.

| Train / validation | Model | Validation result at upper FPR CI <= 0.1% | Finding |
|---|---|---|---|
| 34-1 / 3-1 | ExtraTrees, class-balanced | Recall 96.06%, lower 95% CI 95.97%; 0 FP / 4,536 benign; upper FPR CI 0.0846% | Strong development point; selected on this capture, so not independent |
| 34-1 / 35-1 | Same frozen v9 model/checkpoint | Recall 53.06%, lower CI 52.99%; FPR 99.915%, upper CI 99.917% | Fails both quality limits; confirms severe capture shift |
| 34-1 + sampled 35-1 / 3-1 | ExtraTrees | At the admissible point, recall 0%; 0 FP / 4,536 benign; upper FPR CI 0.0846% | More data did not create a useful operating point |
| 34-1 + 3-1 / sampled 35-1 | ExtraTrees | At the admissible point, recall 0%; 30 FP / 50,000 benign; upper FPR CI 0.0856%; ROC AUC 0.0017 | Strong reverse ranking on the new capture; feature distribution/semantics are not robust |

The 35-1 file was read-only evaluated once before it was promoted to development data. Its SHA-256 is `DDE3AC95A8DFE9C3308D92C9EB9AC75612E2AD1A34341F15351F525933F2DF3A`. The evaluated v9 candidate SHA-256 was `E0596D059B24DB089BF77879D9F7A2D558DDD1C33C2DF79DD99E0A6AA90E8A07`. The detailed one-pass report is `outputs/network-eval/experiment-iot23-domain-v9/35_1_one_pass_test.json`.

The additional v10 features (endpoint ports and observed TCP handshake flags) are defined in `integrityguard/network_flow_schema_v10.py` and are emitted as `features_v10` by the payload-free Pktmon flow aggregator; the active model remains unchanged. The IoT-23 v2 parsers also needed to support both publisher label layouts (tab-separated fields and labels packed into a trailing field); the unified runner now handles both and never maps unknown rows to benign.

After additional real captures were added, the multi-family v10 model (1-1, 8-1, 9-1, 34-1, 35-1 training; 3-1 validation) reached only 32.12% validation recall at 0 FP/4,536 benign (upper FPR CI 0.0846%; lower recall CI 31.88%; AUC 0.8115). In the reverse split (1-1, 3-1, 8-1, 9-1, 34-1 training; 35-1 validation), the ranking remained inverted (AUC 0.000704), and the admissible point had 0% recall. The large capture pair still does not yield a safe, useful cross-capture operating point.

Capture 36-1 (Okiru, distinct device scenario) was downloaded and its hash pinned before its one-pass evaluation. It is now consumed as a failed independent test; its local SHA-256 is `CEC2D4D3736A025694B0B272498CA9B672FD8D37D76E290B93C810E4DF73DC63`.

Training and candidate evaluation are controlled from one entry point: `tools/train_v9.py` (`--dataset iot23 --split ...` for whole-capture development runs; `--action evaluate --capture 60-1 --candidate ...` for the next one-pass independent evaluation). Consumed capture 36-1 is excluded from the current split configurations; 60-1 is the new pinned holdout.

Current result: **release gate not passed**. In addition to model quality failing on cross-capture evidence, the target-network labeled test, target-load P95, measured sensor-loss bound, and end-to-end block/audit/rollback evidence remain separate open gates.

## Continued model-family tests (2026-11-16)

The model remains under development. Capture 36-1 is consumed; capture 60-1 is pinned and unopened while development continues.

| Features / model | Validation operating point (Wilson upper FPR <= 0.1%) | AUC | Result |
|---|---:|---:|---|
| v10 / HistGradientBoosting | 0/151,567 attacks; 0 FP / 6,362 benign; upper FPR 0.0603% | 0.8264 | Safe point has zero recall |
| v10 / RandomForest (400 trees) | 0/151,567 attacks; 1 FP / 6,362 benign; upper FPR 0.0890% | 0.6452 | Safe point has zero recall |
| v11 / ExtraTrees | 4/151,567 attacks; 0 FP / 6,362 benign; upper FPR 0.0603% | 0.9122 | Not valid evidence: v11 offline context uses all flows in each 10-second bucket, including flows later than the scored flow. This is future-information leakage for a live detector. Do not compare/promote this result. |

The v11 context experiment was stopped for further training after identifying the look-ahead issue. Its artifact is retained for traceability but is explicitly disqualified. The unified runner now rejects v11; only causal, runtime-supported schemas v9 and v10 can be trained or evaluated. A future context schema must use strictly past-only information. The v10 tree-family runs provide no release candidate; the later one-pass evaluation below records the MLP result.

## CTU-SME-11 transfer failure and next reserved source family (2026-11-17)

A CTU-13 MLP candidate trained on captures 42–44 and 48–54 plus publisher-designated CTU-Normal-12 benign flows selected its threshold only on capture 45. On a hash-pinned, publisher-checksum-verified CTU-SME-11 Windows7AD-1 archive, it detected only 5 of 2,038 explicitly labeled malicious flows and falsely flagged 33,815 of 137,028 explicitly labeled benign flows. Recall was 0.245% (lower 95% Wilson bound 0.105%); FPR was 24.677% (upper bound 24.906%). This is a decisive transfer failure. The exact capture/checkpoint pair is consumed; Windows7AD-1 is now eligible only for development training.

The streaming trainer now maps that source's Zeek duration, packet counts, directional IP bytes, and protocol into the existing v8 contract. It checks the complete archive SHA-256 and Zenodo MD5, accepts only publisher labels `benign` and `malicious`, and excludes background, unknown, and incomplete-feature rows. The source-label audit found 175,146 explicitly labeled rows, 139,066 usable feature rows, and 45,474 total excluded rows (including 9,394 background/unknown and 36,080 explicit-label rows with incomplete features). It is trained as a separate whole-capture group, not confused with the CTU-13 scenarios.

CTU-IDSEVAL-6 was selected as the next independent source-family test. Its Zeek and label archives were downloaded without the raw pcaps; official MD5 and local SHA-256 values were recorded before scoring. The publisher describes six real captures with explicit `Benign`, `Malicious`, and `Background` flow labels. At reservation time the holdout was unopened to model inference, training, feature design, and threshold selection. The candidate and threshold were frozen before its one-pass evaluation. Background is excluded, never converted into benign.

## Frozen candidate and independent CTU-IDSEVAL-6 result (2026-11-17)

The next training run included the consumed Windows7AD-1 capture as development data, plus CTU-13 42–44 and 48–54 and publisher-labeled CTU-Normal-12. It used 903,216 usable explicit-label flows (438,626 attack; 464,590 benign), equal capture influence within each class, and the separate whole-capture validation set 45. The predeclared selection rule was maximum validation recall subject to 95% Wilson upper FPR <=0.1%.

The selected `balanced_udp_2x` checkpoint SHA-256 is `248bdb546629ea83abb1b04508f9d85fd8714280297dd19ff882eceb3d11a10b`; its validation threshold is `0.832389235496521`. Validation TP/FN=2,451/129 and FP/TN=10/25,185, yielding recall 95.00% and upper 95% CI FPR 0.0731%. This is a development operating point only.

Before inference, the candidate, threshold, run manifest, evaluator code, and holdout archive hashes were pinned in `outputs/network-eval/official-ctu-idseval-6/independent-test-registration.json`. The official Zenodo CTU-IDSEVAL-6 Zeek archive SHA-256 is `7350b5acfffbfd259266bf2f6ca1c3c7c721d80e59bc58502a8c82334a6f8065`; the publisher MD5 matched. The labels archive SHA-256 is `9cc26a52fc5076e691e6e32299fbf0c6a05d4290b1d0040fa50b65b1360e5822`. The one-pass evaluation included only explicit publisher `Benign` and `Malicious` rows, excluding Background/unknown.

The independent result fails decisively. On 29,718 scored attacks and 4,062 scored benign flows, TP/FN=11,910/17,808 and FP/TN=69/3,993. Recall was 40.08% (lower 95% Wilson bound 39.52%); FPR was 1.699% (upper bound 2.144%). Only 33,780/253,539 explicitly labeled rows (13.32%) had complete values for the current v8 feature adapter. The source-family transfer problem remains, and the feature coverage is too low for deployment. Individual capture counts and intervals are retained in the report.

This capture family is now consumed for this candidate and must not be used to retune it while retaining an independent-test claim. It may be moved into development data for a future candidate only after a different untouched source family is reserved. Report: `outputs/network-eval/train-v9-validation-only-focal1-lr0.0003-width128-epochs60-seed1907-add48-49-50-51-52-53-54-normal12-sme11-win7ad1-captureequal/ctu-idseval-6-one-pass-evaluation.json`.

## One-pass independent-capture evaluation (2026-11-16)

The v10 MLP trained on captures 1-1, 8-1, 9-1, 34-1, 35-1 and the available publisher-designated clean captures reached a development operating point on capture 3-1 of recall 80.69% (lower 95% Wilson bound 80.49%) at 0/4,536 false positives (upper bound 0.0846%). This met the single-capture development sample and quality thresholds, so that checkpoint snapshot was evaluated once on pinned capture 36-1 SHA-256 `CEC2D4D3736A025694B0B272498CA9B672FD8D37D76E290B93C810E4DF73DC63`.

The independent evaluation failed decisively: 0/13,642,435 malicious flows detected, 0/2,663 benign false positives, recall 0%, lower recall bound effectively 0%, and upper FPR bound 0.1440%. The capture does not meet the benign sample-size gate (minimum 3,000; at least 3,838 are needed for a zero-FP Wilson upper bound at or below 0.1%). The checkpoint SHA-256 is `2d9a7c47c9eafdb2c3c7a7ed9dc9d07d70defe14ccd4498ff0454b7d75489142`. The capture hash matched. This candidate fails transfer and is not promotable. Capture 36-1 is now consumed as an independent-test result and must not be used for tuning while retaining that test claim.

Artifact: `outputs/network-eval/iot23-unified/multifamily-to-3-v10-mlp/36-1-one-pass-evaluation.json`.

The subsequent reverse-domain development experiment trained the same v10 MLP family on 1-1, 3-1, 8-1, 9-1, 34-1 and publisher-designated clean captures, then sampled 100,000 attack and 100,000 benign flows from 35-1 for validation. At the maximum point meeting upper Wilson FPR <=0.1%, recall was only 3.07% (lower bound 2.97%; TP=3,074, FP=80, FN=96,926, TN=99,920); ROC AUC was 0.0315, indicating near-inverted ranking on this domain. Capture 35-1 is development data now and is not independent test evidence.

The 35-1 curve shows this is not fixed by merely relaxing the threshold: sampled recall remained 3.075% even at raw FPR 10% (9,993/100,000 benign false positives). The model scores are strongly scenario-dependent or inverted for this capture family.

Artifact: `outputs/network-eval/iot23-unified/multifamily-to-35-v10-mlp/summary.json`.

An apples-to-apples feature ablation on the same training/validation captures with v9 (without v10 endpoint/handshake features) improved 35-1 validation recall to 59.31% (lower 95% bound 59.00%) at 80/100,000 benign false positives (upper bound 0.0995%; TP=59,308, FN=40,692, TN=99,920). ROC AUC was 0.8005. This is a material recovery from v10's inverted ranking, but still below the 80% recall gate.

Artifact: `outputs/network-eval/iot23-unified/multifamily-to-35-v9-mlp/summary.json`.

Together, these results show that passing the 3-1 development gate does not generalize across IoT-23 device/scenario captures. The classifier is not release-ready; further iterations must target cross-capture robustness and retain a new sufficiently sized untouched test capture.

## Multi-capture threshold gate and additional Mirai training (2026-11-16)

The unified runner now supports one threshold selected to satisfy the Wilson upper-FPR limit separately on every validation capture, and records per-capture best points. A new `cross-family-3-35` split trains on 1-1, 8-1, 9-1, 34-1 and publisher-designated clean captures, then jointly validates on 3-1 and 35-1. This prevents a pooled FPR from hiding a capture-specific failure.

Capture 48-1 (Mirai) was downloaded from the official IoT-23 v2 source and added as training data. Its expert-labeled flow file contains 3,390,604 malicious and 3,734 benign rows; SHA-256 `9F69946243DF93C199876C0783CB4B5FB188E6D2325C593858F2DB8FB5FA847F`.

| Joint 3-1 + 35-1 validation model | Shared threshold | 3-1 recall | 35-1 recall | Per-capture FPR upper bounds | Finding |
|---|---:|---:|---:|---:|---|
| v9 MLP, without 48-1 training | 0.7258573 | 0.001% (1/100,000 sampled attacks) | 18.85% (18,850/100,000) | 0.0846%; 0.0038% | The shared safe threshold effectively suppresses 3-1 attacks |
| v10 MLP, with 48-1 training | 0.8681008 | 0.001% (1/100,000) | 20.24% (20,242/100,000) | 0.0846%; 0.0984% | Port/handshake features did not solve the domain gap |

Neither candidate passes the per-capture lower-recall gate. 48-1 did not fix the transfer problem; the underlying distributions remain incompatible at the required false-positive rate.

Artifacts: `outputs/network-eval/iot23-unified/cross-family-3-35-v9-mlp/summary.json` and `outputs/network-eval/iot23-unified/cross-family-3-35-train-48-v10-mlp/summary.json`.

Capture 60-1 (Gafgyt) is now the next independent holdout. The official source describes it as expert-labeled IoT network traffic. Its downloaded Zeek flow file was hashed but not parsed or used for training/validation: SHA-256 `4E15902F6C39B1FAD60605E667761B10C0C9866BEB514AA6320B7BAF108EA7C0`, 467,559,811 bytes. The one-pass evaluator is restricted to this capture. It remains unopened until a candidate meets both per-capture development recall/FPR criteria.

## CIC-IDS2017 Thursday one-pass diagnostic (2026-11-17)

The v9 candidate selected on validation capture 45 was frozen before inference on the full Thursday Working Hours Zeek-derived release. Candidate SHA-256: `dfcdbd97a586387919af9bf2a40b6480183fec7ada33ac71e4487db172b00f7a`; threshold: `0.842487275600433`; capture SHA-256: `f2b77777d65ad0843c413d31f17dc1712a1084daff86dcbceafc3471164317dc` (publisher MD5 matched). The 18.7 MB parquet contained 581,993 explicitly labeled rows: 88,815 attacks and 493,178 benign. All rows had sufficient selected features; unsupported/background rows were not relabeled as benign.

One-pass counts: TP/FN=46,991/41,824; FP/TN=8,264/484,914. Recall is 52.91% (95% Wilson lower bound 52.58%); FPR is 1.676% (95% Wilson upper bound 1.712%). Support is adequate, but both quality constraints fail substantially. Do not tune this candidate against this consumed capture and continue to call it an independent test.

The data are real PCAP-derived Zeek flows from a controlled testbed. The upstream CIC-IDS2017 page describes labels based on timestamps and connection identifiers, but the Zenodo-derived Zeek release does not document the exact row-level label-join script. Treat this as a research diagnostic, not release-promotion evidence. It is not a labeled capture of the user's target network. No enforcement was applied. Report: `outputs/network-eval/official-iscx2017-zeek/cic-ids2017-thursday-one-pass-diagnostic.json`; report SHA-256 `1aeef35dc9d0a56a4673a1118e41031f07d569406565a6d49458081240b7e899`.

## APEX-IDS2026 one-pass source-family diagnostic (2026-11-17)

The v9 candidate and validation-only threshold were frozen before scoring APEX-IDS2026 version 1.0.0 from Zenodo. Archive SHA-256 `67bd424cd1a9314fb0b54412ced5600ec8f1aeb7da380de26af26698e919e8ef`; publisher MD5 matched. The full 69,107,018-row Parquet was evaluated once: 42,205,903 `Attack_Verified` and 26,901,115 `Benign_Verified` flows. No other label was counted as benign. The source describes unidirectional NetFlow v9 from a live ISP edge; the adapter used duration, packet count, bytes and protocol only, mapping bytes to originator direction. The archive, candidate, threshold, and evaluator hash are registered before inference; the completed registration is `outputs/network-eval/official-apex-ids2026/candidate-evaluation-registration.json`.

At threshold `0.8424872756`, TP/FN=`41,053,826/1,152,077` and FP/TN=`8,412,698/18,488,417`. Recall was 97.270% (lower 95% Wilson bound 97.265%); FPR was 31.273% (upper bound 31.290%). Thus the FPR criterion is missed by more than two orders of magnitude. The per-flow Wilson intervals do not adjust for temporal or campaign dependence; per-day results are in the report.

This is a diagnostic, not release-promotion evidence: the publisher describes `Benign_Verified` as destination-validated traffic at 95%+ confidence, which cannot substantiate a 0.1% FPR bound, and the ISP feature distribution is not the user's target network. The result still provides strong evidence that this candidate's current feature/threshold behavior transfers poorly and must not be enabled for blocking. APEX is consumed for this candidate and must not be reused as an independent test after tuning on it. No training, threshold change, or enforcement followed this one-pass evaluation. Report: `outputs/network-eval/official-apex-ids2026/apex-high-confidence-one-pass-diagnostic.json`; SHA-256 `557ea2ea3bb8fec823a07597577158e4cd7002580ce3df9df57931afa52309d8`.

The registration now records the completed run, frozen hashes, failed gate result, and the first report-persistence attempt (inference completed, write failed due to Windows path length). The identical inference was repeated only to persist the report; checkpoint, threshold, and data were unchanged. The failed first write did not produce a separate metrics report.
