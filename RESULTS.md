# Preliminary results

*Status: 26 November 2026. Stages S0-S7 of the pre-registered protocol
([`docs/protocol_v0.3.md`](docs/protocol_v0.3.md), tag `prereg-v0.3`), plus
the exploratory stages S4x, S4y and the perturbation test. The 802.11 checks on
the raw captures (exploratory, started on 25 November) are in the journal and not
yet reported here. The first sections
describe the labels of AWID3; the later sections describe detectors trained on
them, their transfer to AWID2, a rule baseline and an imbalance probe.*

## Question

Public Evil Twin and Rogue AP detectors trained on AWID3 report near-perfect
scores. Before asking what these detectors learn, I checked what the labels
themselves encode. The AWID3 website publishes one Wireshark display filter
per attack; I measured how well these filters reproduce the labels.

## Main result: the labels follow the published filters

| | Rogue_AP | Evil_Twin |
|---|---|---|
| Frames in the capture | 1,973,185 | 3,778,679 (27 malformed rows excluded) |
| Frames labelled as attack | 1,310 | 104,827 |
| Agreement filter vs labels (Cohen's kappa) | **1.000** | **0.996** |
| Filter precision / recall | 1.000 / 1.000 | 0.998 / 0.994 |
| Labelled attack frames outside the filter's frame.number window | 0 | 0 |

Source: [`results/S1_filter_agreement.json`](results/S1_filter_agreement.json).
The pre-registered threshold for H1a was kappa >= 0.80.

## What the labels contain

**Rogue_AP** ([`figures/fig1_rogue_ap_capture.png`](figures/fig1_rogue_ap_capture.png))

- The rogue AP clones the legitimate AP: same SSID (`ASUS_5G`), same BSSID
  (`0c:9d:92:54:fe:34`).
- Every one of the 1,310 attack frames is a beacon of exactly **263 bytes**;
  the legitimate beacons are 342-343 bytes. No 263-byte beacon exists outside
  the attack window, so the label is recovered by beacon length alone.
- Beacon length is set by the attacker's software configuration: it is
  a fingerprint of this particular attack run, not of rogue APs in general.
- 62,455 unprotected deauthentication frames carrying the cloned address
  appear inside the attack window (1 outside). They start with the rogue
  beacons and none appear before; all are labelled Normal.

**Evil_Twin** ([`figures/fig2_evil_twin_capture.png`](figures/fig2_evil_twin_capture.png))

- The rogue AP uses the legitimate SSID with BSSID `0c:9d:92:54:fe:35`.
- **Every** labelled attack frame involves this MAC address; 95% also involve
  the IP `192.168.30.1`.
- The class is mostly **post-association data traffic** of victims connected
  to the rogue AP: QoS Data 95.9%, beacons 3.4%, deauthentication and
  disassociation 27 frames in total.
- A rule using only the time window, the rogue MAC address and the frame
  class reproduces the labels with kappa = 0.994.
- The rogue AP runs two beacon configurations in sequence (241 bytes, then
  150 bytes); legitimate beacons are 342-343 bytes.
- 208 rogue beacons (5.5%) are labelled Normal, in two contiguous blocks: 65
  just before the labelled attack period (the rogue AP is active about 69,000
  frames earlier) and 143 around frames 2.85-2.95 M.

Sources: [`results/S1c_label_diagnostics.json`](results/S1c_label_diagnostics.json)
(exploratory, not in the pre-registered plan),
[`results/S1d_figure_data.json`](results/S1d_figure_data.json).

## What this means, and what it does not

- On AWID3, the ground truth for Evil Twin and Rogue AP is a near-deterministic
  function of a few fields: a frame length, a position in the capture file
  (`frame.number`) and the attacker's addresses.
- A detector can therefore reach near-perfect scores on these classes by
  learning one attack run's fingerprint. Whether published detectors actually
  do this is the next step (H1b, H1c and RQ2 of the protocol).
- I do not claim that the AWID3 labels are wrong. Labelling by filter is a
  legitimate design choice; the point is what it implies for evaluation.
  Whether the labels were produced by the filters or the filters were written
  to match the labels cannot be told from the data.

## Reproducing

Data: AWID3 CSV release (University of the Aegean). Commands in
[`RUNBOOK.md`](RUNBOOK.md), stages S0-S1d. Every result file records the git
commit, the input SHA-256 and the run time.

## Do detectors learn the rule? (S3, pre-registered H1b and H1c)

Blocked evaluation: the attack period is cut into 5 consecutive blocks, each
held out in turn with a 10,000-frame gap; 5 model families, 5 seeds. Results
of the re-run with the folds corrected after the code review (purge around the
clean period, validation purged from the test block).

| | Rogue_AP | Evil_Twin |
|---|---|---|
| Depth-3 tree on the filter fields (mean PR-AUC) | 0.999 | 0.874 |
| Best model on all fields | 1.000 (RF) | 0.959 (RF) |
| H1b: depth-3 tree >= 95% of best | **supported** (99.9%) | not supported (91%) |
| H1c: removing the filter fields costs >= 20% for >= 3/5 models | not supported (1/5) | not supported (2/5) |

- On Rogue_AP, three questions on the fields of the labelling rule match the
  best detector.
- Removing those fields does not stop the strongest models (RF, XGB) from
  detecting either attack: the information is also present in other fields.
  Which ones, and whether they are artefacts or real protocol evidence, is the
  question of S4.
- On Evil_Twin, removing the filter fields multiplies the false-positive rate
  on clean traffic: XGB 0.018% -> 0.81%, RF 0.014% -> 0.31%, decision tree
  0.022% -> 20%.
- The first run, before the fold corrections, gave the same conclusions for
  H1b and H1c (`results/S3_label_rule_v1.json`, `results/S3_runs_v1.csv`).
  The scores on all fields now equal those of S4, which uses the same folds.
- The filter fields include `frame.number` but not the other fields that
  encode the position in the capture (relative and absolute times, capture
  timestamps), which stay in the "without filter fields" models.

Source: [`results/S3_label_rule.json`](results/S3_label_rule.json),
[`results/S3_runs.csv`](results/S3_runs.csv).

## Do detectors rely on capture artefacts? (S4, pre-registered H2a-H2c)

Five model families (LR, DT, RF, XGB, MLP), 5 seeds, the blocked protocol of
S3 and, for H2b, a random 80/20 split of the attack window. Four field sets:

- **F-all**: every usable field;
- **F-noA**: without capture artefacts (family A);
- **F-sem**: 802.11 semantic fields only (family S);
- **F-chatz**: the 16 expert features of Chatzoglou et al. (2022), as reused
  in later work.

Mean PR-AUC, blocked protocol:

| | Rogue_AP | Evil_Twin |
|---|---|---|
| F-all (RF / XGB) | 1.000 / 1.000 | 0.958 / 0.955 |
| F-noA (RF / XGB) | 1.000 / 1.000 | 0.969 / 0.960 |
| F-chatz (RF / XGB) | 1.000 / 1.000 | 0.918 / 0.984 |
| F-sem (RF / XGB) | 0.436 / 0.436 | 0.786 / 0.785 |

| Hypothesis | Rogue_AP | Evil_Twin |
|---|---|---|
| H2a: median ARS >= 0.25 **and** removing A costs >= 10% for >= 3/5 models | not supported (ARS 0.67; 1/5) | not supported (ARS 0.69; 0/5) |
| H2b: random split gives higher PR-AUC **and** higher ARS | not supported (PR-AUC 0.844 vs 0.844) | not supported as a whole: PR-AUC 0.998 vs 0.898 (p = 8.5e-16), ARS not higher (p = 0.20) |
| H2c: ranking of families stable across seeds (tau >= 0.6) | supported (0.82-1.00) | supported (0.83-1.00) |

- **The models use the artefacts, but do not need them.** Most of the
  attribution goes to family A, yet RF and XGB reach the same PR-AUC without
  it.
- **With the 802.11 semantic fields kept by S2b, a rogue beacon cannot be told
  from a real one.** (S4y below shows a semantic field that S2b dropped.) On Rogue_AP, F-sem gives 0.32-0.48 in every block, almost the same for
  all models. On Evil_Twin, F-sem reaches 0.995-1.000 on blocks 0-2, which are
  mostly the victims' data frames, and drops to 0.40 and 0.52 on blocks 3-4,
  which are mostly beacons.
- F-sem also costs false alarms on clean traffic: 0.08-0.22% (Evil_Twin) and
  0.15-0.20% (Rogue_AP), against at most 0.03% and 0% with F-all.
- **Random splits inflate the Evil_Twin scores**, from 0.898 to 0.998: mean PR-AUC
  of the 84 runs of the H2b test (5 model families x 4 field sets x 5 seeds, 1 seed
  for the deterministic LR; the score of a blocked run is the mean of its 5 test
  blocks), entry `H2b` of `results/S4_reliance.json`.
- p-values are raw; Holm correction across the confirmatory family comes at
  the end. Permutation importance is computed for seed 0 only and is
  descriptive. The ARS part of H2b was tested on F-all only by the S4 script;
  adding F-chatz gives the same conclusion (journal, deviation 8).

Sources: [`results/S4_reliance.json`](results/S4_reliance.json),
[`results/S4_runs.csv`](results/S4_runs.csv).

## Which fields decide? (S4x, exploratory)

S4 records attribution by feature family only. S4x refits the decision tree
and XGBoost (seed 0, S4 settings) and keeps the attribution of every field,
first on the usual evaluation sample, then on beacon frames only.

**What separates a rogue beacon from a real one**, on the beacons of the
attack window:

| Field (family) | Rogue_AP: rogue / legitimate | Separates them? |
|---|---|---|
| `wlan.fc.type` (S) | management / management | no |
| `wlan.duration` (U) | 0 / 0 | no |
| `frame.len` (C) | 263 / 342-343 bytes | **yes** |
| received signal strength (C) | weaker / stronger | **almost** |

On Evil_Twin beacons, signal strength separates them as well. Frame length
is set by the attacker's software. Signal strength depends on the attacker's
transmit power and position, and on where the sensor stands.

**Why attribution missed it.** On the usual evaluation sample, mostly normal
frames, `frame.len` received 0.4% of the decision tree's attribution and
`wlan.fc.type` 84%. Restricted to beacons, `frame.len` rises to 53%. The
attribution rewards the fields that sort the bulk of the traffic, such as
frame type and addresses, not the field that settles the decision between
two look-alike frames. This is why a high artefact share (H2a) did not mean
that the models depended on artefacts.

**Evil_Twin data frames.** Without artefacts, the models rely on
`wlan.fc.protected` and on the presence of an IP header (`ip.ttl`): the rogue
AP is open, so the victims' data is not encrypted. This is real evidence for
this attack setup, but it would disappear with a WPA2-protected Evil Twin.

**A labelling error the detectors catch.** On Evil_Twin beacons, every model
scores 1.000 in every block except block 3 (0.805). Block 3 holds 590 rogue
beacons labelled attack and the 143 rogue beacons labelled Normal found in
S1c: 590 / (590 + 143) = 0.805. The models rank the mislabelled beacons with
the attack frames, so the drop comes from the labels, not from the detectors.
The perturbation test confirms it (below).

Sources: [`results/S4x_field_detail.json`](results/S4x_field_detail.json),
[`results/S4x_field_runs.csv`](results/S4x_field_runs.csv),
[`results/S4x_beacon_runs.csv`](results/S4x_beacon_runs.csv).

## Would a careful attacker go unnoticed? (perturbation test, exploratory)

The models of the S4 blocked protocol (same settings, same training rows, same
alert threshold; 5 seeds) receive the real rogue beacons of each held-out
block, changed in one of three ways, with values copied from real legitimate
beacons; nothing is retrained:

- **L**: the legitimate length (and the airtime that follows from it);
- **P**: the legitimate received signal strength;
- **L+P**: both.

The design was fixed in the journal before any result.

Share of rogue beacons still flagged, RF / XGB / DT:

| | Unmodified | L | P | L+P |
|---|---|---|---|---|
| Rogue_AP, F-noA | 99 / 97 / 100% | **0 / 0 / 0%** | 48 / 57 / 100% | **0 / 0 / 0%** |
| Rogue_AP, F-chatz | 99 / 97 / 100% | **0 / 0 / 0%** | 55 / 33 / 100% | **0 / 0 / 0%** |
| Evil_Twin, F-noA | 99 / 96 / 96% | 29 / 85 / 79% | **0 / 18 / 0%** | **0 / 0 / 0%** |
| Evil_Twin, F-chatz | 98 / 71 / 39% | 19 / 69 / 39% | **0 / 18 / 0%** | **0 / 0 / 0%** |

- **Copying two values from a real beacon is enough.** On Rogue_AP the length
  alone does it; on Evil_Twin, mostly the signal strength. With both, the tree
  models trained on the 16 published features or on all non-artefact fields
  flag no rogue beacon.
- They also stop ranking rogue beacons above real ones: beacon PR-AUC drops
  from 1.00 to 0.44-0.51, where 0.44 is what a detector that cannot tell them
  apart scores.
- **Evil_Twin with all fields** (F-all): DT and XGB keep flagging 81% and 73%
  of the rogue beacons in every variant. They recognise the rogue BSSID, which
  the test does not change and which the Rogue_AP attacker shows can be cloned.
- On Evil_Twin, the test covers the impersonation only: 96% of the attack
  frames are the victims' data frames, which stay detected.
- **The 143 rogue beacons labelled Normal** are flagged at 100% by 11 of the
  15 model and field-set pairs.
- Logistic regression is left out: on Rogue_AP beacons it flags 50-100% of the
  legitimate ones. Results vary little across seeds (DT and XGB identical, RF
  standard deviation at most 0.09).

Sources: [`results/S4p_perturbation.json`](results/S4p_perturbation.json),
[`results/S4p_perturbation_runs.csv`](results/S4p_perturbation_runs.csv).

## Fields dropped by the cleaning rule (S4y, exploratory)

S2b dropped every column more than 99% empty (protocol 9.3). Fields that exist
only in management frames are 99.6% empty over a capture and were dropped,
although the protocol counts RSN and capability information as semantic
evidence. S4y compares every field of the capture, kept or dropped, between
rogue and legitimate beacons of the attack window (total variation distance:
0 = same values, 1 = no value in common). Timestamps and counters, where nearly
every beacon has a value of its own, are set apart.

Fields that separate them completely (distance 1.00) in both captures:

| Field (family) | Kept by S2b | Rogue_AP: rogue / legitimate |
|---|---|---|
| `frame.len` (C) | yes | 263 / 342-343 |
| `wlan_radio.duration` (A, airtime) | yes | 300 / 408 |
| `wlan.country_info.code` (C) | no | GR / DE |
| `wlan.tag.length` (C), `wlan.tag` (U): list of information elements | no | 13 elements / 17 |
| `wlan.rsn.capabilities.mfpc` (S): management frame protection capable | no | 0 / 1 |

Signal strength separates them almost completely on Rogue_AP (0.89-0.93) and
completely on Evil_Twin. On Evil_Twin the rogue BSSID differs from the
legitimate one (`...fe:35` against `...fe:34`), and half of the rogue beacons
(the 150-byte ones) carry no RSN element at all.

- **The capture holds real 802.11 evidence against the rogue AP**: it does not
  advertise management frame protection, which the legitimate AP does. The
  cleaning rule removed it, so the S3-S4 conclusions about semantic fields hold
  for the fields kept by S2b only.
- This evidence, like the country code and the element list, comes from the
  attacker's configuration and could be copied by a better equipped attacker.
- S3 and S4 are not re-run with these fields: that would be a new analysis.

Source: [`results/S4y_beacon_fields.json`](results/S4y_beacon_fields.json).

## Do detectors transfer between AWID3 and AWID2? (S5, pre-registered H3a, F-sem part of H3b)

Train on all of one dataset, test on all of the other, on the 37 fields the
two datasets share (only 4-5 of them semantic), compared with the in-domain
score of the same model and field set. Transfer gap G = 1 - PR-AUC(transfer) /
PR-AUC(in-domain): 0 = no loss, 1 = everything lost. Five model families,
5 seeds; AWID3 Evil_Twin against AWID2 evil_twin frames.

| Field set | AWID2 -> AWID3: in-domain / transfer | AWID3 -> AWID2: in-domain / transfer |
|---|---|---|
| F-all | 0.94-0.96 / 0.03-0.09 | 0.00-1.00 / 0.002-0.017 |
| F-noA | 0.83-0.96 / 0.02-0.08 | 0.24-1.00 / 0.002-0.063 |
| F-chatz (16 published features) | 0.79-0.98 / 0.03-0.04 | 0.17-1.00 / 0.002-0.043 |
| F-sem | 0.73-0.79 / 0.03-0.12 | 0.01 / 0.007-0.013 |

PR-AUC ranges over the five models. Chance level (the share of attack frames)
is 0.028 in AWID3 and 0.002 in AWID2.

- **Detectors that score 0.93-1.00 within a dataset are close to chance on
  the other one**, for every field set, including the 16 published features:
  on F-all, F-noA and F-chatz, every model with an in-domain PR-AUC above 0.5
  loses 91-100% of it (G = 0.91-1.00).
- The main shortcut does not carry over: rogue beacons are 263, 241 or 150
  bytes in AWID3 and 99 bytes in AWID2.
- **One rule does transfer**: XGB trained on AWID2 with semantic fields only
  detects the Evil_Twin data frames of AWID3 (PR-AUC 0.995 on data frames, all
  seeds). In both datasets the normal traffic is encrypted and the suspect
  frames are not (`wlan.fc.protected`).
- **H3a not supported**: Spearman rho between artefact share and G = 0.31, 95%
  CI [-0.03, 0.67]. Nearly every model fails to transfer, whatever its
  artefact share.
- **H3b, F-sem part**: median G 0.63 (F-sem) against 0.97 (F-all), one-sided
  Wilcoxon p = 0.053 before Holm. Not significant, and partly trivial: in
  AWID2, F-sem models are near chance even in-domain (0.01), so they have
  little to lose. The rule-baseline part comes in S6.
- Time fields break even the in-domain AWID2 score: a decision tree on all
  fields, trained on the AWID2 training file, detects nothing in its test
  file (0.001), whose timestamps lie outside the training range.

Sources: [`results/S5_transfer.json`](results/S5_transfer.json),
[`results/S5_runs.csv`](results/S5_runs.csv),
[`results/S5a_prepare.json`](results/S5a_prepare.json).

## A rule baseline with no training (S6, pre-registered, rule part of H3b)

Five rules fixed in protocol 9.6, calibrated on the first minute of normal
traffic of each dataset (which APs exist, which network name and security
profile they announce), applied to the raw fields. Score = number of rules
fired (0-5).

| Dataset | Chance | Rules, all frames | Rules, beacons and probe responses |
|---|---|---|---|
| AWID3 Rogue_AP | 0.0007 | 0.26 | 0.42 |
| AWID3 Evil_Twin | 0.028 | 0.08 | 0.84 |
| AWID2 | 0.0015 | 0.54 | 0.65 |

Rule by rule (fires on attack frames / all fires):

| Rule | Rogue_AP | Evil_Twin | AWID2 |
|---|---|---|---|
| R1 known name, unknown BSSID | 0 / 0 | 3,594 / 4,366 | 0 / 5 |
| R2 security profile differs | 1,310 / 4,648 | 3,594 / 4,874 | 1,761 / 7,775 |
| R3 sequence-number jump | 258 / 7,363 | 3,523 / 3,643 | 2,629 / 16,752 |
| R4 TSF clock goes back | 1,180 / 1,408 | 2 / 5 | 2,514 / 4,813 |
| R5 deauthentication burst | 0 / 62,428 | 0 / 0 | 0 / 180,999 |

- **R2 flags every rogue announcement in AWID3** (1,310 of 1,310, 3,594 of
  3,594): the security-profile difference that the missingness rule removed
  from the models (S4y) is caught by a one-line rule.
- R1 cannot fire on Rogue_AP and AWID2, where the rogue AP clones the BSSID;
  there R4 (two devices with the same address, two clocks) does the work.
- **On a new network, the rules beat the transferred models**: 0.54 on AWID2
  against 0.002-0.06 for the F-all models trained on AWID3, and 0.08 on AWID3
  Evil_Twin against 0.03-0.09 (0.84 on its beacons). One-sided Wilcoxon over
  the 10 model x direction pairs: p = 0.002 before Holm (deviation 9: the rules
  learn nothing from labels, so their own transfer gap is 0 by construction).
- The rules do not see the victims' data frames, which make up 96% of the
  Evil_Twin attack: hence 0.08 over all frames.
- R5 fires on 62,428 frames labelled Normal in Rogue_AP: these are the
  unprotected deauthentication frames sent during the attack and labelled
  Normal (S1c found 62,455). In AWID2 it fires on 180,999 frames labelled
  normal, not examined further.
- R2 also fires on 3,338 legitimate announcements in Rogue_AP and 1,280 in
  Evil_Twin; their cause was not examined.

Source: [`results/S6_rules.json`](results/S6_rules.json).

## Does SMOTE help? (S7, pre-registered H4)

RF and XGB on all fields, three ways of handling the rare attack class: no
treatment, class weighting (as in S4 and S5), and SMOTE on the training rows
only. Seeds 0-4. Transfer on Evil_Twin only (AWID3 <-> AWID2).

| | No treatment | Weighting | SMOTE |
|---|---|---|---|
| In-domain PR-AUC, mean of RF and XGB, both captures | 0.9785 | 0.9784 | 0.9785 |
| ARS, same | 0.684 | 0.681 | 0.674 |
| Transfer gap G, mean of RF and XGB, both directions | 0.962 | 0.965 | 0.972 |

H4 (all three must hold), SMOTE against weighting, 20 pairs each:

- (i) higher in-domain PR-AUC: **no** (p = 0.87). The scores are already at
  1.000 on Rogue_AP and within 0.001 between arms on Evil_Twin: there is
  nothing left to improve.
- (ii) transfer gap not reduced: **holds** (mean dG = +0.007, 95% CI
  [-0.004, 0.025]).
- (iii) higher ARS: **no** (p = 0.99). SMOTE raises it for RF on Rogue_AP
  (0.64 to 0.65) and lowers it for XGB (0.71 to 0.70).

**H4 is not supported** (p = 0.994 before Holm).

- Because of the cap on normal rows (at most 100,000 per training set), the
  AWID3 Evil_Twin training sets are close to balanced: SMOTE added nothing in
  20 of the 50 in-domain Evil_Twin runs.
- Where the imbalance is strong, SMOTE can lower the score: on AWID2 (2,633
  attack rows for 100,000 normal), RF reaches 0.997 with no treatment, 0.956
  with weighting and 0.910 with SMOTE. Trained on AWID2 and tested on AWID3,
  SMOTE halves its transfer PR-AUC (0.093 to 0.050). Descriptive, not tested.

Source: [`results/S7_smote.json`](results/S7_smote.json).

## Next

- Statistics and figures (S8).
- After the preprint: reproduction of published AWID3 pipelines (Ahmad et al.
  2025, then Solpan et al. 2026).
