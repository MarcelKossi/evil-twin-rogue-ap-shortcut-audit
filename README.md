# Intrusion Detection in Wi-Fi Networks: What Do Evil Twin Detectors Learn from Public 802.11 Datasets – the Attack, the Capture, or the Labelling Rule?

**Kossi Tamplare**, GD Goenka University  
Advisor: Dr. Rajat Sharma, GD Goenka University

_Status (26 November 2026): stages S0-S7 of the pre-registered protocol, the
exploratory stages S4x and S4y and the perturbation test done; the S8 analysis plan
is written (journal, 22 November); 802.11 checks on the raw captures are in progress
(exploratory). All results below are **preliminary**._

---

## Why this research

An **Evil Twin** is a fake Wi-Fi access point that copies the name (SSID), and
sometimes the hardware address (BSSID), of a real one, so that devices connect
to it instead. IoT devices are an easy target: they reconnect automatically to
known networks and have no screen to warn anyone.

Machine-learning detectors of Evil Twin and Rogue AP attacks trained on the
public AWID datasets report 98-100% detection. This project asks **what these
detectors actually learn**:

- **the attack itself**, that is, real 802.11 evidence that a fake AP is present;
- **capture artefacts**: frame counters, timestamps and addresses that belong
  to one recording in one lab;
- **the labelling rule**: AWID3 publishes the Wireshark filter of each attack,
  based on frame-number ranges, frame lengths and the attacker's address;
- or **fields the attacker sets**, such as beacon length or transmit power.

If a detector relies on anything but the first, its 99% says little about a
real network.

## The idea

```
AWID3 capture ──> label provenance: do the published filters reproduce the labels?      (RQ1)
              ──> detectors trained on 4 field sets:
                    all fields | no artefacts | 802.11 semantics only | 16 fields from the literature
                  └─> which fields carry the decision? attribution + ablation           (RQ2)
              ──> transfer AWID3 <-> AWID2                                              (RQ3)
              ──> does SMOTE improve detection, or only the reported numbers?           (RQ4)
```

Every one of the 253 fields of the capture is classified as **S** (802.11
semantics), **A** (capture artefact), **C** (controllable by the attacker) or
**U** (ambiguous or outside 802.11). The hypotheses, thresholds and analysis
plan were frozen before any experiment in
[`docs/protocol_v0.3.md`](docs/protocol_v0.3.md) (git tag `prereg-v0.3`).
Analyses added afterwards are labelled exploratory.

## What was done

1. **Inventory** of the AWID3 Rogue_AP and Evil_Twin captures (5.7 million frames).
2. **Label provenance**: agreement between the published filters and the labels.
3. **Feature taxonomy**: 253 fields classified S/A/C/U by three blind annotators
   (instances of a large language model configured as expert annotators),
   majority vote, then checked and validated by me.
4. **Blocked evaluation**: the attack period is cut into 5 consecutive blocks,
   each held out in turn with a 10,000-frame gap, instead of the random
   frame-level split used in most published work.
5. **Detectors**: logistic regression, decision tree, random forest, XGBoost and
   a small neural network, 5 seeds each, on the 4 field sets.
6. **Reliance**: attribution by feature family (SHAP and path contributions),
   permutation importance, and retraining without each family.

## What we found so far

**1. The labels are the published filters.** The filters reproduce the labels
with Cohen's kappa = 1.000 (Rogue_AP) and 0.996 (Evil_Twin). On Rogue_AP, every
attack frame is a 263-byte beacon of a fake AP that clones the real one; real
beacons are 342-343 bytes. On Evil_Twin, 143 fake beacons are labelled as normal
traffic, and the detectors flag them anyway.

**2. Detectors do not need the labelling rule, nor the artefacts, to score well.**
Removing the filter fields, or all capture artefacts, barely changes the scores
of the strongest models. The information is present in several redundant fields.

**3. With the 802.11 fields that survive the usual cleaning, a fake beacon cannot
be told from a real one.**

| PR-AUC, blocked evaluation, mean of 5 models | Rogue_AP | Evil_Twin |
|---|---|---|
| All fields | 0.99 | 0.92 |
| Without capture artefacts | 0.95 | 0.91 |
| 802.11 semantic fields only | 0.43 | 0.77 |

On Evil_Twin, the semantic fields still detect the victims' data traffic (the
fake AP is open, so their data is not encrypted), but not the fake beacons.
The cleaning rule matters here: see finding 4.

**4. What separates fake beacons from real ones** (exploratory). Comparing every
field of the capture on beacons only, rogue and legitimate beacons differ in:

- length (263 against 342-343 bytes on Rogue_AP) and received signal strength;
- the beacon's content: country code (GR against DE) and the list of
  information elements;
- **management frame protection**: the legitimate AP advertises it in its RSN
  element (`wlan.rsn.capabilities.mfpc` = 1), the rogue AP does not (0, or no
  RSN element at all).

The last one is real 802.11 security evidence. But fields that exist only in
management frames are empty in 99.6% of the rows, and the usual rule that
drops columns more than 99% empty, which this study also applied, removes them.
All of these differences are set by the attacker's configuration: a better
equipped attacker could copy them.

**5. Random splits inflate the scores.** On Evil_Twin, the mean PR-AUC of the 84
runs of S4 rises from 0.898 with the blocked evaluation to 0.998 with a random
split. The 84 runs are 5 model families x 4 field sets x 5 seeds (1 seed for the
deterministic logistic regression); the score of a blocked run is the mean of its
5 test blocks. Source: [`results/S4_reliance.json`](results/S4_reliance.json),
entry `H2b`. S8 recomputes this comparison with one value per model and field set
(journal, 22 November).

**6. Attribution shows where a model looks, not what it depends on.** Most of
the attribution goes to capture artefacts, yet removing them costs less than
10%. On a sample made mostly of normal frames, attribution rewards the fields
that sort the bulk of the traffic (frame type, addresses), not the field that
settles the decision: restricted to beacons, the share of beacon length rises
from 0.4% to 53% (exploratory).

**7. A slightly more careful attacker goes unnoticed** (exploratory). The trained
models receive the real fake beacons, but with the length and the signal strength
copied from real beacons. Tree models trained on the 16 features of the
literature, or on all non-artefact fields, then flag none of them (from 97-100%
on Rogue_AP and 39-99% on Evil_Twin), and rank them no better than chance. On
Rogue_AP the length alone is enough. Evil_Twin models that see all fields still
flag them through the fake AP's hardware address, which the attacker could clone
as well.

**8. Detectors do not transfer between datasets.** Trained on AWID3 and tested
on AWID2, or the reverse, detectors that score 0.93-1.00 within a dataset drop
to near chance, for every field set including the 16 published features. The
beacon-length shortcut takes different values in each dataset. One semantic
rule does carry over: unencrypted frames among encrypted normal traffic.

**9. Five simple rules do better on a new network than models trained
elsewhere.** Calibrated on one minute of normal traffic, with no training, the
rules of the protocol flag every fake announcement in AWID3 through the security
profile the fake AP announces, and reach PR-AUC 0.54 on AWID2, where models
trained on AWID3 stay below 0.07. They see only the beacons, not the victims'
data.

**10. SMOTE does not help here.** Oversampling the attack class in the training
data does not raise the scores, which are already at their ceiling, does not
increase reliance on artefacts, and leaves the transfer gap unchanged. Where the
imbalance is strongest (AWID2), it lowers the random forest's score from 0.997
to 0.910.

### Hypotheses: outcome so far

| | Hypothesis | Outcome |
|---|---|---|
| H1a | The published filters reproduce the labels | **Supported** for both attacks |
| H1b | A depth-3 tree on the filter fields matches the best model | **Supported** for Rogue_AP, **not** for Evil_Twin |
| H1c | Removing the filter fields costs >= 20% | **Not supported** (other fields carry the same information) |
| H2a | Detectors rely on artefacts | **Not supported**: high attribution, but small ablation cost |
| H2b | Random splits inflate scores and artefact reliance | **Partly**: scores inflated on Evil_Twin, artefact share not |
| H2c | The ranking of field families is stable | **Supported** |
| H3a | The more a detector relies on artefacts, the worse it transfers | **Not supported**: nearly every detector fails to transfer |
| H3b | Semantic fields and a rule baseline transfer better than all fields | **Partly**: F-sem not significant (p = 0.053); the untrained rules beat the transferred models (p = 0.002), before Holm |
| H4 | SMOTE improves scores but not transfer | **Not supported**: no gain in score (already at ceiling) nor in artefact share; transfer gap unchanged |

Multiple-testing correction (Holm) is applied at the end, across the
confirmatory family. Details and every number: [`RESULTS.md`](RESULTS.md).

## What it means, for now

High scores on AWID3 Evil Twin and Rogue AP can be reached without detecting the
attack: from the labelling rule, from capture artefacts, or from details the
attacker controls. A fake access point that copies the length and signal
strength of the real one goes unnoticed by these detectors. Meanwhile, the one
802.11 field that does separate fake from real beacons in these captures is
discarded by a common cleaning step.

## Limitations

- **One attack run per class** in AWID3, recorded in one lab.
- **Taxonomy**: the S/A/C/U classes are a judgement; some fields are both a lab
  artefact and an attacker's choice (for example the BSSID).
- **Attribution methods**: path contributions for trees are not exact Shapley
  values (deviation 6 in the journal).
- **One attack configuration per capture**: the differences in beacon content
  and protection capability come from how this attacker set up the fake AP.
- **Perturbation in feature space**: the fake beacons are recorded frames whose
  field values are replaced, not a new capture of a modified attack. Matching
  the signal strength assumes the attacker can reach the legitimate level at the
  sensor, by power or position.
- **Preliminary numbers**: Holm correction (S8) not yet applied.
- **Imbalance probe**: the cap of 100,000 normal rows per training set already balances most AWID3 Evil_Twin training sets, so SMOTE was tested mainly on Rogue_AP and AWID2.

## Next steps

- Statistics, figures and paper (S8).
- After the preprint: reproduction of published AWID3 pipelines (Ahmad et al.
  2025, Solpan et al. 2026) on their own code.

## Progress

| Stage | Question | Status |
|---|---|---|
| S0 | Data inventory | Done |
| S1 | H1a - label provenance | Done |
| S2 | Feature taxonomy | Done |
| S2b | Feature matrices | Done |
| S3 | H1b, H1c - labelling rule | Done (re-run with corrected folds) |
| S4 | H2a-c - reliance on artefacts | Done |
| S4x | Which single fields decide (exploratory) | Done |
| - | Perturbation test (exploratory) | Done |
| - | Reproduction of published pipelines (exploratory) | After the preprint |
| S5 | H3a - transfer AWID3 <-> AWID2 | Done |
| S6 | H3b - rule baseline | Done |
| S7 | H4 - imbalance probe | Done |
| - | 802.11 checks on the raw captures (exploratory) | Done; in the journal, to be reported in RESULTS.md |
| S8 | Statistics, figures, paper | Analysis plan written (journal, 22 November); not run |

## Quick start

The results were produced on Windows 11 with Python 3.11.5. The code uses no
Windows-specific path, and the unit tests run on Linux and Windows with GitHub
Actions at every push ([`.github/workflows/tests.yml`](.github/workflows/tests.yml)).
macOS has not been tested; XGBoost needs OpenMP there (`brew install libomp`).

```bash
git clone https://github.com/MarcelKossi/evil-twin-rogue-ap-shortcut-audit.git
cd evil-twin-rogue-ap-shortcut-audit
python -m venv .venv
source .venv/bin/activate          # Linux, macOS
# .venv\Scripts\activate.bat     # Windows (cmd)
python -m pip install -r requirements.txt pytest==8.3.3
python -m pytest -q                # unit tests on synthetic data, no dataset needed
```

To reproduce the results, place the datasets as in
[`configs/paths.yaml`](configs/paths.yaml) (see [Data](#data)):

| Path | Content | Needed by |
|---|---|---|
| `data/AWID3_Dataset_CSV.zip` | AWID3, CSV release | every stage |
| `data/DATASET/DATASET/AWID-ATK-R-Trn.tar.gz`, `AWID-ATK-R-Tst.tar.gz` | AWID2, reduced attack-level subsets | S5-S7 and the 802.11 checks |
| `data/AWID3_Dataset.zip` | AWID3, pcap release | 802.11 checks (pcap part) only |

Then run the scripts in order, from the repository root:

```bash
python scripts/00_inventory.py
python scripts/01_to_parquet.py
python scripts/02_filter_agreement.py
python scripts/03_label_diagnostics.py
python scripts/04_figures_labels.py
python scripts/05_taxonomy_agreement.py
python scripts/06_build_features.py
python scripts/07_s3_label_rule.py
python scripts/08_s4_reliance.py
python scripts/09_s4x_field_detail.py
python scripts/09_s4x_field_detail.py --beacons
python scripts/10_perturbation.py
python scripts/11_beacon_fields.py
python scripts/12_s5_prepare.py
python scripts/13_s5_transfer.py
python scripts/14_s6_rules.py
python scripts/15_s7_smote.py
python scripts/16_rv2_80211_checks.py
python scripts/17_rv3_file_format.py
python scripts/18_rv4_transfer_checks.py
```

The whole pipeline takes more than a day on a laptop CPU. The long stages can be
stopped and restarted: finished runs are kept. [`RUNBOOK.md`](RUNBOOK.md) gives the
output and the run time of every command, as I ran them.

## Repository guide

| Path | Content |
|---|---|
| `docs/` | Protocol, research journal (every decision and deviation), feature taxonomy |
| `scripts/` | One script per stage |
| `src/` | Shared code |
| `configs/paths.yaml` | Data locations, relative to the repository root |
| `results/` | Machine-generated results behind every number (git commit, package versions, input SHA-256) |
| `figures/` | Figures |
| `tests/` | Unit tests on synthetic data (folds, frame-field helpers) |
| [`RESULTS.md`](RESULTS.md) | Results in detail |
| [`RUNBOOK.md`](RUNBOOK.md) | Every command, in order |

Everything runs on a laptop CPU (8 GB of RAM).

## Data

The datasets are not redistributed. They can be requested from the AWID project
(University of the Aegean): AWID3 (CSV release) and AWID2 (reduced attack-level
subsets AWID-ATK-R-Trn / AWID-ATK-R-Tst). Place them under `data/` as listed in
`configs/paths.yaml`.

## License

Code and documents: MIT ([`LICENSE`](LICENSE)). The AWID datasets are not included
and remain under the terms of their providers.

## References

- Chatzoglou, E., Kambourakis, G., Kolias, C. (2021). Empirical evaluation of attacks against IEEE 802.11 enterprise networks: The AWID3 dataset. *IEEE Access*, 9, 34188-34205.
- Kolias, C., Kambourakis, G., Stavrou, A., Gritzalis, S. (2016). Intrusion detection in 802.11 networks: Empirical evaluation of threats and a public dataset. *IEEE Communications Surveys & Tutorials*, 18(1), 184-208.
- Arp, D., et al. (2022). Dos and don'ts of machine learning in computer security. *USENIX Security Symposium*.
- Geirhos, R., et al. (2020). Shortcut learning in deep neural networks. *Nature Machine Intelligence*, 2, 665-673.
- Kapoor, S., Narayanan, A. (2023). Leakage and the reproducibility crisis in machine-learning-based science. *Patterns*, 4(9).

Full list: Section 16 of the protocol.
