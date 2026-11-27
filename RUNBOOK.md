# Runbook

Commands as I ran them, in the Windows command prompt (cmd), from the repository
root. On Linux and macOS the commands are the same except the activation of the
virtual environment (see Quick start in the README). Each stage is run only after
the output of the previous one has been checked.

At the start of every session, from the repository root:

```cmd
.venv\Scripts\activate.bat
```

## 1. Environment (once)

```cmd
python --version
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt pytest==8.3.3
python -m pytest -q
```

`python -m pytest -q` runs the unit tests of `tests/` on synthetic data (no dataset needed).

## 2. Protocol freeze (done once, kept as a record)

```cmd
git add .
git status
git commit -m "Repository structure and protocol v0.3"
git tag -a prereg-v0.3 -m "Protocol frozen before any experiment"
git push origin main --tags
```

`git status` must not list `data/`.

## 3. Stage S0 - inventory

| Command | Output | Time |
|---|---|---|
| `python scripts/00_inventory.py --layout-only` | Folder list of the AWID3 zip (printed) | < 1 min |
| `python scripts/00_inventory.py` | `results/S0_inventory.json` | about 2 min |
| `python scripts/00_inventory.py --hash` | `results/S0_archive_hashes.json` | about 2 min |

```cmd
git add results/S0_inventory.json results/S0_archive_hashes.json docs/journal.md
git commit -m "S0: AWID3 inventory and archive hashes"
```

## 4. Stage S1 - Parquet conversion and label/filter agreement

| Command | Output | Time |
|---|---|---|
| `python scripts/01_to_parquet.py` | `data/interim/awid3_evil_twin.parquet`, `data/interim/awid3_rogue_ap.parquet`, `results/S1_parquet_manifest.json` | about 10-20 min |
| `python scripts/02_filter_agreement.py` | `results/S1_filter_agreement.json` | about 2-5 min |

```cmd
git add results/S1_parquet_manifest.json results/S1_filter_agreement.json docs/journal.md
git commit -m "S1: Parquet conversion and label/filter agreement"
```

## 5. Stage S1c - label diagnostics (exploratory)

| Command | Output | Time |
|---|---|---|
| `python scripts/03_label_diagnostics.py` | `results/S1c_label_diagnostics.json` | about 5-10 min |

```cmd
git add results/S1c_label_diagnostics.json docs/journal.md
git commit -m "S1c: label diagnostics"
```

## 6. Stage S1d - figures of the label structure

| Command | Output | Time |
|---|---|---|
| `python scripts/04_figures_labels.py` | `figures/fig1_rogue_ap_capture.png`, `figures/fig2_evil_twin_capture.png`, `results/S1d_figure_data.json` | about 5 min |

```cmd
git add figures results/S1d_figure_data.json docs/journal.md RESULTS.md
git commit -m "S1d: label structure figures and preliminary results"
```

## 7. Stage S2 - feature taxonomy

| Command | Output | Time |
|---|---|---|
| `python scripts/05_taxonomy_agreement.py` | `docs/taxonomy.csv`, `results/S2_taxonomy_agreement.json` | < 1 min |

Inputs: the three annotations in `docs/annotation/` and the manual changes in
`docs/annotation/manual_overrides.csv`.

```cmd
git add docs scripts src results
git commit -m "S2: feature taxonomy"
```

## 8. Stage S2b - feature matrices

| Command | Output | Time |
|---|---|---|
| `python scripts/06_build_features.py` | `data/interim/awid3_*_X.npy`, `_y.npy`, `_fn.npy`, `_features.json`; `results/S2b_features.json` | about 20-40 min |

Needs about 3 GB free on the data disk.

## 9. Stage S3 - do detectors learn the labelling rule? (H1b, H1c)

| Command | Output | Time |
|---|---|---|
| `python scripts/07_s3_label_rule.py --seeds 0` | first pass, seed 0 only | about 1-2 h |
| `python scripts/07_s3_label_rule.py` | all seeds (finished runs are skipped) | several hours |

Results: `results/S3_runs.csv` (one row per run) and `results/S3_label_rule.json` (H1b, H1c).
The script can be stopped and restarted; finished runs are kept.

```cmd
git add results docs RUNBOOK.md
git commit -m "S3: label rule (H1b, H1c)"
```

## 10. Stage S4 - reliance on artefacts (H2a, H2b, H2c)

| Command | Output | Time |
|---|---|---|
| `python scripts/08_s4_reliance.py` | `results/S4_runs.csv`, `results/S4_reliance.json` | several hours (overnight) |

Stop and restart at any time; finished runs are kept.

```cmd
git add results docs RUNBOOK.md
git commit -m "S4: reliance on artefacts (H2a, H2b, H2c)"
```

## 11. Re-run of S3 with the corrected folds (after S4)

```cmd
git mv results\S3_runs.csv results\S3_runs_v1.csv
git mv results\S3_label_rule.json results\S3_label_rule_v1.json
git commit -m "Keep S3 v1 results before the re-run"
python scripts/07_s3_label_rule.py
git add results docs
git commit -m "S3 re-run with corrected folds"
```

The first results (folds before the code review, commit `3e70913`) stay in the
`_v1` files; committing the rename first keeps the new results on a clean commit.

## 12. Stage S4x - field-level detail of S4 (exploratory)

| Command | Output | Time |
|---|---|---|
| `python scripts/09_s4x_field_detail.py` | `results/S4x_field_runs.csv`, `results/S4x_field_detail.json` | about 10-20 min |
| `python scripts/09_s4x_field_detail.py --beacons` | `results/S4x_beacon_runs.csv`, `results/S4x_field_detail.json` | about 10-20 min |

Refits DT and XGB (seed 0, S4 hyperparameters) on F-all, F-noA and F-chatz and keeps the
attribution of every field, on the S4 evaluation sample or (`--beacons`) on the
beacon frames of each test block only. Stop and restart at any time; finished runs are kept.

```cmd
git add scripts/09_s4x_field_detail.py results docs RUNBOOK.md
git commit -m "S4x: field-level detail of S4 (exploratory)"
```

## 13. Perturbation test (exploratory)

| Command | Output | Time |
|---|---|---|
| `python scripts/10_perturbation.py --seeds 0` | first pass, seed 0 only | about 1 h |
| `python scripts/10_perturbation.py` | seeds 0-4 (finished runs are skipped) | about 3-5 h |

Results: `results/S4p_perturbation_runs.csv` (one row per run and variant) and
`results/S4p_perturbation.json`. Stop and restart at any time; finished runs are kept.

```cmd
git add scripts/10_perturbation.py results docs RUNBOOK.md RESULTS.md README.md
git commit -m "Perturbation test (exploratory)"
```

## 14. Fields that separate rogue from legitimate beacons (exploratory)

| Command | Output | Time |
|---|---|---|
| `python scripts/11_beacon_fields.py` | `results/S4y_beacon_fields.json` | about 15-30 min (reads every column of both Parquet tables) |

Compares every field of the capture, including those dropped by S2b, on the beacons of
the attack window: rogue against legitimate.

```cmd
git add scripts/11_beacon_fields.py results RUNBOOK.md
git commit -m "S4y: fields that separate rogue from legitimate beacons (exploratory)"
```

## 15. Stage S5 - transfer AWID3 <-> AWID2

| Command | Output | Time |
|---|---|---|
| `python scripts/12_s5_prepare.py` | `data/interim/s5_*`, `results/S5a_prepare.json` | about 20-40 min |
| `python scripts/13_s5_transfer.py --seeds 0` | first pass, seed 0 only | about 2-3 h |
| `python scripts/13_s5_transfer.py` | seeds 0-4 (finished runs are skipped) | about 4-7 h in total |

Reads the two AWID2 archives and the AWID3 Evil_Twin Parquet table, aligns field names
and writes both datasets with the same encoding. Column names of AWID2 come from
`configs/awid2_columns.txt`.

```cmd
git add scripts/12_s5_prepare.py configs/awid2_columns.txt RUNBOOK.md docs/journal.md
git commit -m "S5 part 1: AWID2 preparation and field alignment"
python scripts/12_s5_prepare.py
```

Then the transfer itself (stop and restart at any time; finished runs are kept):

```cmd
git add scripts/13_s5_transfer.py RUNBOOK.md
git commit -m "S5 part 2: transfer script"
python scripts/13_s5_transfer.py --seeds 0
python scripts/13_s5_transfer.py
git add results
git commit -m "S5 transfer results"
```

## 16. Stage S6 - rule baseline

| Command | Output | Time |
|---|---|---|
| `python scripts/14_s6_rules.py` | `results/S6_rules.json` | about 20-40 min |

Five rules fixed in protocol 9.6, applied to the raw fields of AWID3 Rogue_AP, AWID3
Evil_Twin and AWID2; needs the S5 results for the H3b comparison.

```cmd
git add scripts/14_s6_rules.py RUNBOOK.md docs/journal.md
git commit -m "S6: rule baseline script; deviation 9"
python scripts/14_s6_rules.py
git add results
git commit -m "S6 rule baseline results"
```

## 17. Stage S7 - imbalance probe

| Command | Output | Time |
|---|---|---|
| `python scripts/15_s7_smote.py --seeds 0` | `results/S7_runs.csv`, `results/S7_smote.json` | about 40-70 min |
| `python scripts/15_s7_smote.py` | same files, seeds 0-4 | about 3-5 h more |

RF and XGB on F-all, arms "none" and "smote"; the weighting arm is read from the S4 and S5
results. Needs imbalanced-learn (`requirements.txt`). Finished runs are skipped on a re-run.

```cmd
python -c "import imblearn; print(imblearn.__version__)"
git add scripts/15_s7_smote.py RUNBOOK.md docs/journal.md
git commit -m "S7: imbalance probe script and design"
python scripts/15_s7_smote.py --seeds 0
python scripts/15_s7_smote.py
git add results
git commit -m "S7 imbalance probe results"
```


## 18. 802.11 checks (exploratory, plan item 2)

| Command | Output | Time |
|---|---|---|
| `python scripts/16_rv2_80211_checks.py --layout` | List of the AWID3 pcap members (printed, nothing written) | < 1 min |
| `python scripts/16_rv2_80211_checks.py` | `results/RV2_awid3.json`, `results/RV2_awid2.json`, `results/RV2_pcap.json` | about 1 h |
| `python scripts/16_rv2_80211_checks.py --part pcap` | `results/RV2_pcap.json`, or `results/RV2_pcap_archive.json` when the archive cannot be opened | < 1 min if the archive cannot be opened |

Three parts: rule alarms and deauthentication frames on AWID3, the AWID2 rules on all rows,
and the security profile of every announcement read from the pcap files. Each part first
reproduces the S6 counts it builds on, and stops if they differ. A finished part is skipped on
a re-run; `--part pcap --force` redoes one part.

```cmd
git add scripts/16_rv2_80211_checks.py RUNBOOK.md docs/journal.md
git commit -m "802.11 checks: script and plan (exploratory)"
python scripts/16_rv2_80211_checks.py --layout
python scripts/16_rv2_80211_checks.py
git add results
git commit -m "802.11 checks: results"
```

## 19. S6 re-run (deviation 12), file format check, pcap archive diagnostic

| Command | Output | Time |
|---|---|---|
| `python scripts/14_s6_rules.py` | `results/S6_rules.json` | about 20-40 min |
| `python scripts/17_rv3_file_format.py` | `results/RV3_file_format.json` | about 20-45 min (reads every column of both Parquet tables) |
| `python scripts/16_rv2_80211_checks.py --part pcap` | `results/RV2_pcap_archive.json` when the archive cannot be opened (the command then ends with an error message) | < 1 min |

S6: R2 reads an integer written with a trailing `.0` as the same integer; the first results
are kept in `results/S6_rules_v1.json`. File format check (exploratory): how each AWID3 CSV
file writes its values (integers with or without `.0`, exponent notation, clock digits), and
whether a change of format lines up with the attack window; a finished capture is kept on a
re-run. Everything is committed before the runs, so the results carry a clean commit.

```cmd
git mv results\S6_rules.json results\S6_rules_v1.json
git commit -m "Keep S6 v1 results before the re-run (deviation 12)"
git add scripts/14_s6_rules.py scripts/16_rv2_80211_checks.py scripts/17_rv3_file_format.py docs/journal.md RUNBOOK.md README.md
git commit -m "S6 R2 fix (deviation 12), file format check and pcap archive diagnostic"
git status
python scripts/14_s6_rules.py
python scripts/17_rv3_file_format.py
python scripts/16_rv2_80211_checks.py --part pcap
git add results
git commit -m "S6 re-run, file format check and pcap archive diagnostic: results"
git push
```

## 20. pcap check read from the start of the archive (exploratory)

| Command | Output | Time |
|---|---|---|
| `python scripts/16_rv2_80211_checks.py --part pcap` | `results/RV2_pcap_archive.json` (members found, complete or cut), `results/RV2_pcap.json` | about 15-40 min (reads the 12 GB archive from its start) |

The archive has no central directory, so its members are read from the start through their
local headers and decompressed in memory; nothing is extracted to disk. A member cut by the end
of the file is read up to the cut and its result is marked as partial.

```cmd
.venv\Scripts\activate.bat
where python
git add scripts/16_rv2_80211_checks.py docs/journal.md RUNBOOK.md
git commit -m "pcap check: read an archive without central directory from its start (exploratory)"
python scripts/16_rv2_80211_checks.py --part pcap
git add results
git commit -m "pcap check read from the start of the archive: results"
git push
```

## 21. Transfer checks on the S5 results (exploratory, plan item 3)

| Command | Output | Time |
|---|---|---|
| `python scripts/18_rv4_transfer_checks.py` | `results/RV4_transfer.json` | about 10-15 min (re-reads one raw column of each dataset) |

Chance-corrected gap Gc, configurations with constant scores, per-field shift between AWID3
Evil_Twin and AWID2 (with the order of the `radiotap.dbm_antsignal` codes), and LR on F-chatz
on announcements (refit, one field fixed at a time). No S5 result changes.

```cmd
.venv\Scripts\activate.bat
where python
git add scripts/18_rv4_transfer_checks.py docs/journal.md RUNBOOK.md README.md
git commit -m "Transfer checks on the S5 results (exploratory, plan item 3)"
python scripts/18_rv4_transfer_checks.py
git add results
git commit -m "Transfer checks on the S5 results: results"
git push
```
