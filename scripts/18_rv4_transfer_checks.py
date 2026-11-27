"""Exploratory (plan item 3 of 2026-11-22; journal 2026-11-27) - transfer checks on the S5 results.

  a  Chance-corrected gap Gc (S8 note of 2026-11-22) per configuration, over all frames and per
     sub-task (ET-B announcements, ET-D data frames): Gc = 1 - k(T)/k(I), k = (PR-AUC - p)/(1 - p),
     p the prevalence of the set scored; the AWID3 in-domain k is the mean over blocks, each with
     its own prevalence; per seed, then mean over seeds. Configurations with an in-domain PR-AUC
     below 0.5 are left out and counted.
  b  Constant scores: transfer PR-AUC equal to the target prevalence (difference below 1e-9) on
     all frames and on both sub-tasks for every seed; for each, its fields that are missing or
     constant in the target.
  c  Per-field shift AWID3 Evil_Twin vs AWID2 (the 37 shared fields), normal frames, random sample
     of at most 200,000 rows per dataset (seed 0): missing share, Kolmogorov-Smirnov statistic,
     share of values outside the other dataset's range. radiotap.dbm_antsignal: raw values of both
     datasets re-read, codes rebuilt as S5 built them (sorted text), checked against the matrix,
     Spearman correlation between code and first antenna value over frames.
  d  LR on F-chatz, AWID3 -> AWID2, on announcements: refit with the S5 hyperparameters (seed 0;
     must give the S5 PR-AUC within 1e-6), then the ET-B PR-AUC with one field at a time set, in
     the target, to its training median (no refit), and the coefficients of the standardised fields.

Usage (from the repository root):
    python scripts/18_rv4_transfer_checks.py
Output: results/RV4_transfer.json
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp, spearmanr, wilcoxon

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.frames import iter_parquet  # noqa: E402
from src.modeling import fit, pr_auc, predict  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


s5 = _load("s5", "13_s5_transfer.py")          # load, scores, subtask_masks (and s4)
s5a = _load("s5a", "12_s5_prepare.py")         # awid2_names, awid2_chunks, awid3_chunks, MAX_CATEGORIES
RUNS = ROOT / "results" / "S5_runs.csv"
CFG = ["direction", "feature_set", "model"]
SUB = {"all": "", "ET-B": "_ET-B", "ET-D": "_ET-D"}
TARGET = {"AWID3->AWID2": "awid2", "AWID2->AWID3": "awid3"}
EQUAL, MIN_IN_DOMAIN, SAMPLE = 1e-9, 0.5, 200_000


def r4(v):
    return None if v is None or pd.isna(v) else round(float(v), 4)


# ---------------------------------------------------------------- a: chance-corrected gap
def part_a(runs: pd.DataFrame, s5_json: dict) -> dict:
    r = runs.copy()
    for sub, k in SUB.items():
        p = r["prevalence"] if not k else r[f"attack{k}"] / r[f"n{k}"]
        r[f"k{k}"] = (r[f"pr_auc{k}"] - p) / (1 - p)
    key = CFG + ["seed"]
    s2t = r[r["kind"] == "s2t"].set_index(key)
    t2t = r[r["kind"] == "t2t"].groupby(key)
    out = {}
    for sub, k in SUB.items():
        j = pd.concat({"T": s2t[f"pr_auc{k}"], "kT": s2t[f"k{k}"], "I": t2t[f"pr_auc{k}"].mean(),
                       "kI": t2t[f"k{k}"].mean()}, axis=1).dropna()
        j["G"], j["Gc"] = 1 - j["T"] / j["I"], 1 - j["kT"] / j["kI"]
        cfg = j.groupby(level=CFG).mean()
        kept, left = cfg[cfg["I"] >= MIN_IN_DOMAIN], cfg[cfg["I"] < MIN_IN_DOMAIN]
        f_all = (kept.xs("F-all", level="feature_set")["Gc"] if "F-all" in kept.index.get_level_values("feature_set")
                 else pd.Series(dtype=float))
        pair = kept["Gc"].unstack("feature_set").reindex(columns=["F-sem", "F-all"]).dropna()
        test = None
        if len(pair) >= 5:
            test = {"pairs": int(len(pair)), "wilcoxon_p_one_sided_Gc_F-sem_lower": float(
                wilcoxon(pair["F-sem"], pair["F-all"], alternative="less").pvalue)}
        out[sub] = {
            "configurations": {" | ".join(i): {c: r4(v) for c, v in row.items()} for i, row in cfg.iterrows()},
            "left_out_in_domain_below_0.5": [" | ".join(i) for i in left.index],
            "f_all_kept": {" | ".join(i): r4(v) for i, v in f_all.items()},
            "f_all_every_Gc_at_least_0.9": bool(len(f_all) and (f_all >= 0.9).all()),
            "f_all_any_Gc_below_0.5": bool((f_all < 0.5).any()),
            "f_sem_vs_f_all_pairs_kept": int(len(pair)), "f_sem_vs_f_all_test": test}
        if sub == "all":                                     # G must be the S5 value
            diff = [abs(row["G"] - s5_json[" | ".join(i)]["G"]) for i, row in cfg.iterrows()
                    if " | ".join(i) in s5_json and s5_json[" | ".join(i)]["G"] is not None]
            out[sub]["G_largest_difference_from_S5_transfer_json"] = r4(max(diff)) if diff else None
    return out


# ---------------------------------------------------------------- b: constant scores
def constant_configs(runs: pd.DataFrame) -> list[dict]:
    s = runs[runs["kind"] == "s2t"].copy()
    ok = (s["pr_auc"] - s["prevalence"]).abs() < EQUAL
    for k in ("_ET-B", "_ET-D"):
        has = s[f"attack{k}"] > 0
        ok &= ~has | ((s[f"pr_auc{k}"] - s[f"attack{k}"] / s[f"n{k}"]).abs() < EQUAL)
    s["constant"] = ok
    out = []
    for i, g in s.groupby(CFG):
        if g["constant"].all():
            out.append({"configuration": " | ".join(i), "direction": i[0], "seeds": int(len(g)),
                        "fields": g["fields"].iloc[0].split("|")})
    return out


def field_ranges(cap) -> dict:
    """Per field over the whole dataset: share missing, min and max of the non-missing values."""
    n, m = len(cap.y), len(cap.columns)
    miss, lo, hi = np.zeros(m), np.full(m, np.inf), np.full(m, -np.inf)
    for s in range(0, n, 200_000):
        part = np.asarray(cap.X[s:s + 200_000], dtype=np.float64)
        nan = np.isnan(part)
        miss += nan.sum(axis=0)
        lo = np.fmin(lo, np.where(nan, np.inf, part).min(axis=0))
        hi = np.fmax(hi, np.where(nan, -np.inf, part).max(axis=0))
    return {c: {"missing": float(miss[j] / n), "constant_or_missing": bool(not lo[j] < hi[j])}
            for j, c in enumerate(cap.columns)}


# ---------------------------------------------------------------- c: per-field shift
def part_c(caps: dict, meta: list[dict]) -> dict:
    rng = np.random.default_rng(0)
    samp = {}
    for tag, cap in caps.items():
        normal = np.flatnonzero(cap.y == 0)
        rows = np.sort(rng.choice(normal, min(SAMPLE, len(normal)), replace=False))
        samp[tag] = np.asarray(cap.X[rows], dtype=np.float64)
    fields = []
    for j, c in enumerate(meta):
        a, b = samp["awid3"][:, j], samp["awid2"][:, j]
        a_ok, b_ok = a[~np.isnan(a)], b[~np.isnan(b)]
        row = {"field": c["name"], "family": c["family"], "kind": c["kind"],
               "missing_awid3": r4(1 - len(a_ok) / len(a)), "missing_awid2": r4(1 - len(b_ok) / len(b))}
        if len(a_ok) > 1 and len(b_ok) > 1:
            row["ks"] = r4(ks_2samp(a_ok, b_ok).statistic)
            row["awid2_outside_awid3_range"] = r4(np.mean((b_ok < a_ok.min()) | (b_ok > a_ok.max())))
            row["awid3_outside_awid2_range"] = r4(np.mean((a_ok < b_ok.min()) | (a_ok > b_ok.max())))
            row["shift"] = "small" if row["ks"] < 0.1 else ("moderate" if row["ks"] < 0.5 else "large")
        else:
            row["shift"] = "not computed (field missing in one sample)"
        fields.append(row)
    by_family = {}
    for f in fields:
        by_family.setdefault(f["family"], {}).setdefault(f["shift"], []).append(f["field"])
    return {"normal_frames_sampled": {t: int(len(s)) for t, s in samp.items()}, "fields": fields,
            "by_family": by_family}


def dbm_order(paths: dict, caps: dict) -> dict:
    """Codes of radiotap.dbm_antsignal rebuilt as S5 built them, and their order against signal strength."""
    col = "radiotap.dbm_antsignal"
    c3 = pd.Series(dtype="int64")
    for df in s5a.awid3_chunks(paths["interim_dir"] / "awid3_evil_twin.parquet", [col]):
        c3 = c3.add(df[col].value_counts(), fill_value=0)
    c2 = pd.Series(dtype="int64")
    for _, df in s5a.awid2_chunks(paths["awid2_dir"], s5a.awid2_names()):
        df = df.loc[df["class"].isin(["normal", "evil_twin"])]
        c2 = c2.add(df[col].value_counts(), fill_value=0)
    values = sorted(set(c3.index) | set(c2.index))
    if len(values) > s5a.MAX_CATEGORIES:
        return {"distinct_values": len(values), "note": "hash-encoded in S5; no order to check"}
    code = {v: float(i) for i, v in enumerate(values)}
    j = caps["awid3"].columns.index(col)
    out = {"distinct_values": len(values)}
    for tag, cnt in (("awid3", c3), ("awid2", c2)):
        col_x = np.asarray(caps[tag].X[:, j], dtype=np.float64)
        u, n = np.unique(col_x[~np.isnan(col_x)], return_counts=True)
        rebuilt = pd.Series(cnt.values, index=[code[v] for v in cnt.index]).groupby(level=0).sum()
        out[f"codes_match_matrix_{tag}"] = bool(np.array_equal(u, rebuilt.index.to_numpy(float))
                                                and np.array_equal(n, rebuilt.to_numpy(np.int64)))
    both = c3.add(c2, fill_value=0)
    first = pd.Series({v: pd.to_numeric(str(v).split(",")[0], errors="coerce") for v in both.index})
    ok = first.notna()
    codes = np.repeat([code[v] for v in both.index[ok]], both[ok].astype(int).to_numpy())
    firsts = np.repeat(first[ok].to_numpy(float), both[ok].astype(int).to_numpy())
    rho = float(spearmanr(codes, firsts).statistic)
    out.update({"frames": int(both.sum()), "first_value_unreadable_frames": int(both[~ok].sum()),
                "spearman_code_vs_first_antenna_value": r4(rho), "order_kept": bool(abs(rho) >= 0.99),
                "examples_in_code_order": values[:5] + values[-5:]})
    return out


# ---------------------------------------------------------------- d: LR on F-chatz, announcements
def part_d(caps: dict, meta: list[dict], runs: pd.DataFrame) -> dict:
    row = runs[(runs["kind"] == "s2t") & (runs["direction"] == "AWID3->AWID2") & (runs["feature_set"] == "F-chatz")
               & (runs["model"] == "LR") & (runs["seed"] == 0)].iloc[0]
    S, T = caps["awid3"], caps["awid2"]
    names = row["fields"].split("|")
    cols = S.col_index(names)
    model, _, _ = fit(S, "LR", json.loads(row["params"]), 0, np.arange(len(S.y)), cols, sample_seed=0)
    allrows = np.arange(len(T.y))
    sc = s5.scores(T, meta, model, allrows, cols)
    same = abs(sc["pr_auc_ET-B"] - row["pr_auc_ET-B"]) < 1e-6 and abs(sc["pr_auc"] - row["pr_auc"]) < 1e-6
    out = {"s5_pr_auc_ET-B": r4(row["pr_auc_ET-B"]), "refit_pr_auc_ET-B": r4(sc["pr_auc_ET-B"]),
           "reproduces_s5": bool(same)}
    if not same:
        return out
    b = allrows[s5.subtask_masks(T, meta, allrows)["ET-B"]]
    yb, Xb = T.y[b], T.rows(b, cols)
    imputer, lr = model.named_steps["simpleimputer"], model.named_steps["logisticregression"]
    base = pr_auc(yb, model.predict_proba(Xb)[:, 1])
    fixed = []
    for i, f in enumerate(names):
        X2 = Xb.copy()
        X2[:, i] = imputer.statistics_[i]
        ap = pr_auc(yb, model.predict_proba(X2)[:, 1])
        fixed.append({"field": f, "family": S.families[f], "pr_auc_ET-B": r4(ap), "drop": r4(base - ap)})
    fixed.sort(key=lambda x: -(x["drop"] or 0))
    coef = lr.coef_[0]
    inputs = names + [f"missing: {names[i]}" for i in imputer.indicator_.features_] if imputer.indicator_ else names
    coefs = sorted(({"input": n, "coefficient": r4(c)} for n, c in zip(inputs, coef)), key=lambda x: -abs(x["coefficient"]))
    below = [x["field"] for x in fixed if x["pr_auc_ET-B"] is not None and x["pr_auc_ET-B"] < 0.1]
    out.update({"announcements": int(len(b)), "attack_announcements": int(yb.sum()), "chance": r4(yb.mean()),
                "pr_auc_ET-B": r4(base), "one_field_fixed": fixed, "coefficients_standardised": coefs,
                "fields_whose_fixing_brings_ET-B_below_0.1": below})
    return out


def main() -> None:
    paths = load_paths()
    interim = paths["interim_dir"]
    runs = pd.read_csv(RUNS)
    caps, meta = s5.load(interim)
    print("[RV4] a: chance-corrected gap", flush=True)
    s5_json = json.loads((ROOT / "results" / "S5_transfer.json").read_text(encoding="utf-8"))["results"]["configurations"]
    res = {"a_chance_corrected_gap": part_a(runs, s5_json)}
    print("[RV4] b: constant scores", flush=True)
    ranges = {tag: field_ranges(cap) for tag, cap in caps.items()}
    const = constant_configs(runs)
    for c in const:
        tgt = ranges[TARGET[c["direction"]]]
        c["missing_or_constant_in_target"] = [f for f in c["fields"] if tgt[f]["constant_or_missing"]]
        c["all_fields_missing_or_constant_in_target"] = len(c["missing_or_constant_in_target"]) == len(c["fields"])
    res["b_constant_scores"] = {"configurations": len(const), "of": int(runs[runs["kind"] == "s2t"].groupby(CFG).ngroups),
                                "list": const}
    print(f"[RV4]    {len(const)} configurations with constant scores", flush=True)
    print("[RV4] c: per-field shift", flush=True)
    res["c_field_shift"] = part_c(caps, meta)
    res["c_field_shift"]["dbm_antsignal_codes"] = dbm_order(paths, caps)
    print("[RV4] d: LR on F-chatz", flush=True)
    res["d_lr_f_chatz_announcements"] = part_d(caps, meta, runs)
    inputs = {p.name: sha256_file(p) for p in [RUNS, interim / "s5_features.json", ROOT / "results" / "S5_transfer.json"]}
    out = write_result("RV4_transfer", {"results": res}, run_metadata("scripts/18_rv4_transfer_checks.py",
                                                                     inputs_sha256=inputs))
    print(f"[RV4] done -> {out}", flush=True)


if __name__ == "__main__":
    main()
