"""Stage S6 - rule baseline (protocol 9.6) and its part of H3b.

Five rules defined a priori, no parameter tuned on test data. Reference profile: the first
60 seconds of the capture, normal frames only (AWID3: before the attack window):
  - whitelist = BSSIDs that announce themselves (beacons, probe responses);
  - known SSIDs, and per SSID the set of RSN/capability profiles seen (all columns named
    wlan.rsn.* and wlan.fixed.capabilities.* present in the dataset).
  R1  beacon or probe response announcing a known SSID from a BSSID outside the whitelist
  R2  beacon or probe response whose RSN/capability profile differs from those of its SSID
  R3  sequence-number jump > 100 (modulo 4096) between consecutive frames sent by an AP
      (source address = BSSID) less than 1 s apart
  R4  beacon or probe response whose TSF is lower than that of the previous one of its BSSID
  R5  unprotected deauthentication or disassociation frame with >= 10 such frames in the
      last second (itself included)
Score = number of rules fired on the frame (0-5); PR-AUC over all frames of the dataset,
also per sub-task (ET-B, ET-D). A rule whose fields are missing is not applicable.

Profile values (R2): an integer written with a trailing .0 (`1.0`, `0.00`) is read as the same
integer (`1`, `0`), also inside comma-separated lists; every other value is compared as written.
Some AWID3 CSV files write `1.0` where others write `1` (deviation 12, journal 2026-11-27); the
first version compared the text as written and kept its results in results/S6_rules_v1.json.

H3b (rule part). The rules learn nothing from labels: the reference profile is taken from
the target's own first minute, so their transfer gap is 0 by construction. As decided before
running (journal, deviation 9), the rule part of H3b compares the rule PR-AUC on each target
with the transfer PR-AUC of the F-all models (S5), one-sided Wilcoxon over model x direction.

Usage (from the repository root):
    python scripts/14_s6_rules.py
Output: results/S6_rules.json
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.frames import iter_parquet  # noqa: E402
from src.modeling import WINDOWS  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


s2b = _load("s2b", "06_build_features.py")   # parse_numeric, valid_rows
s5a = _load("s5a", "12_s5_prepare.py")       # awid2_names, awid2_chunks

BASE = ["frame.time_epoch", "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.protected",
        "wlan.bssid", "wlan.sa", "wlan.ssid", "wlan.seq", "wlan.fixed.timestamp"]
PROFILE = ("wlan.rsn.", "wlan.fixed.capabilities.")
REF_SECONDS, SEQ_JUMP, DEAUTH_N = 60.0, 100, 10
INT_DOT0 = r"(?<![\w.])(-?\d+)\.0+(?![\w.])"   # 1.0 -> 1, also inside comma-separated lists
S5 = ROOT / "results" / "S5_transfer.json"


def num(s: pd.Series) -> np.ndarray:
    return s2b.parse_numeric(s).to_numpy("float64")


def profile_text(a: pd.DataFrame, cols: list[str]) -> np.ndarray:
    """One text per announcement: its profile values joined by '|', integers written without .0."""
    vals = a[cols].fillna("-").astype(str).apply(lambda c: c.str.replace(INT_DOT0, r"\1", regex=True))
    return vals.agg("|".join, axis=1).to_numpy(str)


def collect(chunks, profile_cols: list[str]) -> dict:
    """Compact arrays: every frame (label, time, type), announcements, AP-sent frames, deauths."""
    parts = {k: [] for k in ("y", "t", "typ", "sub", "pre", "a_idx", "a_ssid", "a_bssid", "a_tsf", "a_prof",
                             "s_idx", "s_bssid", "s_seq", "d_idx")}
    i = 0
    for df, y, pre in chunks:
        n = len(df)
        idx = np.arange(i, i + n)
        t, typ, sub = num(df["frame.time_epoch"]), num(df["wlan.fc.type"]), num(df["wlan.fc.subtype"])
        prot = num(df["wlan.fc.protected"])
        for k, v in (("y", y), ("t", t), ("typ", typ), ("sub", sub), ("pre", pre)):
            parts[k].append(v)
        ann = (typ == 0) & np.isin(sub, [5, 8])
        a = df.loc[ann]
        parts["a_idx"].append(idx[ann])
        parts["a_ssid"].append(a["wlan.ssid"].fillna("").to_numpy(str))
        parts["a_bssid"].append(a["wlan.bssid"].fillna("").to_numpy(str))
        parts["a_tsf"].append(num(a["wlan.fixed.timestamp"]))
        parts["a_prof"].append(profile_text(a, profile_cols)
                               if profile_cols and len(a) else np.full(len(a), "", dtype="<U1"))
        ap = (df["wlan.sa"] == df["wlan.bssid"]).to_numpy() & df["wlan.bssid"].notna().to_numpy()
        parts["s_idx"].append(idx[ap])
        parts["s_bssid"].append(df.loc[ap, "wlan.bssid"].to_numpy(str))
        parts["s_seq"].append(num(df.loc[ap, "wlan.seq"]))
        parts["d_idx"].append(idx[(typ == 0) & np.isin(sub, [10, 12]) & (prot == 0)])
        i += n
    return {k: np.concatenate(v) if v else np.empty(0) for k, v in parts.items()}


def per_group_prev(keys: np.ndarray, order: np.ndarray) -> np.ndarray:
    """For rows sorted by `order`, position of the previous row with the same key (-1 if none)."""
    prev = np.full(len(order), -1)
    last = {}
    for pos, r in enumerate(order):
        k = keys[r]
        prev[pos] = last.get(k, -1)
        last[k] = pos
    return prev


def rules(d: dict, profile_cols: list[str]) -> tuple[np.ndarray, dict]:
    n, t = len(d["y"]), d["t"]
    fired, info = {}, {}
    t0 = np.nanmin(t)
    a_t = t[d["a_idx"]]
    ref = (a_t < t0 + REF_SECONDS) & (d["y"][d["a_idx"]] == 0) & d["pre"][d["a_idx"]].astype(bool)
    known = set(d["a_ssid"][ref]) - {""}
    white = set(d["a_bssid"][ref]) - {""}
    profiles = {}
    for s, p in zip(d["a_ssid"][ref], d["a_prof"][ref]):
        profiles.setdefault(s, set()).add(p)
    info["reference"] = {"announcements": int(ref.sum()), "known_ssids": sorted(known), "whitelist": sorted(white),
                         "attack_frames_in_first_minute": int(d["y"][t < t0 + REF_SECONDS].sum())}
    # R1, R2
    if ref.any():
        r1 = np.isin(d["a_ssid"], list(known)) & ~np.isin(d["a_bssid"], list(white))
        fired["R1"] = d["a_idx"][r1]
        if profile_cols:
            r2 = np.array([s in profiles and p not in profiles[s] for s, p in zip(d["a_ssid"], d["a_prof"])], bool)
            fired["R2"] = d["a_idx"][r2]
    # R3: sequence jump between consecutive AP frames < 1 s apart
    if len(d["s_idx"]) and not np.all(np.isnan(d["s_seq"])):
        order = np.argsort(t[d["s_idx"]], kind="stable")
        prev = per_group_prev(d["s_bssid"], order)
        cur, has = order, prev >= 0
        p_rows = np.where(has, order[np.maximum(prev, 0)], 0)
        dt = t[d["s_idx"][cur]] - t[d["s_idx"][p_rows]]
        jump = np.mod(d["s_seq"][cur] - d["s_seq"][p_rows], 4096)
        fired["R3"] = d["s_idx"][cur[has & (dt <= 1.0) & (jump > SEQ_JUMP)]]
    # R4: TSF lower than the previous announcement of the same BSSID
    if len(d["a_idx"]) and not np.all(np.isnan(d["a_tsf"])):
        order = np.argsort(a_t, kind="stable")
        prev = per_group_prev(d["a_bssid"], order)
        has = prev >= 0
        p_rows = np.where(has, order[np.maximum(prev, 0)], 0)
        fired["R4"] = d["a_idx"][order[has & (d["a_tsf"][order] < d["a_tsf"][p_rows])]]
    # R5: >= 10 unprotected deauth/disassoc in the last second
    if len(d["d_idx"]):
        td = np.sort(t[d["d_idx"]])
        ord_d = d["d_idx"][np.argsort(t[d["d_idx"]], kind="stable")]
        count = np.arange(len(td)) - np.searchsorted(td, td - 1.0, side="left") + 1
        fired["R5"] = ord_d[count >= DEAUTH_N]
    else:
        fired["R5"] = np.empty(0, int)
    score = np.zeros(n, np.int8)
    for r, rows in fired.items():
        score[rows] += 1
    info["applicable"] = sorted(fired)
    info["per_rule"] = {r: {"fires": int(len(rows)), "on_attack": int(d["y"][rows].sum())} for r, rows in fired.items()}
    return score, info


def scores(y: np.ndarray, s: np.ndarray, d: dict) -> dict:
    out = {"prevalence": float(y.mean()), "pr_auc": float(average_precision_score(y, s)),
           "roc_auc": float(roc_auc_score(y, s)), "frames": int(len(y)), "attack": int(y.sum())}
    for k, m in (("ET-B", (d["typ"] == 0) & np.isin(d["sub"], [5, 8])), ("ET-D", d["typ"] == 2)):
        out[f"pr_auc_{k}"] = float(average_precision_score(y[m], s[m])) if y[m].sum() else None
        out[f"attack_{k}"] = int(y[m].sum())
    return out


def awid3(paths: dict, cap: str) -> tuple[dict, list[str]]:
    import pyarrow.parquet as pq
    path = paths["interim_dir"] / f"awid3_{cap}.parquet"
    names = pq.ParquetFile(path).schema.names
    prof = sorted(c for c in names if c.startswith(PROFILE))
    lo = WINDOWS[cap][0]

    def chunks():
        for df in iter_parquet(path, BASE + prof + ["Label", "frame.number"], 50_000):
            df = df.loc[s2b.valid_rows(df)]
            fn = num(df["frame.number"])
            yield df, (df["Label"] != "Normal").to_numpy().astype(np.int8), (fn < lo).astype(np.int8)
    d = collect(chunks(), prof)
    assert np.array_equal(d["y"], np.load(paths["interim_dir"] / f"awid3_{cap}_y.npy"))
    return d, prof


def awid2(paths: dict) -> tuple[dict, list[str]]:
    names = s5a.awid2_names()
    prof = sorted(c for c in names if c.startswith(PROFILE))

    def chunks():
        for _, df in s5a.awid2_chunks(paths["awid2_dir"], names):
            df = df.loc[df["class"].isin(["normal", "evil_twin"])]
            yield df, (df["class"] == "evil_twin").to_numpy().astype(np.int8), np.ones(len(df), np.int8)
    d = collect(chunks(), prof)
    assert np.array_equal(d["y"], np.load(paths["interim_dir"] / "s5_awid2_y.npy"))
    return d, prof


def main() -> None:
    paths = load_paths()
    out = {}
    for name, loader in (("awid3_rogue_ap", lambda: awid3(paths, "rogue_ap")),
                         ("awid3_evil_twin", lambda: awid3(paths, "evil_twin")), ("awid2", lambda: awid2(paths))):
        d, prof = loader()
        s, info = rules(d, prof)
        out[name] = {**scores(d["y"].astype(int), s, d), **info, "profile_fields": prof}
        print(f"[S6] {name}: PR-AUC {out[name]['pr_auc']:.4f} (chance {out[name]['prevalence']:.4f}), "
              f"rules {info['applicable']}, fires {info['per_rule']}", flush=True)
    # H3b, rule part (deviation 9): rule PR-AUC on the target vs F-all transfer PR-AUC of each model
    cfg = json.loads(S5.read_text(encoding="utf-8"))["results"]["configurations"]
    target = {"AWID3->AWID2": "awid2", "AWID2->AWID3": "awid3_evil_twin"}
    pairs = [(out[target[k.split(" | ")[0]]]["pr_auc"], v["pr_auc"]) for k, v in cfg.items() if " | F-all | " in k]
    r, m = np.array(pairs).T
    out["H3b_rule_part"] = {"pairs": len(pairs), "rule_pr_auc": sorted(set(np.round(r, 4).tolist())),
                            "median_model_transfer_pr_auc": float(np.median(m)),
                            "wilcoxon_p_one_sided": float(wilcoxon(r, m, alternative="greater").pvalue),
                            "note": "rule transfer gap is 0 by construction (no labelled training); Holm in S8"}
    print(f"[S6] H3b rule part: {out['H3b_rule_part']}")
    inputs = {p.name: sha256_file(p) for p in [S5, ROOT / "configs" / "awid2_columns.txt"]}
    res = write_result("S6_rules", {"results": out}, run_metadata("scripts/14_s6_rules.py", inputs_sha256=inputs))
    print(f"[S6] Done -> {res}")


if __name__ == "__main__":
    main()
