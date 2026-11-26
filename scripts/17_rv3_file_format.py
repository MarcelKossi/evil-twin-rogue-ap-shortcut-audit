"""Exploratory (journal 2026-11-27) - how each AWID3 CSV file writes its values.

The Parquet tables keep every value as exported, with the source CSV file of each row
(S1a). For Rogue_AP and Evil_Twin, per CSV file and per column, from the non-missing values:
  int_plain  values holding an integer written without decimals (`1`)
  int_dot0   values holding an integer written with a trailing .0 (`1.0`)
  exponent   values holding a number in exponent notation (`1e-05`)
  max_dec    most digits after the decimal point of a single-number value
Per file: frame-number range, position against the attack window (before, inside, after),
attack frames, and for the clock: digits after the decimal point of frame.time_epoch and
share of frame.time_delta equal to 0.

Each file gets one format per column: dot0 (integers written `1.0`), plain (`1`), mixed (both
in the same file) or none (no integer). A column changes format when its files do not all have
the same format (files without integers left aside). A
format lines up with the attack window when it covers at least 80% of the files on one side
of the window start (before / inside) and at most 20% on the other. The same test is applied
to the number of digits of frame.time_epoch. Each column is tagged with its encoding in the
feature matrices of S2b (number, hash or label; or not a model feature).

Usage (from the repository root):
    python scripts/17_rv3_file_format.py
Output: results/RV3_file_format.json (a finished capture is kept on a re-run)
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.frames import iter_parquet  # noqa: E402
from src.modeling import WINDOWS  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402

CAPTURES = {"rogue_ap": "awid3_rogue_ap", "evil_twin": "awid3_evil_twin"}
SKIP = {"source_file", "row_in_file"}
ITEM = r"(?:^|,)\s*{}\s*(?:,|$)"
INT_PLAIN = ITEM.format(r"-?\d+")
INT_DOT0 = ITEM.format(r"-?\d+\.0+")
EXPONENT = ITEM.format(r"-?\d+(?:\.\d+)?[eE][-+]?\d+")
DECIMALS = r"^\s*-?\d+\.(\d+)\s*$"
LINE_UP_HIGH, LINE_UP_LOW = 0.8, 0.2
OUT = ROOT / "results" / "RV3_file_format.json"


def column_stats(s: pd.Series) -> dict:
    """Counts over the non-missing values of one column of one file (regexes run on distinct values)."""
    vc = s.dropna().astype(str).value_counts()
    if vc.empty:
        return {"values": 0, "int_plain": 0, "int_dot0": 0, "exponent": 0, "max_dec": 0}
    u = vc.index.to_series(index=vc.index)
    dec = u.str.extract(DECIMALS, expand=False).str.len().fillna(0)
    return {"values": int(vc.sum()),
            "int_plain": int(vc[u.str.contains(INT_PLAIN, regex=True).to_numpy()].sum()),
            "int_dot0": int(vc[u.str.contains(INT_DOT0, regex=True).to_numpy()].sum()),
            "exponent": int(vc[u.str.contains(EXPONENT, regex=True).to_numpy()].sum()),
            "max_dec": int(dec.max())}


def file_format(st: dict) -> str:
    if st["int_dot0"] and st["int_plain"]:
        return "mixed"
    return "dot0" if st["int_dot0"] else ("plain" if st["int_plain"] else "none")


def lines_up(labels: dict[str, str], position: dict[str, str]) -> dict:
    """Share of each label among the files before and inside the attack window."""
    sides = {s: [f for f in labels if position[f] == s] for s in ("before", "inside")}
    shares = {s: {lab: sum(labels[f] == lab for f in fs) / len(fs) for lab in sorted(set(labels.values()))}
              for s, fs in sides.items() if fs}
    up = len(shares) == 2 and any(
        (shares["before"][lab] >= LINE_UP_HIGH and shares["inside"][lab] <= LINE_UP_LOW)
        or (shares["inside"][lab] >= LINE_UP_HIGH and shares["before"][lab] <= LINE_UP_LOW)
        for lab in shares["before"])
    return {"files": {s: len(fs) for s, fs in sides.items()},
            "share_by_side": {s: {k: round(v, 3) for k, v in d.items()} for s, d in shares.items()},
            "lines_up_with_window": bool(up)}


def scan(path: Path, cap: str) -> tuple[dict, dict]:
    """Per (file, column) counts and per-file facts, one pass over the Parquet table."""
    import pyarrow.parquet as pq
    cols = [c for c in pq.ParquetFile(path).schema.names if c not in SKIP]
    stats = defaultdict(lambda: {"values": 0, "int_plain": 0, "int_dot0": 0, "exponent": 0, "max_dec": 0})
    facts = defaultdict(lambda: {"rows": 0, "fn_min": np.inf, "fn_max": -np.inf, "attack_frames": 0,
                                 "time_delta_values": 0, "time_delta_zero": 0})
    for batch in iter_parquet(path, cols + ["source_file"], 50_000):
        for f, df in batch.groupby("source_file", sort=False):
            fa = facts[f]
            fn = pd.to_numeric(df["frame.number"], errors="coerce").dropna()
            fa["rows"] += len(df)
            if len(fn):
                fa["fn_min"], fa["fn_max"] = min(fa["fn_min"], float(fn.min())), max(fa["fn_max"], float(fn.max()))
            lab = df["Label"]
            fa["attack_frames"] += int((lab.notna() & (lab != "Normal")).sum())
            td = pd.to_numeric(df["frame.time_delta"], errors="coerce").dropna()
            fa["time_delta_values"] += len(td)
            fa["time_delta_zero"] += int((td == 0).sum())
            for c in cols:
                st, new = stats[(f, c)], column_stats(df[c])
                for k in ("values", "int_plain", "int_dot0", "exponent"):
                    st[k] += new[k]
                st["max_dec"] = max(st["max_dec"], new["max_dec"])
        print(f"[RV3] {cap}: {len(facts)} files read", flush=True)
    return stats, facts


def capture_report(paths: dict, cap: str) -> dict:
    stem = CAPTURES[cap]
    stats, facts = scan(paths["interim_dir"] / f"{stem}.parquet", cap)
    feats = json.loads((paths["interim_dir"] / f"{stem}_features.json").read_text(encoding="utf-8"))
    enc = {c["name"]: {"kind": c["kind"], "encoding": c["encoding"], "family": c["family"]} for c in feats["columns"]}
    lo, hi = WINDOWS[cap]
    files = sorted(facts, key=lambda f: facts[f]["fn_min"])
    position = {f: "before" if facts[f]["fn_max"] < lo else ("after" if facts[f]["fn_min"] > hi else "inside")
                for f in files}
    per_file = []
    for f in files:
        fa, te = facts[f], stats[(f, "frame.time_epoch")]
        per_file.append({"file": f, "rows": fa["rows"], "frame_numbers": [int(fa["fn_min"]), int(fa["fn_max"])],
                         "position": position[f], "attack_frames": fa["attack_frames"],
                         "time_epoch_max_decimals": te["max_dec"],
                         "time_epoch_integer_share": round(te["int_plain"] / max(te["values"], 1), 4),
                         "time_delta_zero_share": round(fa["time_delta_zero"] / max(fa["time_delta_values"], 1), 4)})
    columns = sorted({c for _, c in stats})
    changing, mixed_inside = [], []
    for c in columns:
        labels = {f: file_format(stats[(f, c)]) for f in files if stats[(f, c)]["values"]}
        labels = {f: lab for f, lab in labels.items() if lab != "none"}
        if "mixed" in labels.values():
            mixed_inside.append(c)
        if len(set(labels.values())) < 2:
            continue
        changing.append({"column": c, "model_feature": enc.get(c),
                         "files_by_format": {k: int(v) for k, v in Counter(labels.values()).items()},
                         **lines_up(labels, position),
                         "format_by_file": {f: labels[f] for f in files if f in labels}})
    clock = {f: str(stats[(f, "frame.time_epoch")]["max_dec"]) for f in files}
    exponent_cols = sorted({c for (f, c), st in stats.items() if st["exponent"]})
    return {"window": [lo, hi], "files": per_file,
            "columns_read": len(columns),
            "columns_changing_format": len(changing),
            "changing_and_model_feature": [x["column"] for x in changing if x["model_feature"]],
            "changing_text_encoded_feature": [x["column"] for x in changing
                                              if x["model_feature"] and x["model_feature"]["kind"] == "text"],
            "changing_lining_up_with_window": [x["column"] for x in changing if x["lines_up_with_window"]],
            "clock_decimals": {"by_file": clock, **lines_up(clock, position)},
            "columns_with_exponent_notation": exponent_cols,
            "columns_mixed_inside_a_file": mixed_inside,
            "columns": changing}


def main() -> None:
    paths = load_paths()
    done = json.loads(OUT.read_text(encoding="utf-8"))["results"] if OUT.exists() else {}
    inputs = {p.name: sha256_file(p) for p in [ROOT / "results" / "S1_parquet_manifest.json",
                                               ROOT / "results" / "S2b_features.json"]}
    for cap in CAPTURES:
        if cap in done:
            print(f"[RV3] {cap}: already in {OUT.name}, skipped")
            continue
        done[cap] = capture_report(paths, cap)
        r = done[cap]
        print(f"[RV3] {cap}: {r['columns_changing_format']} of {r['columns_read']} columns change format; "
              f"model features among them {len(r['changing_and_model_feature'])} "
              f"(text-encoded {len(r['changing_text_encoded_feature'])}); lining up with the window "
              f"{len(r['changing_lining_up_with_window'])}; clock decimals line up "
              f"{r['clock_decimals']['lines_up_with_window']}", flush=True)
        write_result("RV3_file_format", {"results": done},
                     run_metadata("scripts/17_rv3_file_format.py", inputs_sha256=inputs))


if __name__ == "__main__":
    main()
