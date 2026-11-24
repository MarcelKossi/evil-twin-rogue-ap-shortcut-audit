"""Exploratory (plan item 2 of 2026-11-22) - 802.11 checks behind the S6 rules and the attack labels.

Three parts, one result file each; a finished part is skipped unless --force.
  awid3  For AWID3 Rogue_AP and Evil_Twin: the S6 rules recomputed with the S6 code (counts must
         equal results/S6_rules.json), then the R1-R4 alarms on frames labelled Normal broken down
         by subtype, BSSID, source, length and position; for R2, the profile fields that differ
         from the closest reference profile; for R3/R4, the previous frame of the same BSSID.
         Deauthentication/disassociation frames: label, source, destination, reason code, signal,
         next to the signal of the announcements in the attack window.
  awid2  The S6 rules on the kept rows (normal, evil_twin; must equal S6) and on every row,
         scored on the kept rows; alarm breakdown as above; deauthentication frames by class.
  pcap   Every beacon and probe response of the AWID3 Rogue_AP and Evil_Twin pcap files, read
         with the parser below (radiotap, 802.11 header, information elements): privacy and ESS
         bits, RSN element (ciphers, AKM, MFPC, MFPR), WPA element, country, SSID. Frames are
         matched to the CSV by position in the capture; agreement of length, BSSID and subtype
         is checked before anything is read.

Usage (from the repository root):
    python scripts/16_rv2_80211_checks.py --layout        # list the pcap members, nothing written
    python scripts/16_rv2_80211_checks.py                 # all parts
    python scripts/16_rv2_80211_checks.py --part pcap --force
Output: results/RV2_awid3.json, results/RV2_awid2.json, results/RV2_pcap.json
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awid3 import class_of  # noqa: E402
from src.frames import FRAME_NAMES, iter_parquet, to_int  # noqa: E402
from src.modeling import WINDOWS  # noqa: E402
from src.utils import ROOT, load_paths, natural_key, run_metadata, sha256_file, write_result  # noqa: E402


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


s6 = _load("s6", "14_s6_rules.py")     # collect, rules, scores, awid3, awid2, per_group_prev, constants
S6_JSON = ROOT / "results" / "S6_rules.json"
CAPTURES = {"rogue_ap": "Rogue_AP", "evil_twin": "Evil_Twin"}
DETAIL = ["frame.number", "frame.len", "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.protected", "wlan.sa",
          "wlan.da", "wlan.bssid", "wlan.ssid", "wlan.fixed.reason_code"]
TOP = 10


# ---------------------------------------------------------------- rules, keeping the rows they fire on
def fire(d: dict, prof: list[str]) -> tuple[dict, dict]:
    """Same computation as rules() in 14_s6_rules.py, keeping the rows each rule fires on.
    main() checks that the summed score equals the S6 score row by row."""
    t, fired, extra = d["t"], {}, {}
    t0 = np.nanmin(t)
    a_t = t[d["a_idx"]]
    ref = (a_t < t0 + s6.REF_SECONDS) & (d["y"][d["a_idx"]] == 0) & d["pre"][d["a_idx"]].astype(bool)
    known = set(d["a_ssid"][ref]) - {""}
    white = set(d["a_bssid"][ref]) - {""}
    profiles = {}
    for s, p in zip(d["a_ssid"][ref], d["a_prof"][ref]):
        profiles.setdefault(s, set()).add(p)
    if ref.any():
        fired["R1"] = d["a_idx"][np.isin(d["a_ssid"], list(known)) & ~np.isin(d["a_bssid"], list(white))]
        if prof:
            r2 = np.array([s in profiles and p not in profiles[s] for s, p in zip(d["a_ssid"], d["a_prof"])], bool)
            fired["R2"] = d["a_idx"][r2]
            extra["R2_pos"], extra["profiles"] = np.flatnonzero(r2), profiles
    if len(d["s_idx"]) and not np.all(np.isnan(d["s_seq"])):
        order = np.argsort(t[d["s_idx"]], kind="stable")
        prev = s6.per_group_prev(d["s_bssid"], order)
        has = prev >= 0
        p_rows = np.where(has, order[np.maximum(prev, 0)], 0)
        dt = t[d["s_idx"][order]] - t[d["s_idx"][p_rows]]
        jump = np.mod(d["s_seq"][order] - d["s_seq"][p_rows], 4096)
        m = has & (dt <= 1.0) & (jump > s6.SEQ_JUMP)
        fired["R3"] = d["s_idx"][order[m]]
        extra["R3"] = {"prev": d["s_idx"][p_rows[m]], "jump": jump[m], "dt": dt[m]}
    if len(d["a_idx"]) and not np.all(np.isnan(d["a_tsf"])):
        order = np.argsort(a_t, kind="stable")
        prev = s6.per_group_prev(d["a_bssid"], order)
        has = prev >= 0
        p_rows = np.where(has, order[np.maximum(prev, 0)], 0)
        m = has & (d["a_tsf"][order] < d["a_tsf"][p_rows])
        fired["R4"] = d["a_idx"][order[m]]
        extra["R4"] = {"prev": d["a_idx"][p_rows[m]]}
    if len(d["d_idx"]):
        td = np.sort(t[d["d_idx"]])
        ord_d = d["d_idx"][np.argsort(t[d["d_idx"]], kind="stable")]
        count = np.arange(len(td)) - np.searchsorted(td, td - 1.0, side="left") + 1
        fired["R5"] = ord_d[count >= s6.DEAUTH_N]
    else:
        fired["R5"] = np.empty(0, int)
    return fired, extra


def check_s6(name: str, d: dict, prof: list[str], fired: dict, s6_json: dict | None) -> dict:
    """Row-by-row equality with rules() of S6 and, if given, equality of the stored per-rule counts."""
    score, info = s6.rules(d, prof)
    mine = np.zeros(len(d["y"]), np.int8)
    for rows in fired.values():
        mine[rows] += 1
    same_rows = bool(np.array_equal(mine, score))
    same_json = None if s6_json is None else info["per_rule"] == s6_json[name]["per_rule"]
    if not same_rows or same_json is False:
        raise SystemExit(f"[RV2] {name}: S6 not reproduced (rows equal {same_rows}, stored counts equal {same_json})")
    return {"score": score, "info": info, "same_rows_as_s6_code": same_rows, "same_counts_as_s6_json": same_json}


def short(v) -> str:
    v = str(v)
    return v if len(v) <= 24 else f"{v[:10]}...({len(v)} chars)"


def counts(values, n: int = TOP, full: bool = False) -> dict:
    return {(str(k) if full else short(k)): int(c) for k, c in Counter(map(str, values)).most_common(n)}


def quant(x) -> dict:
    x = np.asarray(x, float)
    ok = x[~np.isnan(x)]
    if not len(ok):
        return {"n": int(len(x)), "missing": int(len(x))}
    q = np.percentile(ok, [10, 50, 90])
    return {"n": int(len(x)), "missing": int(len(x) - len(ok)), "p10": float(q[0]), "median": float(q[1]),
            "p90": float(q[2])}


def subtype_name(typ, sub) -> list[str]:
    return [f"{int(16 * a + b)} ({FRAME_NAMES.get(int(16 * a + b), '?')})" if not (np.isnan(a) or np.isnan(b))
            else "missing" for a, b in zip(typ, sub)]


def r2_diffs(d: dict, prof: list[str], extra: dict, label: np.ndarray) -> dict:
    """For each R2 alarm: the profile fields that differ from the closest reference profile of its SSID."""
    sets, pairs = Counter(), Counter()
    for pos in extra.get("R2_pos", []):
        p = d["a_prof"][pos].split("|")
        best = None
        for r in sorted(extra["profiles"][d["a_ssid"][pos]]):
            rr = r.split("|")
            if len(p) != len(prof) or len(rr) != len(prof):
                diff = [("<unparsed>", "", "")]
            else:
                diff = [(c, a, b) for c, a, b in zip(prof, p, rr) if a != b]
            if best is None or len(diff) < len(best):
                best = diff
        lab = label[d["a_idx"][pos]]
        sets[(lab, " + ".join(c for c, _, _ in best))] += 1
        for c, a, b in best:
            pairs[(lab, c, short(a), short(b))] += 1
    return {"differing_fields": [{"label": k[0], "fields": k[1], "n": v} for k, v in sets.most_common()],
            "values_alarm_vs_reference": [{"label": k[0], "field": k[1], "alarm": k[2], "reference": k[3], "n": v}
                                          for k, v in pairs.most_common(30)]}


def alarm_breakdown(d: dict, fired: dict, extra: dict, det: pd.DataFrame, label: np.ndarray,
                    normal: str, window: tuple[int, int] | None, prof: list[str]) -> dict:
    out = {}
    for r in ("R1", "R2", "R3", "R4"):
        if r not in fired:
            out[r] = "not applicable"
            continue
        rows = fired[r]
        keep = label[rows] == normal
        nrm = rows[keep]
        sub = det.loc[nrm]
        o = {"fires": int(len(rows)), "on_normal": int(keep.sum()), "on_attack": int((~keep).sum()),
             "normal": {"subtype": counts(subtype_name(d["typ"][nrm], d["sub"][nrm])),
                        "bssid": counts(sub["wlan.bssid"]), "source": counts(sub["wlan.sa"]),
                        "destination": counts(sub["wlan.da"], 5), "frame_len": counts(sub["frame.len"]),
                        "ssid": counts(sub["wlan.ssid"], 5)}}
        if window is not None:
            fn = s6.num(sub["frame.number"])
            o["normal"]["inside_attack_window"] = int(((fn >= window[0]) & (fn <= window[1])).sum())
        if r in ("R3", "R4"):
            prev = extra[r]["prev"][keep]
            o["normal"]["previous_frame"] = {"label": counts(label[prev]),
                                             "subtype": counts(subtype_name(d["typ"][prev], d["sub"][prev])),
                                             "frame_len": counts(det.loc[prev, "frame.len"])}
        if r == "R3":
            o["normal"]["seq_jump"] = quant(extra["R3"]["jump"][keep])
            o["normal"]["seconds_since_previous"] = quant(extra["R3"]["dt"][keep])
        if r == "R2":
            o["profile_difference"] = r2_diffs(d, prof, extra, label)
        out[r] = o
    return out


def deauth_tables(det: pd.DataFrame, label: np.ndarray, signal_col: str, window: tuple[int, int] | None) -> dict:
    t, st = s6.num(det["wlan.fc.type"]), s6.num(det["wlan.fc.subtype"])
    lab = pd.Series(label[det.index.to_numpy()], index=det.index)
    sig = pd.Series(s6.num(det[signal_col]), index=det.index)
    dd = det[(t == 0) & np.isin(st, [10, 12])].copy()
    dd["label"], dd["subtype"] = lab[dd.index], np.where(s6.num(dd["wlan.fc.subtype"]) == 12, "deauth", "disassoc")
    keys = ["label", "subtype", "wlan.fc.protected", "wlan.sa", "wlan.da", "wlan.fixed.reason_code"]
    if window is not None:
        fn = s6.num(dd["frame.number"])
        dd["in_window"] = (fn >= window[0]) & (fn <= window[1])
        keys.append("in_window")
    g = dd.fillna({k: "<missing>" for k in keys if k in DETAIL}).groupby(keys, dropna=False).size()
    groups = [{**{k: str(v) for k, v in zip(keys, idx)}, "n": int(n)} for idx, n in g.sort_values(ascending=False).head(30).items()]
    sgroups = []
    for idx, part in dd.fillna({"wlan.sa": "<missing>"}).groupby(["label", "subtype", "wlan.sa"]):
        sgroups.append({"label": idx[0], "subtype": idx[1], "source": idx[2], "signal_dbm": quant(sig[part.index])})
    sgroups = sorted(sgroups, key=lambda x: -x["signal_dbm"]["n"])[:TOP]
    ann = det[(t == 0) & np.isin(st, [5, 8])]
    if window is not None:
        fn = s6.num(ann["frame.number"])
        ann = ann[(fn >= window[0]) & (fn <= window[1])]
    agroups = []
    for idx, part in ann.fillna({"wlan.bssid": "<missing>", "frame.len": "<missing>"}).groupby(
            [lab[ann.index], "wlan.bssid", "frame.len"]):
        agroups.append({"label": idx[0], "bssid": idx[1], "frame_len": idx[2], "signal_dbm": quant(sig[part.index])})
    agroups = sorted(agroups, key=lambda x: -x["signal_dbm"]["n"])[:TOP]
    return {"frames": int(len(dd)), "by_label": counts(dd["label"]),
            "reason_code_by_label": {k: counts(v["wlan.fixed.reason_code"].fillna("<missing>"))
                                     for k, v in dd.groupby("label")},
            "groups": groups, "signal_by_source": sgroups,
            "signal_of_announcements" + ("_in_attack_window" if window else ""): agroups}


# ---------------------------------------------------------------- part awid3
def part_awid3(paths: dict, s6_json: dict) -> dict:
    out = {}
    for cap, cls in CAPTURES.items():
        name = f"awid3_{cap}"
        d, prof = s6.awid3(paths, cap)                       # asserts labels = S2b
        fired, extra = fire(d, prof)
        chk = check_s6(name, d, prof, fired, s6_json)
        label = np.where(d["y"] == 1, cls, "Normal")
        need = set()
        for r in ("R1", "R2", "R3", "R4"):
            if r in fired:
                need.update(fired[r][d["y"][fired[r]] == 0].tolist())
        for r in ("R3", "R4"):
            if r in extra:
                need.update(extra[r]["prev"].tolist())
        need = np.array(sorted(need), dtype=np.int64)
        path = paths["interim_dir"] / f"awid3_{cap}.parquet"
        cols = DETAIL + ["wlan_radio.signal_dbm", "Label"]
        parts, i = [], 0
        for df in iter_parquet(path, cols, 50_000):
            df = df.loc[s6.s2b.valid_rows(df)].reset_index(drop=True)
            df.index += i
            i += len(df)
            t, st = s6.num(df["wlan.fc.type"]), s6.num(df["wlan.fc.subtype"])
            keep = np.isin(df.index, need) | ((t == 0) & np.isin(st, [5, 8, 10, 12]))
            parts.append(df[keep])
        det = pd.concat(parts)
        assert i == len(d["y"]), (i, len(d["y"]))
        assert np.array_equal(np.nan_to_num(s6.num(det["wlan.fc.type"]), nan=-1),
                              np.nan_to_num(d["typ"][det.index.to_numpy()], nan=-1)), "row order differs from S6"
        out[name] = {"reproduces_s6": {k: v for k, v in chk.items() if k.startswith("same")},
                     "profile_fields": prof, "reference": chk["info"]["reference"],
                     "alarms": alarm_breakdown(d, fired, extra, det, label, "Normal", WINDOWS[cap], prof),
                     "deauth_disassoc": deauth_tables(det, label, "wlan_radio.signal_dbm", WINDOWS[cap])}
        print(f"[RV2] {name}: S6 reproduced; normal alarms "
              f"{ {r: v['on_normal'] for r, v in out[name]['alarms'].items() if isinstance(v, dict)} }", flush=True)
    return out


# ---------------------------------------------------------------- part awid2
def part_awid2(paths: dict, s6_json: dict) -> dict:
    d_k, prof = s6.awid2(paths)                              # kept rows, as in S6; asserts labels = S5
    fired_k, extra_k = fire(d_k, prof)
    chk_k = check_s6("awid2", d_k, prof, fired_k, s6_json)
    names = s6.s5a.awid2_names()
    cls_parts = []

    def all_rows():
        for _, df in s6.s5a.awid2_chunks(paths["awid2_dir"], names):
            cls_parts.append(df["class"].fillna("<missing>").to_numpy(str))
            yield df, (df["class"] != "normal").to_numpy().astype(np.int8), np.ones(len(df), np.int8)
    d_a = s6.collect(all_rows(), prof)
    cls = np.concatenate(cls_parts)
    fired_a, extra_a = fire(d_a, prof)
    chk_a = check_s6("awid2", d_a, prof, fired_a, None)
    keep = np.isin(cls, ["normal", "evil_twin"])
    y_et = (cls == "evil_twin").astype(int)
    assert keep.sum() == len(d_k["y"]) and np.array_equal(y_et[keep], d_k["y"].astype(int)), "kept rows differ from S6"
    kept_scores = s6.scores(y_et[keep], chk_a["score"][keep], {"typ": d_a["typ"][keep], "sub": d_a["sub"][keep]})
    # details: kept-row alarms of the S6 version (indices mapped to all rows) and every deauth frame
    to_all = np.flatnonzero(keep)
    need = set()
    for r in ("R1", "R2", "R3", "R4"):
        if r in fired_k:
            need.update(to_all[fired_k[r][d_k["y"][fired_k[r]] == 0]].tolist())
    for r in ("R3", "R4"):
        if r in extra_k:
            need.update(to_all[extra_k[r]["prev"]].tolist())
    need = np.array(sorted(need), dtype=np.int64)
    cols = DETAIL[1:] + ["radiotap.dbm_antsignal", "class"]
    parts, i = [], 0
    for _, df in s6.s5a.awid2_chunks(paths["awid2_dir"], names):
        df = df[cols].reset_index(drop=True)
        df.index += i
        i += len(df)
        t, st = s6.num(df["wlan.fc.type"]), s6.num(df["wlan.fc.subtype"])
        parts.append(df[np.isin(df.index, need) | ((t == 0) & np.isin(st, [5, 8, 10, 12]))])
    det = pd.concat(parts)
    assert i == len(cls), (i, len(cls))
    det["frame.number"] = np.nan                             # AWID2 has no frame numbers
    det_k = det[det.index.isin(to_all)].copy()
    det_k.index = np.searchsorted(to_all, det_k.index.to_numpy())   # back to kept-row positions
    label_k = np.where(d_k["y"] == 1, "evil_twin", "normal")
    per_class = {r: counts(cls[rows]) for r, rows in fired_a.items()}
    out = {"s6_version_kept_rows": {"reproduces_s6": {k: v for k, v in chk_k.items() if k.startswith("same")},
                                    "alarms": alarm_breakdown(d_k, fired_k, extra_k, det_k, label_k, "normal",
                                                              None, prof)},
           "all_rows": {"rows": int(len(cls)), "classes": counts(cls, 20), "reference": chk_a["info"]["reference"],
                        "scores_on_normal_and_evil_twin_rows": kept_scores,
                        "s6_pr_auc": s6_json["awid2"]["pr_auc"],
                        "fires_by_class": per_class},
           "deauth_disassoc_all_rows": deauth_tables(det, cls, "radiotap.dbm_antsignal", None)}
    print(f"[RV2] awid2: S6 reproduced; PR-AUC kept rows {s6_json['awid2']['pr_auc']:.4f}, "
          f"rules on all rows {kept_scores['pr_auc']:.4f}", flush=True)
    return out


# ---------------------------------------------------------------- part pcap
def pcap_packets(stream):
    """(original length, link type, bytes) for each packet of a pcap or pcapng stream."""
    head = stream.read(4)
    if head in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = "<" if head in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        link = struct.unpack(e + "I", stream.read(20)[16:20])[0] & 0xFFFF
        rec = struct.Struct(e + "IIII")
        while len(h := stream.read(16)) == 16:
            _, _, incl, orig = rec.unpack(h)
            yield orig, link, stream.read(incl)
        return
    if head != b"\x0a\x0d\x0d\x0a":
        raise ValueError(f"not a pcap or pcapng stream (magic {head.hex()})")
    e, links, btype = "<", [], head
    while True:
        if btype == b"\x0a\x0d\x0d\x0a":                     # section header: byte order, new interfaces
            raw_len, bom = stream.read(4), stream.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            stream.read(struct.unpack(e + "I", raw_len)[0] - 12)
            links = []
        else:
            body = stream.read(struct.unpack(e + "I", stream.read(4))[0] - 8)
            code = struct.unpack(e + "I", btype)[0]
            if code == 1:                                    # interface description
                links.append(struct.unpack_from(e + "H", body, 0)[0])
            elif code == 6:                                  # enhanced packet
                iface, _, _, cap, orig = struct.unpack_from(e + "IIIII", body, 0)
                yield orig, links[iface], body[20:20 + cap]
            elif code == 3:                                  # simple packet
                orig = struct.unpack_from(e + "I", body, 0)[0]
                yield orig, links[0], body[4:4 + min(orig, len(body) - 8)]
            elif code == 2:                                  # obsolete packet block
                iface, _, _, _, cap, orig = struct.unpack_from(e + "HHIIII", body, 0)
                yield orig, links[iface], body[20:20 + cap]
        btype = stream.read(4)
        if len(btype) < 4:
            return


def wlan_offset(link: int, data: bytes) -> tuple[int, bool]:
    """Start of the 802.11 header and whether an FCS ends the frame."""
    if link == 105:
        return 0, False
    if link != 127:
        raise ValueError(f"link type {link} not handled (expected 127 radiotap or 105 802.11)")
    rt_len, present = struct.unpack_from("<HI", data, 2)
    off, word = 8, present
    while word & 0x80000000:                                 # extended presence bitmaps
        word = struct.unpack_from("<I", data, off)[0]
        off += 4
    if present & 0x1:                                        # TSFT, 8 bytes aligned to 8
        off = ((off + 7) & ~7) + 8
    fcs = bool(present & 0x2) and off < rt_len and bool(data[off] & 0x10)
    return rt_len, fcs


def suite(b: bytes) -> str:
    return f"{b[0]:02x}-{b[1]:02x}-{b[2]:02x}:{b[3]}"


def parse_rsn(b: bytes) -> str:
    try:
        ver, grp = struct.unpack_from("<H", b, 0)[0], suite(b[2:6])
        n = struct.unpack_from("<H", b, 6)[0]
        pw = [suite(b[8 + 4 * k:12 + 4 * k]) for k in range(n)]
        o = 8 + 4 * n
        m = struct.unpack_from("<H", b, o)[0]
        akm = [suite(b[o + 2 + 4 * k:o + 6 + 4 * k]) for k in range(m)]
        o += 2 + 4 * m
        cap = struct.unpack_from("<H", b, o)[0] if len(b) >= o + 2 else None
    except (struct.error, IndexError):
        return f"RSN unparsed ({len(b)} bytes)"
    mfp = "caps missing" if cap is None else f"MFPC {cap >> 7 & 1} MFPR {cap >> 6 & 1}"
    return f"v{ver} group {grp} pairwise {','.join(pw)} akm {','.join(akm)} {mfp}"


def announcement(data: bytes, link: int) -> dict | None:
    if link == 127 and len(data) < 8:
        return None
    start, fcs = wlan_offset(link, data)
    if len(data) <= start or data[start] not in (0x80, 0x50):   # frame control of beacon / probe response
        return None
    f = data[start:len(data) - (4 if fcs else 0)]
    body = 24 + (4 if len(f) > 1 and f[1] & 0x80 else 0)    # +HT Control when the Order bit is set
    if len(f) < body + 12:
        return None
    cap = struct.unpack_from("<H", f, body + 10)[0]
    a = {"subtype": f[0] >> 4, "bssid": ":".join(f"{x:02x}" for x in f[16:22]), "privacy": cap >> 4 & 1,
         "ess": cap & 1, "rsn": "no RSN element", "wpa_element": 0, "country": "", "ssid": "", "elements": []}
    o = body + 12
    while o + 2 <= len(f) and o + 2 + f[o + 1] <= len(f):
        eid, ln = f[o], f[o + 1]
        v = f[o + 2:o + 2 + ln]
        a["elements"].append(eid)
        if eid == 0:
            a["ssid"] = v.decode("utf-8", "replace")
        elif eid == 7:
            a["country"] = v[:2].decode("ascii", "replace")
        elif eid == 48:
            a["rsn"] = parse_rsn(v)
        elif eid == 221 and v[:4] == b"\x00\x50\xf2\x01":
            a["wpa_element"] = 1
        o += 2 + ln
    a["elements"] = ",".join(map(str, a["elements"]))
    return a


def pcap_members(zf: zipfile.ZipFile, cls: str) -> list[zipfile.ZipInfo]:
    return sorted((i for i in zf.infolist() if not i.is_dir() and class_of(i.filename) == cls),
                  key=lambda i: natural_key(i.filename))


MAGIC = {b"PK\x03\x04": "zip", b"7z\xbc\xaf\x27\x1c": "7z", b"Rar!\x1a\x07": "rar", b"\x1f\x8b": "gzip",
         b"\xfd7zXZ\x00": "xz", b"BZh": "bzip2", b"\xd4\xc3\xb2\xa1": "pcap", b"\x0a\x0d\x0d\x0a": "pcapng"}


def describe_archive(path: Path) -> None:
    """When zipfile cannot open the archive: its first bytes and the zip end records in its last MiB."""
    size = path.stat().st_size
    with open(path, "rb") as fh:
        head = fh.read(512)
        fh.seek(max(0, size - (1 << 20)))
        tail = fh.read()
    kind = next((k for m, k in MAGIC.items() if head.startswith(m)), "unknown")
    if kind == "unknown" and head[257:262] == b"ustar":
        kind = "tar"
    print(f"[RV2] {path.name}: {size:,} bytes; first bytes {head[:8].hex()} ({kind})")
    for name, sig in (("end of central directory", b"PK\x05\x06"), ("zip64 end record", b"PK\x06\x06"),
                      ("zip64 locator", b"PK\x06\x07"), ("central directory entries", b"PK\x01\x02"),
                      ("local file headers", b"PK\x03\x04")):
        pos = tail.rfind(sig)
        where = "none" if pos < 0 else f"{tail.count(sig)} found, last one {len(tail) - pos:,} bytes before the end"
        print(f"[RV2]   last MiB, {name}: {where}")


def open_pcap_zip(paths: dict) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(paths["awid3_pcap_zip"])
    except zipfile.BadZipFile:
        describe_archive(paths["awid3_pcap_zip"])
        raise SystemExit("[RV2] the pcap archive cannot be opened as a zip; see the lines above")


def layout(paths: dict) -> None:
    with open_pcap_zip(paths) as zf:
        tops = Counter(i.filename.replace("\\", "/").split("/")[0] for i in zf.infolist())
        print(f"[RV2] {sum(tops.values())} members; top-level: {dict(tops)}")
        folders = Counter("/".join(i.filename.replace("\\", "/").split("/")[:-1]) for i in zf.infolist()
                          if not i.is_dir())
        for f, n in sorted(folders.items(), key=lambda x: natural_key(x[0])):
            print(f"[RV2]   {f}: {n} files")
        for cls in CAPTURES.values():
            mem = pcap_members(zf, cls)
            print(f"[RV2] {cls}: {len(mem)} members")
            for i in (mem if len(mem) <= 5 else mem[:3] + mem[-2:]):
                with zf.open(i) as fh:
                    magic = fh.read(4).hex()
                print(f"[RV2]   {i.filename}  {i.file_size:,} bytes  magic {magic}")


def part_pcap(paths: dict) -> dict:
    out = {}
    with open_pcap_zip(paths) as zf:
        for cap, cls in CAPTURES.items():
            rows, n, links, per_member = [], 0, Counter(), {}
            for info in pcap_members(zf, cls):
                first = n
                with zf.open(info) as raw:
                    stream = io.BufferedReader(raw, buffer_size=8 << 20)
                    for orig, link, data in pcap_packets(stream):
                        n += 1
                        links[link] += 1
                        a = announcement(data, link)
                        if a is not None:
                            a["fn"], a["orig_len"] = n, orig
                            rows.append(a)
                per_member[info.filename] = n - first
                print(f"[RV2] {cls}: {info.filename} {n - first:,} packets (total {n:,})", flush=True)
            pc = pd.DataFrame(rows)
            csv_cols = ["frame.number", "frame.len", "wlan.fc.type", "wlan.fc.subtype", "wlan.bssid", "Label",
                        "wlan.rsn.capabilities.mfpc", "wlan.country_info.code"]
            csv, last = [], 0
            for df in iter_parquet(paths["interim_dir"] / f"awid3_{cap}.parquet", csv_cols, 200_000):
                fn = to_int(df["frame.number"])
                last = max(last, int(fn.max()))
                m = ((to_int(df["wlan.fc.type"]) == 0) & to_int(df["wlan.fc.subtype"]).isin([5, 8])).fillna(False)
                csv.append(df[m.to_numpy(bool)].assign(fn=fn[m.to_numpy(bool)]))
            csv = pd.concat(csv)
            csv = csv[csv["fn"].notna()].astype({"fn": "int64"}).drop_duplicates("fn", keep=False)
            j = pc.merge(csv, on="fn", how="left", indicator=True)
            matched = j["_merge"] == "both"
            jm = j[matched]
            agree = {"length": int((to_int(jm["frame.len"]) == jm["orig_len"]).sum()),
                     "bssid": int((jm["wlan.bssid"].str.lower() == jm["bssid"]).sum()),
                     "subtype": int((to_int(jm["wlan.fc.subtype"]) == jm["subtype"]).sum())}
            share = min(agree.values()) / max(int(matched.sum()), 1)
            valid = n == last and share >= 0.999
            j["label"] = j["Label"].fillna("<no CSV row>")
            groups = []
            for (b, st, ln, lab), g in j.groupby(["bssid", "subtype", "orig_len", "label"]):
                if not (b.startswith("0c:9d:92:54:fe") or (g["ssid"] == "ASUS_5G").any()):
                    continue
                groups.append({"bssid": b, "subtype": "beacon" if st == 8 else "probe response", "frame_len": int(ln),
                               "label": lab, "n": int(len(g)), "frame_numbers": [int(g["fn"].min()), int(g["fn"].max())],
                               "privacy": counts(g["privacy"]), "ess": counts(g["ess"]), "rsn": counts(g["rsn"], 5, full=True),
                               "wpa_element": counts(g["wpa_element"]), "country": counts(g["country"]),
                               "ssid": counts(g["ssid"], 3, full=True), "elements": counts(g["elements"], 3, full=True),
                               "csv_mfpc": counts(g["wlan.rsn.capabilities.mfpc"].fillna("<missing>"), 5)})
            out[cap] = {"members": per_member, "packets": n, "last_csv_frame_number": last, "link_types": dict(links),
                        "announcements_pcap": int(len(pc)), "announcements_csv": int(len(csv)),
                        "matched": int(matched.sum()), "agreement": agree, "valid": bool(valid),
                        "groups": sorted(groups, key=lambda x: (x["bssid"], x["frame_len"], x["label"]))}
            print(f"[RV2] {cls}: {n:,} packets (CSV last frame {last:,}); {int(matched.sum()):,} announcements matched, "
                  f"agreement {agree}; valid = {valid}", flush=True)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--layout", action="store_true")
    ap.add_argument("--part", choices=["awid3", "awid2", "pcap"], action="append")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    paths = load_paths()
    if args.layout:
        layout(paths)
        return
    s6_json = json.loads(S6_JSON.read_text(encoding="utf-8"))["results"]
    inputs = {p.name: sha256_file(p) for p in [S6_JSON, ROOT / "configs" / "awid2_columns.txt",
                                               ROOT / "results" / "S0_archive_hashes.json"]}
    archives = {k: paths[k].stat().st_size for k in ("awid3_pcap_zip",)}
    for part in args.part or ["awid3", "awid2", "pcap"]:
        target = ROOT / "results" / f"RV2_{part}.json"
        if target.exists() and not args.force:
            print(f"[RV2] {part}: {target.name} exists, skipped (use --force to redo)")
            continue
        res = {"awid3": lambda: part_awid3(paths, s6_json), "awid2": lambda: part_awid2(paths, s6_json),
               "pcap": lambda: part_pcap(paths)}[part]()
        meta = run_metadata(f"scripts/16_rv2_80211_checks.py --part {part}", inputs_sha256=inputs,
                            archive_bytes=archives)
        print(f"[RV2] {part}: done -> {write_result(f'RV2_{part}', {'results': res}, meta)}", flush=True)


if __name__ == "__main__":
    main()
