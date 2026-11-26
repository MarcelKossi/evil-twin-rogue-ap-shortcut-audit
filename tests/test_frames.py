"""Field helpers of src/frames.py, on hand-made values (no dataset needed)."""

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import cohen_kappa_score, matthews_corrcoef

from src import frames as f


def test_to_int_reads_decimal_and_hex():
    out = f.to_int(pd.Series(["12", " 0x0c ", "0X1F", None, "abc", "7"]))
    assert out.iloc[0] == 12 and out.iloc[1] == 12 and out.iloc[2] == 31 and out.iloc[5] == 7
    assert pd.isna(out.iloc[3]) and pd.isna(out.iloc[4])


def test_has_value_matches_whole_items_of_comma_lists():
    df = pd.DataFrame({"wlan.sa": ["0C:9D:92:54:FE:35", "aa:bb:cc:dd:ee:ff", None],
                       "wlan.da": ["ff:ff:ff:ff:ff:ff", "x, 0c:9d:92:54:fe:35 ,y", "0c:9d:92:54:fe:3"]})
    hit = f.has_value(df, ["wlan.sa", "wlan.da", "absent.field"], "0c:9d:92:54:fe:35")
    assert hit.tolist() == [True, True, False]                          # case-insensitive, no partial match


def test_add_frame_codes():
    df = pd.DataFrame({"frame.number": ["1", "2"], "frame.len": ["342", "263"], "wlan.fc.type": ["0", "2"],
                       "wlan.fc.subtype": ["8", "0x8"], "wlan.fc.protected": ["0", "1"]})
    df = f.add_frame_codes(df)
    assert df["st"].tolist() == [8, 40]                                 # beacon, QoS data
    assert df["flen"].tolist() == [342, 263] and df["prot"].tolist() == [0, 1]
    assert f.frame_name(df["st"].iloc[1]) == "40 (QoS data)"
    assert f.frame_name(np.nan) == "missing"


@pytest.mark.parametrize("tp,fp,fn,tn", [(40, 3, 5, 952), (10, 0, 0, 90), (7, 20, 1, 500)])
def test_agreement_matches_scikit_learn(tp, fp, fn, tn):
    y = np.array([1] * tp + [0] * fp + [1] * fn + [0] * tn)
    rule = np.array([1] * tp + [1] * fp + [0] * fn + [0] * tn)
    a = f.agreement(tp, fp, fn, tn)
    assert a["n"] == len(y)
    assert a["cohen_kappa"] == pytest.approx(cohen_kappa_score(y, rule), abs=1e-6)
    assert a["mcc"] == pytest.approx(matthews_corrcoef(y, rule), abs=1e-6)
    assert a["precision"] == pytest.approx(tp / (tp + fp), abs=1e-6)
    assert a["recall"] == pytest.approx(tp / (tp + fn), abs=1e-6)
