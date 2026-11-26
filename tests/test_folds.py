"""Blocked and random folds of src/modeling.py, on a synthetic capture (no dataset needed).

The synthetic capture keeps one frame in 50 over the real frame-number range of the AWID3
Evil_Twin capture, so the real attack window (protocol Section 9.2) and the 10,000-frame purge
are used as they are.
"""

import numpy as np
import pytest

from src import modeling as m

STEP = 50


@pytest.fixture(scope="module")
def cap():
    lo, hi = m.WINDOWS["evil_twin"]
    fn = np.arange(1, hi + 1, STEP)
    rng = np.random.default_rng(0)
    y = ((fn >= lo) & (rng.random(len(fn)) < 0.05)).astype(np.int8)   # attacks only in the window
    X = rng.random((len(fn), 3)).astype(np.float32)
    return m.Capture("evil_twin", X, y, fn, ["a", "b", "c"], {"a": "S", "b": "A", "c": "C"})


@pytest.fixture(scope="module")
def blocked(cap):
    return m.make_folds(cap)


def window_rows(cap):
    lo, hi = m.WINDOWS[cap.name]
    return np.flatnonzero((cap.fn >= lo) & (cap.fn <= hi))


def far_from(fn, rows, held):
    """True if no row of `rows` lies within PURGE frames of the frame range of `held`."""
    lo, hi = fn[held[0]] - m.PURGE, fn[held[-1]] + m.PURGE
    return bool(np.all((fn[rows] < lo) | (fn[rows] > hi)))


def test_blocks_partition_the_window_in_order(cap, blocked):
    folds, _, info = blocked
    tests = [f.test for f in folds]
    assert len(folds) == m.K_BLOCKS
    assert np.array_equal(np.concatenate(tests), window_rows(cap))      # every window row once, in order
    sizes = [len(t) for t in tests]
    assert max(sizes) - min(sizes) <= 1
    assert [b["rows"] for b in info["blocks"]] == sizes


def test_training_rows_are_purged_around_the_test_block(cap, blocked):
    folds, _, _ = blocked
    for f in folds:
        assert len(np.intersect1d(f.train, f.test)) == 0
        assert far_from(cap.fn, f.train, f.test)
        assert np.all(np.diff(f.train) > 0)                               # sorted, no duplicates


def test_clean_period_is_the_last_fifth_before_the_attack_and_never_trained_on(cap, blocked):
    folds, clean, info = blocked
    pre = np.flatnonzero(cap.fn < m.WINDOWS[cap.name][0])
    n_clean = int(len(pre) * m.CLEAN_SHARE)
    assert np.array_equal(clean, pre[len(pre) - n_clean:])
    assert info["clean_rows"] == n_clean
    for f in folds:
        assert far_from(cap.fn, f.train, clean)


def test_validation_block_is_adjacent_and_purged(cap, blocked):
    folds, _, _ = blocked
    tests = [f.test for f in folds]
    for f in folds:
        neighbour = tests[f.k + 1] if f.k < m.K_BLOCKS - 1 else tests[f.k - 1]
        assert np.all(np.isin(f.val, neighbour))
        assert far_from(cap.fn, f.val, f.test)
        assert np.all(np.isin(f.tune_train, f.train))
        assert len(np.intersect1d(f.tune_train, f.val)) == 0
        assert far_from(cap.fn, f.tune_train, f.val)


def test_pre_attack_rows_are_used_for_training(cap, blocked):
    folds, clean, _ = blocked
    first_clean = cap.fn[clean[0]]
    early = np.flatnonzero(cap.fn < first_clean - m.PURGE)              # pre-attack, away from the clean period
    for f in folds:
        assert np.all(np.isin(early, f.train))


def test_random_fold_is_a_stratified_fifth_of_the_window(cap):
    f = m.random_window_fold(cap, seed=0)
    window = window_rows(cap)
    assert np.all(np.isin(f.test, window))
    n_att, n_norm = int(cap.y[window].sum()), int((cap.y[window] == 0).sum())
    assert int(cap.y[f.test].sum()) == int(0.2 * n_att)
    assert int((cap.y[f.test] == 0).sum()) == int(0.2 * n_norm)
    assert len(np.intersect1d(f.train, f.test)) == 0
    assert len(f.val) == 0 and len(f.tune_train) == 0


def test_random_fold_training_rows(cap, blocked):
    _, clean, _ = blocked
    f = m.random_window_fold(cap, seed=0)
    pre = np.flatnonzero(cap.fn < m.WINDOWS[cap.name][0])
    candidates = np.setdiff1d(np.concatenate([pre[:len(pre) - len(clean)], window_rows(cap)]), f.test)
    lo, hi = cap.fn[clean[0]] - m.PURGE, cap.fn[clean[-1]] + m.PURGE
    expected = candidates[(cap.fn[candidates] < lo) | (cap.fn[candidates] > hi)]
    assert np.array_equal(f.train, expected)


def test_random_fold_depends_only_on_the_seed(cap):
    a, b, c = (m.random_window_fold(cap, seed=s).test for s in (0, 0, 1))
    assert np.array_equal(a, b)
    assert not np.array_equal(a, c)


def test_training_sample_keeps_every_attack_and_caps_normal_frames(cap, monkeypatch):
    monkeypatch.setattr(m, "MAX_NEGATIVES", 1_000)
    rows = np.arange(len(cap.y))
    s = m.sample_training(rows, cap.y, seed=3)
    assert int(cap.y[s].sum()) == int(cap.y.sum())
    assert int((cap.y[s] == 0).sum()) == 1_000
    assert np.array_equal(s, m.sample_training(rows, cap.y, seed=3))
    assert np.all(np.diff(s) > 0)


def test_pr_auc_is_undefined_with_one_class():
    assert np.isnan(m.pr_auc(np.zeros(5, int), np.arange(5.0)))
    assert m.pr_auc(np.array([0, 0, 1, 1]), np.array([0.1, 0.2, 0.8, 0.9])) == pytest.approx(1.0)
