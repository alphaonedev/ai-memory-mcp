#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #2438 -- Universal Scalability Law (USL) fit + projection over the
# measure-capacity-ramp.sh results JSON.
#
#     T(N) = lambda*N / (1 + sigma*(N-1) + kappa*N*(N-1))
#
#   N      = offered concurrency (workers)      (the ramp x-axis)
#   T      = measured throughput (ops/s)        (the ramp y-axis)
#   lambda = ideal per-agent throughput (slope at N=1)
#   sigma  = serialization / contention coefficient (the mutex / pg-pool fan-in)
#   kappa  = crosstalk / coherency coefficient (AGE write coordination, WAL, O(P^2))
#   knee   N* = sqrt((1 - sigma) / kappa)       (T is retrograde past N* when sigma>0)
#
# The fit is a numpy-FREE linear least squares via the exact USL linearization:
# the model is linear in (lambda, sigma, kappa) after clearing the denominator,
#
#     lambda*N  -  sigma*T*(N-1)  -  kappa*T*N*(N-1)  =  T
#
# so each ramp point contributes one row [N, -T(N-1), -T*N(N-1)] with RHS T, and
# we solve the 3x3 normal equations with column scaling (for conditioning) and
# Gaussian elimination with partial pivoting. Stdlib only -- no numpy dependency.
#
# EVERY projected number (T(target), knee, bounds) is labelled ESTIMATED-not-
# MEASURED. Interpolation inside the measured concurrency range is MEASURED;
# projection to 500/1000 is ESTIMATED and its band widens with distance. If the
# ramp never reached the knee, the projection degrades to a LOWER BOUND rather
# than a fabricated point estimate (the measure-envelope.sh exit-72 discipline).
#
# Usage:
#   usl-fit.py <results.json> [--target 500] [--series total] [--budget-ms 250]
#   usl-fit.py --self-test          # in-memory synthetic recovery (no files)

import argparse
import json
import math
import sys

LABEL_MEASURED = "MEASURED"
LABEL_ESTIMATED = "ESTIMATED-not-MEASURED"
DEFAULT_TARGET = 500
DEFAULT_SERIES = "total"


def _solve3(a, b):
    """Solve a 3x3 linear system a x = b via Gaussian elimination with partial
    pivoting. Returns the solution list, or None if the matrix is singular."""
    m = [list(a[i]) + [b[i]] for i in range(3)]
    for col in range(3):
        piv = max(range(col, 3), key=lambda r: abs(m[r][col]))
        if abs(m[piv][col]) < 1e-15:
            return None
        m[col], m[piv] = m[piv], m[col]
        pv = m[col][col]
        for r in range(3):
            if r == col:
                continue
            f = m[r][col] / pv
            for c in range(col, 4):
                m[r][c] -= f * m[col][c]
    return [m[i][3] / m[i][i] for i in range(3)]


def fit_usl(points):
    """points: list of (N, T). Returns (lambda, sigma, kappa) or None.

    Column-scaled linear least squares of the exact USL linearization."""
    rows = []
    rhs = []
    for n, t in points:
        rows.append([float(n), -t * (n - 1.0), -t * n * (n - 1.0)])
        rhs.append(float(t))
    if len(rows) < 3:
        return None
    # Column scaling for conditioning: T*N*(N-1) is ~1e8 at N=512, whose square
    # in the normal equations would otherwise eat float64 precision.
    scale = [0.0, 0.0, 0.0]
    for r in rows:
        for j in range(3):
            scale[j] += r[j] * r[j]
    scale = [math.sqrt(s) if s > 0 else 1.0 for s in scale]
    srows = [[r[j] / scale[j] for j in range(3)] for r in rows]
    # Normal equations (A'^T A') y = A'^T b.
    ata = [[0.0] * 3 for _ in range(3)]
    atb = [0.0, 0.0, 0.0]
    for i, r in enumerate(srows):
        for j in range(3):
            atb[j] += r[j] * rhs[i]
            for k in range(3):
                ata[j][k] += r[j] * r[k]
    y = _solve3(ata, atb)
    if y is None:
        return None
    return tuple(y[j] / scale[j] for j in range(3))


def usl_t(n, lam, sigma, kappa):
    denom = 1.0 + sigma * (n - 1.0) + kappa * n * (n - 1.0)
    if denom <= 0:
        return float("inf")
    return lam * n / denom


def knee(sigma, kappa):
    if kappa <= 0 or sigma >= 1.0:
        return None
    return math.sqrt((1.0 - sigma) / kappa)


def _rmse(points, lam, sigma, kappa):
    if not points:
        return 0.0, 0.0
    se = 0.0
    tsum = 0.0
    for n, t in points:
        pred = usl_t(n, lam, sigma, kappa)
        se += (pred - t) ** 2
        tsum += t
    rmse = math.sqrt(se / len(points))
    mean = tsum / len(points)
    return rmse, (rmse / mean if mean else 0.0)


def loo_band(points, target):
    """Leave-one-out refit band for T(target): refit dropping each point,
    evaluate T(target). Returns (lo, hi, spread_frac) or None if <4 points."""
    if len(points) < 4:
        return None
    vals = []
    for i in range(len(points)):
        sub = points[:i] + points[i + 1:]
        fit = fit_usl(sub)
        if fit is None:
            continue
        vals.append(usl_t(target, *fit))
    if not vals:
        return None
    lo, hi = min(vals), max(vals)
    mid = (lo + hi) / 2.0
    spread = ((hi - lo) / mid) if mid else 0.0
    return lo, hi, spread


def load_series(results, series):
    """Extract [(N, T)] from a measure-capacity-ramp.sh results JSON.
    series == 'total' fits total_ops_per_s; else the named op-class ops_per_s."""
    pts = []
    for p in results.get("points", []):
        n = p.get("offered_concurrency")
        if n is None:
            continue
        if series == "total":
            t = p.get("total_ops_per_s")
        else:
            t = (p.get("ops", {}).get(series, {}) or {}).get("ops_per_s")
        if t is None:
            continue
        pts.append((float(n), float(t)))
    pts.sort()
    return pts


def report(results, series, target, budget_ms):
    meta = results.get("meta", {})
    pts = load_series(results, series)
    if len(pts) < 3:
        print("REFUSE: need >= 3 ramp points to distinguish linear from "
              "retrograde USL; got %d for series '%s'." % (len(pts), series),
              file=sys.stderr)
        return 2
    fit = fit_usl(pts)
    if fit is None:
        print("REFUSE: USL fit is singular (degenerate ramp -- points not "
              "well separated). Widen the concurrency ramp and re-measure.",
              file=sys.stderr)
        return 2
    lam, sigma, kappa = fit
    max_n = max(n for n, _ in pts)
    max_t = max(t for _, t in pts)
    ns = knee(sigma, kappa)
    rmse, rel = _rmse(pts, lam, sigma, kappa)

    print("=" * 70)
    print("USL fit -- #2438 capacity projection")
    print("=" * 70)
    host = meta.get("host_substrate", "UNRECORDED")
    print("series           : %s" % series)
    print("substrate host   : %s   (numbers are host-relative)" % host)
    print("backend          : %s" % meta.get("backend", "UNRECORDED"))
    print("corpus scale      : %s rows" % meta.get("corpus_scale", "UNRECORDED"))
    print("ramp points       : %d   (offered concurrency %g..%g)  [%s]"
          % (len(pts), min(n for n, _ in pts), max_n, LABEL_MEASURED))
    print("-" * 70)
    print("lambda (ideal ops/s per agent) : %.4f" % lam)
    print("sigma  (serialization)         : %.6f" % sigma)
    print("kappa  (crosstalk / coherency) : %.8f" % kappa)
    print("fit rel-RMSE over ramp         : %.2f%%   [%s within range]"
          % (rel * 100.0, LABEL_MEASURED))
    print("-" * 70)

    # Curve shape (measured, within range).
    if kappa > 1e-12 and sigma < 1.0:
        shape = "retrograde (throughput falls past the knee)"
    elif abs(kappa) <= 1e-12 and sigma > 1e-9:
        shape = "sub-linear saturating (Amdahl; kappa~0)"
    elif sigma <= 1e-9 and abs(kappa) <= 1e-12:
        shape = "near-linear (no measured contention or crosstalk)"
    else:
        shape = "degenerate/near-linear (sigma/kappa at model edge)"
    print("curve shape      : %s   [%s]" % (shape, LABEL_MEASURED))

    # Knee.
    if ns is not None:
        t_at_knee = usl_t(ns, lam, sigma, kappa)
        if ns <= max_n:
            print("knee N*          : %.1f agents  (T_max=%.2f ops/s)   [%s -- "
                  "inside measured range]" % (ns, t_at_knee, LABEL_MEASURED))
        else:
            print("knee N*          : %.1f agents  (T_max=%.2f ops/s)   [%s -- "
                  "beyond measured max N=%g; extrapolated]"
                  % (ns, t_at_knee, LABEL_ESTIMATED, max_n))
    else:
        print("knee N*          : none within model (kappa<=0 or sigma>=1) -- "
              "no retrograde point measured; projection is a saturating bound "
              "[%s]" % LABEL_ESTIMATED)
    print("-" * 70)

    # Projection to target.
    t_target = usl_t(target, lam, sigma, kappa)
    interp = target <= max_n
    regime = LABEL_MEASURED if interp else LABEL_ESTIMATED
    knee_reached = ns is not None and ns <= max_n
    print("PROJECTION to N=%d agents (one substrate module):" % target)
    if interp:
        print("  T(%d) = %.2f ops/s   [%s -- interpolation, inside ramp]"
              % (target, t_target, regime))
    elif knee_reached:
        print("  T(%d) = %.2f ops/s   [%s -- extrapolation past measured max "
              "N=%g]" % (target, t_target, regime, max_n))
        band = loo_band(pts, target)
        if band:
            lo, hi, spread = band
            print("  leave-one-out band : [%.2f, %.2f] ops/s (+/-%.1f%%)   [%s]"
                  % (lo, hi, spread * 100.0, LABEL_ESTIMATED))
    else:
        # Knee not reached in the measured ramp -> lower bound, not a point.
        print("  LOWER BOUND: T(%d) >= T(max measured N=%g) = %.2f ops/s   [%s]"
              % (target, max_n, max_t, LABEL_ESTIMATED))
        print("  (knee not reached in the measured ramp -- the model point "
              "estimate %.2f ops/s is UNTRUSTWORTHY; raise offered concurrency "
              "and re-measure. measure-envelope.sh exit-72 discipline.)"
              % t_target)
    print("-" * 70)

    # Budget verdict (the direct #2438 test: does one module serve the block?).
    if budget_ms is not None:
        print("Budget note: p95 budget is enforced by the ramp knee, not by "
              "this fit. If N*=%s < %d, one module CANNOT serve a %d-agent "
              "block at budget -- which VALIDATES #2438 (compose M modules per "
              "the composition rule)."
              % (("%.0f" % ns) if ns is not None else "n/a", target, target))
    print("=" * 70)
    print("Composition rule (v1.0.0): cluster capacity for A agents = M "
          "independent substrate modules, M = ceil(A / A_module*), A_module* = "
          "the MEASURED knee N* held at the p95 budget on the cited host. "
          "Modules federate as static-list peers, mesh bounded at <= 50 peers "
          "(enterprise-deployment.md 8.8). A block/cluster needing > 50 modules "
          "needs the cross-mesh placement layer that does NOT exist at v1.0.0 "
          "(#2438 path 1) -- NOT certifiable by composition. Every projected "
          "number above is %s." % LABEL_ESTIMATED)
    return 0


def _synth_points(lam, sigma, kappa):
    # A droplet-count x per-droplet-worker grid, mirroring the design's
    # N_d in {1,2,3,5} x concurrency ramp, expressed as offered concurrency.
    ns = [8, 16, 24, 32, 48, 64, 96, 128, 160, 256, 384, 512]
    return [(float(n), usl_t(n, lam, sigma, kappa)) for n in ns]


def self_test():
    # Known ground truth. sigma>0 and kappa>0 => a genuine retrograde curve
    # with a knee inside the ramp, so the fit must recover all three AND N*.
    true_lam, true_sigma, true_kappa = 500.0, 0.02, 0.0005
    pts = _synth_points(true_lam, true_sigma, true_kappa)
    fit = fit_usl(pts)
    if fit is None:
        print("SELF-TEST FAIL: fit returned None on clean synthetic data",
              file=sys.stderr)
        return 1
    lam, sigma, kappa = fit
    true_ns = knee(true_sigma, true_kappa)
    got_ns = knee(sigma, kappa)

    def relerr(a, b):
        return abs(a - b) / abs(b) if b else abs(a - b)

    tol = 1e-4
    checks = [
        ("lambda", lam, true_lam, relerr(lam, true_lam)),
        ("sigma", sigma, true_sigma, relerr(sigma, true_sigma)),
        ("kappa", kappa, true_kappa, relerr(kappa, true_kappa)),
        ("knee N*", got_ns, true_ns, relerr(got_ns, true_ns)),
    ]
    ok = True
    print("USL self-test -- recover known (lambda, sigma, kappa) from synthetic "
          "ramp:")
    for name, got, want, err in checks:
        status = "OK" if err <= tol else "FAIL"
        if err > tol:
            ok = False
        print("  %-8s recovered=%.8g  true=%.8g  rel_err=%.2e  [%s]"
              % (name, got, want, err, status))
    # Also confirm a projection round-trips exactly on the noise-free model.
    t500_fit = usl_t(500, lam, sigma, kappa)
    t500_true = usl_t(500, true_lam, true_sigma, true_kappa)
    err500 = relerr(t500_fit, t500_true)
    if err500 > tol:
        ok = False
    print("  %-8s recovered=%.8g  true=%.8g  rel_err=%.2e  [%s]"
          % ("T(500)", t500_fit, t500_true, err500,
             "OK" if err500 <= tol else "FAIL"))
    if ok:
        print("SELF-TEST OK: fit recovers ground truth within %.0e." % tol)
        return 0
    print("SELF-TEST FAIL: recovery exceeded tolerance.", file=sys.stderr)
    return 1


def main(argv):
    ap = argparse.ArgumentParser(description="USL fit + projection (#2438).")
    ap.add_argument("results", nargs="?",
                    help="measure-capacity-ramp.sh results JSON")
    ap.add_argument("--target", type=int, default=DEFAULT_TARGET,
                    help="project throughput at this offered concurrency "
                         "(default %d)" % DEFAULT_TARGET)
    ap.add_argument("--series", default=DEFAULT_SERIES,
                    help="'total' (default) or an op-class name (store/link/recall)")
    ap.add_argument("--budget-ms", type=float, default=None,
                    help="p95 budget (ms) for the block-fit note")
    ap.add_argument("--self-test", action="store_true",
                    help="run the in-memory synthetic recovery self-test")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.results:
        ap.error("results JSON path required (or use --self-test)")
    with open(args.results, "r", encoding="utf-8") as fh:
        results = json.load(fh)
    return report(results, args.series, args.target, args.budget_ms)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
