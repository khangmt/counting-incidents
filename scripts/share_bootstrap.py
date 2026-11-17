from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Which techniques change share when counting incidents instead of reports? Cluster bootstrap (resample incidents).
ratio = share among report-level mentions / share among incident-level mentions. >1 = over-represented by per-report counting."""
import random, collections as C
def share_ratio_boot(rows, lab, B=1000, min_n=20, level=lambda t: t, seed=0):
    inc = C.defaultdict(list)
    for i, l in enumerate(lab): inc[l].append(i)
    keys = list(inc)
    # per-incident: report-level technique counts and incident-level presence
    per = {}
    for k in keys:
        rc = C.Counter(level(t) for i in inc[k] for t in set(rows[i]['techniques']))
        per[k] = (rc, set(rc))
    def stat(sample):
        R, I = C.Counter(), C.Counter()
        for k in sample: R.update(per[k][0]); I.update(per[k][1])
        sr, si = sum(R.values()), sum(I.values())
        return {t: (R[t] / sr) / (I[t] / si) for t in I}, R, I
    point, R, I = stat(keys)
    random.seed(seed); boots = C.defaultdict(list)
    for _ in range(B):
        s, _, _ = stat(random.choices(keys, k=len(keys)))
        for t in point: boots[t].append(s.get(t, float('nan')))
    out = []
    for t in point:
        if R[t] < min_n: continue
        z = sorted(x for x in boots[t] if x == x); lo, hi = z[int(.025 * len(z))], z[int(.975 * len(z)) - 1]
        out.append({'t': t, 'n_report': R[t], 'n_incident': I[t], 'share_ratio': round(point[t], 3), 'ci_lo': round(lo, 3), 'ci_hi': round(hi, 3),
                    'shift': 'over' if lo > 1 else 'under' if hi < 1 else ''})
    return sorted(out, key=lambda x: -x['share_ratio'])
