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
        p_over = (sum(x <= 1 for x in z) + 1) / (len(z) + 1); p_under = (sum(x >= 1 for x in z) + 1) / (len(z) + 1)
        out.append({'t': t, 'n_report': R[t], 'n_incident': I[t], 'share_ratio': round(point[t], 3), 'ci_lo': round(lo, 3), 'ci_hi': round(hi, 3),
                    'shift': 'over' if lo > 1 else 'under' if hi < 1 else '', 'p_two_sided': round(min(1, 2 * min(p_over, p_under)), 4)})
    bh(out, 'p_two_sided', 'q_bh')
    for x in out: x['shift_bh'] = x['shift'] if x['q_bh'] <= 0.05 else ''
    return sorted(out, key=lambda x: -x['share_ratio'])

def bh(items, pkey, qkey):
    """Benjamini-Hochberg adjusted p-values over all items (all techniques tested)."""
    m = len(items); order = sorted(range(m), key=lambda i: items[i][pkey]); q = [0] * m; prev = 1.0
    for r in range(m - 1, -1, -1):
        i = order[r]; prev = min(prev, items[i][pkey] * m / (r + 1)); q[i] = prev
    for i, x in enumerate(items): x[qkey] = round(q[i], 4)
