from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Two extra analyses for the paper, run after run_attack.py / run_corpus.py (main setting: tau=60, span cap 60).
1. Producer vs duplicate effect: compare per-report shares with (a) vendor-balanced shares (every vendor weight 1, split over its
   reports) and (b) per-incident shares. Ratio > 1 = per-report counting over-states the technique.
2. Yearly top-10 from ATT&CK citations, per report vs per incident: which entries change."""
import json, re, sys, random, collections as C
sys.path.insert(0, RB + 'scripts')
from cluster_rank import load, counts, parent
RES = RB + 'results/'
names = json.load(open(RES + 'attack_names.json'))['names']
ALIAS = {'symantec-enterprise-blogs': 'symantec', 'broadcom': 'symantec', 'fireeye': 'mandiant', 'cloud.google': 'mandiant', 'welivesecurity': 'eset',
         'securelist': 'kaspersky', 'kasperskycontenthub': 'kaspersky', 'paloaltonetworks': 'unit42', 'talosintelligence': 'talos', 'blog.talosintelligence': 'talos',
         'us-cert': 'cisa', 'thedfirreport': 'dfirreport', 'microsoft': 'microsoft', 'crowdstrike': 'crowdstrike', 'trendmicro': 'trendmicro', 'proofpoint': 'proofpoint'}
def vendor(r):
    u = (r.get('url') or '').lower()
    u = re.sub(r'^https?://web\.archive\.org/web/\d+[a-z_]*/', '', u)   # archived copy -> original site
    if not re.match(r'^https?://', u):   # APT-collection / AnnoCTR file path: producer unknown -> its own unit (no down-weighting)
        return (r.get('vendor') or '').lower() or 'unknown:' + r['id']
    h = re.sub(r'^https?://', '', u).split('/')[0]
    for k, v in ALIAS.items():
        if k in h: return v
    parts = [p for p in h.split('.') if p not in ('www', 'blog', 'blogs', 'media', 'go', 'research', 'unit42', 'info', 'labs')]
    if len(parts) >= 2: return parts[-3] if parts[-2] in ('co', 'com', 'org', 'gov') and len(parts) >= 3 else parts[-2]
    return h or 'unknown:' + r['id']

def shares(rows, w):
    S = C.Counter()
    for r, x in zip(rows, w):
        for t in set(r['techniques']): S[t] += x
    tot = sum(S.values()); return {t: v / tot for t, v in S.items()}

def decompose(rows, lab, B=1000, min_n=20, seed=0):
    vend = [vendor(r) for r in rows]
    nv = C.Counter(vend)
    sR = shares(rows, [1] * len(rows))
    sV = shares(rows, [1 / nv[v] for v in vend])
    inc = C.defaultdict(set)
    for r, l in zip(rows, lab): inc[l] |= set(r['techniques'])
    I = C.Counter(t for s in inc.values() for t in s); ti = sum(I.values()); sI = {t: v / ti for t, v in I.items()}
    nR = C.Counter(t for r in rows for t in set(r['techniques']))
    # bootstrap over vendors for the producer ratio
    byv = C.defaultdict(list)
    for i, v in enumerate(vend): byv[v].append(i)
    vs = list(byv); random.seed(seed); boots = C.defaultdict(list)
    for _ in range(B):
        idx = [i for v in random.choices(vs, k=len(vs)) for i in byv[v]]
        sub = [rows[i] for i in idx]; c = C.Counter(vend[i] for i in idx)
        a = shares(sub, [1] * len(sub)); b = shares(sub, [1 / c[vend[i]] for i in idx])
        for t in a: boots[t].append(a[t] / b[t])
    out = []
    for t in sR:
        if nR[t] < min_n: continue
        z = sorted(boots[t]); lo, hi = z[int(.025 * len(z))], z[int(.975 * len(z)) - 1]
        out.append({'t': t, 'name': names.get(t, ''), 'n_report': nR[t], 'share_report': round(sR[t], 5), 'share_vendor_bal': round(sV.get(t, 0), 5),
                    'share_incident': round(sI.get(t, 0), 5), 'producer_ratio': round(sR[t] / sV[t], 3), 'producer_ci': [round(lo, 3), round(hi, 3)],
                    'producer_shift': 'over' if lo > 1 else 'under' if hi < 1 else '', 'duplicate_ratio': round(sR[t] / sI[t], 3)})
    return {'n_reports': len(rows), 'n_vendors': len(nv), 'n_unknown_producer': sum(1 for v in vend if v.startswith('unknown:')), 'top_vendors': nv.most_common(12),
            'top_vendor_share_of_reports': round(nv.most_common(1)[0][1] / len(rows), 3), 'techniques': sorted(out, key=lambda x: -x['producer_ratio'])}

def top_k(rows, lab, k=10, level=lambda t: t):
    inc = C.defaultdict(set)
    for r, l in zip(rows, lab): inc[l] |= {level(t) for t in r['techniques']}
    c = C.Counter(t for s in inc.values() for t in s)
    return [t for t, _ in sorted(c.items(), key=lambda x: (-x[1], x[0]))[:k]], c, len(inc)

if __name__ == '__main__':
    out = {}
    # ATT&CK
    ar = load(RES + 'attack_reports.jsonl'); acl = json.load(open(RES + 'attack_clusters_main.json'))
    alab = [acl[r['id']] for r in ar]
    out['attack'] = decompose(ar, alab)
    # our texts (labelled subset), same row order as run_corpus.py
    cr = [r for r in load(RES + 'corpus_reports.jsonl') if r['vendor'] != 'attack.mitre.org']
    adv = lambda u: (m.group(1) if (m := re.search(r'\b(a[ar]\d{2}-\d{3}[a-z]?)\b', (u or '').lower())) else None)
    have = {adv(r['url']) for r in cr if r['vendor'] == 'CISA'} - {None}
    cr += [r for r in load(RES + 'cisa_reports.jsonl') if adv(r['url']) not in have]
    ccl = json.load(open(RES + 'corpus_clusters_main.json'))
    sub = [r for r in cr if len(r['techniques']) >= 3]
    out['corpus'] = decompose(sub, [ccl[r['id']] for r in sub], min_n=15)
    json.dump(out, open(RES + 'producer_vs_duplicate.json', 'w'), indent=1)
    for k, v in out.items():
        print(k, 'reports', v['n_reports'], 'vendors', v['n_vendors'], 'top', v['top_vendors'][:5])
        print('  producer over:', [(x['t'], x['name'][:22], x['producer_ratio'], x['duplicate_ratio']) for x in v['techniques'] if x['producer_shift'] == 'over'][:12])
        print('  producer under:', [(x['t'], x['name'][:22], x['producer_ratio'], x['duplicate_ratio']) for x in v['techniques'] if x['producer_shift'] == 'under'][:12])
    # yearly top-10, ATT&CK, technique and parent level
    years = C.Counter(r['date'][:4] for r in ar if r['date'])
    yt = []
    for y in sorted(years):
        if years[y] < 60: continue
        idx = [i for i, r in enumerate(ar) if r['date'] and r['date'][:4] == y]
        rows_y = [ar[i] for i in idx]; lab_y = [alab[i] for i in idx]
        for lvl, f in [('tech', lambda t: t), ('parent', parent)]:
            tr, crc, nr = top_k(rows_y, list(range(len(rows_y))), level=f); ti, cic, ni = top_k(rows_y, lab_y, level=f)
            yt.append({'year': y, 'level': lvl, 'reports': nr, 'incidents': ni, 'top10_report': tr, 'top10_incident': ti,
                       'dropped': [t for t in tr if t not in ti], 'entered': [t for t in ti if t not in tr],
                       'same_order': tr == ti, 'n_changed': len(set(tr) - set(ti))})
    json.dump(yt, open(RES + 'attack_yearly_top10.json', 'w'), indent=1)
    for x in yt:
        if x['level'] == 'tech': print(x['year'], x['reports'], '->', x['incidents'], 'changed', x['n_changed'], 'out', [names.get(t, t)[:25] for t in x['dropped']], 'in', [names.get(t, t)[:25] for t in x['entered']])
    print('parent-level changes', [(x['year'], x['n_changed']) for x in yt if x['level'] == 'parent'])
