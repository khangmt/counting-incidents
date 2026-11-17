from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Checks a reviewer would ask for.
A. The exact prior-work rule (Rahman et al.: shared group or malware within 2 months, plain single linkage, no other guards).
B. Stability of the over-counted set across span caps.
C. Permutation null: same incident-size distribution, reports assigned at random within their year."""
import json, sys, random, collections as C
sys.path.insert(0, RB + 'scripts')
from cluster_rank import load, cluster, counts, compare, pairwise_eval, shared_software, cluster_edges, entity_edges
from share_bootstrap import share_ratio_boot
RES = RB + 'results/'
out = {}
# ---------- ATT&CK
rows = load(RES + 'attack_reports.jsonl')
SHARED = shared_software(DATA + 'attack_stix/enterprise-attack.json')
gold = {}
for i, r in enumerate(rows):
    cs = [e for e in r['entities'] if r['entity_types'][e] == 'campaign']
    if len(cs) == 1 and any(r['entity_types'][e] in ('intrusion-set', 'malware') for e in r['entities']): gold[i] = cs[0]
def summ(lab, rows_, gold_):
    ev = pairwise_eval(rows_, lab, gold_); cr, nr = counts(rows_, None); ci, ni = counts(rows_, lab); o = compare(cr, nr, ci, ni)
    return {'incidents': len(set(lab)), 'largest': max(C.Counter(lab).values()), 'P': round(ev['P'], 3), 'R': round(ev['R'], 3),
            'tau_b': round(o['kendall_tau_b'], 3), 'top10': o['top10_overlap'], 'top20': o['top20_overlap']}
rahman = cluster(rows, 60, ('intrusion-set', 'malware'))          # their rule, as published
out['attack_rahman_rule'] = summ(rahman, rows, gold)
out['attack_rahman_rule_no_time_limit'] = summ(cluster(rows, None, ('intrusion-set', 'malware')), rows, gold)
print('A attack', out['attack_rahman_rule'], out['attack_rahman_rule_no_time_limit'])
# ---------- B: stability across span caps
main = None; stab = {}
for S in [45, 60, 90, 180, None]:
    lab = cluster_edges(rows, entity_edges(rows, 60, ('intrusion-set', 'campaign', 'malware'), exclude=SHARED), S)
    over = {x['t'] for x in share_ratio_boot(rows, lab) if x['shift'] == 'over'}
    stab[str(S)] = sorted(over)
    if S == 60: main = over; mainlab = lab
core = sorted(set.intersection(*[set(v) for v in stab.values()]))
out['attack_over_by_span'] = stab; out['attack_over_in_every_span'] = core
print('B over at S=60', len(main), 'in every span', len(core), core)
# ---------- C: permutation null (ATT&CK, main clustering)
def rho(lab):
    inc = C.defaultdict(set); R = C.Counter()
    for r, l in zip(rows, lab):
        ts = set(r['techniques']); R.update(ts); inc[l] |= ts
    I = C.Counter(t for s in inc.values() for t in s); sr, si = sum(R.values()), sum(I.values())
    return {t: (R[t] / sr) / (I[t] / si) for t in I}
real = rho(mainlab)
year = [r['date'][:4] if r['date'] else None for r in rows]
sizes_by_year = C.defaultdict(list)
grp = C.defaultdict(list)
for i, l in enumerate(mainlab): grp[l].append(i)
for l, idx in grp.items():
    ys = {year[i] for i in idx}
    sizes_by_year[year[idx[0]] if len(ys) == 1 else 'mixed'].append(len(idx))
random.seed(1); null = C.defaultdict(list)
for _ in range(200):
    lab = [None] * len(rows); nxt = 0
    pool = C.defaultdict(list)
    for i, y in enumerate(year): pool[y].append(i)
    for y in pool: random.shuffle(pool[y])
    mixed = sizes_by_year.pop('mixed', None)
    for y, sz in sizes_by_year.items():
        for s in sz:
            for _k in range(s): lab[pool[y].pop()] = nxt
            nxt += 1
    if mixed is not None: sizes_by_year['mixed'] = mixed
    for i in range(len(rows)):
        if lab[i] is None: lab[i] = nxt; nxt += 1     # reports of cross-year incidents stay single in the null
    for t, v in rho(lab).items(): null[t].append(v)
nl = {}
for t in sorted(main, key=lambda t: -real[t]):
    z = sorted(null[t]); nl[t] = {'real': round(real[t], 3), 'null_mean': round(sum(z) / len(z), 3), 'null_975': round(z[int(.975 * len(z)) - 1], 3),
                                  'p_null': round(sum(x >= real[t] for x in z) / len(z), 3)}
out['attack_permutation_null'] = nl
print('C', json.dumps(nl, indent=0)[:1500])
# ---------- A on texts: Rahman rule on full texts (any matched group/malware, no subject guard, no indicator links)
src = open(RB + 'scripts/run_corpus.py').read().split('# technique-labelled subset')[0]
g = {}; exec(src, g)
crow = g['rows']; import re
cgold = {i: r['apt_folder'] for i, r in enumerate(crow) if r.get('apt_folder') and re.match(r'\d{4}\.\d{2}\.\d{2}', r['apt_folder'])}
lab_idx = [i for i, r in enumerate(crow) if len(r['techniques']) >= 3]
def csumm(lab):
    ev = pairwise_eval(crow, lab, cgold); sub = [crow[i] for i in lab_idx]; L = [lab[i] for i in lab_idx]
    cr, nr = counts(sub, None); ci, ni = counts(sub, L); o = compare(cr, nr, ci, ni)
    return {'incidents_all': len(set(lab)), 'largest': max(C.Counter(lab).values()), 'P': round(ev['P'], 3), 'R': round(ev['R'], 3),
            'tau_b': round(o['kendall_tau_b'], 3), 'top20': o['top20_overlap']}
out['texts_rahman_rule'] = csumm(cluster(crow, 60, ('intrusion-set', 'malware')))
out['texts_main'] = csumm(g['cluster2'](tau=60))
print('A texts', out['texts_rahman_rule'], out['texts_main'])
json.dump(out, open(RES + 'reviewer_checks.json', 'w'), indent=1)
