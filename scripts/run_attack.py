from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
import json, sys, collections as C
sys.path.insert(0, RB + 'scripts')
from cluster_rank import *
from cluster_rank import pairwise_ci
SHARED = shared_software(DATA + 'attack_stix/enterprise-attack.json')
MAIN_SPAN = 60  # incident may span at most this many days (hand-checked pairs: merges > 60 days apart were almost all wrong)
def clus(rows, tau, link, exclude=(), span=MAIN_SPAN):
    if tau is None: return cluster(rows, None, link, exclude=set(exclude) | SHARED)
    return cluster_edges(rows, entity_edges(rows, tau, link, exclude=set(exclude) | SHARED), span)
RES = RB + 'results/'
rows = load(RES + 'attack_reports.jsonl')
names = json.load(open(RES + 'attack_names.json'))['names']
print('reports', len(rows), 'dated', sum(r['d'] is not None for r in rows))
# Gold: reports cited only for one campaign (and its techniques) -> that campaign
gold = {}
for i, r in enumerate(rows):
    cs = [e for e in r['entities'] if r['entity_types'][e] == 'campaign']
    if len(cs) == 1 and any(r['entity_types'][e] in ('intrusion-set', 'malware') for e in r['entities']): gold[i] = cs[0]
print('gold-labelled reports (one campaign):', len(gold), 'campaigns:', len(set(gold.values())))
camps = set(e for r in rows for e in r['entities'] if r['entity_types'][e] == 'campaign')
summary = []
for link in [('intrusion-set', 'campaign', 'malware'), ('intrusion-set', 'campaign', 'malware', 'tool'), ('intrusion-set', 'campaign')]:
    for tau in [0, 30, 60, 90, 180, 365, None]:
        lab = clus(rows, tau, link)
        lab_nc = clus(rows, tau, link, exclude=camps)    # campaign links removed -> honest validation
        sizes = C.Counter(lab); big = max(sizes.values())
        ev = pairwise_eval(rows, lab_nc, gold)
        row = {'link': '+'.join(x[:3] for x in link), 'tau': tau, 'n_incidents': len(sizes), 'largest': big,
               'singletons': sum(1 for v in sizes.values() if v == 1), 'val_P': round(ev['P'], 3), 'val_R': round(ev['R'], 3), 'val_F1': round(ev['F1'], 3), 'val_tp': ev['tp'], 'val_fp': ev['fp'], 'val_fn': ev['fn'], **pairwise_ci(rows, lab_nc, gold)}
        for lvl in ['tech', 'parent']:
            cr, nr = counts(rows, None, lvl); ci, ni = counts(rows, lab, lvl); cmp_ = compare(cr, nr, ci, ni)
            row.update({f'{lvl}_tau_b': round(cmp_['kendall_tau_b'], 3), f'{lvl}_top10': cmp_['top10_overlap'], f'{lvl}_top20': cmp_['top20_overlap'], f'{lvl}_top50': cmp_['top50_overlap']})
        summary.append(row); print(row)
for span in [45, 90, 180, 365, None]:   # span-cap sweep at tau=60
    link = ('intrusion-set', 'campaign', 'malware')
    lab = clus(rows, 60, link, span=span); lab_nc = clus(rows, 60, link, exclude=camps, span=span)
    ev = pairwise_eval(rows, lab_nc, gold); sizes = C.Counter(lab)
    row = {'link': 'int+cam+mal', 'tau': 60, 'span': span, 'n_incidents': len(sizes), 'largest': max(sizes.values()), 'val_P': round(ev['P'], 3), 'val_R': round(ev['R'], 3), 'val_F1': round(ev['F1'], 3), 'val_tp': ev['tp'], 'val_fp': ev['fp'], 'val_fn': ev['fn'], **pairwise_ci(rows, lab_nc, gold)}
    for lvl in ['tech', 'parent']:
        cr, nr = counts(rows, None, lvl); ci, ni = counts(rows, lab, lvl); cmp_ = compare(cr, nr, ci, ni)
        row.update({f'{lvl}_tau_b': round(cmp_['kendall_tau_b'], 3), f'{lvl}_top10': cmp_['top10_overlap'], f'{lvl}_top20': cmp_['top20_overlap'], f'{lvl}_top50': cmp_['top50_overlap']})
    summary.append(row); print(row)
json.dump(summary, open(RES + 'attack_sensitivity.json', 'w'), indent=1)
# Main setting
lab = clus(rows, 60, ('intrusion-set', 'campaign', 'malware'))
json.dump({r['id']: l for r, l in zip(rows, lab)}, open(RES + 'attack_clusters_main.json', 'w'))
for lvl in ['tech', 'parent']:
    cr, nr = counts(rows, None, lvl); ci, ni = counts(rows, lab, lvl); out = compare(cr, nr, ci, ni)
    for m in out['movers']: m['name'] = names.get(m['t'], '')
    json.dump(out, open(RES + f'attack_main_{lvl}.json', 'w'), indent=1)
    import csv
    with open(RES + f'attack_main_{lvl}.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(out['movers'][0])); w.writeheader(); w.writerows(out['movers'])
sizes = C.Counter(lab)
top = sizes.most_common(8)
for l, n in top:
    mem = [rows[i] for i in range(len(rows)) if lab[i] == l]
    ents = C.Counter(e for r in mem for e in r['entities']).most_common(3)
    ds = sorted(r['date'] for r in mem if r['date'])
    print(n, ds[0], ds[-1], [(names.get(e, e), c) for e, c in ents])

from share_bootstrap import share_ratio_boot
sh = share_ratio_boot(rows, lab)
for x in sh: x['name'] = names.get(x['t'], '')
json.dump(sh, open(RES + 'attack_share_shift.json', 'w'), indent=1)
print('over', [(x['t'], x['name'][:25], x['share_ratio'], x['ci_lo']) for x in sh if x['shift'] == 'over'])
