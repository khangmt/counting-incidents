from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
import json, sys, csv, re, collections as C, itertools
sys.path.insert(0, RB + 'scripts')
from cluster_rank import load, UF, counts, compare, pairwise_eval, pairwise_ci
from share_bootstrap import share_ratio_boot
RES = RB + 'results/'
rows = [r for r in load(RES + 'corpus_reports.jsonl') if r['vendor'] != 'attack.mitre.org']  # ATT&CK group pages are summaries, not reports
import re as _re, os as _os
def _adv(u): m = _re.search(r'\b(a[ar]\d{2}-\d{3}[a-z]?)\b', (u or '').lower()); return m.group(1) if m else None
if _os.environ.get('WITH_CISA', '1') == '1':
    have = {_adv(r['url']) for r in rows if r['vendor'] == 'CISA'} - {None}
    extra = [r for r in load(RES + 'cisa_reports.jsonl') if _adv(r['url']) not in have]
    print('CISA laptop advisories added:', len(extra), 'of', len(extra) + len(have & {_adv(r['url']) for r in load(RES + 'cisa_reports.jsonl')}))
    rows += extra
names = json.load(open(RES + 'attack_names.json'))['names']
titles = {r['url']: r['title'] for r in csv.DictReader(open(DATA + 'fulltext_manifest.csv'))}
def salient(r, k):  # entities mentioned at least k times
    return [e for e in r['entities'] if r['entity_counts'][e] >= k]
def main_entities(r, k=3, rel=0.5, top=2, overview=8):
    """The report's subject: up to `top` link-type entities with >= k mentions and >= rel * the top count.
    Overview reports (more than `overview` salient entities) get none."""
    c = {e: n for e, n in r['entity_counts'].items() if n >= k and e not in SHARED and r['entity_types'][e] in ('intrusion-set', 'campaign', 'malware')}
    if not c or len(c) > overview: return []
    m = max(c.values())
    return [e for e, n in sorted(c.items(), key=lambda x: -x[1]) if n >= rel * m][:top]
ioc_df = C.Counter(x for r in rows for x in set(r['iocs']))
from cluster_rank import shared_software, cluster_edges, entity_edges
SHARED = shared_software(DATA + 'attack_stix/enterprise-attack.json')
def cluster2(tau=60, k_ent=3, min_ioc=3, max_df=20, use_ent=True, use_ioc=True, span=60, link_types=('intrusion-set', 'campaign', 'malware')):
    E = []
    if use_ent:
        E += entity_edges(rows, tau, link_types, exclude=SHARED, ents=lambda r: main_entities(r, k_ent), year_tau=-1)  # year-only dates: no entity links
    if use_ioc:
        inv = C.defaultdict(list)
        for i, r in enumerate(rows):
            for x in r['iocs']:
                if 2 <= ioc_df[x] <= max_df: inv[x].append(i)
        pair = C.Counter()
        for x, idx in inv.items():
            for a, b in itertools.combinations(idx, 2): pair[(a, b)] += 1
        E += [(-c, a, b) for (a, b), c in pair.items() if c >= min_ioc]
    return cluster_edges(rows, E, span)
# technique-labelled subset: >= 3 explicit IDs
lab_idx = [i for i, r in enumerate(rows) if len(r['techniques']) >= 3]
sub = [rows[i] for i in lab_idx]
print('docs', len(rows), 'labelled', len(sub))
gold = {i: r['apt_folder'] for i, r in enumerate(rows) if r.get('apt_folder') and re.match(r'\d{4}\.\d{2}\.\d{2}', r['apt_folder'])}  # dated campaign folders only (not vendor periodic-report folders)
print('APT folder gold: docs', len(gold), 'folders with >=2 docs', sum(1 for v in C.Counter(gold.values()).values() if v > 1))
summary = []
for name, kw in [('ioc_only', dict(use_ent=False)), ('ent_only_t60', dict(use_ioc=False)), ('ent+ioc_t30', dict(tau=30)), ('ent+ioc_t60', dict(tau=60)),
                 ('ent+ioc_t90', dict(tau=90)), ('ent+ioc_t180', dict(tau=180)), ('ent+ioc_t60_k1', dict(tau=60, k_ent=1)), ('ent+ioc_t60_ioc2', dict(tau=60, min_ioc=2)), ('ent+ioc_t60_span45', dict(tau=60, span=45)), ('ent+ioc_t60_span90', dict(tau=60, span=90)), ('ent+ioc_t60_span180', dict(tau=60, span=180)), ('ent+ioc_t60_span365', dict(tau=60, span=365)), ('ent+ioc_t60_nospan', dict(tau=60, span=None))]:
    lab = cluster2(**kw); L = [lab[i] for i in lab_idx]
    sizes = C.Counter(L)
    row = {'setting': name, 'docs_all': len(rows), 'incidents_all': len(set(lab)), 'largest_all': max(C.Counter(lab).values()),
           'labelled_docs': len(sub), 'labelled_incidents': len(sizes), 'labelled_multi_report_incidents': sum(1 for v in sizes.values() if v > 1)}
    for lvl in ['tech', 'parent']:
        cr, nr = counts(sub, None, lvl); ci, ni = counts(sub, L, lvl); o = compare(cr, nr, ci, ni)
        row.update({f'{lvl}_tau_b': round(o['kendall_tau_b'], 3), f'{lvl}_top10': o['top10_overlap'], f'{lvl}_top20': o['top20_overlap'], f'{lvl}_top50': o['top50_overlap']})
    ev = pairwise_eval(rows, lab, gold); row.update({'val_P': round(ev['P'], 3), 'val_R': round(ev['R'], 3), 'val_F1': round(ev['F1'], 3), 'val_pos_pairs': ev['pairs_gold_pos'], 'val_tp': ev['tp'], 'val_fp': ev['fp'], 'val_fn': ev['fn'], **pairwise_ci(rows, lab, gold)})
    summary.append(row); print(row)
json.dump(summary, open(RES + 'corpus_sensitivity.json', 'w'), indent=1)
lab = cluster2(tau=60); L = [lab[i] for i in lab_idx]
json.dump({rows[i]['id']: lab[i] for i in range(len(rows))}, open(RES + 'corpus_clusters_main.json', 'w'))
for lvl in ['tech', 'parent']:
    cr, nr = counts(sub, None, lvl); ci, ni = counts(sub, L, lvl); o = compare(cr, nr, ci, ni)
    for m in o['movers']: m['name'] = names.get(m['t'], '')
    json.dump(o, open(RES + f'corpus_main_{lvl}.json', 'w'), indent=1)
    with open(RES + f'corpus_main_{lvl}.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(o['movers'][0])); w.writeheader(); w.writerows(o['movers'])
sh = share_ratio_boot(sub, L, min_n=15)
for x in sh: x['name'] = names.get(x['t'], '')
json.dump(sh, open(RES + 'corpus_share_shift.json', 'w'), indent=1)
print('shift over', [(x['t'], x['name'][:25], x['share_ratio']) for x in sh if x['shift'] == 'over'])
# biggest labelled incidents, for manual precision check
grp = C.defaultdict(list)
for i in lab_idx: grp[lab[i]].append(i)
with open(RES + 'corpus_multi_report_incidents.txt', 'w') as f:
    for l, idx in sorted(grp.items(), key=lambda x: -len(x[1])):
        if len(idx) < 2: break
        ents = C.Counter(e for i in idx for e in main_entities(rows[i])).most_common(3)
        f.write(f"## incident {l}: {len(idx)} labelled reports; top entities {[(names.get(e, e), c) for e, c in ents]}\n")
        for i in sorted(idx, key=lambda i: rows[i]['date'] or ''):
            r = rows[i]; f.write(f"  {r['date']} {r['vendor'][:28]:28} {titles.get(r['url']) or r.get('title') or r['id'][:90]}\n")
