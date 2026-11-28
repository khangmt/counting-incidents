from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Two checks added after gate G4 (exploratory, reported as such).
E1. Temporal hold-out: the span cap S was chosen on all external groupings. Here we choose S on groupings that begin before
    SPLIT_YEAR only, then report precision and recall on the later groupings, which played no part in the choice.
E2. Counting threshold for texts: the main text analysis counts texts with >= 3 explicit technique IDs. Rerun the share-ratio
    bootstrap for texts with >= 1 and >= 2 IDs (same clusters) and compare the BH over-counted sets."""
import json, sys, re, collections as C
sys.path.insert(0, RB + 'scripts')
from cluster_rank import load, pairwise_eval, pairwise_ci, shared_software, cluster_edges, entity_edges
from share_bootstrap import share_ratio_boot
RES = RB + 'results/'
SPLIT_YEAR = 2019
SPANS = [45, 60, 90, 180, 365, None]
out = {'split_year': SPLIT_YEAR}

def split_eval(rows, lab, gold, gdate):
    early = {i: g for i, g in gold.items() if gdate[g] < SPLIT_YEAR}
    late = {i: g for i, g in gold.items() if gdate[g] >= SPLIT_YEAR}
    res = {}
    for name, gd in [('early', early), ('late', late)]:
        ev = pairwise_eval(rows, lab, gd)
        res[name] = {'P': round(ev['P'], 3), 'R': round(ev['R'], 3), 'F1': round(ev['F1'], 3), 'tp': ev['tp'], 'fp': ev['fp'], 'fn': ev['fn'],
                     'n_labelled': ev['n_labelled'], 'n_groups': len(set(gd.values())), **pairwise_ci(rows, lab, gd)}
    return res

def pick(sweep):  # choose S by F1 on the early half only
    return max(sweep, key=lambda k: (sweep[k]['early']['F1'], -SPANS.index(None if k == 'None' else int(k))))

# ---------- E1 on ATT&CK (campaign links removed, as in the main validation)
rows = load(RES + 'attack_reports.jsonl')
SHARED = shared_software(DATA + 'attack_stix/enterprise-attack.json')
gold = {}
for i, r in enumerate(rows):
    cs = [e for e in r['entities'] if r['entity_types'][e] == 'campaign']
    if len(cs) == 1 and any(r['entity_types'][e] in ('intrusion-set', 'malware') for e in r['entities']): gold[i] = cs[0]
gold = {i: g for i, g in gold.items() if rows[i].get('date')}
gdate = {}
for i, g in gold.items(): gdate[g] = min(gdate.get(g, 9999), int(rows[i]['date'][:4]))
camps = set(e for r in rows for e in r['entities'] if r['entity_types'][e] == 'campaign')
link = ('intrusion-set', 'campaign', 'malware')
sw = {}
for S in SPANS:
    lab = cluster_edges(rows, entity_edges(rows, 60, link, exclude=camps | SHARED), S)
    sw[str(S)] = split_eval(rows, lab, gold, gdate)
    print('E1 attack S', S, sw[str(S)])
out['attack_holdout'] = {'by_span': sw, 'chosen_on_early': pick(sw)}
print('E1 attack chosen on early:', out['attack_holdout']['chosen_on_early'])

# ---------- E1 and E2 on texts (APT-collection dated campaign folders)
src = open(RB + 'scripts/run_corpus.py').read().split('# technique-labelled subset')[0]
g = {}; exec(src, g)
crow = g['rows']
cgold = {i: r['apt_folder'] for i, r in enumerate(crow) if r.get('apt_folder') and re.match(r'\d{4}\.\d{2}\.\d{2}', r['apt_folder'])}
cdate = {f: int(f[:4]) for f in set(cgold.values())}
sw = {}; mainlab = None
for S in SPANS:
    lab = g['cluster2'](tau=60, span=S)
    if S == 60: mainlab = lab
    sw[str(S)] = split_eval(crow, lab, cgold, cdate)
    print('E1 texts S', S, sw[str(S)])
out['texts_holdout'] = {'by_span': sw, 'chosen_on_early': pick(sw)}
print('E1 texts chosen on early:', out['texts_holdout']['chosen_on_early'])

main_over = sorted(x['t'] for x in json.load(open(RES + 'corpus_share_shift.json')) if x['shift_bh'] == 'over')
thr = {}
for k in [1, 2, 3]:
    idx = [i for i, r in enumerate(crow) if len(r['techniques']) >= k]
    sh = share_ratio_boot([crow[i] for i in idx], [mainlab[i] for i in idx], min_n=15)
    over = sorted(x['t'] for x in sh if x['shift_bh'] == 'over')
    thr[str(k)] = {'n_texts': len(idx), 'n_incidents': len(set(mainlab[i] for i in idx)), 'n_tested': len(sh), 'over_bh': over,
                   'main_over_kept': sorted(set(main_over) & set(over))}
    print('E2 min IDs', k, thr[str(k)])
out['texts_min_ids'] = {'main_over_bh': main_over, 'by_threshold': thr}
json.dump(out, open(RES + 'enrich_checks.json', 'w'), indent=1)
