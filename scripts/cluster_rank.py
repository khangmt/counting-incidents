from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Incident clustering of reports + per-report vs per-incident technique rankings.
Generic: input jsonl with fields id/source_name, date (ISO or null), techniques (list), entities (list), entity_types (dict)."""
import json, sys, collections as C, itertools
from datetime import date
from scipy.stats import kendalltau, spearmanr

def load(path):
    rows = [json.loads(l) for l in open(path)]
    for r in rows:
        r['id'] = r.get('id') or r['source_name']
        r['d'] = date.fromisoformat(r['date']).toordinal() if r.get('date') else None
    return rows

class UF:
    def __init__(s, n): s.p = list(range(n))
    def f(s, x):
        while s.p[x] != x: s.p[x] = s.p[s.p[x]]; x = s.p[x]
        return x
    def u(s, a, b): s.p[s.f(a)] = s.f(b)

def cluster(rows, tau=60, link_types=('intrusion-set', 'campaign', 'malware'), exclude=()):
    """Link two reports if they share an entity of link_types and their dates differ by <= tau days.
    tau=None: ignore dates (entity overlap only). Undated reports link only when tau is None."""
    uf = UF(len(rows)); by = C.defaultdict(list)
    for i, r in enumerate(rows):
        for e in r['entities']:
            if r['entity_types'].get(e) in link_types and e not in exclude: by[e].append(i)
    for e, idx in by.items():
        if tau is None:
            for i in idx[1:]: uf.u(idx[0], i)
            continue
        idx = sorted((i for i in idx if rows[i]['d'] is not None), key=lambda i: rows[i]['d'])
        for a, b in zip(idx, idx[1:]):          # single-link along time within entity
            if rows[b]['d'] - rows[a]['d'] <= tau: uf.u(a, b)
    return [uf.f(i) for i in range(len(rows))]

def parent(t): return t.split('.')[0]

def counts(rows, labels=None, level='tech'):
    f = (lambda t: t) if level == 'tech' else parent
    if labels is None: labels = list(range(len(rows)))
    inc = C.defaultdict(set)
    for r, l in zip(rows, labels): inc[l] |= {f(t) for t in r['techniques']}
    return C.Counter(t for s in inc.values() for t in s), len(inc)

def rank(c):
    # competition ranking 1 = most frequent
    order = sorted(c, key=lambda t: -c[t]); rk = {}; prev = None
    for i, t in enumerate(order):
        rk[t] = rk[prev] if prev is not None and c[t] == c[prev] else i + 1; prev = t
    return rk

def compare(cr, nr, ci, ni, k_list=(10, 20, 50)):
    ts = sorted(set(cr) | set(ci))
    a = [cr.get(t, 0) / nr for t in ts]; b = [ci.get(t, 0) / ni for t in ts]
    out = {'n_units_report': nr, 'n_units_incident': ni, 'kendall_tau_b': kendalltau(a, b)[0], 'spearman': spearmanr(a, b)[0]}
    top = lambda c, k: [t for t, _ in sorted(c.items(), key=lambda x: (-x[1], x[0]))[:k]]
    for k in k_list:
        A, B = set(top(cr, k)), set(top(ci, k)); out[f'top{k}_overlap'] = len(A & B) / k
    ra, rb = rank(cr), rank(ci)
    out['movers'] = sorted(({'t': t, 'rank_report': ra.get(t), 'rank_incident': rb.get(t), 'n_report': cr.get(t, 0), 'n_incident': ci.get(t, 0),
                             'share_report': round(cr.get(t, 0) / nr, 4), 'share_incident': round(ci.get(t, 0) / ni, 4),
                             'inflation': round(cr.get(t, 0) / max(ci.get(t, 0), 1), 3)} for t in ts), key=lambda x: x['rank_report'] or 9999)
    return out

def pairwise_eval(rows, labels, gold):
    """gold: dict row index -> gold incident id (only for rows that have one). Pairwise P/R/F1 over gold-labelled rows."""
    idx = list(gold); tp = fp = fn = 0
    for i, j in itertools.combinations(idx, 2):
        g = gold[i] == gold[j]; p = labels[i] == labels[j]
        tp += g and p; fp += p and not g; fn += g and not p
    P = tp / (tp + fp) if tp + fp else float('nan'); R = tp / (tp + fn) if tp + fn else float('nan')
    return {'P': P, 'R': R, 'F1': 2 * P * R / (P + R) if P + R else 0, 'pairs_gold_pos': tp + fn, 'n_labelled': len(idx)}

def shared_software(stix_path, min_groups=4):
    """Software used by >= min_groups groups/campaigns in ATT&CK (Cobalt Strike, Mimikatz, PlugX...): not evidence of a shared incident."""
    s = json.load(open(stix_path))['objects']; byid = {o['id']: o for o in s}
    ext = lambda o: next((e['external_id'] for e in o.get('external_references', []) if e.get('source_name') == 'mitre-attack'), None)
    g = C.defaultdict(set)
    for o in s:
        if o['type'] == 'relationship' and o['relationship_type'] == 'uses' and o['source_ref'].startswith(('intrusion-set', 'campaign')) and o['target_ref'].startswith(('malware', 'tool')):
            g[ext(byid[o['target_ref']])].add(o['source_ref'])
    return {k for k, v in g.items() if len(v) >= min_groups}

def cluster_edges(rows, edges, max_span=None):
    """Constrained single linkage: process candidate edges (key, a, b) in ascending key order and merge
    only if the merged component's date span stays <= max_span days (None = no limit). Undated rows add no span."""
    uf = UF(len(rows)); lo = [r['d'] for r in rows]; hi = [r['d'] for r in rows]
    for _, a, b in sorted(edges):
        ra, rb = uf.f(a), uf.f(b)
        if ra == rb: continue
        l = min((x for x in (lo[ra], lo[rb]) if x is not None), default=None); h = max((x for x in (hi[ra], hi[rb]) if x is not None), default=None)
        if max_span is not None and l is not None and h - l > max_span: continue
        uf.p[ra] = rb; lo[rb], hi[rb] = l, h
    return [uf.f(i) for i in range(len(rows))]

def entity_edges(rows, tau, link_types, exclude=(), ents=None, year_tau=0, year_types=('intrusion-set', 'campaign')):
    """Candidate edges between consecutive (in time) reports sharing an entity, gap <= tau days.
    Rows with year-only dates link only within the same year and only via group/campaign entities."""
    by = C.defaultdict(list)
    for i, r in enumerate(rows):
        for e in (ents(r) if ents else r['entities']):
            if r['entity_types'].get(e) in link_types and e not in exclude: by[e].append(i)
    E = []
    for e, idx in by.items():
        idx = sorted((i for i in idx if rows[i]['d'] is not None), key=lambda i: rows[i]['d'])
        for x, a in enumerate(idx):
            for b in idx[x + 1:]:
                gap = rows[b]['d'] - rows[a]['d']
                if gap > max(tau, year_tau): break
                yr = 'year' in (rows[a].get('date_prec'), rows[b].get('date_prec'))
                if yr and (gap > year_tau or rows[a]['entity_types'][e] not in year_types): continue
                if not yr and gap > tau: continue
                E.append((gap, a, b))
    return E
