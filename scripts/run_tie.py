from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""TIE OpenCTI reports: per-entry vs same-report (shared URL) vs per-incident (actor/malware + 60 days) technique rankings.
Dates and actors come from public OTX pulse metadata (data/otx/pulses.jsonl) or the vendor URL."""
import json, re, sys, csv, collections as C
sys.path.insert(0, RB + 'scripts')
from cluster_rank import load, UF, counts, compare, shared_software, cluster_edges, entity_edges
from share_bootstrap import share_ratio_boot
from datetime import date
PF = DATA + ''; RES = RB + 'results/'
tie = json.load(open(PF + 'tie/combined_dataset_full_frequency.json'))['reports']
otx = {}
for l in open(RB + 'data/otx/pulses.jsonl'):
    p = json.loads(l)
    if 'error' not in p: otx[p['id']] = p
objs = json.load(open(PF + 'attack_stix/enterprise-attack.json'))['objects']
ext = lambda o: next((e['external_id'] for e in o.get('external_references', []) if e.get('source_name') == 'mitre-attack'), None)
names = json.load(open(RES + 'attack_names.json'))['names']
SHARED = shared_software(PF + 'attack_stix/enterprise-attack.json')
alias = {}
for o in objs:
    if o['type'] in ('intrusion-set', 'malware', 'campaign') and not o.get('revoked') and not o.get('x_mitre_deprecated'):
        for n in {o['name'], *o.get('aliases', []), *o.get('x_mitre_aliases', [])}:
            if len(n) >= 4: alias.setdefault(n.lower(), set()).add((ext(o), o['type']))
apat = re.compile(r'(?<![a-z0-9])(' + '|'.join(re.escape(a) for a in sorted(alias, key=len, reverse=True)) + r')(?![a-z0-9])')
def norm(u):
    u = u.strip().lower(); u = re.sub(r'^https?://(www\.)?', '', u); u = u.split('#')[0]
    if not re.search(r'\.(jsp|php|aspx?)\?', u): u = u.split('?')[0]
    return u.rstrip('/')
GENERIC = {'adsecurity.org', 'youtube.com/watch', 'tools.cisco.com/security/center/resources/integrity_assurance.html', 'github.com', 'twitter.com', 'attack.mitre.org'}
def url_date(u):
    m = re.search(r'/(20\d{2}|19\d{2})/(\d{1,2})/(?:(\d{1,2})/)?', u) or re.search(r'(20\d{2})-(\d{2})-(\d{2})', u)
    if m:
        try: return date(int(m.group(1)), int(m.group(2)), int(m.group(3) or 15)).isoformat(), 'day' if m.group(3) else 'month'
        except ValueError: pass
    return None, None
rows = []
for r in tie:
    if r['origin_of_data'] != 'OpenCTI' or not r['mitre_techniques']: continue
    urls = [x['url'] for x in r['references'] if x['url']]
    pid = next((m.group(1) for u in urls for m in [re.search(r'otx\.alienvault\.com/pulse/([0-9a-f]{24})', u)] if m), None)
    p = otx.get(pid) if pid else None
    vend = [norm(u) for u in urls if 'otx.alienvault' not in u]
    if p: vend += [norm(u) for u in (p.get('references') or []) if u]
    vend = sorted({v for v in vend if v not in GENERIC and len(v) > 12})
    d, prec = None, None
    if p and p.get('created'): d, prec = p['created'][:10], 'day'
    else:
        for u in urls:
            d, prec = url_date(u)
            if d: break
    text = ' '.join([p.get('name') or '', p.get('adversary') or '', ' '.join(p.get('malware_families') or []), ' '.join(p.get('tags') or [])] if p else [])
    text += ' ' + ' '.join(re.sub(r'[-_/.]+', ' ', u) for u in vend)
    ents = C.Counter()
    for m in apat.finditer(text.lower()):
        for e, ty in alias[m.group(1)]: ents[(e, ty)] += 1
    for mf in (p.get('malware_families') or []) if p else []:
        m = re.search(r'S\d{4}', mf)
        if m: ents[(m.group(0), 'malware')] += 1
    if p and p.get('adversary') and not any(ty == 'intrusion-set' for _, ty in ents):
        ents[('ADV:' + p['adversary'].lower(), 'intrusion-set')] += 1   # actor not in ATT&CK: keep raw name
    rows.append({'id': r['id'], 'date': d, 'date_prec': prec, 'techniques': sorted(r['mitre_techniques']), 'urls': vend, 'otx': bool(p),
                 'entities': [e for e, _ in ents], 'entity_types': {e: ty for e, ty in ents}})
for r in rows: r['d'] = date.fromisoformat(r['date']).toordinal() if r['date'] else None
print('OpenCTI entries', len(rows), 'with OTX metadata', sum(r['otx'] for r in rows), 'dated', sum(r['d'] is not None for r in rows), 'with entity', sum(bool(r['entities']) for r in rows))
# Level 1: same report (shared vendor URL)
uf = UF(len(rows)); by = C.defaultdict(list)
for i, r in enumerate(rows):
    for u in r['urls']: by[u].append(i)
for u, idx in by.items():
    for i in idx[1:]: uf.u(idx[0], i)
L1 = [uf.f(i) for i in range(len(rows))]
# Level 2: + same incident (shared actor/malware, <= tau days, span <= 180 days)
def level2(tau=60, span=60):
    E = [(-1, a, b) for a, b in zip(range(len(rows)), L1) if a != b]  # keep L1 merges first
    E += entity_edges(rows, tau, ('intrusion-set', 'campaign', 'malware'), exclude=SHARED, year_tau=-1)
    return cluster_edges(rows, E, span)
out = {'n_entries': len(rows), 'levels': []}
for name, lab in [('same_report', L1)] + [(f'incident_t{t}', level2(t)) for t in (30, 60, 90, 180)] + [('incident_t60_span180', level2(60, 180)), ('incident_t60_span365', level2(60, 365))]:
    row = {'setting': name, 'units': len(set(lab)), 'largest': max(C.Counter(lab).values())}
    for lvl in ['tech', 'parent']:
        cr, nr = counts(rows, None, lvl); ci, ni = counts(rows, lab, lvl); o = compare(cr, nr, ci, ni)
        row.update({f'{lvl}_tau_b': round(float(o['kendall_tau_b']), 3), f'{lvl}_top10': o['top10_overlap'], f'{lvl}_top20': o['top20_overlap'], f'{lvl}_top50': o['top50_overlap']})
        if name == 'incident_t60':
            for m in o['movers']: m['name'] = names.get(m['t'], '')
            json.dump(o, open(RES + f'tie_main_{lvl}.json', 'w'), indent=1, default=float)
            with open(RES + f'tie_main_{lvl}.csv', 'w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=list(o['movers'][0])); w.writeheader(); w.writerows(o['movers'])
    out['levels'].append(row); print(row)
    if name == 'incident_t60':
        sh = share_ratio_boot(rows, lab, min_n=30)
        for x in sh: x['name'] = names.get(x['t'], '')
        json.dump(sh, open(RES + 'tie_share_shift.json', 'w'), indent=1)
        print('over', [(x['t'], x['name'][:25], x['share_ratio']) for x in sh if x['shift'] == 'over'][:25])
        big = C.Counter(lab).most_common(10)
        for l, n in big:
            mem = [rows[i] for i in range(len(rows)) if lab[i] == l]
            print(n, min(r['date'] or 'z' for r in mem), max(r['date'] or '' for r in mem), C.Counter(names.get(e, e) for r in mem for e in r['entities']).most_common(3))
json.dump(out, open(RES + 'tie_sensitivity.json', 'w'), indent=1)
