from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Features for the 314 CISA AA/AR advisories copied from the laptop (data/cisa_laptop). Same extraction as corpus_features.py.
Date = advisory number (AAyy-ddd: year and day of year), which is the original publication date (page dates are often update dates)."""
import csv, json, re, collections as C
from datetime import date as _D, timedelta as _TD
src = open(RB + 'scripts/corpus_features.py').read()
exec(src[:src.index('man = {}')])          # alias table, regexes, ip_ok
D = DATA + 'cisa_laptop/'
OUT = RB + 'results/cisa_reports.jsonl'
def id_date(i):
    m = re.match(r'A[AR](\d{2})-(\d{3})', i)
    return (_D(2000 + int(m.group(1)), 1, 1) + _TD(days=int(m.group(2)) - 1)).isoformat() if m else None
n = 0
with open(OUT, 'w') as f:
    for r in csv.DictReader(open(D + 'manifest.csv')):
        t = open(D + 'text/' + r['sha1'][:12] + '.txt', errors='ignore').read()
        tech = sorted(set(TID.findall(t)) & valid)
        ents = C.Counter()
        for m in big.finditer(t):
            for e in alias[m.group(1)]: ents[e] += 1
        iocs = {('h', x.lower()) for x in H.findall(t)} | {('ip', x.replace('[.]', '.')) for x in IP.findall(t) if ip_ok(x)} | {('d', x.lower().replace('[.]', '.')) for x in DOM.findall(t)}
        title = ''
        for line in t.split('\n'):
            l = line.strip()
            if 12 <= len(l) <= 220 and not l.startswith(('Archived Content', 'In an effort', '| Notification', 'Notification')): title = l; break
        m = re.search(r'(MAR-[\d-]+\s*[–-]\s*[^|\n]{4,90})', t)
        if (not title or title.startswith('|')) and m: title = m.group(1)
        title = r['id'] + ' ' + title[:140]
        f.write(json.dumps({'id': 'cisa:' + r['id'], 'source': 'cisa_laptop', 'vendor': 'CISA', 'url': r['url'], 'title': title,
                            'date': id_date(r['id']) or r['published'][:10], 'date_prec': 'day', 'n_chars': len(t), 'apt_folder': None,
                            'techniques': tech, 'entities': [e for (e, _), c in ents.items()], 'entity_types': {e: ty for (e, ty) in ents},
                            'entity_counts': {e: c for (e, _), c in ents.items()}, 'iocs': sorted('|'.join(x) for x in iocs),
                            'cves': sorted({c.upper() for c in CVE.findall(t)})}) + '\n'); n += 1
print(n)
