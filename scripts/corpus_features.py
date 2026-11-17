from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Per-document features for the collected report corpus: explicit ATT&CK IDs, ATT&CK group/malware/campaign names, IOCs, date.
Reads texts from a local copy (BASE) of causality-benchmark/data. Output: results/corpus_reports.jsonl (no text, only ids/features)."""
import csv, json, re, sys, collections as C
BASE = sys.argv[1] if len(sys.argv) > 1 else TEXTS + ''
PF = DATA + ''
OUT = RB + 'results/corpus_reports.jsonl'
objs = json.load(open(PF + 'attack_stix/enterprise-attack.json'))['objects']
def ext(o): return next((e['external_id'] for e in o.get('external_references', []) if e.get('source_name') == 'mitre-attack'), None)
valid = {ext(o) for o in objs if o['type'] == 'attack-pattern'}
revoked_map = {}
alias = {}
for o in objs:
    if o['type'] in ('intrusion-set', 'malware', 'campaign') and not o.get('revoked') and not o.get('x_mitre_deprecated'):
        for n in {o['name'], *o.get('aliases', []), *o.get('x_mitre_aliases', [])}:
            if len(n) >= 4 and n.lower() not in {'none', 'agent', 'stealer', 'dropper', 'backdoor', 'loader', 'ransomware', 'page', 'play', 'wiper'}:  # 'Page' (Elise), 'Play' (Playcrypt) and 'Wiper' match ordinary words
                alias.setdefault(n, set()).add((ext(o), o['type']))
# ambiguous common-word names: only match case-sensitively; all names matched with word boundaries
pat_names = sorted(alias, key=len, reverse=True)
big = re.compile(r'(?<![\w-])(' + '|'.join(re.escape(n) for n in pat_names) + r')(?![\w-])')
TID = re.compile(r'\bT1\d{3}(?:\.\d{3})?\b')
H = re.compile(r'\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b')
IP = re.compile(r'\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b')
DOM = re.compile(r'\b[a-z0-9][a-z0-9-]{1,62}(?:\[\.\][a-z0-9-]{1,62})+\b', re.I)  # defanged domains only
CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)
def ip_ok(s):
    p = [int(x) for x in s.replace('[.]', '.').split('.')]
    return all(x < 256 for x in p) and not (p[0] in (0, 10, 127) or p[0] >= 224 or (p[0] == 192 and p[1] == 168) or (p[0] == 172 and 16 <= p[1] < 32) or p[:2] == [169, 254])
man = {}
for r in csv.DictReader(open(BASE + '/fulltext_manifest.csv')):
    if r['published_date']: man[r['url']] = r['published_date'][:10]
apt = {}
from datetime import date as _D, timedelta as _TD
for a in csv.DictReader(open(BASE + '/apt_collection_private/manifest.csv')):
    m = re.match(r'(\d{4})\.(\d{2})\.(\d{2})', a['campaign_folder'])
    dd = None
    if m:
        try: dd = _D(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
        except ValueError: dd = None
    apt[a['sha1']] = (a['campaign_folder'], dd)
CISA_ID = re.compile(r'\b(?:aa|ar|ta|mar)-?(\d{2})-(\d{3})[a-z]?\b', re.I)
def cisa_date(u):
    m = CISA_ID.search(u or '')
    if not m: return None
    y, doy = 2000 + int(m.group(1)), int(m.group(2))
    return (_D(y, 1, 1) + _TD(days=doy - 1)).isoformat() if 1 <= doy <= 366 else None
n = 0
with open(OUT, 'w') as f:
    for r in csv.DictReader(open(BASE + '/corpus_index.csv')):
        if r['dup_of']: continue
        p = r['path'].replace(PF, BASE + '/')
        try: t = open(p, errors='ignore').read()
        except Exception: continue
        tech = sorted(set(TID.findall(t)) & valid)
        ents = C.Counter()
        for m in big.finditer(t):
            for e in alias[m.group(1)]: ents[e] += 1
        iocs = {('h', x.lower()) for x in H.findall(t)} | {('ip', x.replace('[.]', '.')) for x in IP.findall(t) if ip_ok(x)} | {('d', x.lower().replace('[.]', '.')) for x in DOM.findall(t)}
        d = man.get(r['url']); prec = 'day' if d else None
        folder = None
        if r['doc'].startswith('apt:'):
            folder, dd = apt.get(r['doc'][4:], (None, None))
            if dd: d, prec = dd, 'day'
        if prec != 'day':
            m = re.search(r'(20\d{2}|19\d{2})[-/._](\d{2})[-/._](\d{2})', r['doc'] + ' ' + (r['url'] or ''))
            if m:
                try: d, prec = _D(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat(), 'day'
                except ValueError: pass
        if prec != 'day' and r['vendor'] == 'CISA':
            cd = cisa_date(r['url'])
            if cd: d, prec = cd, 'day'
        if not d and r['year']: d, prec = f"{int(float(r['year']))}-07-01", 'year'
        rec = {'id': r['doc'], 'source': r['source'], 'vendor': r['vendor'], 'url': r['url'], 'date': d, 'date_prec': prec, 'n_chars': len(t), 'apt_folder': folder,
               'techniques': tech, 'entities': [e for (e, _), c in ents.items()], 'entity_types': {e: ty for (e, ty) in ents}, 'entity_counts': {e: c for (e, _), c in ents.items()},
               'iocs': sorted('|'.join(x) for x in iocs), 'cves': sorted({c.upper() for c in CVE.findall(t)})}
        f.write(json.dumps(rec) + '\n'); n += 1
print(n, 'docs')
