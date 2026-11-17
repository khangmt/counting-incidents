from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Candidate report pairs for a checked same-incident set. Strata:
 merged     - pairs the main clustering (tau 60, span 180) put together  -> precision
 entity     - share a main actor/malware but were not merged, <= 365 days apart -> recall, hard cases
 cisa_xref  - a CISA advisory cites another advisory by number
 apt_folder - two PDFs in the same APT-collection campaign folder
Output: results/gold_candidates.csv (no report text). Column label is filled by reading titles: same / different / unsure."""
import json, csv, re, random, itertools, sys, collections as C
sys.path.insert(0, RB + 'scripts')
src = open(RB + 'scripts/run_corpus.py').read()
exec(src[:src.index('# technique-labelled subset')])      # rows, SHARED, main_entities, cluster2, titles, names
lab = cluster2(tau=60)
apt_files = {}
for a in csv.DictReader(open(TEXTS + '/apt_collection_private/manifest.csv')):
    apt_files[a['sha1']] = a['file']
_paths = {x['doc']: x['path'].replace(DATA + '', TEXTS + '/') for x in csv.DictReader(open(TEXTS + '/corpus_index.csv'))}
def _head(doc):
    try: t = open(_paths[doc], errors='ignore').read(6000)
    except Exception: return ''
    m = re.search(r'(MAR-[\d.v-]+\s*[–-]\s*[^|\n]{4,90})', t)
    for line in t.split('\n'):
        l = line.strip()
        if 12 <= len(l) <= 220 and not l.startswith(('Archived Content', 'In an effort', '| Notification', 'Notification', 'An official website', 'Here', 'Share', 'Skip')): return l
    return m.group(1) if m else ''
def title(r):
    if r['vendor'] == 'CISA' and not r.get('title') and not titles.get(r['url']): return (r['url'] or '').rsplit('/', 1)[-1][:30] + ' ' + _head(r['id'])
    if r['id'].startswith('apt:'): return f"[{r.get('apt_folder')}] {apt_files.get(r['id'][4:], '')}"
    if r.get('title'): return r['title']
    return titles.get(r['url']) or (r.get('url') or r['id'])[-90:]
ME = [main_entities(r) for r in rows]
def shared_iocs(a, b): return len(set(rows[a]['iocs']) & set(rows[b]['iocs']))
random.seed(7)
cand = {}
def add(a, b, stratum):
    a, b = sorted((a, b))
    if a != b and (a, b) not in cand: cand[(a, b)] = stratum
# merged pairs: sample within multi-report incidents, at most 3 pairs per incident
grp = C.defaultdict(list)
for i, l in enumerate(lab): grp[l].append(i)
mp = []
for l, idx in grp.items():
    if len(idx) > 1: mp += random.sample(list(itertools.combinations(idx, 2)), min(3, len(idx) * (len(idx) - 1) // 2))
for a, b in random.sample(mp, min(70, len(mp))): add(a, b, 'merged')
# entity pairs not merged
by = C.defaultdict(list)
for i, es in enumerate(ME):
    for e in es: by[e].append(i)
ep = [(a, b) for e, idx in by.items() for a, b in itertools.combinations(idx, 2)
      if lab[a] != lab[b] and rows[a]['d'] and rows[b]['d'] and abs(rows[a]['d'] - rows[b]['d']) <= 365]
for a, b in random.sample(ep, min(60, len(ep))): add(a, b, 'entity')
# CISA cross references (skip hub advisories cited by many: lists of exploited CVEs etc.)
cid = {}
for i, r in enumerate(rows):
    m = re.search(r'\b(a[ar]\d{2}-\d{3}[a-z]?)\b', (r.get('url') or '').lower())
    if r['vendor'] == 'CISA' and m: cid[m.group(1).upper()] = i
D = DATA + 'cisa_laptop/'
xr = []
for r in csv.DictReader(open(D + 'manifest.csv')):
    if r['id'] not in cid: continue
    t = open(D + 'text/' + r['sha1'][:12] + '.txt', errors='ignore').read()
    for x in {m.upper() for m in re.findall(r'\b(A[AR]\d{2}-\d{3}[A-Z]?)\b', t, re.I)} - {r['id']}:
        if x in cid: xr.append((cid[r['id']], cid[x]))
deg = C.Counter(b for a, b in xr)
xr = [(a, b) for a, b in xr if deg[b] <= 4]
for a, b in random.sample(xr, min(40, len(xr))): add(a, b, 'cisa_xref')
# APT folder pairs
fold = C.defaultdict(list)
for i, r in enumerate(rows):
    if r.get('apt_folder') and re.match(r'\d{4}\.\d{2}\.\d{2}', r['apt_folder']): fold[r['apt_folder']].append(i)
fp = [p for idx in fold.values() if len(idx) > 1 for p in itertools.combinations(idx, 2)]
for a, b in random.sample(fp, min(40, len(fp))): add(a, b, 'apt_folder')
nm = lambda es: '; '.join(names.get(e, e) for e in es)
with open(RES + 'gold_candidates.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['pair', 'stratum', 'merged_by_method', 'days_apart', 'shared_iocs', 'date_a', 'vendor_a', 'title_a', 'main_a', 'date_b', 'vendor_b', 'title_b', 'main_b', 'id_a', 'id_b', 'label', 'note'])
    for k, ((a, b), s) in enumerate(sorted(cand.items(), key=lambda x: (x[1], rows[x[0][0]]['date'] or ''))):
        ra, rb = rows[a], rows[b]
        w.writerow([k + 1, s, int(lab[a] == lab[b]), abs(ra['d'] - rb['d']) if ra['d'] and rb['d'] else '', shared_iocs(a, b),
                    ra['date'], ra['vendor'], title(ra)[:110], nm(ME[a]), rb['date'], rb['vendor'], title(rb)[:110], nm(ME[b]), ra['id'], rb['id'], '', ''])
print(len(cand), C.Counter(cand.values()))
