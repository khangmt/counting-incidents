from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Build per-citation (report) records from ATT&CK Enterprise STIX 'uses' relationships.
Output: results/attack_reports.jsonl  one row per citation: source_name, url, date, techniques, entities."""
import json, re, sys, collections as C
from datetime import date
SRC = DATA + 'attack_stix/enterprise-attack.json'
OUT = RB + 'results/attack_reports.jsonl'
M = {m: i+1 for i, m in enumerate(['january','february','march','april','may','june','july','august','september','october','november','december'])}
def pdate(desc):
    m = re.search(r'\((\d{4}), ([A-Za-z]+)\.? ?(\d{1,2})?[,)]', desc or '')
    if m:
        mon = M.get(m.group(2).lower()) or next((v for k, v in M.items() if k.startswith(m.group(2).lower()[:3])), None)
        if mon:
            return date(int(m.group(1)), mon, int(m.group(3) or 15)).isoformat(), 'day' if m.group(3) else 'month'
    m = re.search(r'\((\d{4})[,)]', desc or '')
    if m: return date(int(m.group(1)), 7, 1).isoformat(), 'year'
    return None, None
objs = json.load(open(SRC))['objects']
live = {o['id']: o for o in objs if not o.get('revoked') and not o.get('x_mitre_deprecated')}
def tid(o): return next(e['external_id'] for e in o['external_references'] if e.get('source_name') == 'mitre-attack')
R = {}
for o in live.values():
    if o['type'] != 'relationship' or o['relationship_type'] != 'uses': continue
    s, t = live.get(o['source_ref']), live.get(o['target_ref'])
    if not s or not t or t['type'] != 'attack-pattern': continue
    cited = set(re.findall(r'\(Citation: ([^)]+)\)', o.get('description', '')))
    for e in o.get('external_references', []):
        if e['source_name'] not in cited: continue
        r = R.setdefault(e['source_name'], {'source_name': e['source_name'], 'url': e.get('url'), 'desc': e.get('description'),
                                              'techniques': set(), 'entities': set(), 'entity_types': {}})
        r['techniques'].add(tid(t)); r['entities'].add(tid(s)); r['entity_types'][tid(s)] = s['type']
names = {tid(o): o['name'] for o in live.values() if o['type'] in ('intrusion-set','malware','tool','campaign','attack-pattern')}
camp = {tid(o): (o.get('first_seen'), o.get('last_seen')) for o in live.values() if o['type'] == 'campaign'}
with open(OUT, 'w') as f:
    for r in R.values():
        r['date'], r['date_prec'] = pdate(r['desc'])
        r['techniques'] = sorted(r['techniques']); r['entities'] = sorted(r['entities'])
        f.write(json.dumps(r) + '\n')
json.dump({'names': names, 'campaigns': camp}, open(OUT.replace('attack_reports.jsonl', 'attack_names.json'), 'w'))
print(len(R), 'citations;', C.Counter(r['date_prec'] for r in R.values()))
