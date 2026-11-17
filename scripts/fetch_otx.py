from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Fetch public OTX pulse metadata (indicators need an API key) for pulses referenced by TIE. Polite: 1 request/s, resumable."""
import json, os, re, time, urllib.request
TIE = DATA + 'tie/combined_dataset_full_frequency.json'
import shutil
SHARED_OUT = RB + 'data/otx/pulses.jsonl'
OUT = os.environ.get('OTX_LOCAL', RB + 'data/otx/pulses.local.jsonl')  # append locally; copy to the shared folder every 50 pulses
if not os.path.exists(OUT) and os.path.exists(SHARED_OUT): shutil.copy(SHARED_OUT, OUT)
d = json.load(open(TIE))['reports']
ids = sorted({m.group(1) for r in d for u in r['references'] for m in [re.search(r'otx\.alienvault\.com/pulse/([0-9a-f]{24})', u['url'])] if m})
done = set()
if os.path.exists(OUT): done = {json.loads(l)['id'] for l in open(OUT)}
print(len(ids), 'pulses,', len(done), 'done', flush=True)
def get(u):
    for a in range(4):
        try:
            req = urllib.request.Request(u, headers={'User-Agent': 'research-corpus-fetcher/1.0'})
            return json.load(urllib.request.urlopen(req, timeout=30))
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404): return {'_error': e.code}
            time.sleep(5 * (a + 1))
        except Exception: time.sleep(5 * (a + 1))
    return {'_error': 'fail'}
with open(OUT, 'a') as f:
    for n, i in enumerate(ids):
        if i in done: continue
        p = get(f'https://otx.alienvault.com/api/v1/pulses/{i}'); time.sleep(1)
        rec = {'id': i}
        if '_error' in p: rec['error'] = p['_error']
        else:
            for k in ['name', 'created', 'modified', 'author_name', 'tags', 'references', 'adversary', 'malware_families', 'attack_ids', 'targeted_countries', 'industries']:
                rec[k] = p.get(k)
            pass  # indicators endpoint needs an API key: not collected
        f.write(json.dumps(rec) + '\n'); f.flush()
        if n % 50 == 0: print(n, flush=True); shutil.copy(OUT, SHARED_OUT + '.tmp'); os.replace(SHARED_OUT + '.tmp', SHARED_OUT)
shutil.copy(OUT, SHARED_OUT); print('done')
