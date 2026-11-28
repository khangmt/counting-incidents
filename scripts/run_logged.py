"""Run one pipeline script and save a run record (evidence gate).
Usage: python3 run_logged.py <script.py> [args...]
Writes results/runs/<script>-<timestamp>.json and appends one line to results/runs.jsonl.
A run whose exit code is not 0 is recorded with status 'failed' and must not be reported."""
import sys, os, json, time, hashlib, socket, platform, subprocess, glob, datetime
from paths import RB, DATA, TEXTS
def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()
INPUTS = {  # declared inputs per script (outputs of earlier steps are listed too)
    'attack_citations.py': [DATA + 'attack_stix/enterprise-attack.json'],
    'run_attack.py': [RB + 'results/attack_reports.jsonl', RB + 'results/attack_names.json', DATA + 'attack_stix/enterprise-attack.json'],
    'corpus_features.py': [TEXTS + '/corpus_index.csv', TEXTS + '/apt_collection_private/manifest.csv', DATA + 'attack_stix/enterprise-attack.json'],
    'cisa_features.py': [DATA + 'cisa_laptop/manifest.csv', DATA + 'attack_stix/enterprise-attack.json'],
    'run_corpus.py': [RB + 'results/corpus_reports.jsonl', RB + 'results/cisa_reports.jsonl', DATA + 'fulltext_manifest.csv'],
    'run_tie.py': [DATA + 'tie/combined_dataset_full_frequency.json', RB + 'data/otx/pulses.jsonl'],
    'paper_extra.py': [RB + 'results/attack_reports.jsonl', RB + 'results/attack_clusters_main.json', RB + 'results/corpus_reports.jsonl', RB + 'results/corpus_clusters_main.json'],
    'reviewer_checks.py': [RB + 'results/attack_reports.jsonl', RB + 'results/corpus_reports.jsonl'],
    'enrich_checks.py': [RB + 'results/attack_reports.jsonl', RB + 'results/corpus_reports.jsonl', RB + 'results/corpus_share_shift.json'],
    'make_figures.py': [RB + 'results/attack_share_shift.json', RB + 'results/corpus_share_shift.json', RB + 'results/attack_clusters_main.json'],
}
script, args = sys.argv[1], sys.argv[2:]
here = os.path.dirname(os.path.abspath(__file__))
def git(*a):
    try: return subprocess.run(['git', '-C', here] + list(a), capture_output=True, text=True).stdout.strip()
    except Exception: return ''
before = {p: os.path.getmtime(p) for p in glob.glob(RB + 'results/*') + glob.glob(RB + 'paper/*') if os.path.isfile(p)}
t0 = time.time(); start = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
log = RB + f'results/runs/{script[:-3]}-{start.replace(":", "")}.log'
os.makedirs(RB + 'results/runs', exist_ok=True)
with open(log, 'w') as lf:
    rc = subprocess.run([sys.executable, os.path.join(here, script)] + args, cwd=here, stdout=lf, stderr=subprocess.STDOUT).returncode
outs = sorted(p for p in glob.glob(RB + 'results/*') + glob.glob(RB + 'paper/*') if os.path.isfile(p) and os.path.getmtime(p) != before.get(p))
rec = {'script': script, 'args': args, 'status': 'ok' if rc == 0 else 'failed', 'exit_code': rc,
       'start_utc': start, 'seconds': round(time.time() - t0, 1), 'machine': socket.gethostname(), 'platform': platform.platform(),
       'python': platform.python_version(), 'git_commit': git('rev-parse', 'HEAD'), 'git_dirty': bool(git('status', '--porcelain', '--', '.')),
       'script_sha256': sha(os.path.join(here, script)), 'command': ' '.join([os.path.basename(sys.executable), script] + args),
       'env': {k: os.environ.get(k) for k in ('RB_ROOT', 'RB_DATA', 'RB_TEXTS', 'WITH_CISA')},
       'seeds': 'bootstrap seed 0 (share_bootstrap.py, paper_extra.py); permutation seed 1 (reviewer_checks.py)',
       'llm_used': None,
       'inputs': {p.replace(RB, '$RB/').replace(DATA, '$DATA/').replace(TEXTS, '$TEXTS'): sha(p) if os.path.exists(p) else 'MISSING' for p in INPUTS.get(script, [])},
       'outputs': {p.replace(RB, '$RB/'): sha(p) for p in outs}, 'log': log.replace(RB, '$RB/')}
json.dump(rec, open(log[:-4] + '.json', 'w'), indent=1)
with open(RB + 'results/runs.jsonl', 'a') as f: f.write(json.dumps(rec) + '\n')
print(script, rec['status'], rec['seconds'], 's,', len(outs), 'outputs')
sys.exit(rc)
