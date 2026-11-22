from paths import RB, DATA, TEXTS  # set RB_ROOT, RB_DATA, RB_TEXTS to relocate
"""Paper figures (PDF): fig_share_ratio.pdf, fig_2026_top10.pdf."""
import json, sys, collections as C
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
sys.path.insert(0, RB + 'scripts')
from cluster_rank import load
RES = RB + 'results/'; OUT = RB + 'paper/'
names = json.load(open(RES + 'attack_names.json'))['names']
plt.rcParams.update({'font.family': 'serif', 'font.size': 8, 'axes.spines.top': False, 'axes.spines.right': False,
                     'axes.edgecolor': '#555', 'xtick.color': '#333', 'ytick.color': '#333', 'pdf.fonttype': 42})
INK, ACC, MUTED = '#1f1f1f', '#2a5fa8', '#9a9a9a'
SHORT = {'T1528': 'Steal Application Access Token', 'T1195.001': 'Compromise Software Dependencies', 'T1583.001': 'Acquire Infrastructure: Domains',
         'T1555.006': 'Cloud Secrets Management Stores', 'T1677': 'Poisoned Pipeline Execution', 'T1140': 'Deobfuscate/Decode Files',
         'T1027.013': 'Encrypted/Encoded File', 'T1059.001': 'PowerShell', 'T1021.002': 'SMB/Windows Admin Shares'}
lab = lambda t: f"{SHORT.get(t, names.get(t, t))} ({t})"

# Figure 1: share ratio with 95% CI for techniques whose CI lies above 1; filled marker = BH q <= 0.05, two panels
att = [x for x in json.load(open(RES + 'attack_share_shift.json')) if x['shift'] == 'over'][:9]
_tn = json.load(open(RES + 'reviewer_checks.json'))['texts_permutation_null']
txt = [x for x in json.load(open(RES + 'corpus_share_shift.json')) if x['shift'] == 'over' and _tn[x['t']]['q_null_bh'] <= 0.05]   # same filter as panel (a)
fig, axes = plt.subplots(2, 1, figsize=(4.6, 3.6), gridspec_kw={'height_ratios': [len(att), len(txt)]})
for ax, data, title, base in [(axes[0], att, '(a) ATT&CK citations: 1,936 reports, 1,428 incidents', None),
                               (axes[1], txt, '(b) Report texts: 532 reports, 470 incidents', None)]:
    data = data[::-1]; y = range(len(data))
    for i, x in zip(y, data):
        ax.plot([x['ci_lo'], x['ci_hi']], [i, i], color=INK, lw=1.2, solid_capstyle='round')
        sig = x.get('q_bh', 1) <= 0.05   # filled: still significant after Benjamini-Hochberg; hollow: nominal 95% CI only
        ax.plot(x['share_ratio'], i, 'o', ms=4.5, color=ACC if sig else 'white', mec=ACC if not sig else 'white', mew=0.8 if sig else 1.1, zorder=3)
    ax.axvline(1, color=MUTED, lw=0.8, ls='--', zorder=0)
    ax.set_yticks(list(y)); ax.set_yticklabels([lab(x['t']) for x in data], fontsize=7.5)
    ax.set_title(title, fontsize=8, loc='left')
    ax.tick_params(axis='y', length=0); ax.grid(axis='x', color='#e6e6e6', lw=0.6); ax.set_axisbelow(True)
axes[0].set_xlim(0.9, 3.0); axes[1].set_xlim(0.9, 3.0)
axes[1].set_xlabel('share ratio ρ = per-report share / per-incident share (95% CI)', fontsize=7)
fig.tight_layout(h_pad=1.2); fig.savefig(OUT + 'fig_share_ratio.pdf', bbox_inches='tight'); fig.savefig(OUT + 'fig_share_ratio.png', dpi=200, bbox_inches='tight')

# Figure 2: 2026 ATT&CK top-10, per report vs per incident (slope chart of ranks)
ar = load(RES + 'attack_reports.jsonl'); cl = json.load(open(RES + 'attack_clusters_main.json'))
rows = [r for r in ar if r['date'] and r['date'][:4] == '2026']
def ranks(units):
    c = C.Counter(t for s in units for t in s); order = sorted(c, key=lambda t: (-c[t], t)); return {t: i + 1 for i, t in enumerate(order)}, c
rR, cR = ranks([set(r['techniques']) for r in rows])
inc = C.defaultdict(set)
for r in rows: inc[cl[r['id']]] |= set(r['techniques'])
rI, cI = ranks(list(inc.values()))
top = sorted({t for t, k in rR.items() if k <= 10} | {t for t, k in rI.items() if k <= 10}, key=lambda t: rR[t])
out = [t for t in top if rR[t] <= 10 and rI[t] > 10]; inn = [t for t in top if rI[t] <= 10 and rR[t] > 10]
fig, ax = plt.subplots(figsize=(5.6, 3.2))
slotL = {t: 11.6 + i for i, t in enumerate(sorted(inn, key=lambda t: rR[t]))}   # entering techniques, below the line on the left
slotR = {t: 11.6 + i for i, t in enumerate(sorted(out, key=lambda t: rI[t]))}   # dropped techniques, below the line on the right
for t in top:
    a = rR[t] if rR[t] <= 10 else slotL[t]; b = rI[t] if rI[t] <= 10 else slotR[t]
    col = ACC if t in out else (INK if t in inn else MUTED); lw = 1.6 if col != MUTED else 0.9; tc = INK if col != MUTED else '#666'
    ax.plot([0, 1], [a, b], color=col, lw=lw, marker='o', ms=3.5, mec='white', mew=0.6)
    ax.text(-0.03, a, f"{lab(t)}  {rR[t]}", ha='right', va='center', fontsize=6.5, color=tc)
    ax.text(1.03, b, f"{rI[t]}  {lab(t)}", ha='left', va='center', fontsize=6.5, color=tc)
ax.axhline(11.05, color='#bbbbbb', lw=0.6, ls=':')
ax.set_ylim(15.2, -0.6); ax.set_xlim(-0.02, 1.02); ax.axis('off')
ax.text(0, -0.4, f'Rank per report ({len(rows)} reports)', ha='center', va='bottom', fontsize=7.5)
ax.text(1, -0.4, f'Rank per incident ({len(inc)} incidents)', ha='center', va='bottom', fontsize=7.5)
fig.savefig(OUT + 'fig_2026_top10.pdf', bbox_inches='tight'); fig.savefig(OUT + 'fig_2026_top10.png', dpi=200, bbox_inches='tight')
print('2026 out', [(t, rR[t], rI[t]) for t in out], 'in', [(t, rR[t], rI[t]) for t in inn])
