import glob, json, os, urllib.parse
from collections import Counter

from brain_code_vsystem import BrainCodeVSystem
from titan_v_pro_core import TITAN_VERSION, score_finding

brain = BrainCodeVSystem()
items, actions, runner_stats = [], [], []

for p in glob.glob('results/*.json'):
    try:
        d = json.load(open(p, encoding='utf-8'))
        if not isinstance(d, dict):
            continue
        items.extend(d.get('findings', []))
        actions.extend(d.get('actions', []))
        if d.get('stats'):
            runner_stats.append(d.get('stats'))
    except Exception:
        pass

# Deduplicate repeated findings while preserving the strongest observation.
by_key = {}
for x in items:
    key = (x.get('program'), x.get('module'), x.get('target'), x.get('title'))
    existing = by_key.get(key)
    if not existing or int(x.get('priority_score', 0)) > int(existing.get('priority_score', 0)):
        by_key[key] = x
items = list(by_key.values())

filtered, suppressed = [], []
for x in items:
    prog = x.get('program', 'unknown')
    mod = x.get('module', 'unknown')
    target = x.get('target', '')
    host = urllib.parse.urlsplit(target).hostname or 'unknown'
    signal = ' | '.join([x.get('title', ''), target])

    if brain.is_known_false_positive(prog, host, mod, signal) or brain.is_known_false_positive(prog, host, mod, target):
        x['brain_status'] = 'known_false_positive'
        x['priority_score'] = 0
        suppressed.append(x)
        brain.remember_observation(prog, host, mod, signal, status='known_false_positive', score=0)
        continue

    fam = brain.classify_family(' '.join([mod, x.get('title', ''), target]), module=mod)
    if fam:
        x['brain_family'] = fam.get('id')
        x['brain_cwe'] = fam.get('cwe', [])
        x['brain_expected_impact'] = fam.get('impact', [])
        x['brain_false_positive_hints'] = fam.get('common_false_positives', [])

    # Recompute score after Brain enrichment and observed reproducibility/impact.
    x['priority_score'] = score_finding(x)
    if x.get('reproducible') and int(x.get('priority_score', 0)) >= 35 and x.get('confidence') != 'info':
        x['brain_status'] = 'reproducible_candidate'
    else:
        x['brain_status'] = 'new_signal'

    brain.remember_observation(prog, host, mod, signal, status=x['brain_status'], score=x['priority_score'])
    filtered.append(x)

items = filtered
items.sort(key=lambda x: (-int(x.get('priority_score', 0)), x.get('program', ''), x.get('module', ''), x.get('target', '')))

# Per-action report: one record for every module execution, even when it found nothing.
action_rows = []
for a in actions:
    row = {
        'program': a.get('program', 'unknown'),
        'target': a.get('target', ''),
        'module': a.get('module', 'unknown'),
        'requests_used': int(a.get('requests_used', 0) or 0),
        'findings_added': int(a.get('findings_added', 0) or 0),
        'blocked_urls': int(a.get('blocked_urls', 0) or 0),
        'error': a.get('error'),
        'duration_ms': a.get('duration_ms'),
    }
    action_rows.append(row)

action_rows.sort(key=lambda x: (x['program'], x['target'], x['module']))
searched_modules = sorted({a['module'] for a in action_rows})
programs_scanned = sorted({a['program'] for a in action_rows})
targets_scanned = sorted({a['target'] for a in action_rows})
module_findings = Counter(x.get('module', 'unknown') for x in items)
confidence_counts = Counter(x.get('confidence', 'candidate') for x in items)

reportable = [x for x in items if x.get('confidence') == 'validated' and x.get('impact_evidence')]
high_value_candidates = [x for x in items if x.get('confidence') != 'info' and int(x.get('priority_score', 0)) >= 45]
validation_needed = [x for x in items if x.get('confidence') != 'info' and x not in reportable]
action_errors = [a for a in action_rows if a.get('error')]
scope_blocks = sum(a.get('blocked_urls', 0) for a in action_rows)

if reportable:
    recommendation = 'continue_and_prepare_report'
    recommendation_reason = 'At least one validated finding has impact evidence.'
elif high_value_candidates:
    recommendation = 'continue_targeted_validation'
    recommendation_reason = 'There are high-priority candidates worth validating before rotating targets.'
elif validation_needed:
    recommendation = 'finish_candidate_validation_then_consider_rotation'
    recommendation_reason = 'Only lower-priority candidates remain; validate them efficiently, then rotate if they fail.'
else:
    recommendation = 'consider_rotating_to_another_authorized_asset'
    recommendation_reason = 'The campaign produced only informational signals or known false positives.'

summary = {
    'titan_version': TITAN_VERSION,
    'total': len(items),
    'suppressed_false_positives': len(suppressed),
    'by_program': {},
    'by_module': dict(module_findings),
    'by_confidence': dict(confidence_counts),
    'findings': items,
    'suppressed': suppressed,
    'brain_stats': brain.stats(),
    'campaign': {
        'programs_scanned': programs_scanned,
        'targets_scanned': targets_scanned,
        'bugs_searched_modules': searched_modules,
        'actions_executed': len(action_rows),
        'requests_used': sum(a['requests_used'] for a in action_rows),
        'scope_blocks': scope_blocks,
        'action_errors': len(action_errors),
        'reportable_confirmed': len(reportable),
        'candidates_needing_validation': len(validation_needed),
        'recommendation': recommendation,
        'recommendation_reason': recommendation_reason,
        'missing_or_remaining': {
            'action_errors': action_errors,
            'candidate_validations': [
                {'program': x.get('program'), 'module': x.get('module'), 'target': x.get('target'), 'title': x.get('title'), 'priority_score': x.get('priority_score')}
                for x in validation_needed
            ],
        },
    },
    'actions': action_rows,
}

for x in items:
    prog = x.get('program', 'unknown'); mod = x.get('module', 'unknown')
    host = urllib.parse.urlsplit(x.get('target', '')).hostname or 'unknown'
    ps = summary['by_program'].setdefault(prog, {'total': 0, 'by_host': {}, 'by_module': {}})
    ps['total'] += 1
    ps['by_host'][host] = ps['by_host'].get(host, 0) + 1
    ps['by_module'][mod] = ps['by_module'].get(mod, 0) + 1

brain.save()
os.makedirs('results', exist_ok=True)
open('results/combined.json', 'w', encoding='utf-8').write(json.dumps(summary, indent=2, ensure_ascii=False))
open('results/action-report.json', 'w', encoding='utf-8').write(json.dumps({'titan_version': TITAN_VERSION, 'actions': action_rows}, indent=2, ensure_ascii=False))

with open('results/action-report.txt', 'w', encoding='utf-8') as f:
    f.write(f'TITAN {TITAN_VERSION} - ACTION REPORT\n')
    for i, a in enumerate(action_rows, 1):
        status = 'ERROR' if a.get('error') else 'OK'
        f.write(f"ACTION {i:03d} | {status} | {a['program']} | {a['module']} | {a['target']} | requests={a['requests_used']} | findings={a['findings_added']} | scope_blocks={a['blocked_urls']}\n")
        if a.get('error'):
            f.write(f"  error={a['error']}\n")

print(f'=== TITAN {TITAN_VERSION} AGGREGATOR ===')
print('Unique new signals:', len(items))
print('Suppressed known false positives:', len(suppressed))
print('Actions executed:', len(action_rows))
print('Requests used:', summary['campaign']['requests_used'])
print('ScopeGuard blocks:', scope_blocks)
print('Brain Code VSystem:', json.dumps(summary['brain_stats'], ensure_ascii=False))
for prog, data in summary['by_program'].items():
    print(f"PROGRAM {prog}: {data['total']} new signals across {len(data['by_host'])} hosts")
print('Reportable confirmed:', len(reportable))
print('Candidates needing validation:', len(validation_needed))
print('Recommendation:', recommendation)
print('Reason:', recommendation_reason)
for x in items:
    if x.get('confidence') != 'info':
        fam = x.get('brain_family', x.get('family_hint', 'unclassified'))
        print(f"[{x.get('confidence')}] score={x.get('priority_score')} | {x.get('program')} | {x.get('module')} | {fam} | {x.get('title')} | {x.get('target')}")
