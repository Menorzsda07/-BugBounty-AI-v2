"""TITAN V PRO single-module compatibility runner.

This replaces the legacy runner so manual module execution uses the same
ScopeGuard, request budget, evidence policy and detector implementations as
the 12-runner engine.
"""
import argparse, json, os

from titan_v_pro_core import ActionTrace, RequestBudget, ScopeGuard, TITAN_VERSION, validate_config
from multi_scan import FUNCS, ScopedClient


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', required=True)
    ap.add_argument('--module', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    cfg = json.load(open(args.config, encoding='utf-8'))
    errors = validate_config(cfg)
    if errors:
        raise SystemExit('invalid TITAN V PRO config: ' + '; '.join(errors))
    if args.module not in FUNCS:
        raise SystemExit(f'unknown module: {args.module}')
    if args.module not in cfg.get('enabled_modules', []):
        raise SystemExit(f'module {args.module} not enabled by config')

    findings, actions = [], []
    max_req = int(cfg.get('max_requests_per_target_per_runner', 30))
    delay_ms = int(cfg.get('delay_ms', 1000))

    for prog in cfg.get('programs', []):
        name = prog.get('name', 'unknown')
        guard = ScopeGuard(prog)
        for base in prog.get('targets', []):
            if not guard.check(base)[0]:
                continue
            budget = RequestBudget(max_req, delay_ms)
            client = ScopedClient(guard, budget)
            trace = ActionTrace(name, base, args.module, requests_before=budget.used, findings_before=len(findings), blocked_urls=budget.blocked)
            try:
                FUNCS[args.module](name, base, findings, client)
            except Exception as e:
                trace.error = type(e).__name__ + ':' + str(e)[:160]
            trace.blocked_urls = max(0, budget.blocked - trace.blocked_urls)
            actions.append(trace.finish(budget, findings))

    payload = {
        'titan_version': TITAN_VERSION,
        'mode': 'single-module-compatibility',
        'module': args.module,
        'findings': findings,
        'actions': actions,
        'stats': {
            'findings': len(findings),
            'actions': len(actions),
            'requests_used': sum(x.get('requests_used', 0) for x in actions),
            'scope_blocks': sum(x.get('blocked_urls', 0) for x in actions),
            'action_errors': sum(1 for x in actions if x.get('error')),
        },
    }
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(json.dumps({'titan_version': TITAN_VERSION, 'module': args.module, 'findings': len(findings), 'actions': len(actions)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
