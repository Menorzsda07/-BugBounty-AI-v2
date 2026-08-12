import json, tempfile, unittest
from pathlib import Path

from titan_v_pro_core import ScopeGuard, materially_equivalent, normalize_text, validate_config
from brain_code_vsystem import BrainCodeVSystem


class FakeResponse:
    def __init__(self, text, status=404, headers=None):
        self.text = text
        self.content = text.encode()
        self.status_code = status
        self.headers = headers or {'content-type': 'text/html; charset=utf-8'}


class TitanVProCoreTests(unittest.TestCase):
    def test_scope_guard_blocks_third_party_and_excluded(self):
        p = {
            'name': 'demo',
            'targets': ['https://app.example.com/api/'],
            'excluded_hosts': ['blocked.example.com']
        }
        g = ScopeGuard(p)
        self.assertTrue(g.check('https://app.example.com/api/v1')[0])
        self.assertFalse(g.check('https://app.example.com/admin')[0])
        self.assertFalse(g.check('https://cdn.example.net/a.js')[0])
        self.assertFalse(g.check('https://blocked.example.com/')[0])

    def test_root_target_allows_same_host_paths(self):
        g = ScopeGuard({'name': 'demo', 'targets': ['https://app.example.com']})
        self.assertTrue(g.check('https://app.example.com/api/v1?q=A')[0])
        self.assertFalse(g.check('http://app.example.com/api/v1')[0])

    def test_dynamic_telemetry_normalization(self):
        a = 'x applicationTime: 6 queueTime=2 2026-08-12T20:10:11Z'
        b = 'x applicationTime: 9 queueTime=8 2026-08-12T20:10:59Z'
        self.assertEqual(normalize_text(a), normalize_text(b))

    def test_semantic_equivalence_ignores_dynamic_application_time(self):
        a = FakeResponse('<html><body><script>applicationTime: 6</script><div>Not Found</div></body></html>')
        b = FakeResponse('<html><body><script>applicationTime: 9</script><div>Not Found</div></body></html>')
        eq, evidence = materially_equivalent(a, b)
        self.assertTrue(eq)
        self.assertGreaterEqual(evidence['semantic_similarity'], 0.999)

    def test_config_safety_caps(self):
        cfg = {
            'programs': [{'name': 'x', 'targets': ['https://x.example/']}],
            'max_requests_per_target_per_runner': 61,
            'delay_ms': 100,
            'aggressive_modules': ['danger']
        }
        errors = validate_config(cfg)
        self.assertTrue(any('safety cap' in x for x in errors))
        self.assertTrue(any('safety floor' in x for x in errors))
        self.assertTrue(any('aggressive_modules' in x for x in errors))

    def test_brain_exact_false_positive_does_not_hide_same_class_other_signal(self):
        with tempfile.TemporaryDirectory() as td:
            mem = Path(td) / 'memory.json'
            know = Path(td) / 'knowledge.json'
            know.write_text(json.dumps({'families': [], 'module_family_map': {}}))
            brain = BrainCodeVSystem(mem, know)
            signal = 'A | https://app.example/api/'
            brain.remember_false_positive('p', 'app.example', 'encoding_diff', signal, scope='exact')
            self.assertTrue(brain.is_known_false_positive('p', 'app.example', 'encoding_diff', signal))
            self.assertFalse(brain.is_known_false_positive('p', 'app.example', 'encoding_diff', 'B | https://app.example/other'))

    def test_legacy_seed_migrates_to_group_scope(self):
        with tempfile.TemporaryDirectory() as td:
            mem = Path(td) / 'memory.json'
            know = Path(td) / 'knowledge.json'
            know.write_text(json.dumps({'families': [], 'module_family_map': {}}))
            mem.write_text(json.dumps({
                'version': 2,
                'programs': {},
                'global_false_positives': [{
                    'fingerprint': 'seed-one', 'program': 'p', 'host': 'h.example',
                    'bug_class': 'sensitive_files', 'signal': 'old', 'reason': 'validated old group'
                }]
            }))
            brain = BrainCodeVSystem(mem, know)
            self.assertTrue(brain.is_known_false_positive('p', 'h.example', 'sensitive_files', 'anything'))


if __name__ == '__main__':
    unittest.main()
