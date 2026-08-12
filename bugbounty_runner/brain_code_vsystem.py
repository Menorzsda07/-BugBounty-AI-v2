import json, hashlib, time
from pathlib import Path

DEFAULT_PATH = Path('bugbounty_runner/memory/brain-code-vsystem.json')
KNOWLEDGE_PATH = Path('bugbounty_runner/memory/vulnerability-knowledge.json')

class BrainCodeVSystem:
    def __init__(self, path=DEFAULT_PATH, knowledge_path=KNOWLEDGE_PATH):
        self.path = Path(path)
        self.knowledge_path = Path(knowledge_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._migrate(self._load())
        self.knowledge = self._load_knowledge()

    def _fresh(self):
        return {
            'name': 'Brain Code VSystem',
            'version': 2,
            'created_at': int(time.time()),
            'programs': {},
            'global_false_positives': [],
            'confirmed_vulnerabilities': [],
            'novel_anomalies': [],
            'history': []
        }

    def _load(self):
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding='utf-8'))
            except Exception:
                pass
        return self._fresh()

    def _migrate(self, data):
        if not isinstance(data, dict):
            data = self._fresh()
        data.setdefault('name', 'Brain Code VSystem')
        data['version'] = max(int(data.get('version', 1)), 2)
        data.setdefault('created_at', int(time.time()))
        data.setdefault('programs', {})
        data.setdefault('global_false_positives', [])
        data.setdefault('confirmed_vulnerabilities', [])
        data.setdefault('novel_anomalies', [])
        data.setdefault('history', [])
        for _, p in data['programs'].items():
            if not isinstance(p, dict):
                continue
            p.setdefault('hosts', {})
            p.setdefault('false_positives', [])
            p.setdefault('validated_candidates', [])
            p.setdefault('confirmed_vulnerabilities', [])
            p.setdefault('novel_anomalies', [])
        return data

    def _load_knowledge(self):
        if self.knowledge_path.exists():
            try:
                return json.loads(self.knowledge_path.read_text(encoding='utf-8'))
            except Exception:
                pass
        return {'families': [], 'novel_discovery_principles': []}

    def save(self):
        self.data = self._migrate(self.data)
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding='utf-8')

    @staticmethod
    def fingerprint(program, host, bug_class, signal):
        raw = f'{program}|{host}|{bug_class}|{signal}'.lower().strip()
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def ensure_program(self, program):
        p = self.data.setdefault('programs', {}).setdefault(program, {})
        p.setdefault('hosts', {})
        p.setdefault('false_positives', [])
        p.setdefault('validated_candidates', [])
        p.setdefault('confirmed_vulnerabilities', [])
        p.setdefault('novel_anomalies', [])
        return p

    def remember_false_positive(self, program, host, bug_class, signal, reason='validated false positive'):
        fp = self.fingerprint(program, host, bug_class, signal)
        rec = {'fingerprint': fp, 'program': program, 'host': host, 'bug_class': bug_class, 'signal': signal, 'reason': reason, 'ts': int(time.time())}
        p = self.ensure_program(program)
        if not any(x.get('fingerprint') == fp for x in p['false_positives']): p['false_positives'].append(rec)
        if not any(x.get('fingerprint') == fp for x in self.data.setdefault('global_false_positives', [])): self.data['global_false_positives'].append(rec)
        self.data.setdefault('history', []).append({'event':'false_positive','fingerprint':fp,'ts':rec['ts']})
        self.save(); return fp

    def remember_candidate(self, program, host, bug_class, signal, status='validated_candidate'):
        fp = self.fingerprint(program, host, bug_class, signal)
        rec = {'fingerprint': fp, 'program': program, 'host': host, 'bug_class': bug_class, 'signal': signal, 'status': status, 'ts': int(time.time())}
        p = self.ensure_program(program)
        if not any(x.get('fingerprint') == fp for x in p['validated_candidates']): p['validated_candidates'].append(rec)
        self.data.setdefault('history', []).append({'event':'candidate','fingerprint':fp,'ts':rec['ts']})
        self.save(); return fp

    def remember_novel_anomaly(self, program, host, bug_class, signal, evidence=None, reproducible=False):
        fp = self.fingerprint(program, host, bug_class, signal)
        rec = {'fingerprint': fp, 'program': program, 'host': host, 'bug_class': bug_class, 'signal': signal, 'evidence': evidence, 'reproducible': bool(reproducible), 'status': 'novel_candidate', 'ts': int(time.time())}
        p = self.ensure_program(program)
        if not any(x.get('fingerprint') == fp for x in p['novel_anomalies']): p['novel_anomalies'].append(rec)
        if not any(x.get('fingerprint') == fp for x in self.data.setdefault('novel_anomalies', [])): self.data['novel_anomalies'].append(rec)
        self.data.setdefault('history', []).append({'event':'novel_anomaly','fingerprint':fp,'ts':rec['ts']})
        self.save(); return fp

    def remember_vulnerability(self, program, host, bug_class, signal, severity=None, report=None):
        fp = self.fingerprint(program, host, bug_class, signal)
        rec = {'fingerprint': fp, 'program': program, 'host': host, 'bug_class': bug_class, 'signal': signal, 'severity': severity, 'report': report, 'ts': int(time.time())}
        p = self.ensure_program(program)
        if not any(x.get('fingerprint') == fp for x in p['confirmed_vulnerabilities']): p['confirmed_vulnerabilities'].append(rec)
        if not any(x.get('fingerprint') == fp for x in self.data.setdefault('confirmed_vulnerabilities', [])): self.data['confirmed_vulnerabilities'].append(rec)
        self.data.setdefault('history', []).append({'event':'confirmed_vulnerability','fingerprint':fp,'ts':rec['ts']})
        self.save(); return fp

    def is_known_false_positive(self, program, host, bug_class, signal):
        fp = self.fingerprint(program, host, bug_class, signal)
        if any(x.get('fingerprint') == fp for x in self.data.get('global_false_positives', [])):
            return True
        # Also suppress seeded/grouped false positives by same program+host+class when the seed reason says validated.
        for x in self.data.get('global_false_positives', []):
            if x.get('program') == program and x.get('host') == host and x.get('bug_class') == bug_class and 'validated' in str(x.get('reason','')).lower():
                return True
        return False

    def classify_family(self, text):
        low=(text or '').lower(); scored=[]
        for fam in self.knowledge.get('families', []):
            score=0
            for s in fam.get('signals', []):
                toks=[t for t in s.lower().replace('-', ' ').split() if len(t)>4]
                score += sum(1 for t in toks if t in low)
            if fam.get('id','').lower() in low: score += 3
            if score: scored.append((score,fam))
        scored.sort(key=lambda x:-x[0]); return scored[0][1] if scored else None

    def stats(self):
        return {'programs':len(self.data.get('programs',{})),'false_positives':len(self.data.get('global_false_positives',[])),'confirmed_vulnerabilities':len(self.data.get('confirmed_vulnerabilities',[])),'novel_anomalies':len(self.data.get('novel_anomalies',[])),'knowledge_families':len(self.knowledge.get('families',[])),'history_events':len(self.data.get('history',[]))}

if __name__ == '__main__':
    brain=BrainCodeVSystem(); brain.save(); print(json.dumps(brain.stats(),ensure_ascii=False))
