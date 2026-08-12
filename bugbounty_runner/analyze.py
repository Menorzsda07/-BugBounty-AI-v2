import glob,json,os,urllib.parse
from brain_code_vsystem import BrainCodeVSystem

brain=BrainCodeVSystem()
items=[]
for p in glob.glob('results/*.json'):
    try:
        d=json.load(open(p,encoding='utf-8'))
        items.extend(d.get('findings',[]))
    except Exception:
        pass

# Deduplicate repeated signals from different runners.
seen=set(); dedup=[]
for x in items:
    key=(x.get('program'),x.get('module'),x.get('target'),x.get('title'))
    if key in seen:
        continue
    seen.add(key); dedup.append(x)
items=dedup

# Brain Code VSystem: suppress already validated false positives and enrich new findings.
filtered=[]; suppressed=[]
for x in items:
    prog=x.get('program','unknown')
    mod=x.get('module','unknown')
    target=x.get('target','')
    host=urllib.parse.urlsplit(target).hostname or 'unknown'
    signal=' | '.join([x.get('title',''), target])
    if brain.is_known_false_positive(prog,host,mod,signal) or brain.is_known_false_positive(prog,host,mod,target):
        x['brain_status']='known_false_positive'
        suppressed.append(x)
        continue
    fam=brain.classify_family(' '.join([mod,x.get('title',''),target]))
    if fam:
        x['brain_family']=fam.get('id')
        x['brain_cwe']=fam.get('cwe',[])
        x['brain_expected_impact']=fam.get('impact',[])
        x['brain_false_positive_hints']=fam.get('common_false_positives',[])
    # Findings explicitly marked anomaly/novel/differential are remembered even without a known signature.
    blob=' '.join([mod,x.get('title',''),x.get('description',''),str(x.get('evidence',''))]).lower()
    if any(k in blob for k in ('anomaly','differential','inconsistent','unexpected','state mismatch','novel')):
        x['brain_status']='novel_candidate'
        brain.remember_novel_anomaly(prog,host,mod,signal,evidence=x.get('evidence'),reproducible=x.get('reproducible',False))
    else:
        x['brain_status']='new_signal'
    filtered.append(x)
items=filtered

rank={'validated':4,'candidate':3,'info':1}
items.sort(key=lambda x:(-rank.get(x.get('confidence','candidate'),0),x.get('program',''),x.get('module',''),x.get('target','')))
summary={'total':len(items),'suppressed_false_positives':len(suppressed),'by_program':{},'by_module':{},'findings':items,'brain_stats':brain.stats()}
for x in items:
    prog=x.get('program','unknown'); mod=x.get('module','unknown')
    host=urllib.parse.urlsplit(x.get('target','')).hostname or 'unknown'
    ps=summary['by_program'].setdefault(prog,{'total':0,'by_host':{},'by_module':{}})
    ps['total']+=1; ps['by_host'][host]=ps['by_host'].get(host,0)+1; ps['by_module'][mod]=ps['by_module'].get(mod,0)+1
    summary['by_module'][mod]=summary['by_module'].get(mod,0)+1
os.makedirs('results',exist_ok=True)
open('results/combined.json','w',encoding='utf-8').write(json.dumps(summary,indent=2,ensure_ascii=False))
print('=== BUGBOUNTY AI MULTI-PROGRAM AGGREGATOR ===')
print('Unique new signals:',len(items))
print('Suppressed known false positives:',len(suppressed))
print('Brain Code VSystem:',json.dumps(summary['brain_stats'],ensure_ascii=False))
for prog,data in summary['by_program'].items():
    print(f"PROGRAM {prog}: {data['total']} new signals across {len(data['by_host'])} hosts")
for x in items:
    if x.get('confidence')!='info':
        fam=x.get('brain_family','unclassified')
        print(f"[{x.get('confidence')}] {x.get('program')} | {x.get('module')} | {fam} | {x.get('title')} | {x.get('target')}")
