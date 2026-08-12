import glob,json,os,urllib.parse
items=[]
for p in glob.glob('results/*.json'):
    try:
        d=json.load(open(p,encoding='utf-8'))
        items.extend(d.get('findings',[]))
    except: pass

# Deduplicate repeated signals from different runners.
seen=set(); dedup=[]
for x in items:
    key=(x.get('program'),x.get('module'),x.get('target'),x.get('title'))
    if key in seen: continue
    seen.add(key); dedup.append(x)
items=dedup

rank={'validated':4,'candidate':3,'info':1}
items.sort(key=lambda x:(-rank.get(x.get('confidence','candidate'),0),x.get('program',''),x.get('module',''),x.get('target','')))
summary={'total':len(items),'by_program':{},'by_module':{},'findings':items}
for x in items:
    prog=x.get('program','unknown'); mod=x.get('module','unknown')
    host=urllib.parse.urlsplit(x.get('target','')).hostname or 'unknown'
    ps=summary['by_program'].setdefault(prog,{'total':0,'by_host':{},'by_module':{}})
    ps['total']+=1; ps['by_host'][host]=ps['by_host'].get(host,0)+1; ps['by_module'][mod]=ps['by_module'].get(mod,0)+1
    summary['by_module'][mod]=summary['by_module'].get(mod,0)+1
os.makedirs('results',exist_ok=True)
open('results/combined.json','w',encoding='utf-8').write(json.dumps(summary,indent=2,ensure_ascii=False))
print('=== BUGBOUNTY AI MULTI-PROGRAM AGGREGATOR ===')
print('Unique signals:',len(items))
for prog,data in summary['by_program'].items():
    print(f"PROGRAM {prog}: {data['total']} signals across {len(data['by_host'])} hosts")
for x in items:
    if x.get('confidence')!='info':
        print(f"[{x.get('confidence')}] {x.get('program')} | {x.get('module')} | {x.get('title')} | {x.get('target')}")
