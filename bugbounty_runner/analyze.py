import glob,json,os
items=[]
for p in glob.glob('results/*.json'):
    try:
        d=json.load(open(p,encoding='utf-8'))
        items.extend(d.get('findings',[]))
    except: pass
rank={'validated':3,'candidate':2,'info':1}
items.sort(key=lambda x:(-rank.get(x.get('confidence','candidate'),0),x.get('module',''),x.get('target','')))
summary={'total':len(items),'by_module':{},'findings':items}
for x in items:
    summary['by_module'][x['module']]=summary['by_module'].get(x['module'],0)+1
open('results/combined.json','w',encoding='utf-8').write(json.dumps(summary,indent=2,ensure_ascii=False))
print('=== BUGBOUNTY AI AGGREGATOR ===')
print('Candidates:',len(items))
for x in items:
    print(f"[{x.get('confidence')}] {x.get('module')} | {x.get('title')} | {x.get('target')}")
