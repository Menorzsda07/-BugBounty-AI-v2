import json, re, requests, urllib.parse, hashlib, os, time
UA='BugBounty-AI-TITAN/1.1 validation-low-impact'
TIMEOUT=12

def get(url):
    return requests.get(url,headers={'User-Agent':UA},timeout=TIMEOUT,allow_redirects=False)

def summarize(r):
    return {'status':r.status_code,'bytes':len(r.content),'content_type':r.headers.get('content-type',''),'hash':hashlib.sha256(r.content).hexdigest()[:16]}

out={'xss_context_validation':[]}
faucet='https://faucet.polygon.technology/'
# Non-executing probes only: determine whether HTML metacharacters survive and where reflection lands.
probes=[
 ('plain','TITANCTX_A91'),
 ('angle','TITANCTX_A91<probe>'),
 ('double_quote','TITANCTX_A91"probe'),
 ('single_quote',"TITANCTX_A91'probe"),
 ('amp','TITANCTX_A91&probe')
]
for kind, marker in probes:
    u=faucet+'?q='+urllib.parse.quote(marker,safe='')
    rec={'kind':kind,'url':u,'marker':marker}
    try:
        r=get(u); body=r.text
        rec.update(summarize(r))
        needle='TITANCTX_A91'
        idx=body.find(needle)
        rec['base_reflected']=idx!=-1
        ctx=body[max(0,idx-250):idx+500] if idx!=-1 else ''
        rec['context']=ctx
        rec['raw_marker_present']=marker in body
        rec['escaped_angle']=('&lt;probe&gt;' in body or '\\u003cprobe\\u003e' in body.lower()) if kind=='angle' else None
        rec['escaped_double_quote']=('&quot;probe' in body or '&#34;probe' in body or '\\u0022probe' in body.lower()) if kind=='double_quote' else None
        rec['escaped_single_quote']=('&#39;probe' in body or '&#x27;probe' in body.lower() or '\\u0027probe' in body.lower()) if kind=='single_quote' else None
        low=ctx.lower()
        rec['context_hint']='html_text'
        if '<script' in low: rec['context_hint']='script_block'
        elif re.search(r'\w+\s*=\s*["\'][^"\']*titanctx_a91',low): rec['context_hint']='html_attribute'
        elif 'application/json' in low or '__next_data__' in low: rec['context_hint']='serialized_data'
    except Exception as e:
        rec['error']=str(e)
    out['xss_context_validation'].append(rec)
    time.sleep(.8)

# Classification deliberately requires raw metacharacter survival in a potentially executable context.
risky=[]
for x in out['xss_context_validation']:
    if x.get('raw_marker_present') and x.get('context_hint') in ('script_block','html_attribute') and x['kind'] in ('angle','double_quote','single_quote'):
        risky.append(x['kind'])
classification='needs_manual_browser_validation' if risky else 'reflection_only_not_confirmed_xss'
result={'classification':classification,'risky_probes':risky,'results':out}
os.makedirs('validation-results',exist_ok=True)
with open('validation-results/polygon-xss-context.json','w',encoding='utf-8') as f: json.dump(result,f,indent=2,ensure_ascii=False)
print(json.dumps({'classification':classification,'risky_probes':risky},ensure_ascii=False))