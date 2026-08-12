import json, re, requests, urllib.parse, hashlib, sys, os, time
UA='BugBounty-AI-TITAN/1.0 validation-low-impact'
TIMEOUT=12

def get(url, **kwargs):
    h=kwargs.pop('headers',{})
    h.setdefault('User-Agent',UA)
    return requests.get(url,headers=h,timeout=TIMEOUT,allow_redirects=False,**kwargs)

def summarize(r):
    ctype=r.headers.get('content-type','')
    text=r.text[:4000]
    return {'status':r.status_code,'bytes':len(r.content),'content_type':ctype,'location':r.headers.get('location',''),'hash':hashlib.sha256(r.content).hexdigest()[:16],'prefix':text[:500]}

out={'auth_boundary':[],'xss_reflection':[]}
base='https://api-polygon-tokens.polygon.technology'
paths=['/account','/admin','/api/account','/api/me','/api/user','/settings']
controls=['/','/__titan_nonexistent_8f3c1a']
control_data={}
for p in controls:
    try:
        r=get(base+p); control_data[p]=summarize(r)
    except Exception as e:
        control_data[p]={'error':str(e)}
    time.sleep(.8)

sensitive_terms=re.compile(r'("?(email|user(_?id)?|account(_?id)?|merchant(_?id)?|token|secret|wallet|role|permissions?)"?\s*[:=])',re.I)
for p in paths:
    rec={'url':base+p}
    try:
        r=get(base+p); s=summarize(r); rec['response']=s
        body=r.text[:10000]
        rec['sensitive_markers']=sorted(set(m.group(2).lower() for m in sensitive_terms.finditer(body)))[:20]
        rec['same_as_root_hash']=s.get('hash')==control_data.get('/',{}).get('hash')
        rec['same_as_404_hash']=s.get('hash')==control_data.get('/__titan_nonexistent_8f3c1a',{}).get('hash')
        ctype=s.get('content_type','').lower()
        rec['looks_structured']=('json' in ctype) or body.lstrip().startswith(('{','['))
        rec['candidate_survives']=bool(r.status_code==200 and rec['looks_structured'] and rec['sensitive_markers'] and not rec['same_as_404_hash'])
    except Exception as e:
        rec['error']=str(e); rec['candidate_survives']=False
    out['auth_boundary'].append(rec)
    time.sleep(.8)

# Reflection validation: harmless unique markers only, no script execution payloads.
faucet='https://faucet.polygon.technology/'
markers=['titan_reflect_A7f91','titan_lt_%3C_A7f91','titan_quote_%22_A7f91']
for raw in markers:
    marker=urllib.parse.unquote(raw)
    u=faucet+'?q='+raw
    rec={'url':u,'marker':marker}
    try:
        r=get(u); body=r.text
        rec['status']=r.status_code; rec['bytes']=len(r.content)
        idx=body.find(marker)
        rec['reflected']=idx!=-1
        rec['context']=body[max(0,idx-180):idx+len(marker)+180] if idx!=-1 else ''
        rec['html_escaped_lt']=('&lt;' in rec['context']) if '<' in marker else None
        rec['html_escaped_quote']=('&quot;' in rec['context'] or '&#34;' in rec['context']) if '"' in marker else None
    except Exception as e:
        rec['error']=str(e)
    out['xss_reflection'].append(rec)
    time.sleep(.8)

os.makedirs('validation-results',exist_ok=True)
with open('validation-results/polygon-validation.json','w',encoding='utf-8') as f:
    json.dump({'controls':control_data,'results':out},f,indent=2,ensure_ascii=False)
print(json.dumps({'auth_survivors':[x['url'] for x in out['auth_boundary'] if x.get('candidate_survives')], 'xss_reflections':[x['url'] for x in out['xss_reflection'] if x.get('reflected')]},ensure_ascii=False))