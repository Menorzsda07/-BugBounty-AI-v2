import json,re,requests,urllib.parse,hashlib,os,time
UA='BugBounty-AI-TITAN/1.2 validation-low-impact'
TIMEOUT=12

def get(url):
    return requests.get(url,headers={'User-Agent':UA},timeout=TIMEOUT,allow_redirects=False)

def s(r):
    return {'status':r.status_code,'bytes':len(r.content),'content_type':r.headers.get('content-type',''),'hash':hashlib.sha256(r.content).hexdigest()[:16],'location':r.headers.get('location','')}

out={'sensitive_path_validation':[],'sqli_validation':[]}
# Validate whether sensitive-path candidates are actual file disclosure or generic SPA/fallback responses.
targets=[
 ('klarna','https://portal.playground.klarna.com',['/.git/HEAD','/server-status']),
 ('klarna','https://app.klarna.com',['/.git/HEAD','/server-status']),
 ('polygon','https://portal.polygon.technology',['/server-status']),
 ('polygon','https://staking.polygon.technology',['/server-status']),
 ('polygon','https://api-polygon-tokens.polygon.technology',['/server-status'])
]
for program,base,paths in targets:
    try:
        root=get(base+'/'); root_sum=s(root); root_prefix=root.text[:180]
    except Exception as e:
        root=None; root_sum={'error':str(e)}; root_prefix=''
    for path in paths:
        rec={'program':program,'base':base,'path':path,'root':root_sum}
        try:
            r=get(base+path); rec['candidate']=s(r); body=r.text[:500]
            rec['same_hash_as_root']=bool(root and rec['candidate']['hash']==root_sum.get('hash'))
            rec['same_size_as_root']=bool(root and rec['candidate']['bytes']==root_sum.get('bytes'))
            rec['git_head_signature']=bool(path=='/.git/HEAD' and re.search(r'^ref:\s+refs/',r.text,re.M))
            rec['server_status_signature']=bool(path=='/server-status' and ('Apache Server Status' in r.text or 'Server Version:' in r.text))
            rec['looks_html_fallback']='text/html' in rec['candidate'].get('content_type','').lower() and (rec['same_hash_as_root'] or rec['same_size_as_root'])
            rec['classification']='potential_exposure' if (rec['git_head_signature'] or rec['server_status_signature']) else ('fallback_false_positive' if rec['looks_html_fallback'] else 'needs_review')
            rec['prefix']=body[:180]
        except Exception as e:
            rec['error']=str(e); rec['classification']='request_error'
        out['sensitive_path_validation'].append(rec); time.sleep(.5)

# Re-check the single SQL differential candidate without extracting data or changing server state.
base='https://faucet.polygon.technology/'
try:
    normal=get(base+'?id=1'); mutated=get(base+'?id=1%27')
    er=re.compile(r'sql|syntax error|unterminated|mysql|postgres|sqlite|ora-\d+',re.I)
    nr=bool(er.search(normal.text)); mr=bool(er.search(mutated.text))
    rec={'program':'polygon','target':base,'normal':s(normal),'mutated':s(mutated),'normal_sql_error_marker':nr,'mutated_sql_error_marker':mr}
    rec['classification']='sql_error_differential' if mr and not nr else 'not_confirmed_sqli'
    out['sqli_validation'].append(rec)
except Exception as e:
    out['sqli_validation'].append({'program':'polygon','target':base,'error':str(e),'classification':'request_error'})

summary={
 'sensitive_exposures':[x for x in out['sensitive_path_validation'] if x.get('classification')=='potential_exposure'],
 'sensitive_false_positives':[x for x in out['sensitive_path_validation'] if x.get('classification')=='fallback_false_positive'],
 'sensitive_needs_review':[x for x in out['sensitive_path_validation'] if x.get('classification')=='needs_review'],
 'sqli':[x.get('classification') for x in out['sqli_validation']]
}
os.makedirs('validation-results',exist_ok=True)
with open('validation-results/titan-12runner-candidate-validation.json','w',encoding='utf-8') as f: json.dump({'summary':summary,'results':out},f,indent=2,ensure_ascii=False)
print(json.dumps({'sensitive_exposures':len(summary['sensitive_exposures']),'sensitive_false_positives':len(summary['sensitive_false_positives']),'sensitive_needs_review':len(summary['sensitive_needs_review']),'sqli':summary['sqli']},ensure_ascii=False))