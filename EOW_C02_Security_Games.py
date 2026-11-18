#!/usr/bin/env python3
"""EOW-C02: executable security games for enrolled optical witnesses.

Finite-domain EXACT toy-model evaluation; NOT a general proof, PQ signature
implementation, physical optical verifier, or human study. Python >=3.10.
Standard library only. Does not modify C01 or fabricate empirical results.
"""
from __future__ import annotations
import argparse, csv, hashlib, itertools, json, math, random, sys, zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SCHEMES = ('EOW1_full_reference','EOW2_separable_tag','EOW3_masked_challenge')
VIEWS = ('one_share','public_witness','one_share_plus_public_witness','full_witness','one_share_plus_full_witness')
GAMES = ('IND_PRIV','MOD_INT','ISSUER_BIND','CUSTODY','ADAPTIVE_ORACLE','REPLAY','HUMAN_OPTICAL')

def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def write_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True,ensure_ascii=False)+'\n',encoding='utf-8')

def write_csv(path,rows,fields):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)

def encode(s,r): return (r,s^r)

def enroll(scheme,s,r,k1,k2):
    a,b=encode(s,r)
    if scheme==SCHEMES[0]:return (a,b)
    if scheme==SCHEMES[1]:return (s,)
    if scheme==SCHEMES[2]:return (a^k1,b^k2,k1,k2)
    raise ValueError(scheme)

def public(scheme,w):return w[:2] if scheme==SCHEMES[2] else w

def accept(scheme,a,b,w):
    if scheme==SCHEMES[0]:return (a,b)==w
    if scheme==SCHEMES[1]:return True # deliberately separable, retained tag
    if scheme==SCHEMES[2]:return (a^w[2]==w[0] and b^w[3]==w[1])
    raise ValueError(scheme)

def view(scheme,s,r,k1,k2,name):
    a,b=encode(s,r);w=enroll(scheme,s,r,k1,k2)
    return {'one_share':(a,), 'public_witness':public(scheme,w),
            'one_share_plus_public_witness':(a,)+public(scheme,w),
            'full_witness':w,'one_share_plus_full_witness':(a,)+w}[name]

def tv(x,y):
    nx=sum(x.values());ny=sum(y.values())
    return sum(abs(x.get(z,0)/nx-y.get(z,0)/ny) for z in x.keys()|y.keys())/2

def privacy(n):
    q=1<<n; rows=[]
    for scheme in SCHEMES:
        for v in VIEWS:
            ds=[]
            for s in range(q):
                counts=Counter(view(scheme,s,r,k1,k2,v) for r,k1,k2 in itertools.product(range(q),repeat=3))
                ds.append(counts)
            pairs=[(tv(ds[i],ds[j]),i,j) for i in range(q) for j in range(i+1,q)]
            value,s0,s1=max(pairs,default=(0.0,0,0))
            rows.append(dict(game='IND_PRIV',scheme=scheme,view=v,n_bits=n,max_tv=round(value,12),s0=s0,s1=s1,privacy_holds=(value<1e-12),enrollments_per_secret=q**3))
    return rows

def attacks(n):
    q=1<<n;rows=[];examples=[]
    # All enrolled states, all alternate share pairs. Exclude exact copies.
    for scheme in SCHEMES:
        for kind in ('any_changed_share','content_changing','share_only_change','exact_copy'):
            tested=success=0; example=None
            for s,r,k1,k2 in itertools.product(range(q),repeat=4):
                a,b=encode(s,r);w=enroll(scheme,s,r,k1,k2)
                submissions=itertools.product(range(q),repeat=2) if kind!='exact_copy' else ((a,b),)
                for aa,bb in submissions:
                    if kind=='any_changed_share' and (aa,bb)==(a,b):continue
                    if kind=='content_changing' and (aa^bb)==s:continue
                    if kind=='share_only_change' and ((aa,bb)==(a,b) or (aa^bb)!=s):continue
                    tested+=1
                    if accept(scheme,aa,bb,w):
                        success+=1
                        if example is None:example={'secret':s,'enrolled':[a,b],'submitted':[aa,bb],'enrolled_reconstruction':s,'submitted_reconstruction':aa^bb,'keys_private':True}
            rows.append(dict(game='MOD_INT' if kind!='exact_copy' else 'REPLAY',scheme=scheme,attack=kind,n_bits=n,accepted=success,attempts=tested,rate=round(success/tested,12) if tested else None,example_exists=example is not None))
            if example:examples.append({'scheme':scheme,'attack':kind,'witness':example})
    return rows,examples

def issuer_binding():
    # An intentionally modeled *unsigned* optical enrollment. This is a
    # logical capability attack, not an ML-DSA forgery test.
    return [dict(game='ISSUER_BIND',scheme=s,attack='adversary_controls_enrollment',result='TRIVIAL_REENROLLMENT_IF_NO_AUTHENTICATED_CHANNEL',electronic_signature_tested=False,optical_issuer_authentication='NOT_ESTABLISHED') for s in SCHEMES]

def adaptive(n,max_queries,seed):
    """Deterministic bounded oracle search, using uniform randomized submission order.

    The attacker knows one original share, public witness, and obtains yes/no
    responses. The target is a DIFFERENT reconstruction. A positive oracle
    response means success; exact-copy responses do not count.
    """
    q=1<<n; rng=random.Random(seed); rows=[]; traces=[]
    for scheme in SCHEMES:
        for budget in sorted(set([0,1,2,4,8,max_queries])):
            total=won=0;queries=0; first=None
            for s,r,k1,k2 in itertools.product(range(q),repeat=4):
                a,b=encode(s,r);w=enroll(scheme,s,r,k1,k2)
                # Adaptive oracle attack: fixed honest share a, modified partner b.
                # Excludes the honest reconstruction; this is a restricted adversary.
                candidates=[(a,bb) for bb in range(q) if (a^bb)!=s]
                rng.shuffle(candidates)
                total+=1
                for index,(aa,bb) in enumerate(candidates[:budget]):
                    queries+=1
                    if accept(scheme,aa,bb,w):
                        won+=1
                        if first is None:first={'secret':s,'enrolled':[a,b],'submitted':[aa,bb],'queries_to_success':index+1}
                        break
            rows.append(dict(game='ADAPTIVE_ORACLE',scheme=scheme,budget=budget,n_bits=n,winning_enrollments=won,total_enrollments=total,success_rate=round(won/total,12),total_queries=queries,attack_scope='fixed_first_share_modified_second_share'))
            if first:traces.append({'scheme':scheme,'budget':budget,'example':first})
    return rows,traces

def load_c01(path):
    if path is None:return {'status':'NOT_SUPPLIED'}
    path=Path(path)
    needed=('reports/summary.json','reports/model_assumptions.json','reports/privacy_exact.csv')
    if path.is_file() and path.suffix.lower()=='.zip':
        with zipfile.ZipFile(path) as z:
            names=z.namelist();matches={n:next((k for k in names if k.endswith('/'+n) or k==n),None) for n in needed}
            if any(v is None for v in matches.values()):raise ValueError('C01 archive missing required files')
            summ=json.loads(z.read(matches[needed[0]]));assum=json.loads(z.read(matches[needed[1]]))
    elif path.is_dir():
        root=path if (path/'reports/summary.json').exists() else path/'EOW_C01'
        if not all((root/n).exists() for n in needed):raise ValueError('C01 directory missing required files')
        summ=json.loads((root/needed[0]).read_text(encoding='utf-8'));assum=json.loads((root/needed[1]).read_text(encoding='utf-8'))
    else:raise FileNotFoundError(path)
    return {'status':'LOADED','source':str(path),'sha256':digest(path) if path.is_file() else None,'c01_summary':summ,'c01_assumptions':assum}

def self_tests():
    checks={}
    checks['xor_correctness']=all(encode(s,r)[0]^encode(s,r)[1]==s for s in range(4) for r in range(4))
    checks['eow1_exact']=all(accept(SCHEMES[0],*encode(s,r),enroll(SCHEMES[0],s,r,0,0)) for s in range(4) for r in range(4))
    checks['eow2_tag_transplant']=accept(SCHEMES[1],1,1,enroll(SCHEMES[1],1,0,0,0))
    checks['eow3_exact']=all(accept(SCHEMES[2],*encode(s,r),enroll(SCHEMES[2],s,r,k1,k2)) for s,r,k1,k2 in itertools.product(range(2),repeat=4))
    checks['eow3_reject_changed']=all(not accept(SCHEMES[2],a,b^1,enroll(SCHEMES[2],s,r,k1,k2)) for s,r,k1,k2 in itertools.product(range(2),repeat=4) for a,b in [encode(s,r)])
    checks['tv_identity']=tv(Counter({0:1,1:1}),Counter({0:1,1:1}))==0
    checks['tv_disjoint']=tv(Counter({0:1}),Counter({1:1}))==1
    checks['replay_accepts']=all(accept(s,*encode(0,0),enroll(s,0,0,0,0)) for s in SCHEMES)
    return {'checks':checks,'passed':sum(checks.values()),'total':len(checks),'all_passed':all(checks.values())}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bits',type=int,default=2,choices=[1,2,3],help='Exact domain bit width (3 may be slow)')
    p.add_argument('--max-queries',type=int,default=8)
    p.add_argument('--seed',type=int,default=20261115)
    p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent)
    p.add_argument('--output',type=Path)
    p.add_argument('--c01',type=Path,help='Optional EOW_C01.zip or extracted folder')
    a=p.parse_args()
    if a.max_queries<0 or a.max_queries>256:p.error('--max-queries must be between 0 and 256')
    out=a.output or a.root/'Results'/'EOW_C02'
    out.mkdir(parents=True,exist_ok=True)
    c01=load_c01(a.c01)
    tests=self_tests()
    if not tests['all_passed']:raise RuntimeError('Self-tests failed')
    pr=privacy(a.bits);att,examples=attacks(a.bits);ad,traces=adaptive(a.bits,a.max_queries,a.seed);iss=issuer_binding()
    write_csv(out/'reports/privacy_games.csv',pr,['game','scheme','view','n_bits','max_tv','s0','s1','privacy_holds','enrollments_per_secret'])
    write_csv(out/'reports/integrity_games.csv',att,['game','scheme','attack','n_bits','accepted','attempts','rate','example_exists'])
    write_csv(out/'reports/adaptive_oracle_games.csv',ad,['game','scheme','budget','n_bits','winning_enrollments','total_enrollments','success_rate','total_queries','attack_scope'])
    write_csv(out/'reports/issuer_binding_games.csv',iss,['game','scheme','attack','result','electronic_signature_tested','optical_issuer_authentication'])
    write_json(out/'reports/attack_counterexamples.json',examples)
    write_json(out/'reports/adaptive_attack_traces.json',traces)
    write_json(out/'reports/c01_source_audit.json',c01)
    write_json(out/'reports/self_tests.json',tests)
    definitions={
      'IND_PRIV':{'win':'distinguish two secrets from an explicitly declared view','metric':'max pairwise total-variation distance','note':'Exact information-theoretic finite-domain experiment'},
      'MOD_INT':{'win':'accepted submitted share pair changes protected reconstruction','metric':'accepted/eligible submissions','note':'Ideal verifier only; exhaustive enumeration'},
      'ISSUER_BIND':{'win':'attacker enrolls its own materials as purported issuer','metric':'logical capability','note':'No authenticated enrollment channel modeled; no ML-DSA implementation'},
      'CUSTODY':{'win':'secret indistinguishability after private witness disclosure','metric':'IND_PRIV full_witness and one_share_plus_full_witness','note':'Witness compromise is an explicitly different threat view'},
      'ADAPTIVE_ORACLE':{'win':'find content-changing second-share submission with yes/no verifier access','metric':'fraction of enrollments where attack succeeds within budget','note':'Restricted fixed-first-share attacker; shuffled candidate order; no cryptographic security claim'},
      'REPLAY':{'win':'previously authorized exact copy accepted again','metric':'exact-copy acceptance','note':'No freshness/challenge issuance implemented'},
      'HUMAN_OPTICAL':{'win':'human accepts legitimate and rejects malicious physical overlays','metric':'not evaluated','note':'Requires fabrication and human study; digital predicates are not optical realizations'}
    }
    write_json(out/'reports/security_game_definitions.json',definitions)
    assumptions={'scope':'FINITE_DOMAIN_TOY_MODELS_NOT_SECURITY_PROOFS','human_optics':'NOT_IMPLEMENTED','physical_fabrication':'NOT_PERFORMED','post_quantum_authentication':'NOT_TESTED','issuer_enrollment':'UNAUTHENTICATED_IN_TOY_MODELS','eow2':'Tag is retained independent of share data; accept predicate is always true for enrolled tag','eow3':'Private keys stored in verifier state; exact XOR comparator is digital','replay':'No freshness','adaptive':'Bounded oracle search on fixed first share; not general adaptive security','secret_sharing':'2-of-2 XOR sharing, perfect secrecy of one share','privacy_views':list(VIEWS)}
    write_json(out/'reports/model_assumptions.json',assumptions)
    gates=[]
    for s in SCHEMES:
        pv=next(r for r in pr if r['scheme']==s and r['view']=='one_share_plus_public_witness')
        cv=next(r for r in pr if r['scheme']==s and r['view']=='one_share_plus_full_witness')
        it=next(r for r in att if r['scheme']==s and r['attack']=='content_changing')
        gates.extend([
            {'scheme':s,'gate':'PUBLIC_VIEW_PRIVACY','status':'PASS_TOY' if pv['privacy_holds'] else 'FAIL_TOY','evidence':f"max_tv={pv['max_tv']}"},
            {'scheme':s,'gate':'COMPROMISED_CUSTODY_PRIVACY','status':'PASS_TOY' if cv['privacy_holds'] else 'FAIL_TOY','evidence':f"max_tv={cv['max_tv']}"},
            {'scheme':s,'gate':'CONTENT_INTEGRITY','status':'PASS_IDEAL_ORACLE' if it['accepted']==0 else 'FAIL_TOY','evidence':f"accepted={it['accepted']}/{it['attempts']}"},
            {'scheme':s,'gate':'ISSUER_AUTHENTICITY','status':'NOT_ESTABLISHED','evidence':'No authenticated physical enrollment or verified signature'},
            {'scheme':s,'gate':'REPLAY_RESISTANCE','status':'FAIL_STATIC','evidence':'Exact copies accepted'},
            {'scheme':s,'gate':'HUMAN_OPTICAL_REALIZATION','status':'NOT_TESTED','evidence':'Digital equality/XOR only'},
            {'scheme':s,'gate':'POST_QUANTUM_SECURITY','status':'NOT_TESTED','evidence':'No signature algorithm executed in C02'}])
    write_csv(out/'reports/feasibility_gates.csv',gates,['scheme','gate','status','evidence'])
    verdict={'execution':'PASS' if tests['all_passed'] else 'FAIL','research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION','eligible_for_next_stage':['EOW3_masked_challenge_AS_IDEAL_DIGITAL_BASELINE'],'human_optical_authentication':'NOT_ESTABLISHED','post_quantum_issuer_authentication':'NOT_TESTED','general_security_proof':'NOT_PROVIDED','c01_source_status':c01['status']}
    write_json(out/'reports/verdict.json',verdict)
    summary={'n_bits':a.bits,'privacy_game_rows':len(pr),'integrity_game_rows':len(att),'adaptive_game_rows':len(ad),'issuer_game_rows':len(iss),'gate_rows':len(gates),'self_tests':tests,'verdict':verdict}
    write_json(out/'reports/summary.json',summary)
    write_json(out/'configuration/run.json',{'script':Path(__file__).name,'utc':datetime.now(timezone.utc).isoformat(),'bits':a.bits,'max_queries':a.max_queries,'seed':a.seed,'output':str(out),'c01':str(a.c01) if a.c01 else None,'python':sys.version.split()[0]})
    report=['# EOW-C02 — Executable Security Games','',f"Finite-domain width: **{a.bits} bits**. Self-tests: **{tests['passed']}/{tests['total']}**.",'','## Privacy (one share + public witness)','']
    for s in SCHEMES:
        x=next(r for r in pr if r['scheme']==s and r['view']=='one_share_plus_public_witness')
        report.append(f"- {s}: maximum pairwise TV = **{x['max_tv']}**.")
    report+=['','## Integrity (content-changing submissions)','']
    for s in SCHEMES:
        x=next(r for r in att if r['scheme']==s and r['attack']=='content_changing')
        report.append(f"- {s}: **{x['accepted']}/{x['attempts']}** accepted under idealized verifier.")
    report+=['','## Essential limits','', '- The tested verifiers are digital predicates, **not passive human optical checks**.','- No real ML-DSA signing or verification is performed.','- Exact-copy replay succeeds in all three static schemes.','- Protected verifier custody is essential to the masked-reference construction.','- A bounded, restricted adaptive oracle game does not establish general adaptive security.','- A failed finite-domain test is a valid counterexample; passing a finite-domain test is not a proof for arbitrary sizes.','','**Verdict: NO_SECURITY_QUALIFIED_CONSTRUCTION.**','', 'References: https://doi.org/10.1007/BFb0053419 ; https://doi.org/10.6028/NIST.FIPS.204']
    (out/'reports/scientific_report.md').write_text('\n'.join(report)+'\n',encoding='utf-8')
    inventory=[]
    for f in sorted(out.rglob('*')):
        if f.is_file() and f.name!='evidence_inventory.csv':inventory.append({'relative_path':f.relative_to(out).as_posix(),'sha256':digest(f),'bytes':f.stat().st_size})
    write_csv(out/'reports/evidence_inventory.csv',inventory,['relative_path','sha256','bytes'])
    print(json.dumps({'output':str(out),'summary':summary},indent=2))

if __name__=='__main__':main()
