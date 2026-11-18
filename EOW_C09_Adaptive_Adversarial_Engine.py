#!/usr/bin/env python3
"""EOW_C09 — exact adaptive adversarial engine for OR optical witnesses.

Python >=3.10, standard library only. Evaluates ideal digital observer
surrogates, NOT human optical verification. For fixed hidden masks, an
attacker sees binary accept/reject feedback and adaptively chooses new
content-changing shares. An accepted attack ends the game. For fresh masks,
independent challenges are drawn after each submission. Exact enumeration,
not Monte Carlo. Signed enrollment tests are imported as C08 evidence only;
no cryptographic tests are simulated or repeated here.
"""
from __future__ import annotations
import argparse, csv, hashlib, itertools, json, math, sys, zipfile
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

REFS={"visual_cryptography":"https://doi.org/10.1007/BFb0053419",
      "ml_dsa":"https://doi.org/10.6028/NIST.FIPS.204"}

def write_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')
def write_csv(path,rows,columns):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=columns,extrasaction='ignore');w.writeheader();w.writerows(rows)
def bit(x,i): return (x>>i)&1
def bits(x,n): return ''.join(str(bit(x,i)) for i in range(n))
def shares(secret,pad,n):
    a=b=0
    for i in range(n):
        v=bit(pad,i)
        a|=1<<(2*i+v)
        b|=1<<(2*i+(v^bit(secret,i)))
    return a,b
def content(a,b,n):
    x=a|b
    return tuple(bit(x,2*i)+bit(x,2*i+1) for i in range(n))
def observe(b,mask,n,observer):
    x=b|mask
    if observer=='exact_or': return x
    if observer=='black_count':
        return tuple(bit(x,2*i)+bit(x,2*i+1) for i in range(n))
    raise ValueError(observer)

def candidate_masks(a,b,n,observer):
    """Map altered share -> bitset of challenges accepting that share."""
    width=2*n; count=1<<width
    target=content(a,b,n)
    expected=[observe(b,m,n,observer) for m in range(count)]
    result={}
    for altered in range(1<<width):
        if content(a,altered,n)==target: continue
        acceptance=0
        for mask in range(count):
            if observe(altered,mask,n,observer)==expected[mask]:
                acceptance|=1<<mask
        result[altered]=acceptance
    return result

def optimal_fixed(mapping,challenge_count,queries):
    """Optimal adaptive attack under uniform fixed hidden mask.

    State is a bitset of remaining possible masks after failed submissions.
    Each action succeeds on its accepting masks. On rejection, posterior is
    uniform over the remaining masks. Exact dynamic programming maximizes
    total original mask mass of eventual success; records first action.
    """
    full=(1<<challenge_count)-1
    actions=sorted(mapping.items())
    @lru_cache(None)
    def dp(remaining,steps):
        if steps==0 or remaining==0: return (0,None)
        best=(-1,None)
        for altered,success_set in actions:
            hit=remaining & success_set
            # A no-hit action can never improve an optimal policy.
            if not hit: continue
            remainder=remaining & ~success_set
            future=dp(remainder,steps-1)[0] if steps>1 else 0
            score=hit.bit_count()+future
            if score>best[0]: best=(score,altered)
        return best if best[0]>=0 else (0,None)
    count,first=dp(full,queries)
    # Extract a rejection-path policy; after acceptance the game terminates.
    remaining=full;policy=[]
    for step in range(1,queries+1):
        value,action=dp(remaining,queries-step+1)
        if action is None: break
        hit=remaining & mapping[action]
        policy.append({'query':step,'modified_share':action,
                       'remaining_before':remaining.bit_count(),
                       'accepted_masks':hit.bit_count(),
                       'remaining_after_rejection':(remaining&~mapping[action]).bit_count()})
        remaining &= ~mapping[action]
    return count/challenge_count,first,policy,dp.cache_info().currsize

def optimal_fresh(mapping,challenge_count,queries):
    # Each challenge is independently uniform and never revealed before
    # commitment. Rejection provides no information about the next mask.
    best=max((m.bit_count() for m in mapping.values()),default=0)
    p=best/challenge_count
    return 1-(1-p)**queries,p

def public_challenge(mapping,challenge_count):
    vulnerable=0
    for mask in range(challenge_count):
        if any((accepting>>mask)&1 for accepting in mapping.values()):
            vulnerable+=1
    return vulnerable/challenge_count,vulnerable

def upstream(source,tag):
    if source is None:return {'status':'NOT_PROVIDED'}
    p=Path(source)
    if p.is_dir():
        candidates=[p/'reports'/'verdict.json',p/tag/'reports'/'verdict.json']
        for candidate in candidates:
            if candidate.is_file():
                data=candidate.read_bytes()
                return {'status':'LOADED','source':str(candidate),
                        'sha256':hashlib.sha256(data).hexdigest(),'verdict':json.loads(data)}
    if p.is_file() and zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            matches=[n for n in z.namelist() if n.endswith(tag+'/reports/verdict.json')]
            if matches:
                data=z.read(matches[0]);return {'status':'LOADED','source':str(p),
                    'member':matches[0],'sha256':hashlib.sha256(data).hexdigest(),
                    'verdict':json.loads(data)}
    return {'status':'MISSING_VERDICT','source':str(p)}

def c08_tests(source):
    """Import actual C08 test outcomes; DO NOT manufacture signature outcomes."""
    if source is None:return []
    p=Path(source); data=None
    if p.is_dir():
        for candidate in (p/'reports'/'adversarial_cases.csv',p/'EOW_C08'/'reports'/'adversarial_cases.csv'):
            if candidate.is_file(): data=candidate.read_text(encoding='utf-8');break
    elif p.is_file() and zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            matches=[x for x in z.namelist() if x.endswith('EOW_C08/reports/adversarial_cases.csv')]
            if matches:data=z.read(matches[0]).decode('utf-8')
    if data is None:return []
    import io
    return list(csv.DictReader(io.StringIO(data)))

def self_tests():
    checks={}
    for n in (1,2,3):
        for s,pad in itertools.product(range(1<<n),repeat=2):
            a,b=shares(s,pad,n)
            assert content(a,b,n)==tuple(1+bit(s,i) for i in range(n))
    checks['classical_reconstruction']='PASS'
    assert observe(0,3,1,'exact_or')==3
    checks['or_observer']='PASS'
    assert observe(1,2,1,'black_count')==(2,)
    checks['black_count_observer']='PASS'
    assert optimal_fixed({0:1,1:2},2,1)[0]==0.5
    checks['one_query_optimality']='PASS'
    assert optimal_fixed({0:1,1:2},2,2)[0]==1
    checks['adaptive_fixed_two_queries']='PASS'
    assert optimal_fixed({0:1},2,2)[0]==0.5
    checks['fixed_replay_no_new_information']='PASS'
    p,_=optimal_fresh({0:1},2,2)
    assert p==0.75
    checks['independent_fresh_challenges']='PASS'
    assert public_challenge({0:1,1:2},2)==(1,2)
    checks['public_mask_attack']='PASS'
    assert len(candidate_masks(*shares(0,0,1),1,'exact_or'))>0
    checks['content_changing_candidates']='PASS'
    return checks

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bits',type=int,default=3,help='1..3; exact exhaustive toy domain')
    ap.add_argument('--queries',type=int,default=2,help='1..3 adaptive submissions')
    ap.add_argument('--c08',type=Path,help='C08 results folder or ZIP')
    ap.add_argument('--strict-c08',action='store_true')
    ap.add_argument('--c07',type=Path,help='Optional C07 results folder or ZIP')
    ap.add_argument('--root',type=Path,help='Experiments root')
    ap.add_argument('--output',type=Path)
    args=ap.parse_args()
    if args.bits not in (1,2,3):ap.error('--bits must be 1, 2, or 3')
    if not 1<=args.queries<=3:ap.error('--queries must be 1..3')
    root=args.root or Path(__file__).resolve().parent.parent
    out=args.output or root/'Results'/'EOW_C09';rep=out/'reports'
    src08=args.c08 or root/'Results'/'EOW_C08'
    audit08=upstream(src08,'EOW_C08')
    if args.strict_c08 and audit08['status']!='LOADED':
        ap.error('C08 verdict not loaded; specify --c08 path or ZIP')
    audit07=upstream(args.c07 or root/'Results'/'EOW_C07','EOW_C07')
    evidence=c08_tests(src08)
    if args.strict_c08 and not evidence:
        ap.error('C08 adversarial_cases.csv not found; cannot audit upstream tests')
    tests=self_tests()
    challenge_count=1<<(2*args.bits)
    rows=[];traces=[]
    for observer in ('exact_or','black_count'):
        for s,pad in itertools.product(range(1<<args.bits),repeat=2):
            a,b=shares(s,pad,args.bits)
            mapping=candidate_masks(a,b,args.bits,observer)
            fixed,first,policy,states=optimal_fixed(mapping,challenge_count,args.queries)
            fresh,single=optimal_fresh(mapping,challenge_count,args.queries)
            public,public_count=public_challenge(mapping,challenge_count)
            rows.append({'observer':observer,'secret':bits(s,args.bits),
                'pad':bits(pad,args.bits),'eligible_modifications':len(mapping),
                'queries':args.queries,'single_private_success':single,
                'adaptive_fixed_success':fixed,'independent_fresh_success':fresh,
                'public_challenge_vulnerable_fraction':public,
                'public_challenge_vulnerable_masks':public_count,
                'first_optimal_share':bits(first,2*args.bits) if first is not None else '',
                'dp_states':states})
            if len(traces)<12:
                traces.append({'observer':observer,'secret':bits(s,args.bits),
                    'pad':bits(pad,args.bits),'share_A':bits(a,2*args.bits),
                    'share_B':bits(b,2*args.bits),'optimal_rejection_path':[
                        {**x,'modified_share':bits(x['modified_share'],2*args.bits)}
                        for x in policy]})
    # Treat imported C08 outcomes as evidence with explicit provenance.
    imported=[]
    for row in evidence:
        imported.append({'case':row.get('case',''),
                         'expected_accept':row.get('expected_accept',''),
                         'observed_accept':row.get('observed_accept',''),
                         'test_pass':row.get('test_pass',''),
                         'provenance':'IMPORTED_FROM_C08_NOT_REEXECUTED'})
    write_json(out/'configuration'/'run.json',{
        'experiment':'EOW_C09','timestamp_utc':datetime.now(timezone.utc).isoformat(),
        'bits':args.bits,'queries':args.queries,'python':sys.version.split()[0],
        'c08_status':audit08['status'],'c07_status':audit07['status']})
    write_json(rep/'c08_source_audit.json',audit08)
    write_json(rep/'c07_source_audit.json',audit07)
    write_json(rep/'self_tests.json',{'passed':len(tests),'total':len(tests),'checks':tests})
    write_csv(rep/'adaptive_attack_results.csv',rows,[
        'observer','secret','pad','eligible_modifications','queries',
        'single_private_success','adaptive_fixed_success',
        'independent_fresh_success','public_challenge_vulnerable_fraction',
        'public_challenge_vulnerable_masks','first_optimal_share','dp_states'])
    write_json(rep/'adaptive_policy_counterexamples.json',traces)
    write_csv(rep/'imported_c08_enrollment_evidence.csv',imported,[
        'case','expected_accept','observed_accept','test_pass','provenance'])
    # Explicitly separate independent electronic enrollment authenticity from
    # conditional optical adversarial games.
    write_json(rep/'model_assumptions.json',{
        'optical_scheme':'Standard 2-subpixel (2,2) OR visual secret sharing',
        'distribution':'Uniform n-bit secrets, n-bit pads, and 2n-bit masks',
        'attacker_knowledge':'Both legitimate shares A and B, plus verification feedback',
        'candidate_space':'All 2^(2n) binary B-prime values that change the OR content',
        'fixed_hidden_challenge':'One uniformly sampled mask reused; attacker adapts after rejection',
        'fresh_private_challenge':'Independent uniform mask for each attempt, hidden until commitment',
        'public_challenge':'Attacker learns mask before choosing a modified share',
        'feedback':'Ideal binary accept/reject oracle; no timing or side-channel leakage',
        'verification':'Ideal exact OR or per-pixel black-count comparison, not human vision',
        'success':'At least one accepted content-changing submission in query budget',
        'c08':'Imported test evidence only; NO new ML-DSA operations executed',
        'freshness':'External enrollment revision/revocation needed for replay prevention',
        'limitations':['Toy domains n<=3','No real optics or human study',
          'No probabilistic signature-forgery bound estimated',
          'No assertion of universal impossibility','No production key custody'],
        'references':REFS})
    by_obs={}
    for observer in ('exact_or','black_count'):
        subset=[r for r in rows if r['observer']==observer]
        by_obs[observer]={
            'single_private_mean':sum(r['single_private_success'] for r in subset)/len(subset),
            'fixed_adaptive_mean':sum(r['adaptive_fixed_success'] for r in subset)/len(subset),
            'fresh_independent_mean':sum(r['independent_fresh_success'] for r in subset)/len(subset),
            'public_mask_vulnerable_mean':sum(r['public_challenge_vulnerable_fraction'] for r in subset)/len(subset),
            'fixed_adaptive_worst':max(r['adaptive_fixed_success'] for r in subset),
            'fresh_independent_worst':max(r['independent_fresh_success'] for r in subset)}
    electronic_pass=(audit08['status']=='LOADED' and
        audit08['verdict'].get('electronic_enrollment_authenticity')=='PASS_TESTED_ONLY' and
        len(imported)>0 and all(x['test_pass'].lower()=='true' for x in imported))
    gates=[
        {'gate':'adaptive_optical_integrity','status':'FAIL_TOY','evidence':'Nonzero exact adaptive content-changing forgery probability'},
        {'gate':'electronic_enrollment_authenticity','status':'PASS_UPSTREAM_TESTED_ONLY' if electronic_pass else 'NOT_CONFIRMED',
         'evidence':'Imported C08 results; no new cryptographic operations'},
        {'gate':'replay_freshness','status':'NOT_ESTABLISHED','evidence':'C08 exact replay accepted without external state'},
        {'gate':'optical_human_verification','status':'NOT_ESTABLISHED','evidence':'No human study'},
        {'gate':'physical_share_binding','status':'NOT_ESTABLISHED','evidence':'No physical-to-digital attestation'},
        {'gate':'confidentiality','status':'NOT_RETESTED','evidence':'Refer to C07 privacy matrices'},
    ]
    write_csv(rep/'feasibility_gates.csv',gates,['gate','status','evidence'])
    verdict={'execution':'PASS','research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION',
             'adaptive_optical_integrity':'FAIL_TOY',
             'electronic_enrollment_authenticity':'PASS_UPSTREAM_TESTED_ONLY' if electronic_pass else 'NOT_CONFIRMED',
             'human_optical_authentication':'NOT_ESTABLISHED',
             'universal_impossibility_theorem':'NOT_CLAIMED'}
    write_json(rep/'verdict.json',verdict)
    summary={'bits':args.bits,'queries':args.queries,'self_tests_passed':len(tests),
             'attack_instances':len(rows),'policy_examples':len(traces),
             'c08_source_status':audit08['status'],'c08_evidence_rows':len(imported),
             'c07_source_status':audit07['status'],
             'observer_results':by_obs,'research_verdict':verdict['research_verdict']}
    write_json(rep/'summary.json',summary)
    report=['# EOW_C09 — Adaptive Adversarial Engine','',
        '**Verdict:** NO_SECURITY_QUALIFIED_CONSTRUCTION.','',
        '## Exact finite-domain results','',
        '| Observer | One private attempt | Adaptive fixed mask | Fresh independent masks | Public mask vulnerable |',
        '|---|---:|---:|---:|---:|']
    for name,r in by_obs.items():
        report.append(f"| {name} | {r['single_private_mean']:.6f} | {r['fixed_adaptive_mean']:.6f} | {r['fresh_independent_mean']:.6f} | {r['public_mask_vulnerable_mean']:.6f} |")
    report+=['','## Security interpretation','',
        'Fixed-mask results use exact optimal adaptive policies after negative feedback.',
        'Fresh-mask results assume independent uniformly random masks for every query.',
        'Public-mask vulnerability permits selection after the mask is known.',
        'The optical verifier is an ideal digital surrogate; no human perceptual claim follows.',
        'C08 enrollment test results are imported, not re-executed. They cannot repair optical OR collisions.',
        'No universal impossibility theorem is asserted.','',
        '## Sources','',f"- [Naor and Shamir]({REFS['visual_cryptography']})",
        f"- [NIST FIPS 204]({REFS['ml_dsa']})"]
    (rep/'scientific_report.md').write_text('\n'.join(report)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2))
    return 0

if __name__=='__main__':raise SystemExit(main())
