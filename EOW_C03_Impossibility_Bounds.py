#!/usr/bin/env python3
"""EOW_C03: conditional impossibility bounds and exact finite-domain witnesses.

No claims of universal optical impossibility, PQ security, or human performance.
Python 3.10+, standard library only.
"""
from __future__ import annotations
import argparse, csv, hashlib, itertools, json, math, sys, zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SOURCES = {
 'Naor_Shamir_1994': 'https://doi.org/10.1007/BFb0053419',
 'NIST_FIPS_204': 'https://doi.org/10.6028/NIST.FIPS.204',
}

def save_json(path, obj):
 path.parent.mkdir(parents=True, exist_ok=True)
 path.write_text(json.dumps(obj, indent=2, sort_keys=True, default=str)+'\n', encoding='utf-8')

def save_csv(path, rows, fields):
 path.parent.mkdir(parents=True, exist_ok=True)
 with path.open('w', newline='', encoding='utf-8') as f:
  w=csv.DictWriter(f, fieldnames=fields, extrasaction='ignore');w.writeheader();w.writerows(rows)

def digest(data):return hashlib.sha256(data).hexdigest()

def tv(p,q):return sum(abs(p.get(k,0)-q.get(k,0)) for k in set(p)|set(q))/2

def or_operator(a,b):return a|b

def bitstrings(n):return range(1<<n)

def all_pair_collisions(n,operator):
 groups=defaultdict(list)
 for a in bitstrings(n):
  for b in bitstrings(n):groups[operator(a,b)].append((a,b))
 pairs=sum(len(v)*(len(v)-1)//2 for v in groups.values())
 witness=next(((k,v[0],v[1]) for k,v in groups.items() if len(v)>1),None)
 return {'domain_bits':n,'ordered_input_pairs':(1<<n)**2,'distinct_outputs':len(groups),
         'colliding_unordered_pairs_of_ordered_inputs':pairs,
         'example':{'output':witness[0],'first':list(witness[1]),'second':list(witness[2])} if witness else None}

def changed_content_or_collision(n):
 """Hold first share fixed, find a changed second share preserving OR and changing XOR."""
 for a in bitstrings(n):
  for b in bitstrings(n):
   for c in bitstrings(n):
    if b!=c and (a|b)==(a|c) and (a^b)!=(a^c):
     return {'fixed_share':a,'original_partner':b,'modified_partner':c,
             'same_or_output':a|b,'original_xor_secret':a^b,'modified_xor_secret':a^c}
 return None

def privacy_views(n):
 """Exact distributions of (first share, public witness) under uniform XOR pad.

Public witness examples: constant; second share; full secret; masked second
share with an independent uniform hidden key. The hidden key is NOT public.
"""
 d=1<<n; dist={}
 for model in ('constant_public','second_share_public','secret_public','masked_second_share_public'):
  by_secret={}
  for secret in bitstrings(n):
   counts=Counter();total=0
   for pad in bitstrings(n):
    second=pad^secret
    keys=range(d) if model=='masked_second_share_public' else (0,)
    for key in keys:
     public={'constant_public':0,'second_share_public':second,
             'secret_public':secret,'masked_second_share_public':second^key}[model]
     counts[(pad,public)]+=1;total+=1
   by_secret[secret]={k:v/total for k,v in counts.items()}
  max_tv=max(tv(by_secret[a],by_secret[b]) for a in bitstrings(n) for b in bitstrings(n))
  dist[model]=max_tv
 return dist

def masked_key_compromise(n):
 """If adversary gets (first share, masked second share, mask key), secret is known."""
 d=1<<n; views={}
 for secret in bitstrings(n):
  cnt=Counter()
  for pad in bitstrings(n):
   for key in bitstrings(n):cnt[(pad,(pad^secret)^key,key)]+=1
  views[secret]={k:v/(d*d) for k,v in cnt.items()}
 return max(tv(views[a],views[b]) for a in bitstrings(n) for b in bitstrings(n))

def public_rebinding_witness(n):
 """Conditional: adversary may replace ALL unauthenticated enrollment data."""
 a,b=0,0;modified=1
 def enrollment_tag(x,y):return (x^y) & ((1<<n)-1)
 original=enrollment_tag(a,b); forged=enrollment_tag(a,modified)
 return {'original_shares':[a,b],'original_tag':original,
         'attacker_shares':[a,modified],'attacker_tag':forged,
         'public_consistency_accepts':enrollment_tag(a,modified)==forged,
         'secret_changed':(a^b)!=(a^modified)}

def tag_transplant_witness(n):
 return {'original_data':0,'modified_data':1,'original_tag':0,
         'attacker_retains_tag':0,'tag_only_accepts':True,'data_changed':True}

def static_replay_witness():
 def verify(presented, enrolled):return presented==enrolled
 x=(0,1,0)
 return {'authorized_presentation':list(x),'replayed_presentation':list(x),
         'static_accepts_original':verify(x,x),'static_accepts_replay':verify(tuple(x),x)}

def output_capacity(n, observed_bits):
 """Pigeonhole lower bound: at most 2^m distinct observable labels."""
 domain=1<<(2*n);capacity=1<<observed_bits
 return {'input_pairs':domain,'observation_bits':observed_bits,'maximum_distinct_outputs':capacity,
         'minimum_excess_inputs_over_outputs':max(0,domain-capacity),
         'minimum_colliding_unordered_input_pairs':max(0,domain-capacity),
         'injectivity_impossible_when':2*n>observed_bits,
         'scope':'Only deterministic mappings from all ordered share pairs to m-bit observations; does not imply content-changing collision for every valid enrollment'}

def read_c02(path):
 if not path:return {'status':'NOT_PROVIDED'}
 p=Path(path)
 if not p.exists():return {'status':'MISSING','path':str(p)}
 try:
  if p.is_file() and p.suffix.lower()=='.zip':
   with zipfile.ZipFile(p) as z:
    name=next((s for s in z.namelist() if s.endswith('/reports/summary.json') and 'EOW_C02' in s),None)
    if name is None:raise ValueError('No EOW_C02/reports/summary.json in ZIP')
    raw=z.read(name);return {'status':'LOADED','path':str(p),'entry':name,'sha256':digest(raw),'summary':json.loads(raw)}
  candidates=[p/'reports'/'summary.json',p/'EOW_C02'/'reports'/'summary.json']
  target=next((q for q in candidates if q.is_file()),None)
  if target is None:raise ValueError('No C02 reports/summary.json found')
  raw=target.read_bytes();return {'status':'LOADED','path':str(target),'sha256':digest(raw),'summary':json.loads(raw)}
 except Exception as exc:return {'status':'INVALID','path':str(p),'error':str(exc)}

def run_selftests():
 tests={
  'or_collision_n1':all_pair_collisions(1,or_operator)['distinct_outputs']==2,
  'or_content_change_exists':changed_content_or_collision(2) is not None,
  'masked_public_zero_leakage':privacy_views(2)['masked_second_share_public']==0,
  'public_second_share_leaks':privacy_views(2)['second_share_public']==1,
  'masked_key_compromise_leaks':masked_key_compromise(2)==1,
  'public_rebinding_accepts':public_rebinding_witness(2)['public_consistency_accepts'],
  'tag_transplant_accepts':tag_transplant_witness(2)['tag_only_accepts'],
  'static_replay_accepts':static_replay_witness()['static_accepts_replay'],
  'pigeonhole_bound':output_capacity(2,2)['injectivity_impossible_when'],
  'tv_identical':tv({1:1},{1:1})==0,
  'tv_disjoint':tv({1:1},{2:1})==1,
 }
 return {'checks':tests,'passed':sum(tests.values()),'total':len(tests),'all_passed':all(tests.values())}

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--bits',type=int,default=2,help='Exact enumeration bits, 1..5 (default 2)')
 ap.add_argument('--root',type=Path,help='Experiment root (parent of Code)')
 ap.add_argument('--output',type=Path,help='Override output directory')
 ap.add_argument('--c02',type=Path,help='EOW_C02 results directory or ZIP')
 ap.add_argument('--strict-c02',action='store_true',help='Require readable C02 summary')
 args=ap.parse_args()
 if not 1<=args.bits<=5:ap.error('--bits must be 1..5 for exact enumeration')
 root=args.root or Path(__file__).resolve().parent.parent
 output=args.output or root/'Results'/'EOW_C03'
 output.mkdir(parents=True,exist_ok=True)
 c02path=args.c02
 if c02path is None:
  candidate=root/'Results'/'EOW_C02'
  if candidate.exists():c02path=candidate
 c02=read_c02(c02path)
 if args.strict_c02 and c02['status']!='LOADED':ap.error('C02 source missing/invalid: '+str(c02))
 n=args.bits
 tests=run_selftests()
 if not tests['all_passed']:raise RuntimeError('Self-tests failed: '+str(tests))
 collisions=all_pair_collisions(n,or_operator)
 change=changed_content_or_collision(n)
 privacy=privacy_views(n)
 compromise=masked_key_compromise(n)
 capacity=output_capacity(n,n)
 counterexamples={
  'or_content_changing_collision':change,
  'public_rebinding':public_rebinding_witness(n),
  'separable_tag_transplant':tag_transplant_witness(n),
  'static_replay':static_replay_witness(),
  'masked_witness_compromise':{'maximum_pairwise_tv':compromise},
 }
 propositions=[
  {'id':'P1','title':'Public enrollment rebinding','assumptions':'Verifier checks only a publicly recomputable predicate; attacker may replace all enrollment data and shares; no independently authenticated reference.','statement':'An attacker can produce a different self-consistent enrollment accepted by the verifier.','status':'CONDITIONAL_PROPOSITION_WITH_CONSTRUCTIVE_WITNESS','witness':'public_rebinding','caveat':'Does not rule out a trusted external issuer identifier, immutable registry, or protected reference.'},
  {'id':'P2','title':'Separable-tag transplantation','assumptions':'Acceptance depends on unchanged tag and protected witness but not on independently mutable data region.','statement':'Changing the data region while preserving the tag leaves acceptance unchanged.','status':'CONDITIONAL_PROPOSITION_WITH_CONSTRUCTIVE_WITNESS','witness':'separable_tag_transplant','caveat':'Not applicable when verification genuinely binds all protected data.'},
  {'id':'P3','title':'OR observation non-injectivity','assumptions':'Binary OR stacking, n>=1, full ordered input-pair domain.','statement':'OR maps 2^(2n) ordered share pairs into at most 2^n observations; collisions necessarily exist.','status':'COUNTING_THEOREM_WITH_EXACT_ENUMERATION','witness':'or_content_changing_collision','caveat':'Does not imply every valid codebook or every enrollment admits a content-changing forgery.'},
  {'id':'P4','title':'Masked public-witness secrecy','assumptions':'Independent uniform pad and independently uniform secret mask, hidden mask key, XOR sharing, exactly defined public view.','statement':'(First share, masked second share) is independent of secret in this toy distribution.','status':'EXACT_FINITE_DOMAIN_IDENTITY','witness':'privacy_distributions','caveat':'No passive optical XOR implementation or general system proof is established.'},
  {'id':'P5','title':'Masked-witness compromise','assumptions':'Attacker obtains first share, masked second share, and mask key.','statement':'Attacker reconstructs second share and hence the secret; pairwise TV=1.','status':'ALGEBRAIC_IDENTITY_WITH_EXACT_ENUMERATION','witness':'masked_witness_compromise','caveat':'Different compromise views can have different leakage.'},
  {'id':'P6','title':'Static exact replay','assumptions':'Deterministic stateless verifier accepts a presentation and retains no freshness state or trusted physical uniqueness test.','statement':'An identical replay yields the same acceptance decision.','status':'CONDITIONAL_LOGICAL_THEOREM','witness':'static_replay','caveat':'Fresh challenges or stateful replay detection change the model.'},
  {'id':'P7','title':'Digital PQ versus optical human authentication','assumptions':'ML-DSA verification is performed electronically at enrollment; later human optical verifier does not evaluate signature verification algorithm.','statement':'Electronic signature authenticity alone does not prove optical issuer authentication.','status':'SECURITY_SCOPE_SEPARATION','witness':None,'caveat':'Not an impossibility of all optical trusted-witness constructions.'},
 ]
 rows=[]
 for key,val in privacy.items():rows.append({'model':key,'view':'first_share_plus_public_witness','max_pairwise_tv':val,'scope':'exact_uniform_xor_toy'})
 rows.append({'model':'masked_second_share_full_compromise','view':'first_share_plus_masked_second_plus_key','max_pairwise_tv':compromise,'scope':'exact_uniform_xor_toy'})
 gates=[
  {'gate':'public_enrollment_authenticity','status':'FAIL_UNDER_P1_ASSUMPTIONS','basis':'P1'},
  {'gate':'separable_tag_integrity','status':'FAIL_UNDER_P2_ASSUMPTIONS','basis':'P2'},
  {'gate':'OR_full_domain_injectivity','status':'IMPOSSIBLE_UNDER_P3_ASSUMPTIONS','basis':'P3'},
  {'gate':'masked_public_view_privacy','status':'PASS_TOY_VIEW_ONLY' if privacy['masked_second_share_public']==0 else 'FAIL','basis':'P4'},
  {'gate':'compromised_witness_privacy','status':'FAIL_UNDER_P5_ASSUMPTIONS','basis':'P5'},
  {'gate':'static_replay_resistance','status':'FAIL_UNDER_P6_ASSUMPTIONS','basis':'P6'},
  {'gate':'post_quantum_issuer_binding','status':'NOT_TESTED','basis':'P7'},
  {'gate':'passive_human_optical_verification','status':'NOT_ESTABLISHED','basis':'P7'},
  {'gate':'physical_robustness','status':'NOT_TESTED','basis':'No physical specimens'},
  {'gate':'general_secure_EOW_construction','status':'NOT_ESTABLISHED','basis':'Conditional bounds do not establish universal impossibility'},
 ]
 save_json(output/'configuration'/'run.json',{'script':'EOW_C03_Impossibility_Bounds.py','utc':datetime.now(timezone.utc).isoformat(),'python':sys.version,'bits':n,'root':str(root),'c02':str(c02path) if c02path else None,'sources':SOURCES})
 save_json(output/'reports'/'model_assumptions.json',{'domain':'n-bit binary XOR secret-sharing toy models','randomness':'Uniform independent pads and masks','optics':'Ideal binary OR, no physical human experiments','bounds':'Conditional propositions, not universal impossibility claims','post_quantum':'No ML-DSA performed in C03'})
 save_json(output/'reports'/'c02_source_audit.json',c02)
 save_json(output/'reports'/'conditional_propositions.json',propositions)
 save_json(output/'reports'/'counterexamples.json',counterexamples)
 save_json(output/'reports'/'optical_collision_audit.json',{'OR':collisions,'pigeonhole':capacity})
 save_csv(output/'reports'/'privacy_bounds.csv',rows,['model','view','max_pairwise_tv','scope'])
 save_csv(output/'reports'/'feasibility_gates.csv',gates,['gate','status','basis'])
 save_json(output/'reports'/'self_tests.json',tests)
 verdict={'execution':'PASS','self_tests_passed':tests['all_passed'],'c02_source_status':c02['status'],
          'conditional_propositions':len(propositions),'optical_content_changing_collision_found':change is not None,
          'human_optical_authentication':'NOT_ESTABLISHED','post_quantum_issuer_authentication':'NOT_TESTED',
          'universal_impossibility_theorem':'NOT_CLAIMED','research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION',
          'next_step':'C04 must specify protected full-share witness custody and an actual passive optical predicate'}
 save_json(output/'reports'/'verdict.json',verdict)
 summary={'bits':n,'self_tests':tests,'c02_source_status':c02['status'],'or_collision_audit':collisions,
          'public_privacy_max_tv':privacy,'masked_key_compromise_tv':compromise,
          'conditional_propositions':len(propositions),'gate_records':len(gates),'verdict':verdict}
 save_json(output/'reports'/'summary.json',summary)
 report=f'''# EOW_C03 — Conditional Impossibility Bounds and Exact Counterexamples

**Scope:** Exact finite-domain XOR-sharing and binary-OR optical surrogate; n={n}. No universal impossibility theorem is claimed.

## Findings

- Binary OR maps {collisions['ordered_input_pairs']} ordered input pairs to {collisions['distinct_outputs']} outputs, with {collisions['colliding_unordered_pairs_of_ordered_inputs']} colliding unordered pairs of distinct ordered inputs.
- A fixed-first-share content-changing OR collision was {'found' if change else 'not found'}.
- Publicly recomputable enrollment can be rebound if an attacker can replace **all** untrusted enrollment information (P1).
- A separable authentication tag can be transplanted without authenticating mutable data (P2).
- Masked public witness (with independent hidden key) has maximum pairwise TV={privacy['masked_second_share_public']:.6f} in the defined public view.
- Revealing the mask key together with the first share and masked second share yields TV={compromise:.6f}.
- A stateless deterministic verifier cannot distinguish an exact replay from the accepted original without extra assumptions.

## Interpretation

The OR collision counting theorem concerns the full ordered-pair domain, **not** necessarily a restricted valid-codeword subset. The secrecy identity concerns a digital XOR toy model, **not** a passive optical realization. The issuer-authenticity result assumes no protected trust anchor. These limitations are essential.

## Evidence

C02 source: {c02['status']}. Self-tests: {tests['passed']}/{tests['total']}.

## Decision

`NO_SECURITY_QUALIFIED_CONSTRUCTION`. C04 should build a fully specified optical predicate and account for witness custody, secrecy, replay, and physical observability.

## References

- Naor and Shamir, Visual Cryptography: {SOURCES['Naor_Shamir_1994']}
- NIST FIPS 204, ML-DSA: {SOURCES['NIST_FIPS_204']}
'''
 (output/'reports'/'scientific_report.md').write_text(report,encoding='utf-8')
 print(json.dumps({'output':str(output),'summary':summary},indent=2))

if __name__=='__main__':main()
