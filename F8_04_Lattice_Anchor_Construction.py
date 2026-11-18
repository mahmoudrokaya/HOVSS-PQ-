#!/usr/bin/env python3
"""F8_04: research-grade *candidate audit*, NOT a proven PQ authentication scheme.

Candidate A: content-coupled, public lattice-style anchor derived from an issuer
record. A toy modular linear map illustrates the lattice connection; SHA-256
binds bytes deterministically; an optional HMAC models a PRIVATE issuance
capability but is explicitly NOT post-quantum digital signature, public-key
verification, or a substitute for ML-DSA. The optical-only observer cannot
check the HMAC. This script intentionally searches for optical forgeries.

Standard library only. Never overwrites F8_01..F8_03 results.
"""
import argparse, csv, hashlib, hmac, itertools, json, math, os, random, secrets, sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ROOT = Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')
DOMAIN = b'HOVSS-F8-04-ANCHOR-v1\x00'

def digest(x): return hashlib.sha256(x).digest()
def canonical(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def bits_from_bytes(b, n):
    return tuple((b[(i//8)%len(b)] >> (7-i%8))&1 for i in range(n))
def lattice_public_vector(record_bytes, q=257, dimension=16):
    """PUBLIC modular linear toy transform; NO SIS/LWE security claim."""
    seed=digest(b'PUBLIC-MATRIX'+DOMAIN)
    rng=random.Random(int.from_bytes(seed,'big'))
    matrix=[[rng.randrange(q) for _ in range(dimension)] for _ in range(dimension)]
    x=[int.from_bytes(digest(b'PUBLIC-INPUT'+record_bytes+i.to_bytes(2,'big'))[:2],'big')%q for i in range(dimension)]
    return tuple(sum(a*b for a,b in zip(row,x))%q for row in matrix)
def anchor(record, pixels, lattice=True):
    b=canonical(record)
    vec=lattice_public_vector(b) if lattice else ()
    payload=DOMAIN+b+canonical(vec)
    # Domain-separated SHA256 expansion, public and fully recomputable.
    return tuple(bits_from_bytes(digest(payload+i.to_bytes(4,'big')),min(256,pixels-i)) for i in range(0,pixels,256))
def flat_anchor(record, pixels, lattice=True):
    return tuple(itertools.chain.from_iterable(anchor(record,pixels,lattice)))
def make_record(secret, issuer='ISSUER_A', edition=0):
    return {'protocol':'F8_04_CANDIDATE_A','issuer_label':issuer,'edition':edition,
            'secret_sha256':hashlib.sha256(bytes(secret)).hexdigest(),'length':len(secret)}
def hmac_tag(record,key): return hmac.new(key,DOMAIN+canonical(record),'sha256').hexdigest()
def verify_tag(record,tag,key): return hmac.compare_digest(hmac_tag(record,key),tag)

def or_observe(a,b): return tuple(x|y for x,y in zip(a,b))
def dual_observe(a,b):
    # Two-channel idealized complementary differential observable, NOT hardware.
    # Per-pixel response 0,1,2 for a+b. Symmetric and thus collision-prone.
    return tuple(x+y for x,y in zip(a,b))
def leakage_observe(a,b,dark=.06):
    return tuple(round((1 if x==0 else dark)*(1 if y==0 else dark),12) for x,y in zip(a,b))
def optical_observe(a,b,mode):
    if mode=='or': return or_observe(a,b)
    if mode=='dual': return dual_observe(a,b)
    if mode=='leaky': return leakage_observe(a,b)
    raise ValueError(mode)
def change_one(seq,idx):
    y=list(seq);y[idx]^=1;return tuple(y)
def pair_share(secret,rng):
    """Standard 2-subpixel Naor-Shamir pattern, 0=white,1=black."""
    s1=[];s2=[]
    for b in secret:
        r=rng.randrange(2)
        s1.extend((r,1-r))
        s2.extend((r,1-r) if b==0 else (1-r,r))
    return tuple(s1),tuple(s2)
def encoded_anchor_pair(anchor_bits,rng):
    return pair_share(anchor_bits,rng)
def masked_changes(reference, altered):
    return sum(x==y for x,y in zip(reference,altered))
def tv_binary(a,b):
    """Exact total variation of distributions represented by equal-length sample lists."""
    ca,cb=Counter(a),Counter(b); n=len(a);m=len(b)
    return .5*sum(abs(ca[k]/n-cb[k]/m) for k in ca.keys()|cb.keys())
def exact_privacy():
    # For one Naor-Shamir pixel, each share is uniform in {01,10} for both secrets.
    d={}
    for secret in (0,1):
        d[secret]=[tuple((r,1-r)) for r in (0,1)]
    return {'single_share_total_variation':tv_binary(d[0],d[1]),
            'scope':'one secret pixel, standard randomized 2-subpixel Naor-Shamir encoding'}
def output_json(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(obj,indent=2,ensure_ascii=False,default=str)+'\n',encoding='utf-8')
def write_csv(p,rows,fields):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def audit_inputs(root):
    out={}
    for phase in ('F8_01','F8_02','F8_03'):
        p=root/'Results'/phase/'reports'/'verdict.json'
        if not p.exists(): p=root/'Results'/phase/'verdict.json'
        try: out[phase]={'available':True,'path':str(p),'verdict':json.loads(p.read_text(encoding='utf-8'))}
        except Exception as e: out[phase]={'available':False,'reason':str(e)}
    return out

def run(args):
    root=Path(args.root)
    out=Path(args.output) if args.output else root/'Results'/'F8_04'
    out.mkdir(parents=True,exist_ok=True)
    rng=random.Random(args.seed)
    key=secrets.token_bytes(32) # never persisted; only private issuance *surrogate*
    n=args.secret_pixels
    operators=args.operators.split(',')
    if not operators or any(x not in ('or','dual','leaky') for x in operators):
        raise ValueError('operators must be comma-separated from or,dual,leaky')
    dependencies=audit_inputs(root)
    if args.strict_data and not all(v['available'] for v in dependencies.values()):
        raise RuntimeError('Missing F8_01/F8_02/F8_03 verdict files: '+str(dependencies))
    results=[]; witnesses=[]
    stats=Counter()
    # Small-domain exhaustive content and single-subpixel modifications.
    # Each secret is encoded with random sharing per trial; no security proof for larger domains.
    for secret in itertools.product((0,1),repeat=n):
        rec=make_record(secret)
        pub=flat_anchor(rec,n,args.lattice)
        signed=hmac_tag(rec,key)
        for trial in range(args.trials):
            a,b=pair_share(secret,rng)
            ua,ub=encoded_anchor_pair(pub,rng)
            # Visual output contains content reconstruction plus a public anchor.
            # Anchor is not a trusted expected value: attacker can recompute it.
            for mode in operators:
                legit=(optical_observe(a,b,mode),optical_observe(ua,ub,mode))
                # Attack 1: change content share without changing public anchor.
                for i in range(len(a)):
                    changed=change_one(a,i)
                    forged=(optical_observe(changed,b,mode),optical_observe(ua,ub,mode))
                    equal=forged==legit
                    stats[(mode,'single_subpixel','cases')]+=1
                    stats[(mode,'single_subpixel','equal')]+=int(equal)
                    if equal and len(witnesses)<args.max_witnesses:
                        witnesses.append({'operator':mode,'attack':'single_subpixel','secret':secret,
                                         'index':i,'share_a':a,'share_b':b,'altered_share_a':changed,
                                         'optical_output':legit,'equal':True})
                # Attack 2: replace both shares with freshly generated pair of same secret.
                fa,fb=pair_share(secret,rng)
                fua,fub=encoded_anchor_pair(pub,rng)
                forged=(optical_observe(fa,fb,mode),optical_observe(fua,fub,mode))
                # Comparison to original issuance exact optical pattern, not human decision.
                equal=forged==legit
                stats[(mode,'same_secret_reissuance','cases')]+=1
                stats[(mode,'same_secret_reissuance','equal')]+=int(equal)
                # Attack 3: publicly recompute anchor for changed secret, replace all layers.
                modified=change_one(secret,0)
                fake_rec=make_record(modified)
                fake_pub=flat_anchor(fake_rec,n,args.lattice)
                fca,fcb=pair_share(modified,rng)
                faa,fab=encoded_anchor_pair(fake_pub,rng)
                forge_output=(optical_observe(fca,fcb,mode),optical_observe(faa,fab,mode))
                public_consistency=(fake_pub==flat_anchor(fake_rec,n,args.lattice))
                private_valid=verify_tag(fake_rec,signed,key)
                stats[(mode,'public_rebinding','cases')]+=1
                stats[(mode,'public_rebinding','public_consistency')]+=int(public_consistency)
                stats[(mode,'public_rebinding','private_signature_valid')]+=int(private_valid)
                stats[(mode,'public_rebinding','equal_to_original')]+=int(forge_output==legit)
                # Attack 4: exact copy is optically identical by definition.
                stats[(mode,'exact_copy','cases')]+=1
                stats[(mode,'exact_copy','equal')]+=1
                if trial==0 and len(witnesses)<args.max_witnesses:
                    witnesses.append({'operator':mode,'attack':'public_rebinding','secret':secret,
                                      'modified_secret':modified,'original_record':rec,'forged_record':fake_rec,
                                      'forged_anchor_publicly_consistent':public_consistency,
                                      'original_private_tag_valid_for_forged_record':private_valid,
                                      'optically_equal_to_original':forge_output==legit,
                                      'interpretation':'A public consistency test accepts the attacker-created record and anchor; private issuance tag does not.'})
    for (mode,attack,metric),value in sorted(stats.items()):
        results.append({'operator':mode,'attack':attack,'metric':metric,'value':value})
    summaries=[]
    for mode in operators:
        for attack in ('single_subpixel','same_secret_reissuance','public_rebinding','exact_copy'):
            cases=stats[(mode,attack,'cases')]
            summaries.append({'operator':mode,'attack':attack,'cases':cases,
                'optically_equal_count':stats[(mode,attack,'equal' if attack!='public_rebinding' else 'equal_to_original')],
                'optically_equal_rate':stats[(mode,attack,'equal' if attack!='public_rebinding' else 'equal_to_original')]/cases,
                'public_consistency_rate':stats[(mode,attack,'public_consistency')]/cases if attack=='public_rebinding' else None,
                'private_tag_valid_rate':stats[(mode,attack,'private_signature_valid')]/cases if attack=='public_rebinding' else None})
    self_tests={
      'privacy':exact_privacy()['single_share_total_variation']==0,
      'public_anchor_reproducible':flat_anchor(make_record((0,1,0)),3)==flat_anchor(make_record((0,1,0)),3),
      'content_changes_record':make_record((0,1))!=make_record((1,1)),
      'private_tag_rejects_change':not verify_tag(make_record((1,1)),hmac_tag(make_record((0,1)),key),key),
      'exact_copy_all':all(stats[(m,'exact_copy','equal')]==stats[(m,'exact_copy','cases')] for m in operators),
      'public_rebinding_all':all(stats[(m,'public_rebinding','public_consistency')]==stats[(m,'public_rebinding','cases')] for m in operators),
    }
    verdict={'execution':'PASS' if all(self_tests.values()) else 'FAIL',
       'single_share_baseline_privacy':'PROVEN_ALGEBRAICALLY_FOR_CLASSICAL_BASELINE',
       'combined_view_privacy':'NOT_ESTABLISHED',
       'content_binding':'PUBLIC_RECOMPUTABLE',
       'optical_integrity':'COUNTEREXAMPLE_FOUND' if any(stats[(m,'single_subpixel','equal')]>0 for m in operators) else 'NOT_ESTABLISHED',
       'issuer_authenticity_optical_only':'NOT_ESTABLISHED',
       'post_quantum_signature':'NOT_IMPLEMENTED',
       'physical_validation':'NOT_PERFORMED',
       'human_validation':'NOT_PERFORMED',
       'candidate_A_complete_HOVSS_PQ':'NOT_ESTABLISHED',
       'security_claim':'The public lattice-style anchor and optical output are NOT issuer authentication. HMAC is a private-key control-only surrogate; no ML-DSA or PQ signature is executed.'}
    run_cfg={'program':'F8_04','timestamp_utc':datetime.now(timezone.utc).isoformat(),
       'root':str(root),'output':str(out),'secret_pixels':n,'trials_per_secret':args.trials,
       'operators':operators,'seed':args.seed,'lattice_public_map':args.lattice,
       'secret_patterns':2**n,'privacy_scope':'classical single share only',
       'attack_scope':'full share substitution, public rebinding, local subpixel flip, exact copy'}
    output_json(out/'configuration'/'run.json',run_cfg)
    output_json(out/'reports'/'dependency_audit.json',dependencies)
    output_json(out/'mathematical_validation'/'exact_privacy_baseline.json',exact_privacy())
    output_json(out/'mathematical_validation'/'counterexamples.json',witnesses)
    write_csv(out/'reports'/'attack_metrics.csv',results,['operator','attack','metric','value'])
    write_csv(out/'reports'/'attack_summary.csv',summaries,['operator','attack','cases','optically_equal_count','optically_equal_rate','public_consistency_rate','private_tag_valid_rate'])
    output_json(out/'reports'/'self_tests.json',self_tests)
    output_json(out/'reports'/'model_assumptions.json',{
       'lattice':'Toy public modular matrix transform, not SIS/LWE, not a cryptographic hardness instantiation.',
       'anchor':'Public SHA-256 expansion from content digest and issuer label. Anyone can recompute it.',
       'private_issuer_control':'Ephemeral HMAC-SHA256 tag used solely to demonstrate private-vs-public verification separation; key never saved.',
       'optics':'OR is binary visual stacking; dual is ideal two-channel sum; leaky is ideal independent transmission. No physical measurements.',
       'human':'Exact tuple equality is a digital instrumented comparison, NOT a human-observer decision.',
       'threat':'Adversary can learn public rules, replace shares and recompute public anchor; issuer HMAC key stays private.',
       'important':'No issuer-enrolled trusted reference or independently authenticated physical anchor is available to the human verifier.'})
    output_json(out/'reports'/'summary.json',{'configuration':run_cfg,'self_tests':self_tests,
       'attack_summary':summaries,'witnesses_saved':len(witnesses),'dependencies':{k:v['available'] for k,v in dependencies.items()},
       'interpretation':'Publicly content-coupled optical anchors cannot alone establish issuer origin. Optical collisions and exact copying remain.'})
    output_json(out/'reports'/'verdict.json',verdict)
    (out/'README.md').write_text('F8_04 Candidate A: lattice-style PUBLIC anchor audit.\n\nThis is a falsification-oriented toy candidate, NOT an ML-DSA implementation or proven issuer authentication.\n\nOutputs are in reports/ and mathematical_validation/.\n',encoding='utf-8')
    print(json.dumps({'output':str(out),'verdict':verdict,'summary':summaries},indent=2))
    return 0 if all(self_tests.values()) else 2

def main():
    ap=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('--root',default=str(DEFAULT_ROOT))
    ap.add_argument('--output',default=None)
    ap.add_argument('--secret-pixels',type=int,default=4)
    ap.add_argument('--trials',type=int,default=30)
    ap.add_argument('--seed',type=int,default=20261114)
    ap.add_argument('--operators',default='or,dual,leaky')
    ap.add_argument('--max-witnesses',type=int,default=50)
    ap.add_argument('--strict-data',action='store_true')
    ap.add_argument('--no-lattice',dest='lattice',action='store_false')
    ap.set_defaults(lattice=True)
    a=ap.parse_args()
    if not 1<=a.secret_pixels<=10: ap.error('secret-pixels must be 1..10 (exhaustive limit)')
    if not 1<=a.trials<=100000: ap.error('trials must be 1..100000')
    if not 0<=a.max_witnesses<=10000: ap.error('max-witnesses must be 0..10000')
    try: return run(a)
    except Exception as e: print(f'F8_04 ERROR: {e}',file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
