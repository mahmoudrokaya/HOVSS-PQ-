#!/usr/bin/env python3
"""F8_08: adaptive adversarial audit of HOVSS-PQ candidates A/B/C.

This is an instrumented computational security experiment, NOT human-only
verification or a proof of post-quantum optical authentication. The script
reuses the actual F8_04/F8_06 optical models if those scripts are beside it,
and F8_07's ML-DSA adapter when available. No fabricated human observations.

Dependencies: Python standard library; optional pqcrypto for real ML-DSA.
Run: python F8_08_Adaptive_Attack_Engine.py --trials 100 --secret-pixels 4 \
       --seed 20261114 --strict-data --require-ml-dsa
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import importlib.util
import json
import math
import os
import platform
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_ROOT = Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')
ATTACKS = ('legitimate','single_subpixel','known_content_reissue','public_anchor_rebinding',
           'full_share_substitution','adaptive_optical_search','reference_substitution',
           'exact_copy','signed_record_tamper','signed_share_replacement')
MODELS = ('or','public_anchor','trusted_stack','trusted_layers','polarization','signed_digital')
FIELDS = ('trial','model','attack','noise','threshold','search_budget','queries_used',
          'actual_changed_subpixels','actual_changed_content_pixels','severity_content',
          'issuer_authorized','reference_compromised','optical_distance','optical_accept',
          'electronic_accept','electronic_signature_valid','electronic_commitments_valid',
          'acceptance_scope','success','baseline_observation_hash','attack_observation_hash')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


def bits(rng,n):
    return tuple(rng.randrange(2) for _ in range(n))


def flip(v,index):
    w=list(v);w[index]^=1;return tuple(w)


def ns_share(secret,rng):
    """Naor-Shamir 2x2 basis; 2 subpixels per secret pixel."""
    a=[];b=[]
    for s in secret:
        r=rng.randrange(2)
        a.extend((r,1-r))
        b.extend((r,1-r) if s==0 else (1-r,r))
    return tuple(a),tuple(b)


def decoded(a,b):
    """Ideal decoder for the baseline OR, not an issuer authentication test."""
    obs=tuple(x|y for x,y in zip(a,b))
    return tuple(int(obs[i]==1 and obs[i+1]==1) for i in range(0,len(obs),2))


def load_previous(name, path):
    if not path.is_file():
        return None, 'not found: '+str(path)
    try:
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module,None
    except Exception as e:
        return None,type(e).__name__+': '+str(e)


def observe(model,a,b,f6=None):
    if model in ('or','public_anchor','trusted_stack','signed_digital'):
        return tuple(float(x|y) for x,y in zip(a,b))
    if model=='trusted_layers':
        # Digital layer-by-layer equality surrogate; not a passive optical device.
        return tuple(float(x) for x in a+b)
    if model=='polarization':
        if f6 is None:
            raise RuntimeError('F8_06 module is required for polarization')
        return tuple(f6.stack(a,b,'polarization',0.01,math.pi/2,math.pi/4))
    raise ValueError(model)


def mean_abs(a,b):
    assert len(a)==len(b)
    return sum(abs(x-y) for x,y in zip(a,b))/len(a)


def quant_hash(v):
    return sha(canonical([round(float(x),9) for x in v]))


def random_noise(v,rng,sigma):
    if sigma==0:return v
    return tuple(max(0.0,min(1.0,x+rng.gauss(0,sigma))) for x in v)


def sign_record(f7,crypto,record):
    msg=f7.encoded_record(record)
    sig=f7.sign_message(crypto['sign'],crypto['sk'],msg,crypto['context_support'])
    return sig


def electronic_status(f7,crypto,record,sig,pk,shares,anchor):
    """Returns None values if ML-DSA is not available. Never a fake signature."""
    if crypto is None or f7 is None:
        return None,None,None
    valid=f7.verify_ok(crypto['verify'],pk,f7.encoded_record(record),sig,crypto['context_support'])
    commits=(record.get('share_commitments')==[f7.sha(''.join(map(str,s)).encode()) for s in shares]
             and record.get('anchor_commitment')==f7.sha(''.join(map(str,anchor)).encode()))
    return bool(valid),bool(commits),bool(valid and commits)


def build_record(f7,secret,shares,anchor,trial):
    return f7.make_record(''.join(map(str,secret)),
                          [''.join(map(str,s)) for s in shares],
                          ''.join(map(str,anchor)), 'ISSUER_A',f'F8_08_{trial:06d}')


def attack_proposal(kind,secret,a,b,anchor,record,rng,model,reference):
    """Return altered shares, anchor, record, reference, and compromise flag.

    A change to the digital record alone cannot change optical output. This is
    intentional and exposes the cryptographic-to-optical binding gap.
    """
    aa,bb=a,b; anch=anchor; rec=dict(record) if record is not None else None
    ref=reference; compromised=False
    if kind=='single_subpixel':
        aa=flip(a,rng.randrange(len(a)))
    elif kind=='known_content_reissue':
        aa,bb=ns_share(secret,rng)
    elif kind=='public_anchor_rebinding':
        # Public anchor is recomputed after unauthorized issuer-label change.
        if rec is not None:rec['issuer_id']='ATTACKER'
        anch=tuple(rng.randrange(2) for _ in anchor)
        aa,bb=ns_share(secret,rng)
    elif kind=='full_share_substitution':
        other=flip(secret,rng.randrange(len(secret)))
        aa,bb=ns_share(other,rng)
    elif kind=='reference_substitution':
        other=flip(secret,rng.randrange(len(secret)))
        aa,bb=ns_share(other,rng)
        ref=observe(model,aa,bb, None) if model!='polarization' else None
        compromised=True
    elif kind=='signed_record_tamper':
        if rec is not None:rec['issuer_id']='ATTACKER'
    elif kind=='signed_share_replacement':
        aa=flip(a,rng.randrange(len(a)))
    elif kind in ('legitimate','exact_copy'):
        pass
    else:raise ValueError(kind)
    return aa,bb,anch,rec,ref,compromised


def adaptive_search(model,a,b,target,rng,budget,f6):
    """Black-box oracle returns minimum-distance altered presentation.

    Includes random local mutations and random reissues. No hidden issuer keys.
    The number of calls to the observation oracle is recorded.
    """
    best=None;best_d=float('inf');queries=0
    for q in range(budget):
        if q%3==0:
            aa=flip(a,rng.randrange(len(a)));bb=b
        elif q%3==1:
            aa=a;bb=flip(b,rng.randrange(len(b)))
        else:
            aa=tuple(flip(a,rng.randrange(len(a))));bb=tuple(flip(b,rng.randrange(len(b))))
        if (aa,bb)==(a,b):continue
        o=observe(model,aa,bb,f6);queries+=1
        d=mean_abs(target,o)
        if d<best_d:
            best_d=d;best=(aa,bb)
            if d==0:break
    return best,best_d,queries


def ci_wilson(k,n,z=1.959963984540054):
    if not n:return [None,None]
    p=k/n;d=1+z*z/n;c=(p+z*z/(2*n))/d
    h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [max(0,c-h),min(1,c+h)]


def save_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True,ensure_ascii=False,allow_nan=False)+'\n',encoding='utf-8')


def save_csv(path,rows,columns):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as fp:
        w=csv.DictWriter(fp,fieldnames=columns,extrasaction='ignore');w.writeheader();w.writerows(rows)


def self_tests(f6):
    rng=random.Random(99)
    a,b=ns_share((0,1,0,1),rng)
    assert decoded(a,b)==(0,1,0,1)
    assert observe('or',(0,1),(0,1))==(0.0,1.0)
    assert observe('trusted_layers',(0,1),(1,0))==(0.,1.,1.,0.)
    assert mean_abs((0.,1.),(1.,1.))==.5
    assert ci_wilson(0,10)[0]==0
    assert quant_hash((0.2,))==quant_hash((0.2,))
    if f6:
        o=observe('polarization',a,b,f6)
        assert len(o)==len(a) and all(0<=x<=1.00001 for x in o)
    return {'passed':6+int(f6 is not None),'failed':0}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=DEFAULT_ROOT)
    p.add_argument('--output',type=Path,default=None)
    p.add_argument('--trials',type=int,default=100)
    p.add_argument('--secret-pixels',type=int,default=4)
    p.add_argument('--seed',type=int,default=20261114)
    p.add_argument('--search-budget',type=int,default=100)
    p.add_argument('--noise-levels',type=float,nargs='+',default=[0.,.01,.05])
    p.add_argument('--thresholds',type=float,nargs='+',default=[0.,.02,.05])
    p.add_argument('--max-witnesses',type=int,default=120)
    p.add_argument('--strict-data',action='store_true')
    p.add_argument('--require-ml-dsa',action='store_true')
    args=p.parse_args(argv)
    if not (1<=args.secret_pixels<=256 and 1<=args.trials<=100000 and 1<=args.search_budget<=100000):
        p.error('invalid secret-pixels, trials or search-budget')
    if any(x<0 or x>1 for x in args.noise_levels+args.thresholds):p.error('noise/threshold must be within [0,1]')
    root=args.root.expanduser()
    output=args.output or root/'Results'/'F8_08'
    for folder in ('configuration','reports','mathematical_validation','logs'):
        (output/folder).mkdir(parents=True,exist_ok=True)
    deps={f'F8_{i:02d}':(root/'Results'/f'F8_{i:02d}').is_dir() for i in range(1,8)}
    if args.strict_data and not all(deps.values()):
        print('BLOCKED: missing result folders: '+', '.join(k for k,v in deps.items() if not v),file=sys.stderr)
        save_json(output/'reports'/'verdict.json',{'status':'BLOCKED','missing':[k for k,v in deps.items() if not v]})
        return 2
    local=Path(__file__).resolve().parent
    f6,e6=load_previous('f8_06_dependency',local/'F8_06_Polarization_Construction.py')
    f7,e7=load_previous('f8_07_dependency',local/'F8_07_Cryptographic_Binding_Audit.py')
    f4,e4=load_previous('f8_04_dependency',local/'F8_04_Lattice_Anchor_Construction.py')
    if f6 is None:
        print('BLOCKED: F8_06 source is required for polarization: '+str(e6),file=sys.stderr)
        save_json(output/'reports'/'verdict.json',{'status':'BLOCKED','reason':e6})
        return 3
    if f4 is None:
        print('BLOCKED: F8_04 source is required for public anchor: '+str(e4),file=sys.stderr)
        save_json(output/'reports'/'verdict.json',{'status':'BLOCKED','reason':e4})
        return 3
    backend_info={'available':False,'reason':'F8_07 source unavailable'}
    crypto=None
    if f7:
        backend,backend_info=f7.resolve_backend()
        if backend:
            try:
                crypto=f7.negotiate(backend)
                backend_info['roundtrip']=True
                backend_info['context_support']=crypto['context_support']
                backend_info['public_key_size']=crypto['public_key_size']
                backend_info['signature_size']=crypto['signature_size']
            except Exception as exc:
                backend_info['roundtrip']=False
                backend_info['error']=str(exc)
    if args.require_ml_dsa and crypto is None:
        print('BLOCKED: real ML-DSA unavailable; use pqcrypto or omit --require-ml-dsa',file=sys.stderr)
        save_json(output/'reports'/'verdict.json',{'status':'BLOCKED','reason':'ML-DSA unavailable','backend':backend_info})
        return 4
    save_json(output/'configuration'/'run.json',{'root':str(root),'output':str(output),'trials':args.trials,
       'secret_pixels':args.secret_pixels,'seed':args.seed,'search_budget':args.search_budget,
       'noise_levels':args.noise_levels,'thresholds':args.thresholds,'strict_data':args.strict_data,
       'require_ml_dsa':args.require_ml_dsa,'models':MODELS,'attacks':ATTACKS})
    save_json(output/'reports'/'dependency_audit.json',{'results':deps,'sources':{'F8_04':e4 or 'loaded','F8_06':e6 or 'loaded','F8_07':e7 or 'loaded'}})
    save_json(output/'reports'/'crypto_backend.json',backend_info)
    tests=self_tests(f6);save_json(output/'reports'/'self_tests.json',tests)
    rng=random.Random(args.seed)
    rows=[];witnesses=[]
    for t in range(args.trials):
        secret=bits(rng,args.secret_pixels)
        a,b=ns_share(secret,rng)
        record=f7.make_record(''.join(map(str,secret)),[''.join(map(str,a)),''.join(map(str,b))],
                             ''.join(map(str,secret)),'ISSUER_A',f'F8_08_{t:06d}') if f7 else None
        anchor=f4.flat_anchor(f4.make_record(secret),args.secret_pixels)
        sig=sign_record(f7,crypto,record) if crypto else None
        for model in MODELS:
            baseline=observe(model,a,b,f6)
            for attack in ATTACKS:
                if attack=='adaptive_optical_search':
                    pair,_,queries=adaptive_search(model,a,b,baseline,rng,args.search_budget,f6)
                    aa,bb=pair;anch=anchor;rec=dict(record) if record else None;ref=baseline;compromised=False
                else:
                    aa,bb,anch,rec,ref,compromised=attack_proposal(attack,secret,a,b,anchor,record,rng,model,baseline)
                    queries=0
                    if attack=='reference_substitution' and model=='polarization':
                        ref=observe(model,aa,bb,f6)
                obs=observe(model,aa,bb,f6)
                changed=sum(x!=y for x,y in zip(a+b,aa+bb))
                changed_content=sum(x!=y for x,y in zip(secret,decoded(aa,bb)))
                # For the public-anchor candidate, a public recomputation is NOT issuer authorization.
                if model=='public_anchor' and attack=='public_anchor_rebinding':
                    anch=f4.flat_anchor(f4.make_record(decoded(aa,bb),issuer='ATTACKER'),args.secret_pixels)
                sign_ok,commit_ok,e_accept=electronic_status(f7,crypto,rec,sig,crypto['pk'] if crypto else None,(aa,bb),secret)
                # The F8_07 signed record uses the original secret as the anchor payload.
                if model=='signed_digital':
                    sign_ok,commit_ok,e_accept=electronic_status(f7,crypto,rec,sig,crypto['pk'] if crypto else None,(aa,bb),secret)
                for noise in args.noise_levels:
                    # Same perturbation draw across thresholds to avoid threshold-selection bias.
                    measured=random_noise(obs,rng,noise)
                    target=ref if model in ('trusted_stack','trusted_layers') else baseline
                    d=mean_abs(target,measured)
                    for threshold in args.thresholds:
                        optical_accept=d<=threshold+1e-12
                        # Only digital model has an electronic decision; all others report it as auxiliary.
                        if model=='signed_digital':
                            success=e_accept if e_accept is not None else None
                            scope='ELECTRONIC_ML_DSA_AND_COMMITMENTS' if e_accept is not None else 'UNAVAILABLE'
                        else:
                            success=optical_accept
                            scope=('IDEAL_DIGITAL_LAYER_COMPARISON' if model=='trusted_layers' else
                                   'TRUSTED_REFERENCE_SIMULATION' if model=='trusted_stack' else
                                   'PUBLIC_OPTICAL_REFERENCE_SIMULATION')
                        row={'trial':t,'model':model,'attack':attack,'noise':noise,'threshold':threshold,
                             'search_budget':args.search_budget if attack=='adaptive_optical_search' else 0,
                             'queries_used':queries,'actual_changed_subpixels':changed,
                             'actual_changed_content_pixels':changed_content,
                             'severity_content':changed_content/len(secret),
                             'issuer_authorized':int(attack=='legitimate'),
                             'reference_compromised':int(compromised),
                             'optical_distance':round(d,12),'optical_accept':int(optical_accept),
                             'electronic_accept':None if e_accept is None else int(e_accept),
                             'electronic_signature_valid':None if sign_ok is None else int(sign_ok),
                             'electronic_commitments_valid':None if commit_ok is None else int(commit_ok),
                             'acceptance_scope':scope,
                             'success':None if success is None else int(success),
                             'baseline_observation_hash':quant_hash(baseline),
                             'attack_observation_hash':quant_hash(obs)}
                        rows.append(row)
                        if attack!='legitimate' and success and len(witnesses)<args.max_witnesses:
                            witnesses.append({'trial':t,'model':model,'attack':attack,'noise':noise,
                               'threshold':threshold,'original_shares':[a,b],
                               'presented_shares':[aa,bb],
                               'reference_compromised':compromised,
                               'baseline_observation':baseline,'presented_observation':obs,
                               'optical_distance':d,'queries_used':queries,
                               'electronic_accept':e_accept,'scope':scope})
        if (t+1)%max(1,args.trials//10)==0:
            print(f'Completed {t+1}/{args.trials} trials',flush=True)
    save_csv(output/'reports'/'trial_results.csv',rows,FIELDS)
    groups=defaultdict(list)
    for row in rows:groups[(row['model'],row['attack'],row['noise'],row['threshold'])].append(row)
    summary_rows=[]
    for (model,attack,noise,threshold),rr in sorted(groups.items()):
        optical=sum(x['optical_accept'] for x in rr)
        usable=[x['success'] for x in rr if x['success'] is not None]
        accepted=sum(usable)
        summary_rows.append({'model':model,'attack':attack,'noise':noise,'threshold':threshold,
            'n':len(rr),'n_decidable':len(usable),'optical_acceptance_rate':optical/len(rr),
            'acceptance_rate':accepted/len(usable) if usable else None,
            'wilson95_lower':ci_wilson(accepted,len(usable))[0],
            'wilson95_upper':ci_wilson(accepted,len(usable))[1],
            'mean_optical_distance':statistics.fmean(x['optical_distance'] for x in rr),
            'mean_changed_content_pixels':statistics.fmean(x['actual_changed_content_pixels'] for x in rr),
            'mean_oracle_queries':statistics.fmean(x['queries_used'] for x in rr)})
    save_csv(output/'reports'/'attack_summary.csv',summary_rows,list(summary_rows[0]))
    save_json(output/'mathematical_validation'/'attack_witnesses.json',witnesses)
    assumptions={'human_only_verified':False,'physical_prototype':False,
       'cryptographic_binding_to_optical':False,
       'models':{'or':'OR reconstruction with PUBLIC expected observation (simulation)',
         'public_anchor':'Public F8_04 lattice-style anchor recomputation; anchor not physically embedded in optical response',
         'trusted_stack':'Independently protected reconstructed-stack reference; simulated numerical comparator',
         'trusted_layers':'Ideal DIGITAL comparison of both original share layers; not passive optics',
         'polarization':'F8_06 ideal Jones response; simulated numerical comparator',
         'signed_digital':'Real ML-DSA signature and digital commitments if pqcrypto available; NOT optical signature checking'},
       'reference_substitution':'Attacker controls expected reference; models without a reference cannot be judged secure under this attack',
       'noise':'Independent additive Gaussian intensity noise clipped to [0,1], not hardware calibrated',
       'attack_success':'Acceptance of an unauthorized presentation by the stated model, not human acceptance',
       'exact_copy':'Observationally identical copies cannot be distinguished by static comparison',
       'privacy':'Not tested by F8_08; unauthorized views with references require separate privacy analysis',
       'attack_search':'Bounded randomized black-box local search; failure does not prove security',
       'limitations':['No optical hardware','No human subjects','No issuer-dependent optical verifier',
                      'Reference baseline is assumed enrolled for trusted models',
                      'Public anchor is not a complete authenticated optical encoding',
                      'Electronic signature experiments do not prove PQ optical authentication']}
    save_json(output/'reports'/'model_assumptions.json',assumptions)
    save_json(output/'reports'/'summary.json',{'status':'COMPLETED_SIMULATION','trials':args.trials,
        'trial_rows':len(rows),'summary_rows':len(summary_rows),'witnesses_saved':len(witnesses),
        'ml_dsa_executed':crypto is not None,'models':MODELS,'attacks':ATTACKS,
        'notable':{'exact_copy_observation_unchanged':True,'issuer_optical_binding_established':False}})
    save_json(output/'reports'/'verdict.json',{'execution':'PASS','self_tests':tests,
        'candidate_authentication':'NOT_ESTABLISHED','human_only_verification':'NOT_ESTABLISHED',
        'physical_validation':'NOT_PERFORMED','ml_dsa_electronic_control':'PASS' if crypto else 'UNAVAILABLE',
        'interpretation':'Computational adversarial baseline; inspect attack_summary.csv and witnesses.'})
    print(json.dumps({'status':'COMPLETED_SIMULATION','output':str(output),'rows':len(rows),
                      'ml_dsa_executed':crypto is not None,'witnesses':len(witnesses)},indent=2))
    return 0

if __name__=='__main__':
    sys.exit(main())
