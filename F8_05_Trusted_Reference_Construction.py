#!/usr/bin/env python3
"""F8_05: Trusted-reference optical construction audit (Candidate B).

Research simulator, NOT a demonstrated physical verifier or PQ authenticator.
Python standard library only. Outputs reproducible JSON/CSV reports.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, math, os, platform, random, sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ROOT = Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')
MODES = ('or_only', 'enrolled_stack', 'enrolled_layers')
ATTACKS = ('single_subpixel', 'public_reissue', 'known_content_reissue', 'full_replacement', 'reference_swap', 'exact_copy')


def share(secret, rng):
    """Classic (2,2) VC: each bit maps to 2 subpixels, share1 uniform."""
    a=[]; b=[]
    for bit in secret:
        t=rng.randrange(2)
        first=(t,1-t)
        second=first if bit==0 else first[::-1]
        a.extend(first); b.extend(second)
    return tuple(a),tuple(b)


def stack(a,b):
    return tuple(x|y for x,y in zip(a,b))


def observation(mode,a,b):
    if mode=='or_only': return stack(a,b)
    if mode=='enrolled_stack': return stack(a,b)
    if mode=='enrolled_layers': return a+b
    raise ValueError(mode)


def reference_for(mode,a,b):
    return observation(mode,a,b)


def hamming(a,b):
    return sum(x!=y for x,y in zip(a,b))/len(a)


def noise(values,rng,p):
    return tuple(1-x if rng.random()<p else x for x in values)


def evaluate(mode, ref, a,b, noise_probability, threshold,rng):
    seen=noise(observation(mode,a,b),rng,noise_probability)
    return hamming(seen,ref)<=threshold


def attack(kind, secret, a,b, ref, mode,rng):
    """Return forged shares and (possibly substituted) reference.

    Reference_swap models adversarial control over the trusted anchor, hence
    is explicitly OUTSIDE protected-custody security assumptions.
    """
    if kind=='single_subpixel':
        aa=list(a); i=rng.randrange(len(aa)); aa[i]^=1
        return tuple(aa),b,ref
    if kind in ('public_reissue','known_content_reissue'):
        aa,bb=share(secret,rng)
        return aa,bb,ref
    if kind=='full_replacement':
        other=tuple(1-x for x in secret)
        aa,bb=share(other,rng)
        return aa,bb,ref
    if kind=='reference_swap':
        other=tuple(1-x for x in secret)
        aa,bb=share(other,rng)
        return aa,bb,reference_for(mode,aa,bb)
    if kind=='exact_copy':
        return a,b,ref
    raise ValueError(kind)


def write_json(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def write_csv(path,rows,fields):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)


def self_tests():
    r=random.Random(13)
    for n in range(1,7):
        for value in range(1<<n):
            s=tuple((value>>i)&1 for i in range(n))
            a,b=share(s,r)
            assert len(a)==2*n and len(b)==2*n
            assert all(sum(a[2*i:2*i+2])==1 for i in range(n))
            assert all(sum(b[2*i:2*i+2])==1 for i in range(n))
            assert tuple(int(sum(stack(a,b)[2*i:2*i+2])==2) for i in range(n))==s
            assert observation('enrolled_layers',a,b)==a+b
    assert hamming((0,1),(1,1))==0.5
    return {'passed':True,'secret_sizes_tested':list(range(1,7))}


def privacy_audit(n):
    """Exact marginal single-share distributions, and reference exposure.

    A full enrolled_layers reference contains both shares and reveals the
    secret. A public OR reference also reveals the secret in this baseline.
    """
    return {
      'single_share_uniform_distribution': 'PROVEN_ALGEBRAICALLY for independent fair permutation bits',
      'proof_scope':'Each two-subpixel share block is a uniform choice of (0,1) or (1,0), independent of secret bit.',
      'public_reference_leakage':{
          'or_only':'OR reconstruction reveals secret to anyone observing the stack',
          'enrolled_stack':'Enrolled OR reference reveals the reconstructed secret if disclosed',
          'enrolled_layers':'Enrolled pair of full shares reveals the reconstructed secret if disclosed'},
      'combined_view_privacy':'NOT_ESTABLISHED when reference or reconstructed stack is exposed',
      'secret_pixels':n
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=DEFAULT_ROOT)
    p.add_argument('--output',type=Path,default=None)
    p.add_argument('--secret-pixels',type=int,default=4)
    p.add_argument('--trials',type=int,default=30)
    p.add_argument('--seed',type=int,default=20261114)
    p.add_argument('--noise-levels',default='0,0.01,0.05')
    p.add_argument('--thresholds',default='0,0.05,0.15')
    p.add_argument('--strict-data',action='store_true')
    args=p.parse_args(argv)
    if not 1<=args.secret_pixels<=12: p.error('--secret-pixels must be 1..12')
    if not 1<=args.trials<=100000: p.error('--trials must be 1..100000')
    try:
        noises=[float(x) for x in args.noise_levels.split(',')]
        thresholds=[float(x) for x in args.thresholds.split(',')]
        if not noises or not thresholds or any(not 0<=x<=1 for x in noises+thresholds):raise ValueError()
    except ValueError:p.error('noise levels and thresholds must be comma-separated numbers in [0,1]')
    out=args.output or (args.root/'Results'/'F8_05')
    previous=[f'F8_0{i}' for i in range(1,5)]
    deps={k:(args.root/'Results'/k).exists() for k in previous}
    if args.strict_data and not all(deps.values()):
        p.error('Missing prerequisite result directories: '+', '.join(k for k,v in deps.items() if not v))
    tests=self_tests()
    rng=random.Random(args.seed)
    aggregate=defaultdict(lambda:[0,0])
    examples=[]
    total=(1<<args.secret_pixels)*args.trials*len(MODES)*len(noises)*len(thresholds)
    print(f'F8_05 starting: {total:,} legitimate trials and {total*len(ATTACKS):,} adversarial trials',flush=True)
    # Paired experiment: identical random noise stream for each legitimate/attack
    # is NOT used, because decisions require independent acquisition noise.
    for value in range(1<<args.secret_pixels):
        secret=tuple((value>>i)&1 for i in range(args.secret_pixels))
        for trial in range(args.trials):
            a,b=share(secret,rng)
            for mode in MODES:
                ref=reference_for(mode,a,b)
                for noise_p in noises:
                    for threshold in thresholds:
                        key=(mode,noise_p,threshold,'legitimate')
                        aggregate[key][1]+=1
                        if evaluate(mode,ref,a,b,noise_p,threshold,rng):aggregate[key][0]+=1
                        for kind in ATTACKS:
                            aa,bb,rr=attack(kind,secret,a,b,ref,mode,rng)
                            key=(mode,noise_p,threshold,kind)
                            aggregate[key][1]+=1
                            accepted=evaluate(mode,rr,aa,bb,noise_p,threshold,rng)
                            if accepted:aggregate[key][0]+=1
                            if len(examples)<120 and noise_p==0 and threshold==0 and kind!='exact_copy' and accepted:
                                examples.append({'secret':''.join(map(str,secret)),'trial':trial,'mode':mode,'attack':kind,
                                                 'original_share1':''.join(map(str,a)), 'original_share2':''.join(map(str,b)),
                                                 'forged_share1':''.join(map(str,aa)),'forged_share2':''.join(map(str,bb)),
                                                 'reference_changed':rr!=ref,'optical_equivalent':observation(mode,aa,bb)==observation(mode,a,b)})
        print(f'Completed {value+1}/{1<<args.secret_pixels} secret patterns',flush=True)
    rows=[]
    for (mode,noise_p,threshold,kind),(accepted,count) in sorted(aggregate.items()):
        rows.append({'mode':mode,'noise_probability':noise_p,'decision_threshold':threshold,'presentation':kind,
                     'accepted':accepted,'total':count,'acceptance_rate':round(accepted/count,8)})
    by={(r['mode'],r['noise_probability'],r['decision_threshold'],r['presentation']):r for r in rows}
    metrics=[]
    for mode in MODES:
        for np in noises:
            for th in thresholds:
                legitimate=by[(mode,np,th,'legitimate')]
                for kind in ATTACKS:
                    adversarial=by[(mode,np,th,kind)]
                    metrics.append({'mode':mode,'noise_probability':np,'decision_threshold':th,'attack':kind,
                                    'false_rejection_rate':round(1-legitimate['acceptance_rate'],8),
                                    'forgery_acceptance_rate':adversarial['acceptance_rate'],
                                    'trials':adversarial['total'],
                                    'custody_assumption':'COMPROMISED' if kind=='reference_swap' else 'PROTECTED',
                                    'note':'Exact-copy indistinguishability' if kind=='exact_copy' else ''})
    config={'root':str(args.root),'output':str(out),'secret_pixels':args.secret_pixels,'trials_per_secret':args.trials,
            'seed':args.seed,'noise_levels':noises,'thresholds':thresholds,'modes':MODES,'attacks':ATTACKS,
            'strict_data':args.strict_data,'timestamp_utc':datetime.now(timezone.utc).isoformat()}
    assumptions={
       'construction':'Classical Naor-Shamir (2,2) VC shares with an independently enrolled reference',
       'issuer_enrollment':'Reference assumed securely enrolled and authenticated externally; NOT cryptographically proven here',
       'reference_models':{
          'or_only':'No protected enrolled reference; comparison against original OR output is a diagnostic oracle, not implementable by unaided inspection without expected image',
          'enrolled_stack':'Trusted stored expected OR image; comparison is digital idealized equality with threshold',
          'enrolled_layers':'Trusted stored complete original share vectors; comparison is digital idealized equality with threshold, NOT a demonstrated passive optical operation'},
       'noise':'Independent Bernoulli bit-flip acquisition noise, not calibrated physical optics',
       'human_verification':'NOT_TESTED', 'post_quantum_authentication':'NOT_IMPLEMENTED',
       'optical_device_independence':'NOT_ESTABLISHED',
       'issuer_authentication':'CONDITIONAL on external custody and enrolled-reference provenance; exact copies remain indistinguishable',
       'privacy_warning':'A disclosed full reference can reveal secret; single-share privacy alone is insufficient',
       'security_warning':'An enrolled expected optical pattern is an idealized comparator. Physical and human realization is prospective.'}
    verdict={
       'execution':'PASS','self_tests':'PASS','single_share_privacy':'PROVEN_ALGEBRAICALLY for baseline',
       'reference_privacy':'NOT_ESTABLISHED','optical_content_integrity':'FAILED for OR masking; CONDITIONAL for enrolled-layer ideal comparator',
       'issuer_authentication':'NOT_ESTABLISHED','post_quantum_authentication':'NOT_IMPLEMENTED',
       'human_only_verification':'NOT_ESTABLISHED','physical_validation':'NOT_PERFORMED',
       'exact_copy_resistance':'IMPOSSIBLE under static identical observations',
       'candidate_B':'RESTRICTED ENGINEERING BASELINE; not a validated HOVSS-PQ construction'}
    summary={'config':config,'dependencies':deps,'self_tests':tests,'number_of_records':len(rows),
             'number_of_attack_metric_rows':len(metrics),'number_of_counterexample_witnesses':len(examples),
             'baseline_zero_noise_zero_threshold':[
                 r for r in rows if r['noise_probability']==0 and r['decision_threshold']==0],
             'verdict':verdict}
    write_json(out/'configuration'/'run.json',config)
    write_json(out/'configuration'/'environment.json',{'python':sys.version,'platform':platform.platform(),'stdlib_only':True})
    write_json(out/'mathematical_validation'/'privacy_audit.json',privacy_audit(args.secret_pixels))
    write_json(out/'mathematical_validation'/'counterexamples.json',examples)
    write_json(out/'reports'/'dependency_audit.json',deps)
    write_json(out/'reports'/'model_assumptions.json',assumptions)
    write_json(out/'reports'/'self_tests.json',tests)
    write_csv(out/'reports'/'acceptance_rates.csv',rows,['mode','noise_probability','decision_threshold','presentation','accepted','total','acceptance_rate'])
    write_csv(out/'reports'/'attack_metrics.csv',metrics,['mode','noise_probability','decision_threshold','attack','false_rejection_rate','forgery_acceptance_rate','trials','custody_assumption','note'])
    write_json(out/'reports'/'summary.json',summary)
    write_json(out/'reports'/'verdict.json',verdict)
    print(json.dumps({'output':str(out),'status':'PASS','attack_metric_rows':len(metrics),'counterexamples':len(examples)},indent=2))
    return 0

if __name__=='__main__':
    sys.exit(main())
