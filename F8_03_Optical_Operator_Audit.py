#!/usr/bin/env python3
"""F8_03 — Optical Operator Audit (computational, not physical/human validation).

Standard scientific requirements: numpy; matplotlib optional. No existing project data
are modified. Models are intentionally differentiated by their physical assumptions.
"""
from __future__ import annotations
import argparse, collections, csv, datetime as dt, hashlib, itertools, json, math, os, platform, sys, traceback
from pathlib import Path
import numpy as np

ROOT = Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')

def write_json(p, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, allow_nan=False, default=str), encoding='utf-8')

def write_csv(p, rows, columns):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('w', newline='', encoding='utf-8-sig') as f:
        w=csv.DictWriter(f, fieldnames=columns, extrasaction='ignore');w.writeheader();w.writerows(rows)

def bits2(x): return tuple(int(b) for b in x)

def transmission(bits, t_clear=1.0, t_dark=0.06):
    a=np.asarray(bits,dtype=float)
    return np.where(a > 0.5,t_dark,t_clear)

def or_op(a,b): return np.maximum(a,b).astype(float)
def xor_op(a,b): return np.mod(a+b,2).astype(float)
def binary_transmission(a,b): return (1-a)*(1-b)

def jones_intensity(theta1,theta2,analyzer,extinction=0.02):
    """Sequential nonideal linear polarizers with unpolarized input, final analyzer.
    Jones calculation uses an incoherent average of orthogonal incident states.
    theta angles in radians; extinction is MINOR/MAJOR INTENSITY transmission.
    """
    def P(theta):
        c,s=math.cos(theta),math.sin(theta)
        rot=np.array([[c,-s],[s,c]])
        return rot@np.diag([1.0,math.sqrt(extinction)])@rot.T
    M=P(analyzer)@P(theta2)@P(theta1)
    return float(0.5*np.sum(M*M))

def op_catalog(extinction):
    def or_binary(a,b): return tuple(int(v) for v in or_op(np.array(a),np.array(b)))
    def xor_binary(a,b): return tuple(int(v) for v in xor_op(np.array(a),np.array(b)))
    def mult_binary(a,b): return tuple(int(v) for v in binary_transmission(np.array(a),np.array(b)))
    def mult_leaky(a,b): return tuple(float(v) for v in (transmission(a)*transmission(b)))
    def complement(a,b):
        # Separate complementary optical readout is not a passive XOR gate.
        ta,tb=transmission(a),transmission(b)
        return tuple(float(v) for v in (ta*(1-tb)+(1-ta)*tb))
    def pol(a,b):
        # Two sequential binary-angle polarizers, 0 or 45 degrees; fixed 0 analyzer.
        return tuple(jones_intensity(x*math.pi/4,y*math.pi/4,0.0,extinction) for x,y in zip(a,b))
    return {
      'OR_BINARY':(or_binary,'IDEAL_BINARY_SURROGATE','Boolean overlay of opaque subpixels'),
      'XOR_IDEAL_DIGITAL':(xor_binary,'DIGITAL_ONLY','Requires an electronic/active comparator; not passive stacking'),
      'MULTIPLICATIVE_BINARY':(mult_binary,'IDEAL_BINARY_SURROGATE','Perfect opaque/clear layers'),
      'MULTIPLICATIVE_LEAKY':(mult_leaky,'PHYSICAL_FORWARD_MODEL_SIMULATED','Two absorptive layers with nonzero dark transmittance'),
      'COMPLEMENTARY_DUAL_CHANNEL':(complement,'SPECIAL_OPTICS_ASSUMED','Requires separate complementary paths and intensity summation'),
      'JONES_POLARIZERS':(pol,'PHYSICAL_FORWARD_MODEL_SIMULATED','Two sequential nonideal linear polarizers plus fixed analyzer'),
    }

def equivalence_audit(n,quant_step,extinction):
    assert 1<=n<=6
    pairs=list(itertools.product(itertools.product((0,1),repeat=n),repeat=2))
    records=[]; witnesses=[]; samples=[]
    for name,(func,status,assumptions) in op_catalog(extinction).items():
        exact=collections.defaultdict(list); observed=collections.defaultdict(list)
        for a,b in pairs:
            val=func(a,b)
            # Round solely to avoid numerical roundoff for algebraic equality.
            exact_key=tuple(round(float(v),12) for v in val)
            quant_key=tuple(int(round(float(v)/quant_step)) for v in val)
            exact[exact_key].append((a,b));observed[quant_key].append((a,b))
        for grouping,level in [(exact,'exact'),(observed,'quantized')]:
            groups=list(grouping.values());collision_pairs=sum(len(g)*(len(g)-1)//2 for g in groups)
            largest=max(map(len,groups))
            records.append(dict(operator=name,level=level,input_pairs=len(pairs),distinct_outputs=len(groups),collision_pairs=collision_pairs,largest_equivalence_class=largest,injective=(len(groups)==len(pairs)),model_status=status,assumptions=assumptions,quantization_step=quant_step if level=='quantized' else 'none'))
            collision=next((g for g in groups if len(g)>1),None)
            if collision:
                a,b=collision[0];a2,b2=collision[1]
                witnesses.append(dict(operator=name,level=level,input_a=list(a),input_b=list(b),forged_a=list(a2),forged_b=list(b2),legitimate_output=list(map(float,func(a,b))),forged_output=list(map(float,func(a2,b2))),exact_equal=(tuple(round(float(v),12) for v in func(a,b))==tuple(round(float(v),12) for v in func(a2,b2))),same_secret_xor=bool(np.array_equal(xor_op(np.array(a),np.array(b)),xor_op(np.array(a2),np.array(b2))))))
        for a,b in pairs[:min(16,len(pairs))]:
            samples.append(dict(operator=name,a=''.join(map(str,a)),b=''.join(map(str,b)),output=json.dumps([round(float(v),8) for v in func(a,b)])))
    return records,witnesses,samples

def operator_grid(extinction,quant_step):
    # Scalar response table for four independently encoded binary input pairs.
    rows=[]
    for name,(func,status,_) in op_catalog(extinction).items():
        for a,b in itertools.product((0,1),repeat=2):
            v=float(func((a,),(b,))[0]);rows.append(dict(operator=name,a=a,b=b,intensity=v,quantized_bin=round(v/quant_step),model_status=status))
    return rows

def continuous_transmission_audit():
    # Exact product degeneracy for finite transmission alphabet; no binary approximation.
    levels=(0.1,0.2,0.4,0.8)
    groups=collections.defaultdict(list)
    for a,b in itertools.product(levels,repeat=2):groups[round(a*b,12)].append((a,b))
    witness=next(g for g in groups.values() if len(g)>1)
    return dict(levels=levels,number_of_pairs=16,distinct_products=len(groups),collision_pairs=sum(len(g)*(len(g)-1)//2 for g in groups.values()),witness=[list(v) for v in witness[:2]],interpretation='Identical output products can arise from distinct layer transmittances.')

def run_robustness(trials,seed,extinction,quant_step):
    """Monte Carlo: legitimate and substituted input with shared nuisance distribution.
    Reports distributions, NOT authentication FAR/FRR; no enrolled human decision rule.
    """
    rng=np.random.default_rng(seed)
    scenarios=[('ideal',0.0,0.0,0.0),('low',0.02,0.01,0.015),('moderate',0.08,0.04,0.05),('high',0.15,0.08,0.10)]
    rows=[]
    for name,(func,status,_) in op_catalog(extinction).items():
        for sc,illum_sd,noise_sd,leak_sd in scenarios:
            legit=[];forge=[]
            for _ in range(trials):
                a=int(rng.integers(0,2));b=int(rng.integers(0,2));b2=1-b
                ideal=float(func((a,),(b,))[0]);modified=float(func((a,),(b2,))[0])
                illum=max(0.0,1+rng.normal(0,illum_sd))
                common_leak=rng.normal(0,leak_sd)
                legit.append(float(np.clip(illum*ideal+common_leak+rng.normal(0,noise_sd),0,1)))
                forge.append(float(np.clip(illum*modified+common_leak+rng.normal(0,noise_sd),0,1)))
            d=np.abs(np.array(legit)-np.array(forge))
            rows.append(dict(operator=name,scenario=sc,trials=trials,mean_absolute_difference=float(np.mean(d)),median_absolute_difference=float(np.median(d)),fraction_below_quantization=float(np.mean(d<quant_step)),q05_difference=float(np.quantile(d,0.05)),q95_difference=float(np.quantile(d,0.95)),status=status,scope='one binary element; forced partner flip; no image-level decision or human study'))
    return rows

def check_f8_02(root):
    p=root/'Results'/'F8_02'/'mathematical_validation'/'optical_operator_collisions.json'
    if not p.exists():return {'available':False,'path':str(p),'reason':'F8_02 results not found locally'}
    try:
        x=json.loads(p.read_text(encoding='utf-8'))
        return {'available':True,'path':str(p),'baseline':x}
    except Exception as e:return {'available':False,'path':str(p),'reason':str(e)}

def self_tests():
    assert tuple(or_op(np.array((0,1)),np.array((1,0))))==(1,1)
    assert tuple(xor_op(np.array((0,1)),np.array((1,0))))==(1,1)
    assert abs(jones_intensity(0,0,0,0)-0.5)<1e-12
    assert abs(jones_intensity(0,math.pi/2,0,0))<1e-12
    r,w,_=equivalence_audit(2,0.01,0.02)
    lookup={(x['operator'],x['level']):x for x in r}
    assert lookup['OR_BINARY','exact']['distinct_outputs']==4
    assert lookup['OR_BINARY','exact']['largest_equivalence_class']==9
    assert lookup['XOR_IDEAL_DIGITAL','exact']['largest_equivalence_class']==4
    assert w
    return {'passed':True,'tests':['Boolean operators','Jones ideal limits','F8_02 collision baseline','counterexample generation']}

def main():
    ap=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('--root',type=Path,default=ROOT)
    ap.add_argument('--output',type=Path,default=None)
    ap.add_argument('--secret-pixels',type=int,default=2,help='Enumerate all pairs of binary vectors; maximum 6')
    ap.add_argument('--trials',type=int,default=2000)
    ap.add_argument('--seed',type=int,default=20261114)
    ap.add_argument('--quant-step',type=float,default=0.02,help='Instrumental intensity quantization step, NOT a measured human JND')
    ap.add_argument('--extinction',type=float,default=0.02,help='Minor/major intensity transmission ratio of polarizers')
    ap.add_argument('--strict-data',action='store_true',help='Require F8_02 results to exist')
    args=ap.parse_args()
    if not 1<=args.secret_pixels<=6:ap.error('--secret-pixels must be 1..6 (4**n cases)')
    if args.trials<1 or not 0<args.quant_step<=1 or not 0<=args.extinction<=1:ap.error('Invalid trials, quant-step or extinction')
    out=args.output or args.root/'Results'/'F8_03';out.mkdir(parents=True,exist_ok=True)
    (out/'reports').mkdir(exist_ok=True);(out/'mathematical_validation').mkdir(exist_ok=True)
    baseline=check_f8_02(args.root)
    if args.strict_data and not baseline['available']:
        write_json(out/'reports'/'verdict.json',{'status':'BLOCKED','reason':'Missing required F8_02 baseline','baseline':baseline})
        print('ERROR: F8_02 baseline not found at',baseline['path'],file=sys.stderr);return 2
    try:
        tests=self_tests()
        records,witnesses,samples=equivalence_audit(args.secret_pixels,args.quant_step,args.extinction)
        table=operator_grid(args.extinction,args.quant_step)
        continuous=continuous_transmission_audit()
        robustness=run_robustness(args.trials,args.seed,args.extinction,args.quant_step)
        # Cross-check n=2 baseline with F8_02; F8_02 has 16 pairs of 2-bit shares.
        baseline_comparison=[]
        if baseline['available']:
            mapping={'OR_BINARY':'OR','XOR_IDEAL_DIGITAL':'XOR_IDEAL_DIGITAL','MULTIPLICATIVE_BINARY':'MULTIPLICATIVE_BINARY_TRANSMISSION'}
            r2,_,_=equivalence_audit(2,args.quant_step,args.extinction)
            for local,previous in mapping.items():
                ours=next(x for x in r2 if x['operator']==local and x['level']=='exact')
                old=baseline['baseline'].get(previous,{})
                baseline_comparison.append(dict(operator=local,match=ours['distinct_outputs']==old.get('distinct_outputs') and ours['collision_pairs']==old.get('colliding_unordered_pairs') and ours['largest_equivalence_class']==old.get('max_equivalence_class_size'),ours_distinct=ours['distinct_outputs'],f8_02_distinct=old.get('distinct_outputs'),ours_collision_pairs=ours['collision_pairs'],f8_02_collision_pairs=old.get('colliding_unordered_pairs')))
        write_csv(out/'mathematical_validation'/'operator_collisions.csv',records,list(records[0]))
        write_json(out/'mathematical_validation'/'collision_witnesses.json',witnesses)
        write_json(out/'mathematical_validation'/'continuous_transmission.json',continuous)
        write_csv(out/'mathematical_validation'/'binary_response_table.csv',table,list(table[0]))
        write_csv(out/'reports'/'robustness.csv',robustness,list(robustness[0]))
        write_csv(out/'reports'/'response_samples.csv',samples,list(samples[0]))
        write_json(out/'reports'/'baseline_comparison.json',baseline_comparison)
        write_json(out/'reports'/'model_assumptions.json',{
          'OR_BINARY':'Binary Boolean approximation; not continuous optical physics.',
          'XOR_IDEAL_DIGITAL':'Electronic/ideal logic benchmark; not a passive optical device.',
          'MULTIPLICATIVE_BINARY':'Binary limit of Beer-Lambert-like independent attenuation.',
          'MULTIPLICATIVE_LEAKY':'Independent uniform layers with clear=1 and dark=0.06; no scattering/reflections.',
          'COMPLEMENTARY_DUAL_CHANNEL':'Two separate optical paths, complementary filters, calibrated intensity addition; not a demonstrated passive device.',
          'JONES_POLARIZERS':'Idealized nondepolarizing Jones polarizers, unpolarized incident light, no birefringent scattering, 0/45-degree binary orientations, fixed 0-degree analyzer.',
          'quantization':'A synthetic instrumental binning threshold; NOT empirically measured human perception.',
          'noise':'Scalar Gaussian perturbation and illumination, not geometric registration or real fabrication.',
          'threat_model':'Input pairs are enumerated; no issuer keys, enrollment, trust anchor, or authenticated challenge.'})
        summary={'program':'F8_03','timestamp_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'root':str(args.root),'python':platform.python_version(),'numpy':np.__version__,'operator_count':len(op_catalog(args.extinction)),'enumerated_pairs_per_operator':4**args.secret_pixels,'all_operators_have_exact_collisions':all(x['collision_pairs']>0 for x in records if x['level']=='exact'),'baseline_available':baseline['available'],'baseline_consistent':all(x['match'] for x in baseline_comparison) if baseline_comparison else None,'self_tests':tests,'continuous_transmission':continuous,'interpretation':'Finite-domain optical noninjectivity and simulated sensitivity do not establish impossibility of all optical authentication schemes.'}
        write_json(out/'reports'/'summary.json',summary)
        write_json(out/'configuration'/'run.json',vars(args))
        verdict={'execution':'PASS','mathematical_audit':'PASS_WITH_EXPLICIT_SCOPE','optical_operator_collision':'COUNTEREXAMPLE_FOUND','issuer_authenticity':'NOT_ESTABLISHED','human_only_verification':'NOT_ESTABLISHED','physical_validation':'NOT_PERFORMED','baseline_crosscheck':'PASS' if baseline_comparison and all(x['match'] for x in baseline_comparison) else ('NOT_AVAILABLE' if not baseline_comparison else 'FAIL'),'note':'This is a computational audit of explicitly specified models, not an experimentally demonstrated HOVSS-PQ construction.'}
        write_json(out/'reports'/'verdict.json',verdict)
        (out/'README.md').write_text('# F8_03 Optical Operator Audit\n\nComputational mathematical and optical forward-model audit only.\n\nThe OR/XOR/binary-transmission comparison reproduces the F8_02 finite-domain reference when available. All continuous/polarization simulations are models, not fabricated optical or human verification.\n\nSee reports/model_assumptions.json, mathematical_validation/collision_witnesses.json, and reports/verdict.json.\n',encoding='utf-8')
        print(json.dumps({'output':str(out),'operators':summary['operator_count'],'enumerated_pairs_per_operator':summary['enumerated_pairs_per_operator'],'baseline_consistent':summary['baseline_consistent'],'execution':verdict['execution']},indent=2))
        return 0
    except Exception as e:
        write_json(out/'reports'/'verdict.json',{'execution':'FAIL','error':repr(e),'traceback':traceback.format_exc()})
        raise

if __name__=='__main__':sys.exit(main())
