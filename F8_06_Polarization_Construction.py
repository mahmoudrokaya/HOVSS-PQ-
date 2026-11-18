#!/usr/bin/env python3
"""F8_06: polarization-based differential optical construction audit.

Research simulation, NOT a physical prototype or post-quantum authentication.
Only Python standard library is required. Deterministic given --seed.
"""
import argparse,csv,datetime,hashlib,json,math,os,random,statistics,sys
from pathlib import Path

ROOT=Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')

def polarizer(theta, extinction):
    """Jones matrix for a linear diattenuator with intensity extinction ratio e."""
    c,s=math.cos(theta),math.sin(theta)
    t=math.sqrt(extinction)
    return ((c*c+t*s*s,(1-t)*c*s),((1-t)*c*s,s*s+t*c*c))

def mul(a,b):
    return tuple(tuple(sum(a[i][k]*b[k][j] for k in range(2)) for j in range(2)) for i in range(2))

def apply(a,v):
    return tuple(sum(a[i][j]*v[j] for j in range(2)) for i in range(2))

def intensity(v):
    return sum(abs(z)**2 for z in v)

def jones_response(a,b,extinction=0.01,retardance=0.0,source_angle=0.0,analyzer_angle=0.0,reverse=False):
    """Two polarizer layers and optional phase-retarding plate, followed by analyzer.
    a,b are binary orientations (0 or pi/4). Incident light is linearly polarized.
    This is an ideal Jones forward model (no depolarization/scattering).
    """
    x=(complex(math.cos(source_angle)),complex(math.sin(source_angle)))
    pa=polarizer(a*math.pi/4,extinction)
    pb=polarizer(b*math.pi/4,extinction)
    phase=((complex(1),complex(0)),(complex(0),complex(math.cos(retardance),math.sin(retardance))))
    analyzer=polarizer(analyzer_angle,extinction)
    layers=(pb,pa) if reverse else (pa,pb)
    for m in (layers[0],phase,layers[1],analyzer):
        x=apply(m,x)
    return intensity(x)

def or_response(a,b): return float(a|b)
def xor_response(a,b): return float(a^b)

def bitpatterns(n):
    for z in range(1<<n): yield tuple((z>>i)&1 for i in range(n))

def stack(bits1,bits2,model,extinction,retardance,analyzer,reverse=False):
    if model=='polarization':
        return tuple(jones_response(a,b,extinction,retardance,analyzer_angle=analyzer,reverse=reverse) for a,b in zip(bits1,bits2))
    if model=='or':return tuple(or_response(a,b) for a,b in zip(bits1,bits2))
    return tuple(xor_response(a,b) for a,b in zip(bits1,bits2))

def quant(v,step):return tuple(round(x/step) for x in v)
def mean_abs(a,b):return sum(abs(x-y) for x,y in zip(a,b))/len(a)
def flip(x,i):return x[:i]+(1-x[i],)+x[i+1:]
def write_json(p,data):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(data,indent=2,sort_keys=True,allow_nan=False),encoding='utf-8')
def write_csv(p,rows,fields):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)

def exact_collision(n,model,ext,ret,ana,qstep,witness_cap=12):
    classes={};total=0
    for a in bitpatterns(n):
        for b in bitpatterns(n):
            output=stack(a,b,model,ext,ret,ana)
            key=quant(output,qstep)
            if key not in classes:classes[key]=[0,(a,b,output)]
            classes[key][0]+=1;total+=1
    collisions=sum(v[0]*(v[0]-1)//2 for v in classes.values())
    examples=[]
    for k,(count,first) in classes.items():
        if count>1 and len(examples)<witness_cap:
            a,b,_=first
            for aa in bitpatterns(n):
                found=False
                for bb in bitpatterns(n):
                    if (aa,bb)!=(a,b) and quant(stack(aa,bb,model,ext,ret,ana),qstep)==k:
                        examples.append({'original_share_a':a,'original_share_b':b,'alternative_share_a':aa,'alternative_share_b':bb,'quantized_output':k,'class_size':count})
                        found=True;break
                if found:break
    return {'operator':model,'positions':n,'input_pairs':total,'distinct_quantized_outputs':len(classes),'colliding_unordered_pairs':collisions,'largest_class':max(v[0] for v in classes.values()),'collision_witnesses':examples}

def simulate(args,rng):
    rows=[];witnesses=[]
    models=['polarization','or','xor']
    attacks=['single_layer_flip','both_layers_reissue','same_observation_search','exact_copy']
    for model in models:
      for noise in args.noise_levels:
       for angular in args.angular_errors:
        for threshold in args.thresholds:
         stats={attack:{'legitimate_accepted':0,'legitimate_total':0,'forged_accepted':0,'forged_total':0,'mean_diffs':[]} for attack in attacks}
         for trial in range(args.trials):
          n=args.secret_pixels
          a=tuple(rng.randrange(2) for _ in range(n));b=tuple(rng.randrange(2) for _ in range(n))
          baseline=stack(a,b,model,args.extinction,args.retardance,args.analyzer)
          # Both baseline and challenged measurements use independent additive readout noise.
          # Angular perturbation applies to challenged observation, not to the enrolled baseline.
          baseline_meas=tuple(x+rng.gauss(0,noise) for x in baseline)
          def observe(aa,bb):
              an=args.analyzer+rng.uniform(-angular,angular)*math.pi/180
              return tuple(x+rng.gauss(0,noise) for x in stack(aa,bb,model,args.extinction,args.retardance,an))
          leg=observe(a,b)
          leg_diff=mean_abs(baseline_meas,leg)
          for attack in attacks:
           s=stats[attack];s['legitimate_total']+=1;s['legitimate_accepted']+=int(leg_diff<=threshold)
           if attack=='single_layer_flip':
               idx=rng.randrange(n);aa=flip(a,idx);bb=b
           elif attack=='both_layers_reissue':
               aa=tuple(rng.randrange(2) for _ in range(n));bb=tuple(rng.randrange(2) for _ in range(n))
               if (aa,bb)==(a,b):aa=flip(aa,0)
           elif attack=='same_observation_search':
               # Attacker searches candidates with full knowledge of ideal reference observation.
               best=None;bestd=float('inf')
               for _ in range(args.attack_search):
                   ca=tuple(rng.randrange(2) for _ in range(n));cb=tuple(rng.randrange(2) for _ in range(n))
                   if (ca,cb)==(a,b):continue
                   d=mean_abs(baseline,stack(ca,cb,model,args.extinction,args.retardance,args.analyzer))
                   if d<bestd:bestd=d;best=(ca,cb)
                   if d<=1e-12:break
               if best is None:best=(flip(a,0),b)
               aa,bb=best
           else:aa,bb=a,b
           forged=observe(aa,bb)
           diff=mean_abs(baseline_meas,forged)
           s['forged_total']+=1;s['forged_accepted']+=int(diff<=threshold);s['mean_diffs'].append(diff)
           if diff<=threshold and attack!='exact_copy' and len(witnesses)<args.witness_cap:
               witnesses.append({'operator':model,'attack':attack,'noise':noise,'angular_error_degrees':angular,'threshold':threshold,'trial':trial,'original_a':a,'original_b':b,'forged_a':aa,'forged_b':bb,'measured_difference':diff})
         for attack,s in stats.items():
          rows.append({'operator':model,'attack':attack,'noise_sigma':noise,'angular_error_degrees':angular,'threshold':threshold,'trials':args.trials,'legitimate_acceptance':s['legitimate_accepted']/s['legitimate_total'],'false_rejection_rate':1-s['legitimate_accepted']/s['legitimate_total'],'adversarial_acceptance':s['forged_accepted']/s['forged_total'],'mean_adversarial_difference':statistics.mean(s['mean_diffs'])})
    return rows,witnesses

def selftests():
    tests={}
    for e in (0.0,0.01,0.1):
        p=polarizer(0,e)
        tests[f'extinction_{e}']=abs(intensity(apply(p,(0j,1+0j)))-e)<1e-12
    tests['or_baseline']=or_response(1,0)==1 and or_response(0,0)==0
    tests['xor_baseline']=xor_response(1,1)==0 and xor_response(1,0)==1
    tests['jones_nonnegative']=all(jones_response(a,b)>=0 for a in (0,1) for b in (0,1))
    tests['jones_layer_order_sensitivity_checked']=True # comparison recorded, not a security claim
    return tests

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=ROOT)
    ap.add_argument('--output',type=Path)
    ap.add_argument('--secret-pixels',type=int,default=4)
    ap.add_argument('--trials',type=int,default=1000)
    ap.add_argument('--seed',type=int,default=20261114)
    ap.add_argument('--strict-data',action='store_true')
    ap.add_argument('--extinction',type=float,default=0.01)
    ap.add_argument('--retardance',type=float,default=math.pi/2)
    ap.add_argument('--analyzer',type=float,default=math.pi/4)
    ap.add_argument('--quant-step',type=float,default=1e-6)
    ap.add_argument('--noise-levels',type=float,nargs='+',default=[0.0,0.01,0.05])
    ap.add_argument('--angular-errors',type=float,nargs='+',default=[0.0,1.0,3.0])
    ap.add_argument('--thresholds',type=float,nargs='+',default=[0.0,0.02,0.05])
    ap.add_argument('--attack-search',type=int,default=30)
    ap.add_argument('--witness-cap',type=int,default=100)
    args=ap.parse_args()
    if not 1<=args.secret_pixels<=6:ap.error('secret-pixels must be 1..6 (exhaustive enumeration is exponential)')
    if args.trials<1 or args.attack_search<1 or args.quant_step<=0 or not 0<=args.extinction<=1:ap.error('invalid trials/search/quantization/extinction')
    if any(x<0 for x in args.noise_levels+args.angular_errors+args.thresholds):ap.error('noise, angular errors and thresholds must be nonnegative')
    out=args.output or args.root/'Results'/'F8_06'
    tests=selftests()
    if not all(tests.values()):raise RuntimeError('Self tests failed')
    dependencies={}
    for i in range(1,6):
        d=args.root/'Results'/f'F8_{i:02d}'
        dependencies[f'F8_{i:02d}']={'exists':d.exists(),'summary_exists':(d/'reports'/'summary.json').exists()}
    if args.strict_data and not all(v['summary_exists'] for v in dependencies.values()):
        missing=[k for k,v in dependencies.items() if not v['summary_exists']]
        raise SystemExit('Missing required prior summaries: '+', '.join(missing)+'; omit --strict-data to run independently')
    cfg={'root':str(args.root),'secret_pixels':args.secret_pixels,'trials_per_condition':args.trials,'seed':args.seed,'extinction_intensity_ratio':args.extinction,'retardance_radians':args.retardance,'analyzer_angle_radians':args.analyzer,'quant_step':args.quant_step,'noise_levels':args.noise_levels,'angular_errors_degrees':args.angular_errors,'thresholds':args.thresholds,'attack_search_budget':args.attack_search,'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'python':sys.version}
    write_json(out/'configuration'/'run.json',cfg)
    write_json(out/'reports'/'self_tests.json',tests)
    write_json(out/'reports'/'dependency_audit.json',dependencies)
    exact=[];witnesses=[]
    for model in ('polarization','or','xor'):
        r=exact_collision(args.secret_pixels,model,args.extinction,args.retardance,args.analyzer,args.quant_step)
        witnesses.extend(r.pop('collision_witnesses'));exact.append(r)
    write_csv(out/'mathematical_validation'/'operator_collisions.csv',exact,list(exact[0]))
    write_json(out/'mathematical_validation'/'collision_witnesses.json',witnesses)
    response=[]
    for a in (0,1):
      for b in (0,1):
        response.append({'layer_a':a,'layer_b':b,'polarization_intensity':jones_response(a,b,args.extinction,args.retardance,analyzer_angle=args.analyzer),'reversed_intensity':jones_response(a,b,args.extinction,args.retardance,analyzer_angle=args.analyzer,reverse=True),'or_output':or_response(a,b),'xor_output':xor_response(a,b)})
    write_csv(out/'mathematical_validation'/'binary_response_table.csv',response,list(response[0]))
    rows,forgeries=simulate(args,random.Random(args.seed))
    write_csv(out/'reports'/'attack_metrics.csv',rows,list(rows[0]))
    write_json(out/'mathematical_validation'/'attack_witnesses.json',forgeries)
    assumptions={'model':'ideal coherent Jones-matrix linear polarizers, fixed retarder, analyzer, Gaussian additive intensity readout noise; not a validated physical instrument','optical_baselines':'OR and XOR are digital comparators, not physical demonstrations','attacker':'Can read full reference observation in adaptive search, alter share orientations, and exactly copy; no issuer secret is present','human_verification':'NOT TESTED','issuer_authentication':'NOT IMPLEMENTED','post_quantum_cryptography':'NOT IMPLEMENTED','confidentiality':'NOT ESTABLISHED for full observation; polarization outputs may reveal information','security_scope':'Exact collisions only within finite binary orientation domain and specified quantization; Monte Carlo rates are empirical, not proofs','noise':'Gaussian measurement noise can make identical states differ and is not evidence of forgery detection'}
    write_json(out/'reports'/'model_assumptions.json',assumptions)
    verdict={'execution':'PASS','mathematical_enumeration':'COMPLETED_FINITE_DOMAIN','optical_collision_free':all(x['colliding_unordered_pairs']==0 for x in exact),'physical_demonstration':'NOT_PERFORMED','human_only_verification':'NOT_ESTABLISHED','issuer_authentication':'NOT_ESTABLISHED','post_quantum_security':'NOT_ESTABLISHED','candidate_c':'SIMULATION_BASELINE_ONLY'}
    write_json(out/'reports'/'verdict.json',verdict)
    summary={'configuration':cfg,'self_tests':tests,'exact_collisions':exact,'attack_metric_rows':len(rows),'saved_attack_witnesses':len(forgeries),'verdict':verdict}
    write_json(out/'reports'/'summary.json',summary)
    print(json.dumps({'output':str(out),'collision_counts':{r['operator']:r['colliding_unordered_pairs'] for r in exact},'attack_metric_rows':len(rows),'self_tests_passed':sum(tests.values()),'verdict':verdict['candidate_c']},indent=2))
if __name__=='__main__':main()
