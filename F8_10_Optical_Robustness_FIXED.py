#!/usr/bin/env python3
"""F8_10: paired, simulation-only optical robustness and tolerance audit.

Requires F8_09_Full_Dataset_Benchmark_REVISED.py in the same Code folder.
Reuses its F8_01 manifest, image normalization, Naor-Shamir shares, and
computational observation surrogates. NO hardware or human measurements.

Example (Windows, Python >=3.10):
 python F8_10_Optical_Robustness.py --strict-data --trials 3 --seed 20261114
Quick check:
 python F8_10_Optical_Robustness.py --image-limit 12 --trials 1 --bootstrap-replicates 50
"""
from __future__ import annotations
import argparse,csv,hashlib,importlib.util,json,math,sys,time
from collections import defaultdict
from pathlib import Path
import numpy as np
from PIL import Image,ImageFilter

ROOT=Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')
MODELS=('or','public_anchor','trusted_stack','trusted_layers','polarization')
ATTACKS=('legitimate','single_subpixel','content_flip','exact_copy','reference_substitution')
PERTURBATIONS=('ideal','gaussian_noise','translation','blur','illumination','angular_misalignment','fabrication_dropout','combined')
LEVELS=(0.0,0.5,1.0)
FIELDS=('image','source','split','trial','model','attack','perturbation','severity','threshold','distance_mean','distance_max','distance_affected','accepted','attack_applicable','unauthorized','share_changed','content_changed','reference_compromised','noise_seed','calibration_role')

def write_json(path,obj):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(obj,indent=2,sort_keys=True,default=str)+'\n',encoding='utf-8')
def seed_for(*parts):return int.from_bytes(hashlib.sha256('|'.join(map(str,parts)).encode()).digest()[:8],'big')
def load_baseline():
 p=Path(__file__).resolve().parent/'F8_09_Full_Dataset_Benchmark_REVISED.py'
 if not p.is_file():raise FileNotFoundError('Required F8_09 revised script not found next to F8_10: '+str(p))
 spec=importlib.util.spec_from_file_location('f809_baseline',p)
 mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 for n in ('read_manifest','load_image','ns','decode','observation'):
  if not hasattr(mod,n):raise RuntimeError('F8_09 dependency missing '+n)
 return mod,p

def perturb(x,kind,level,rng,model):
 """Dimensionless synthetic distortions, not calibrated physical units.

 Each 2-D observation channel receives identical geometric displacement;
 independent noise and dropout apply per observation element. No wrap-around.
 """
 if level==0 or kind=='ideal':return x.copy()
 z=x.astype(np.float32,copy=True)
 if kind in ('translation','combined'):
  shift=1 if level<=0.5 else 2
  # edge padding, not cyclic shift; one axis each to preserve paired geometry
  z=np.pad(z,((shift,0),(0,0))+((0,0),)*(z.ndim-2),mode='edge')[:x.shape[0],:]
 if kind in ('blur','combined'):
  # channel-wise gaussian blur in pixel coordinates; no mixing between layers
  sigma=0.4 if level<=0.5 else 1.0
  if kind=='combined':sigma=0.4 if level<=0.5 else 0.8
  from scipy.ndimage import gaussian_filter
  z=gaussian_filter(z,sigma=(sigma,sigma)+(0,)*(z.ndim-2),mode='nearest')
 if kind in ('illumination','combined'):
  gain=1+(0.06 if level<=0.5 else 0.15)
  offset=(0.01 if level<=0.5 else 0.04)
  z=z*gain+offset
 if kind in ('angular_misalignment','combined'):
  # polarization-only Jones-derived scalar intensity perturbation;
  # others unaffected, and explicitly treated as inapplicable downstream.
  if model=='polarization':
   angle=(math.pi/180)*(1 if level<=0.5 else 3)
   z=z*np.cos(angle)**2 + (1-z)*np.sin(angle)**2
 if kind in ('fabrication_dropout','combined'):
  p=0.001 if level<=0.5 else 0.01
  mask=rng.random(z.shape)<p
  z=np.where(mask,1-z,z)
 if kind in ('gaussian_noise','combined'):
  sigma=0.01 if level<=0.5 else 0.05
  z=z+rng.normal(0,sigma,z.shape).astype(np.float32)
 return np.clip(z,0,1).astype(np.float32)

def attack_shares(name,secret,a,b,rng):
 aa=a.copy();bb=b.copy();reference_compromised=False
 h,w=secret.shape
 if name=='single_subpixel':
  i=int(rng.integers(h));j=int(rng.integers(w));k=int(rng.integers(2))
  if rng.integers(2):aa[i,j,k]^=1
  else:bb[i,j,k]^=1
 elif name=='content_flip':
  i=int(rng.integers(h));j=int(rng.integers(w))
  # Force a changed reconstructed content pixel using valid (2,2) encoding
  ss=secret[i:i+1,j:j+1].copy();ss^=1
  ca,cb=baseline.ns(ss,rng);aa[i,j]=ca[0,0];bb[i,j]=cb[0,0]
 elif name=='reference_substitution':reference_compromised=True
 return aa,bb,reference_compromised

def metrics(observed,target,changed_mask):
 d=np.abs(observed-target)
 if d.ndim>2:local=np.max(d,axis=tuple(range(2,d.ndim)))
 else:local=d
 region=float(np.mean(local[changed_mask])) if np.any(changed_mask) else 0.0
 return float(d.mean()),float(d.max()),region

def distance_for_rule(model,mean,maxval):
 # exact-layer rule remains exact in F8_09; under noise, threshold 0 implies
 # equality only. Other models retain their declared comparator type.
 return maxval if model in ('trusted_layers','polarization') else mean

def wilson(k,n):
 if not n:return (None,None)
 z=1.959963984540054;p=k/n;den=1+z*z/n
 c=(p+z*z/(2*n))/den;h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
 return (round(max(0,c-h),6),round(min(1,c+h),6))

def cluster_ci(per_image,reps,rng):
 if not per_image:return [None,None]
 vals=np.asarray(list(per_image.values()),dtype=np.float64)
 if not reps:return [None,None]
 idx=rng.integers(0,len(vals),(reps,len(vals)))
 draws=vals[idx]
 denom=draws[:,:,1].sum(axis=1)
 rate=np.divide(draws[:,:,0].sum(axis=1),denom,out=np.zeros(len(draws)),where=denom>0)
 return [round(float(np.quantile(rate,0.025)),6),round(float(np.quantile(rate,0.975)),6)]

def self_test():
 x=np.zeros((8,8,2),np.float32);r=np.random.default_rng(1)
 assert np.array_equal(perturb(x,'ideal',0,r,'or'),x)
 assert np.array_equal(perturb(x,'translation',0,r,'or'),x)
 assert perturb(x,'gaussian_noise',1,r,'or').shape==x.shape
 assert perturb(x,'blur',1,r,'or').shape==x.shape
 assert np.max(perturb(x,'illumination',1,r,'or'))>0
 assert distance_for_rule('trusted_layers',0.00001,1.0)==1.0
 return {'passed':6,'failed':0}

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--root',type=Path,default=ROOT)
 p.add_argument('--output',type=Path,default=None)
 p.add_argument('--side',type=int,default=128)
 p.add_argument('--trials',type=int,default=3)
 p.add_argument('--image-limit',type=int,default=0)
 p.add_argument('--seed',type=int,default=20261114)
 p.add_argument('--strict-data',action='store_true')
 p.add_argument('--bootstrap-replicates',type=int,default=400)
 p.add_argument('--target-frr',type=float,default=0.05)
 p.add_argument('--calibration-split',default='val')
 p.add_argument('--evaluation-split',default='test')
 args=p.parse_args()
 if args.side<4 or args.trials<1 or args.image_limit<0 or args.bootstrap_replicates<0 or not 0<args.target_frr<1:p.error('Invalid parameters')
 global baseline
 baseline,dependency=load_baseline()
 out=args.output or args.root/'Results'/'F8_10'
 for sub in ('reports','configuration','mathematical_validation'):(out/sub).mkdir(parents=True,exist_ok=True)
 items,inventory=baseline.read_manifest(args.root,args.side,args.strict_data,args.image_limit,args.seed)
 # Split membership is fixed from F8_01. Calibration uses validation only.
 # Diagnostic synthetic samples are never used for calibration or held-out claims.
 split_names=sorted(set(item[2] for item in items))
 # Normalize common descriptive names to the exact F8_01 manifest labels.
 aliases={'validation':'val','training':'train','testing':'test'}
 args.calibration_split=aliases.get(args.calibration_split,args.calibration_split)
 args.evaluation_split=aliases.get(args.evaluation_split,args.evaluation_split)
 if args.calibration_split not in split_names or args.evaluation_split not in split_names:
  raise ValueError('Calibration split '+repr(args.calibration_split)+' and evaluation split '+repr(args.evaluation_split)+' must both exist; available: '+str(split_names)+'. Check split names or increase --image-limit.')
 config=vars(args).copy();config.update({'models':MODELS,'attacks':ATTACKS,'perturbations':PERTURBATIONS,'severity_levels':LEVELS,'images':len(items),'baseline_script':str(dependency),'unit_note':'severity is dimensionless synthetic parameter, NOT measured millimeters/degrees except stated illustrative angle'})
 write_json(out/'configuration'/'run.json',config)
 write_json(out/'reports'/'dataset_audit.json',inventory)
 write_json(out/'reports'/'self_tests.json',self_test())
 write_json(out/'reports'/'dependency_audit.json',{'f8_09_script':str(dependency),'f8_09_import':'PASS','f8_01_manifest':inventory['manifest'],'f8_01_splits':inventory['splits'],'python':sys.version,'numpy':np.__version__})
 write_json(out/'reports'/'model_assumptions.json',{
  'evidence':'COMPUTATIONAL_SIMULATION_ONLY; NO physical fabrication, calibration, or human observers',
  'surrogates':'F8_09_REVISED observation models reused exactly; polarization is a scalar intensity surrogate, not complete Jones hardware',
  'perturbations':'dimensionless synthetic distortions; translation 1/2 pixels; blur Gaussian sigma 0.4/1.0 pixels; additive Gaussian sigma 0.01/0.05; gain/offset; angle 1/3 degrees; element dropout p=0.001/0.01',
  'angular_applicability':'polarization only; other models excluded from angular-misalignment estimates',
  'trusted_layers':'exact layer equality in F8_09; tolerance >0 is a new digital comparator, not human optical verification',
  'public_anchor':'same OR optical observation; no issuer authorization',
  'trusted_stack':'independent reference custody assumed except explicit substitution',
  'reference_substitution':'only trusted_stack and trusted_layers; assumed compromised expected reference',
  'exact_copy':'identical issued bytes are not distinguishable from replay in a static comparator',
  'calibration':'validation-split legitimate distances only; threshold chosen as empirical (1-target_frr) quantile, then held-out test without adjustment',
  'paired_noise':'same random perturbation seed for legitimate and attacks in each model/image/trial/condition; independent realizations are used per attack to avoid accidental coupling of random streams',
  'statistical':'image-cluster bootstrap on held-out test; Wilson intervals descriptive only',
  'threat_model':'single localized subpixel alteration, one forced content flip, exact copy, reference compromise; NOT an exhaustive adaptive attack engine',
  'privacy':'whole-system secrecy not proved','post_quantum':'no cryptographic operations or issuer-authenticated optics in F8_10'})
 start=time.monotonic();n=0
 # Intermediate records permit exact deterministic threshold calibration without
 # holding full image observations in memory. ~ 546*3*5*5*8*3=~1m rows.
 raw=out/'reports'/'distances.csv'
 with raw.open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=[x for x in FIELDS if x not in ('threshold','accepted','calibration_role')]);w.writeheader()
  for index,(rel,source,split,path,syn) in enumerate(items):
   secret=baseline.load_image(path,syn,args.side)
   for trial in range(args.trials):
    rng=np.random.default_rng(seed_for(args.seed,rel,trial,'shares'))
    a,b=baseline.ns(secret,rng);original=baseline.decode(a,b)
    for model in MODELS:
     expected=baseline.observation(model,a,b)
     for attack in ATTACKS:
      arng=np.random.default_rng(seed_for(args.seed,rel,trial,model,attack,'attack'))
      aa,bb,comp=attack_shares(attack,secret,a,b,arng)
      actual=baseline.observation(model,aa,bb)
      share_changed=int(np.count_nonzero(aa!=a)+np.count_nonzero(bb!=b))
      content_changed=int(np.count_nonzero(baseline.decode(aa,bb)!=original))
      mask=np.any((aa!=a)|(bb!=b),axis=-1)
      applicable=not (attack=='reference_substitution' and model not in ('trusted_stack','trusted_layers'))
      if not applicable:continue
      target=actual if comp else expected
      for perturbation in PERTURBATIONS:
       if perturbation=='angular_misalignment' and model!='polarization':continue
       for level in LEVELS:
        # A common observation perturbation mechanism with independent draws
        # for each attack. This models an observed presentation against a
        # separately enrolled ideal target; not a calibrated acquisition device.
        noise_seed=seed_for(args.seed,rel,trial,model,attack,perturbation,level)
        observed=perturb(actual,perturbation,level,np.random.default_rng(noise_seed),model)
        mean,mx,affected=metrics(observed,target,mask)
        w.writerow({'image':rel,'source':source,'split':split,'trial':trial,'model':model,'attack':attack,'perturbation':perturbation,'severity':level,'distance_mean':mean,'distance_max':mx,'distance_affected':affected,'attack_applicable':1,'unauthorized':int(attack!='legitimate'),'share_changed':share_changed,'content_changed':content_changed,'reference_compromised':int(comp),'noise_seed':noise_seed})
        n+=1
   if (index+1)%50==0:print(f'Processed {index+1}/{len(items)} images',flush=True)
 # Calibration thresholds: for each model / perturbation / severity, validation
 # legitimate distances only. Quantile higher interpolation conservatively
 # protects the requested empirical FRR on calibration data.
 calibration=defaultdict(list)
 with raw.open(newline='',encoding='utf-8') as f:
  for r in csv.DictReader(f):
   if r['split']==args.calibration_split and r['attack']=='legitimate':
    key=(r['model'],r['perturbation'],r['severity'])
    calibration[key].append(float(r['distance_max'] if r['model'] in ('trusted_layers','polarization') else r['distance_mean']))
 thresholds={}
 for key,vals in calibration.items():
  vals=np.sort(np.asarray(vals,dtype=float))
  rank=max(0,min(len(vals)-1,math.ceil((1-args.target_frr)*len(vals))-1))
  thresholds[key]=float(vals[rank])+1e-12
 if not thresholds:raise ValueError('No validation legitimate records available')
 write_json(out/'reports'/'calibration_thresholds.json',[{'model':k[0],'perturbation':k[1],'severity':float(k[2]),'threshold':v,'validation_samples':len(calibration[k]),'target_frr':args.target_frr} for k,v in sorted(thresholds.items())])
 # Evaluate on held-out test only, excluding synthetic diagnostics and training.
 stats=defaultdict(lambda:[0,0,0,0,0,0])
 clusters=defaultdict(lambda:defaultdict(lambda:[0,0]))
 witness=[];heldout=0
 with raw.open(newline='',encoding='utf-8') as fin,(out/'reports'/'heldout_results.csv').open('w',newline='',encoding='utf-8') as fout:
  reader=csv.DictReader(fin);writer=csv.DictWriter(fout,fieldnames=FIELDS);writer.writeheader()
  for r in reader:
   if r['split']!=args.evaluation_split:continue
   key=(r['model'],r['perturbation'],r['severity'])
   if key not in thresholds:continue
   threshold=thresholds[key]
   score=float(r['distance_max'] if r['model'] in ('trusted_layers','polarization') else r['distance_mean'])
   accept=int(score<=threshold)
   r.update({'threshold':threshold,'accepted':accept,'calibration_role':'heldout_test'})
   writer.writerow(r);heldout+=1
   group=(r['model'],r['attack'],r['perturbation'],r['severity'])
   st=stats[group];st[0]+=1;st[1]+=accept
   if r['attack']=='legitimate':st[2]+=1-accept
   else:
    st[3]+=accept
    if int(r['content_changed'])>0 and accept:st[4]+=1
    if int(r['share_changed'])>0 and accept:st[5]+=1
   cc=clusters[group][r['image']];cc[0]+=accept;cc[1]+=1
   if r['attack']!='legitimate' and accept and len(witness)<100:
    witness.append({'image':r['image'],'model':r['model'],'attack':r['attack'],'perturbation':r['perturbation'],'severity':r['severity'],'share_changed':r['share_changed'],'content_changed':r['content_changed'],'distance_mean':r['distance_mean'],'distance_max':r['distance_max'],'threshold':threshold})
 summary=out/'reports'/'robustness_summary.csv'
 with summary.open('w',newline='',encoding='utf-8') as f:
  fields=('model','attack','perturbation','severity','threshold','n','accepted','acceptance_rate','rejection_rate','false_rejection_rate','false_acceptance_rate','accepted_content_changing','accepted_share_modifications','wilson_low','wilson_high','image_bootstrap_low','image_bootstrap_high','images')
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
  for key,st in sorted(stats.items()):
   m,a,pert,sev=key;total,accepted,fr,fa,content,share=st
   lo,hi=wilson(accepted,total)
   ci=cluster_ci(clusters[key],args.bootstrap_replicates,np.random.default_rng(seed_for(args.seed,key,'bootstrap')))
   w.writerow({'model':m,'attack':a,'perturbation':pert,'severity':sev,'threshold':thresholds[(m,pert,sev)],'n':total,'accepted':accepted,'acceptance_rate':accepted/total,'rejection_rate':1-accepted/total,'false_rejection_rate':fr/total if a=='legitimate' else '','false_acceptance_rate':fa/total if a!='legitimate' else '','accepted_content_changing':content,'accepted_share_modifications':share,'wilson_low':lo,'wilson_high':hi,'image_bootstrap_low':ci[0],'image_bootstrap_high':ci[1],'images':len(clusters[key])})
 write_json(out/'mathematical_validation/attack_witnesses.json',witness)
 write_json(out/'reports/summary.json',{'dataset_images':len(items),'distance_records':n,'heldout_records':heldout,'calibration_conditions':len(thresholds),'summary_groups':len(stats),'seconds':round(time.monotonic()-start,2),'calibration_split':args.calibration_split,'evaluation_split':args.evaluation_split,'target_frr':args.target_frr,'simulation_only':True})
 write_json(out/'reports/verdict.json',{'execution':'PASS','computational_robustness':'MEASURED_UNDER_DECLARED_SIMULATIONS','physical_optical_robustness':'NOT_MEASURED','human_only_verification':'NOT_PERFORMED','issuer_authentication':'NOT_ESTABLISHED','pq_optical_authentication':'NOT_ESTABLISHED','calibration_holdout_separation':'PASS','replay_resistance':'NOT_ESTABLISHED'})
 print('PASS | images',len(items),'| distance rows',n,'| held-out rows',heldout,'| output',out)

if __name__=='__main__':main()
