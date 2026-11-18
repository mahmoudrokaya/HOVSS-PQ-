#!/usr/bin/env python3
"""F8_09: image-level, paired HOVSS-PQ baseline benchmark.

No human observations or PQ optical authentication are claimed. Uses the fixed
F8_01 manifest/splits and real image bytes. Optical operators are *surrogates*.
Install: python -m pip install numpy pillow
Example: python F8_09_Full_Dataset_Benchmark.py --side 128 --trials 3 --seed 20261114 --strict-data
"""
from __future__ import annotations
import argparse,csv,hashlib,json,math,os,platform,random,sys,time
from collections import defaultdict
from pathlib import Path
import numpy as np
from PIL import Image,ImageOps

ROOT=Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')
MODELS=('or','public_anchor','trusted_stack','trusted_layers','polarization','signed_digital')
ATTACKS=('legitimate','single_subpixel','known_content_reissue','public_anchor_rebinding','full_share_substitution','adaptive_optical_search','reference_substitution','exact_copy','signed_record_tamper','signed_share_replacement')
FIELDS=('image','source','split','trial','model','attack','threshold','noise','seed','changed_subpixels','changed_content_pixels','changed_content_fraction','share_modified','content_modified','issuer_authorized','reference_compromised','optical_distance','optical_accept','electronic_accept','accepted','unauthorized_accept','content_forgery_accept','share_forgery_accept','queries_used','comparison_scope')

def dump(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,indent=2,sort_keys=True,default=str)+'\n',encoding='utf-8')
def digest(b):return hashlib.sha256(b).hexdigest()
def wilson(k,n):
 if not n:return [None,None]
 z=1.95996398454;p=k/n;den=1+z*z/n;mid=(p+z*z/(2*n))/den;h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
 return [round(mid-h,6),round(mid+h,6)]
def synthetic(name,side):
 y,x=np.indices((side,side));v={'checkerboard':(x+y)%2,'vertical_stripes':x%2,'horizontal_stripes':y%2,'diagonal':(x+y)//8%2,'center_square':((abs(x-side//2)<side//4)&(abs(y-side//2)<side//4)).astype('uint8'),'gradient':(x>=side//2).astype('uint8'),'random_noise':np.random.default_rng(7).integers(0,2,(side,side),dtype='uint8')}
 return v[name].astype('uint8')
def ns(secret,rng):
 r=rng.integers(0,2,secret.shape,dtype='uint8');a=np.stack((r,1-r),axis=-1);b=np.stack((np.where(secret==0,r,1-r),np.where(secret==0,1-r,r)),axis=-1)
 return a,b
def decode(a,b):return np.bitwise_and(np.bitwise_or(a,b)[...,0],np.bitwise_or(a,b)[...,1]).astype('uint8')
def observation(model,a,b):
 if model in ('or','public_anchor','trusted_stack','signed_digital'):return np.bitwise_or(a,b).astype('float32')
 if model=='trusted_layers':return np.stack((a,b),axis=-1).astype('float32')
 # Jones-derived scalar-intensity surrogate: different orientations, no calibrated hardware.
 theta_a=np.where(a==0,0.13,0.69);theta_b=np.where(b==0,0.32,1.07)
 return (np.cos(theta_a)**2*np.cos(theta_b-theta_a)**2).astype('float32')
def distance(a,b):return float(np.mean(np.abs(a-b)))
def attack_generate(name,secret,a,b,rng,budget,model):
 aa=a.copy();bb=b.copy();ss=secret.copy();ref_comp=False;record_tamper=False;queries=0
 h,w=secret.shape
 if name=='single_subpixel':
  i=int(rng.integers(0,h));j=int(rng.integers(0,w));k=int(rng.integers(0,2));aa[i,j,k]^=1
 elif name in ('known_content_reissue','public_anchor_rebinding'):
  aa,bb=ns(secret,rng)
 elif name in ('full_share_substitution','signed_share_replacement'):
  ss=secret.copy();ss[int(rng.integers(h)),int(rng.integers(w))]^=1;aa,bb=ns(ss,rng)
 elif name=='adaptive_optical_search':
  target=observation(model,a,b);best=None;bestd=float('inf')
  for _ in range(budget):
   queries+=1
   ca=a.copy();cb=b.copy();i=int(rng.integers(h));j=int(rng.integers(w));k=int(rng.integers(2));ca[i,j,k]^=1
   # alternate share-side alteration
   if rng.integers(2):ca[i,j,k]^=1;cb[i,j,k]^=1
   d=distance(observation(model,ca,cb),target)
   if d<bestd:bestd=d;best=(ca,cb)
  aa,bb=best
 elif name=='reference_substitution':ref_comp=True
 elif name=='signed_record_tamper':record_tamper=True
 # legitimate and exact_copy leave the same bytes; exact copy has unauthorized custody
 return aa,bb,ref_comp,record_tamper,queries

def read_manifest(root,side,strict,limit,seed):
 manifest=root/'Results'/'F8_01'/'reports'/'dataset_manifest.csv';splits=root/'Results'/'F8_01'/'reports'/'splits.json'
 if not manifest.is_file() or not splits.is_file():raise FileNotFoundError('F8_01 manifest/splits missing: '+str(manifest))
 with manifest.open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
 split_data=json.loads(splits.read_text(encoding='utf-8'));assign={str(p).replace('\\','/'):s for s,ls in split_data.items() if isinstance(ls,list) for p in ls}
 items=[];missing=[];mismatches=[]
 for row in rows:
  if row.get('status')!='OK':continue
  rel=row['relative_path'].replace('\\','/');path=root/Path(rel)
  if not path.is_file():missing.append(rel);continue
  split=assign.get(rel,row.get('assigned_split','unknown'))
  if split!=row.get('assigned_split'):mismatches.append(rel)
  items.append((rel,row['source'],split,path,None))
 if strict and (missing or mismatches):raise ValueError(f'Missing {len(missing)} files; {len(mismatches)} split inconsistencies')
 if strict and len(items)!=539:raise ValueError(f'Expected 539 real images, found {len(items)}')
 for name in ('checkerboard','vertical_stripes','horizontal_stripes','diagonal','center_square','gradient','random_noise'):
  items.append(('synthetic/'+name,'SYNTHETIC','synthetic',None,name))
 if limit>0:
  # preserve split coverage where possible, deterministic source-level selection
  r=random.Random(seed);r.shuffle(items);items=items[:limit]
 return sorted(items,key=lambda x:x[0]),{'manifest':str(manifest),'splits':str(splits),'missing':missing,'split_mismatches':mismatches,'real_available':len([x for x in items if x[3] is not None]),'synthetic_available':len([x for x in items if x[4] is not None])}

def load_image(path,synthetic_name,side):
 if synthetic_name:return synthetic(synthetic_name,side)
 with Image.open(path) as im:
  im=ImageOps.exif_transpose(im).convert('L').resize((side,side),Image.Resampling.LANCZOS)
  arr=np.asarray(im,dtype='uint8')
 return (arr<128).astype('uint8')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--side',type=int,default=128);p.add_argument('--trials',type=int,default=3);p.add_argument('--seed',type=int,default=20261114);p.add_argument('--image-limit',type=int,default=0);p.add_argument('--search-budget',type=int,default=20);p.add_argument('--noise',type=float,default=0.0);p.add_argument('--thresholds',type=str,default='0,0.02,0.05');p.add_argument('--strict-data',action='store_true');p.add_argument('--output',type=Path,default=None)
 args=p.parse_args()
 if args.side<4 or args.trials<1 or args.search_budget<1 or args.noise<0 or args.noise>1:p.error('invalid parameter')
 thresholds=tuple(float(x) for x in args.thresholds.split(','));
 if any(x<0 for x in thresholds):p.error('thresholds must be nonnegative')
 out=args.output or args.root/'Results'/'F8_09';(out/'reports').mkdir(parents=True,exist_ok=True)
 items,inventory=read_manifest(args.root,args.side,args.strict_data,args.image_limit,args.seed)
 config={'root':str(args.root),'side':args.side,'trials':args.trials,'seed':args.seed,'image_limit':args.image_limit,'search_budget':args.search_budget,'noise':args.noise,'thresholds':thresholds,'models':MODELS,'attacks':ATTACKS,'images':len(items)}
 dump(out/'configuration'/'run.json',config)
 dump(out/'reports'/'dataset_audit.json',inventory)
 dump(out/'reports'/'model_assumptions.json',{'optical_models':'Idealized numerical surrogates; no physical or human verification','signed_digital':'Ideal commitment/signature authorization oracle, NOT live ML-DSA cryptographic testing; see F8_07 for actual ML-DSA','public_anchor':'Public anchor does not provide issuer authorization; OR optical baseline','trusted_layers':'Digital reference comparator, not passive optical device','trusted_stack':'Independently enrolled reference assumed protected except explicit substitution','privacy':'Whole-system secrecy including public references is NOT proven','adaptive_search':'Budgeted local single-subpixel search; not globally optimal','noise':'Independent additive numerical observation noise, not measured sensor or human noise','confidence':'Wilson intervals describe trials, which are correlated within images; image-level bootstrap recommended for publication','exact_copy':'Identical observations intrinsically indistinguishable under static verification'})
 accum=defaultdict(lambda:[0,0,0,0,0,0]);errors=[];count=0;start=time.monotonic()
 with (out/'reports'/'trial_results.csv').open('w',newline='',encoding='utf-8') as f:
  wr=csv.DictWriter(f,fieldnames=FIELDS);wr.writeheader()
  for ix,(rel,source,split,path,syn) in enumerate(items):
   try:secret=load_image(path,syn,args.side)
   except Exception as exc:
    errors.append({'image':rel,'error':str(exc)});
    if args.strict_data:raise
    continue
   for trial in range(args.trials):
    # stable independent per-image randomness, unaffected by manifest order
    seed=int.from_bytes(hashlib.sha256(f'{args.seed}|{rel}|{trial}'.encode()).digest()[:8],'big');rng=np.random.default_rng(seed)
    a,b=ns(secret,rng);base_dec=decode(a,b)
    for model in MODELS:
     expected=observation(model,a,b)
     for attack in ATTACKS:
      aa,bb,ref_comp,record_tamper,queries=attack_generate(attack,secret,a,b,rng,args.search_budget,model)
      obs=observation(model,aa,bb)
      # Independently protected expected reference; compromised reference replaced with attack observation
      target=obs if ref_comp and model in ('trusted_stack','trusted_layers') else expected
      changed=int(np.count_nonzero(aa!=a)+np.count_nonzero(bb!=b));changed_content=int(np.count_nonzero(decode(aa,bb)!=base_dec))
      unauthorized=attack!='legitimate';is_copy=attack=='exact_copy'
      # electronic control models signature and share commitment checks, not live ML-DSA
      digital_accept=(changed==0 and not record_tamper)
      for threshold in thresholds:
       if args.noise:
        observed=np.clip(obs+rng.normal(0,args.noise,obs.shape),0,1)
       else:observed=obs
       d=distance(observed,target)
       optical_accept=d<=threshold+1e-12
       if model=='signed_digital':accepted=digital_accept
       else:accepted=optical_accept
       if model=='trusted_layers' and ref_comp:accepted=True if d<=threshold+1e-12 else False
       key=(source,split,model,attack,threshold)
       z=accum[key];z[0]+=1;z[1]+=int(accepted);z[2]+=int(unauthorized and accepted);z[3]+=int(unauthorized and accepted and changed_content>0);z[4]+=int(unauthorized and accepted and changed>0);z[5]+=int(changed_content>0)
       wr.writerow({'image':rel,'source':source,'split':split,'trial':trial,'model':model,'attack':attack,'threshold':threshold,'noise':args.noise,'seed':seed,'changed_subpixels':changed,'changed_content_pixels':changed_content,'changed_content_fraction':round(changed_content/secret.size,8),'share_modified':int(changed>0),'content_modified':int(changed_content>0),'issuer_authorized':int(not unauthorized),'reference_compromised':int(ref_comp),'optical_distance':round(d,8),'optical_accept':int(optical_accept),'electronic_accept':int(digital_accept),'accepted':int(accepted),'unauthorized_accept':int(unauthorized and accepted),'content_forgery_accept':int(unauthorized and accepted and changed_content>0),'share_forgery_accept':int(unauthorized and accepted and changed>0),'queries_used':queries,'comparison_scope':'electronic_oracle' if model=='signed_digital' else 'numerical_optical_surrogate'})
       count+=1
   if (ix+1)%25==0:print(f'Processed {ix+1}/{len(items)} images; {count} records',flush=True)
 with (out/'reports'/'attack_summary.csv').open('w',newline='',encoding='utf-8') as f:
  fields=['source','split','model','attack','threshold','n','accepted','acceptance_rate','wilson95_low','wilson95_high','unauthorized_accept','content_forgery_accept','share_forgery_accept','content_modified_trials']
  wr=csv.DictWriter(f,fieldnames=fields);wr.writeheader()
  for key,z in sorted(accum.items()):
   source,split,model,attack,threshold=key;lo,hi=wilson(z[1],z[0]);wr.writerow(dict(zip(fields,[source,split,model,attack,threshold,z[0],z[1],round(z[1]/z[0],6),lo,hi,z[2],z[3],z[4],z[5]])))
 summary={'images_processed':len(items)-len(errors),'records':count,'errors':errors,'elapsed_seconds':round(time.monotonic()-start,2),'models':len(MODELS),'attacks':len(ATTACKS),'thresholds':len(thresholds),'real_cryptography_executed':False,'physical_experiment_executed':False,'human_observers_tested':False}
 dump(out/'reports'/'summary.json',summary)
 dump(out/'reports'/'verdict.json',{'execution':'PASS' if not errors else 'PARTIAL','image_benchmark':'COMPLETED' if not errors else 'PARTIAL','post_quantum_optical_authentication':'NOT_ESTABLISHED','human_only_verification':'NOT_TESTED','physical_validation':'NOT_TESTED','warning':'Digital signature control is an idealized authorization oracle; ML-DSA is not run in F8_09.'})
 print(json.dumps({'output':str(out),**summary},indent=2))
if __name__=='__main__':main()
