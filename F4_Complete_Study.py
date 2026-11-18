#!/usr/bin/env python3
"""F4-VICO: Verifier-Interactive Content-bound Optical Spot-check Feasibility Study.

Research candidate, NOT proven human-only or post-quantum optical authentication.
The verifier privately chooses fresh content locations and compares the stacked
optical reconstruction against a trusted expected image. This is *interactive
inspection*, not cryptographic origin authentication. Perfect copies pass.

Run: python F4_Complete_Study.py --image-limit 0 --side 128 --trials 30 --optical-samples 30 --strict-data
Requires: numpy, pillow. Optional: pqcrypto for *electronic* ML-DSA audit.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,math,platform,time,sys,collections,itertools
from pathlib import Path
from datetime import datetime,timezone
import numpy as np
from PIL import Image,ImageFilter
ROOT=Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')

def write_json(p,x):
 p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def write_csv(p,rows):
 p.parent.mkdir(parents=True,exist_ok=True)
 if not rows:p.write_text('',encoding='utf-8');return
 keys=list(dict.fromkeys(k for r in rows for k in r))
 with p.open('w',newline='',encoding='utf-8-sig') as f:
  w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(rows)
def discover(data,manifest,limit,strict):
 if not manifest.is_file():
  if strict:raise FileNotFoundError(manifest)
  return []
 with manifest.open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
 out=[];seen=set();missing=[]
 for row in rows:
  rel=row.get('relative_path','').replace('\\','/')
  if not (rel.startswith('BSR/BSDS500/data/images/') or rel.startswith('misc/')):continue
  if Path(rel).suffix.lower() not in ('.jpg','.jpeg','.tif','.tiff','.png'):continue
  if not (data/rel).is_file():missing.append(rel);continue
  digest=row.get('sha256') or rel
  if digest in seen:continue
  seen.add(digest);out.append((rel,'sipi' if rel.startswith('misc/') else rel.split('/')[4]))
 out.sort()
 if strict and missing:raise FileNotFoundError(f'{len(missing)} missing; first {missing[0]}')
 if strict and limit==0 and len(out)!=539:raise ValueError(f'Expected 539 canonical real images, found {len(out)}')
 return out[:limit] if limit else out
def synthetic(side):
 y,x=np.indices((side,side));c=(side-1)/2
 return [('checker',((x+y)%2).astype('uint8')),('stripes',((x//4)%2).astype('uint8')),('circle',(((x-c)**2+(y-c)**2)<(side/3)**2).astype('uint8')),('symbol_H',(((x>side//5)&(x<side//3)&(y>side//6)&(y<5*side//6))|((x>2*side//3)&(x<4*side//5)&(y>side//6)&(y<5*side//6))|((abs(y-side//2)<2)&(x>side//5)&(x<4*side//5))).astype('uint8')),('random',np.random.default_rng(19).integers(0,2,(side,side),dtype='uint8')),('all_white',np.zeros((side,side),dtype='uint8')),('all_black',np.ones((side,side),dtype='uint8'))]
def load_image(p,side,threshold):
 with Image.open(p) as im:
  im=im.convert('L');im.thumbnail((side,side),Image.Resampling.LANCZOS)
  return (np.asarray(im,dtype='uint8')<threshold).astype('uint8')

def issue(m,rng):
 """Classical (2,2) basis. Each share marginal is independent of M."""
 a=rng.integers(0,2,size=m.shape,dtype='uint8');R=np.stack((a,1-a),axis=-1)
 D=np.stack((a^m,1-(a^m)),axis=-1).astype('uint8')
 return R,D

def overlay(R,D):return np.bitwise_or(R,D)
def decode(R,D):return (np.sum(overlay(R,D),axis=-1)==2).astype('uint8')
def reference_recovery(D,m):
 """Exact known-content reference recovery for this basis."""
 a=D[...,0]^m
 return np.stack((a,1-a),axis=-1).astype('uint8')
def forge_content(R,D,m,idx):
 """Attacker using inferred R: force selected bits to invert while preserving valid basis."""
 out=D.copy();flat=out.reshape(-1,2);r=R.reshape(-1,2);bits=m.ravel()
 flat[idx]=np.stack((r[idx,0]^(1-bits[idx]),1-(r[idx,0]^(1-bits[idx]))),axis=-1)
 return out

def select_indices(N,k,rng,distribution='uniform',tile=16,shape=None):
 k=min(k,N)
 if distribution=='uniform':return rng.choice(N,size=k,replace=False)
 if distribution=='stratified':
  h,w=shape;ys=np.arange(0,h,tile);xs=np.arange(0,w,tile)
  tiles=[]
  for y in ys:
   for x in xs:
    yy,xx=np.mgrid[y:min(y+tile,h),x:min(x+tile,w)];tiles.append((yy*w+xx).ravel())
  rng.shuffle(tiles)
  picks=[]
  for i,t in enumerate(tiles):
   if len(picks)>=k:break
   picks.append(int(rng.choice(t)))
  if len(picks)<k:
   remaining=np.setdiff1d(np.arange(N),np.asarray(picks,dtype=int),assume_unique=True)
   picks.extend(rng.choice(remaining,size=k-len(picks),replace=False).tolist())
  return np.asarray(picks,dtype=int)
 raise ValueError(distribution)

def inspect(R,D,expected,indices):
 """Digital *ideal observer* surrogate: checks visible decoded pixels at selected positions."""
 decoded=decode(R,D).ravel();truth=expected.ravel()
 return bool(np.array_equal(decoded[indices],truth[indices]))
def exact_accept(N,k,t):
 """Hypergeometric P[miss all t changed cells] for k hidden uniform samples."""
 if t==0:return 1.
 if k>N-t:return 0.
 return math.exp(math.lgamma(N-t+1)-math.lgamma(N-t-k+1)-math.lgamma(N+1)+math.lgamma(N-k+1))
def finite_theory():
 """Enumerate all legitimate 2-subpixel cases and all four possible presented blocks."""
 rows=[]
 for m,a in itertools.product((0,1),repeat=2):
  R=np.array([a,1-a],dtype='uint8');D=np.array([a^m,1-(a^m)],dtype='uint8')
  for d0,d1 in itertools.product((0,1),repeat=2):
   X=np.array([d0,d1],dtype='uint8');Y=R|X
   rows.append({'m':m,'a':a,'R':R.tolist(),'D':D.tolist(),'forged':X.tolist(),'overlay':Y.tolist(),'overlay_weight':int(Y.sum()),'same_overlay':bool(np.array_equal(Y,R|D)),'valid_decoded_bit':int(Y.sum()==2)})
 return {'cases':rows,'single_share_marginals_equal':True,'reference_recoverable_from_D_and_m':True,'perfect_copy_indistinguishable':True,'OR_invisible_subpixel_changes':sum(x['same_overlay'] and x['forged']!=x['D'] for x in rows),'all_cases':len(rows)}
def optical_trials(R,D,m,rng):
 """Pixel-level *synthetic* misregistration; not a physical/human experiment."""
 base=overlay(R,D).reshape(R.shape[0],R.shape[1]*2)
 out=[]
 for mode in ('shift_x1','shift_y1','blur','bit_noise'):
  if mode=='shift_x1':pert=np.roll(D.reshape(D.shape[0],D.shape[1]*2),1,axis=1).reshape(D.shape)
  elif mode=='shift_y1':pert=np.roll(D,1,axis=0)
  elif mode=='bit_noise':pert=D^ (rng.random(D.shape)<.01).astype('uint8')
  else:
   raw=(255*(1-D.reshape(D.shape[0],D.shape[1]*2))).astype('uint8')
   sm=np.asarray(Image.fromarray(raw).filter(ImageFilter.GaussianBlur(0.8)))
   pert=(sm<128).astype('uint8').reshape(D.shape)
  ov=overlay(R,pert).reshape(base.shape)
  out.append({'mode':mode,'overlay_disagreement':float(np.mean(ov!=base)),'decoded_content_error':float(np.mean(decode(R,pert)!=m))})
 return out

def cryptographic_audit(m,R,D):
 """No false PQ success: optional API probing, fail closed on unavailable implementation."""
 payload=hashlib.sha256(m.tobytes()+R.tobytes()+D.tobytes()).digest()
 result={'sha256_binding_detects_changed_payload':payload!=hashlib.sha256(m.tobytes()+R.tobytes()+(D^1).tobytes()).digest(),'mldsa_status':'NOT_EXECUTED','optical_signature_verification':False}
 try:
  from pqcrypto.sign import ml_dsa_65 as lib
  fn=getattr(lib,'generate_keypair',None);sg=getattr(lib,'sign',None);vf=getattr(lib,'verify',None)
  if not all(callable(x) for x in (fn,sg,vf)):
   result['mldsa_status']='API_UNAVAILABLE';result['module_path']=str(getattr(lib,'__file__','unknown'));return result
  pk,sk=fn();sig=sg(sk,payload)
  try:ok=vf(pk,payload,sig);verified=(ok is None or ok is True)
  except Exception:verified=False
  try:bad=vf(pk,payload+b'!',sig);tamper_rejected=(bad is False)
  except Exception:tamper_rejected=True
  result.update(mldsa_status='EXECUTED' if verified and tamper_rejected else 'FAILED',signature_length=len(sig),tamper_rejected=tamper_rejected)
 except Exception as exc:result['mldsa_status']='UNAVAILABLE_OR_FAILED';result['detail']=f'{type(exc).__name__}: {exc}'
 return result

def save_fig(path,m,R,D,attack):
 path.parent.mkdir(parents=True,exist_ok=True)
 imgs=[m,decode(R,D),decode(R,attack),np.not_equal(m,decode(R,attack)).astype('uint8')]
 pil=[]
 for x in imgs:
  im=Image.fromarray((255*(1-x)).astype('uint8'));im=im.resize((256,256),Image.Resampling.NEAREST);pil.append(im)
 dst=Image.new('L',(1024,256),255)
 for i,im in enumerate(pil):dst.paste(im,(256*i,0))
 dst.save(path)

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--root',type=Path,default=ROOT);ap.add_argument('--image-limit',type=int,default=0);ap.add_argument('--side',type=int,default=128);ap.add_argument('--trials',type=int,default=30);ap.add_argument('--optical-samples',type=int,default=30);ap.add_argument('--strict-data',action='store_true');ap.add_argument('--seed',type=int,default=20261107);ap.add_argument('--threshold',type=int,default=128);ap.add_argument('--checks',type=str,default='16,64,256,1024');ap.add_argument('--tile',type=int,default=16);ap.add_argument('--feedback-queries',type=int,default=16)
 a=ap.parse_args();start=time.perf_counter();rng=np.random.default_rng(a.seed)
 data=a.root/'Data';manifest=a.root/'Data_Inspection'/'file_manifest.csv';out=a.root/'Results'/'F4_Complete'
 for sub in ('configuration','mathematical_validation','reconstruction','adversarial_attacks','optical_simulation','cryptographic_audit','figures','reports'):(out/sub).mkdir(parents=True,exist_ok=True)
 images=discover(data,manifest,a.image_limit,a.strict_data);checks=sorted(set(int(s) for s in a.checks.split(',') if s.strip()))
 if not checks or min(checks)<1:raise ValueError('checks must be positive')
 if a.trials<1:raise ValueError('trials must be >=1')
 write_json(out/'configuration'/'run.json',{'args':vars(a),'python':sys.version,'numpy':np.__version__,'pillow':Image.__version__,'utc':datetime.now(timezone.utc).isoformat(),'model':'verifier-private fresh spot-check of content against trusted expected image','physical_observer':'NOT_PERFORMED'})
 theory=finite_theory();write_json(out/'mathematical_validation'/'basis_enumeration.json',theory)
 attack_rows=[];rec_rows=[];opt_rows=[];bounds=[];errors=[];pq=None;total=0;real=0;sample_images=0
 group=collections.defaultdict(lambda:[0,0,0,0.,0.]);attack_record_count=0
 trial_file=out/'reports'/'attacks_trials.csv'
 trial_columns=['image','split','attack','strength','trial','checks','changed_content_pixels','changed_content_fraction','accepted','unauthorized_content_accepted','theoretical_uniform_accept','feedback_queries_allowed','feedback_oracle_actually_used','known_content','reference_available']
 trial_handle=trial_file.open('w',newline='',encoding='utf-8-sig');trial_writer=csv.DictWriter(trial_handle,fieldnames=trial_columns);trial_writer.writeheader()
 attacks=('blind_flip','known_content_forge','reference_aware_forge','exact_copy','full_random','cross_issuance','ink_add','ink_remove','block','adaptive_feedback')
 strengths=(.001,.01,.05)
 for j,(name,kind) in enumerate(images+[(name,'synthetic') for name,_ in synthetic(a.side)]):
  try:
   if kind=='synthetic':m=dict(synthetic(a.side))[name]
   else:m=load_image(data/name,a.side,a.threshold);real+=1
   R,D=issue(m,rng);N=m.size;flat=m.ravel();rr=reference_recovery(D,m)
   assert np.array_equal(rr,R),'known-content reference recovery expected for this basis'
   assert np.array_equal(decode(R,D),m)
   rec_rows.append({'image':name,'split':kind,'pixels':N,'reconstruction_accuracy':float(np.mean(decode(R,D)==m)),'reference_recovery_accuracy':float(np.mean(rr==R)),'share_expansion':2})
   if pq is None:pq=cryptographic_audit(m,R,D)
   if sample_images<a.optical_samples:
    for record in optical_trials(R,D,m,rng):opt_rows.append({'image':name,**record})
    sample_images+=1
   if j<8:
    inds=rng.choice(N,size=max(1,int(N*.01)),replace=False);save_fig(out/'figures'/f'{j:03d}_genuine_forged_difference.png',m,R,D,forge_content(rr,D,m,inds))
   # Each attack/strength/check budget has a separate fresh, hidden verifier challenge.
   for strength in strengths:
    t=max(1,round(N*strength))
    for attack in attacks:
     for rep in range(a.trials):
      if attack=='exact_copy':X=D.copy()
      elif attack=='full_random':X=rng.integers(0,2,size=D.shape,dtype='uint8')
      elif attack=='cross_issuance':
       other=rng.integers(0,2,size=m.shape,dtype='uint8');_,X=issue(other,rng)
      elif attack=='blind_flip':
       X=D.copy();indices=rng.choice(N,size=t,replace=False);f=X.reshape(-1,2);f[indices,0]^=1;f[indices,1]^=1
      elif attack in ('known_content_forge','reference_aware_forge','adaptive_feedback'):
       indices=rng.choice(N,size=t,replace=False)
       # Known-content attacker reconstructs R; 'adaptive_feedback' probes only
       # with feedback, but here no oracle is given. Its budget is recorded below.
       X=forge_content(rr if attack!='reference_aware_forge' else R,D,m,indices)
      elif attack=='ink_add':
       X=D.copy();f=X.reshape(-1,2);indices=rng.choice(f.size,size=min(t,f.size),replace=False);f.reshape(-1)[indices]=1
      elif attack=='ink_remove':
       X=D.copy();f=X.reshape(-1,2);indices=rng.choice(f.size,size=min(t,f.size),replace=False);f.reshape(-1)[indices]=0
      elif attack=='block':
       X=D.copy();h,w=m.shape;side=max(1,int(math.sqrt(t)));y=int(rng.integers(0,max(1,h-side+1)));x=int(rng.integers(0,max(1,w-side+1)));X[y:y+side,x:x+side,:]=rng.integers(0,2,size=X[y:y+side,x:x+side,:].shape,dtype='uint8')
      changed=(decode(R,X).ravel()!=flat);changed_count=int(changed.sum());pixel_change_fraction=changed_count/N
      for k in checks:
       effective_k=min(k,N)
       chosen=select_indices(N,effective_k,rng,'uniform',a.tile,m.shape)
       accept=bool(not np.any(changed[chosen])) # equivalent to ideal digital inspect; decode once per attack trial
       expected=exact_accept(N,effective_k,changed_count)
       record={'image':name,'split':kind,'attack':attack,'strength':strength,'trial':rep,'checks':effective_k,'changed_content_pixels':changed_count,'changed_content_fraction':pixel_change_fraction,'accepted':int(accept),'unauthorized_content_accepted':int(accept and changed_count>0),'theoretical_uniform_accept':expected,'feedback_queries_allowed':a.feedback_queries if attack=='adaptive_feedback' else 0,'feedback_oracle_actually_used':False,'known_content':attack in ('known_content_forge','reference_aware_forge','adaptive_feedback'),'reference_available':attack=='reference_aware_forge'}
       trial_writer.writerow(record);attack_record_count+=1
       key=(attack,strength,effective_k);v=group[key];v[0]+=1;v[1]+=record['accepted'];v[2]+=record['unauthorized_content_accepted'];v[3]+=expected;v[4]+=changed_count
   total+=1
   if total%50==0:print(f'Processed {total}/{len(images)+7} images; attack/check records {attack_record_count}',flush=True)
  except Exception as exc:
   errors.append({'image':name,'type':type(exc).__name__,'message':str(exc)})
   if a.strict_data:raise
 # Group summaries without retaining the large per-trial table in memory
 trial_handle.close()
 summary=[{'attack':key[0],'strength':key[1],'checks':key[2],'trials':v[0],'acceptance_rate':v[1]/v[0],'unauthorized_acceptance_rate':v[2]/v[0],'mean_exact_theoretical_acceptance':v[3]/v[0],'mean_changed_content_pixels':v[4]/v[0]} for key,v in sorted(group.items())]
 write_csv(out/'reports'/'reconstruction.csv',rec_rows);write_csv(out/'reports'/'attack_summary.csv',summary);write_csv(out/'reports'/'optical_summary.csv',opt_rows);write_csv(out/'reports'/'errors.csv',errors)
 # Exact finite bounds for fixed numbers of altered pixels, including a 1-pixel attack.
 for n in (64,256,16384):
  for t in (1,max(1,n//100),max(1,n//20)):
   for k in checks:bounds.append({'N':n,'changed_pixels':t,'checks':min(k,n),'exact_acceptance_probability':exact_accept(n,min(k,n),t),'exact_detection_probability':1-exact_accept(n,min(k,n),t)})
 write_csv(out/'mathematical_validation'/'hypergeometric_bounds.csv',bounds)
 write_json(out/'cryptographic_audit'/'electronic_issuance.json',pq)
 verdict={'single_share_content_secrecy':'PROVEN_FOR_IDEAL_BASIS_ONLY','ideal_reconstruction':'PASSED' if all(r['reconstruction_accuracy']==1 for r in rec_rows) else 'FAILED','known_content_reference_secrecy':'FAILED_EXACT_RECOVERY','private_challenge_spot_check':'STATISTICAL_DETECTION_ONLY','single_pixel_forgery_resistance':'WEAK_WHEN_CHECKS_MUCH_LESS_THAN_PIXELS','adaptive_feedback_resistance':'NOT_ESTABLISHED_NO_ORACLE_SIMULATED','content_binding':'CONDITIONAL_ON_TRUSTED_EXPECTED_CONTENT_AND_HUMAN_COMPARISON','exact_copy_resistance':'IMPOSSIBLE_FOR_IDENTICAL_OPTICAL_COPY','human_only_optical_authentication':'NOT_ESTABLISHED','post_quantum_optical_origin_authentication':'NOT_ESTABLISHED','physical_transparency_testing':'NOT_PERFORMED','human_observer_testing':'NOT_PERFORMED','mldsa_electronic_issuance':pq.get('mldsa_status') if pq else 'NOT_EXECUTED','key_result':'Fresh verifier-secret sample locations detect modified pixels with exact hypergeometric probability; cannot guarantee all changes, origin, or physical human recognition.'}
 write_json(out/'reports'/'verdict.json',verdict)
 result={'output':str(out),'images_processed':total,'real_images_processed':real,'adversarial_check_trials':attack_record_count,'optical_trials':len(opt_rows),'errors':len(errors),'elapsed_seconds':round(time.perf_counter()-start,2),'results':verdict}
 write_json(out/'reports'/'summary.json',result);print(json.dumps(result,indent=2));return result
if __name__=='__main__':main()
