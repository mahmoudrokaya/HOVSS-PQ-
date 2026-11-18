#!/usr/bin/env python3
"""F7: Registration-tolerant differential optical verification with an externally
trusted physical reference. Computational *instrumented* alignment and detection
only; registration search and scoring use digital processing, NOT unaided vision.
Python 3.10+, numpy, Pillow. Run from Experiments/Code.
"""
import argparse,csv,hashlib,json,math,platform,time
from pathlib import Path
import numpy as np
from PIL import Image,ImageFilter

ATTACKS=('random_flip','localized_block','ink_add','ink_remove','single_pixel','substitution','exact_copy','reference_swap','fiducial_damage')
CONDITIONS=('ideal','noise','high_noise','shift_x1','shift_y1','shift_xy1','blur','shift_blur','gain','fiducial_occlusion')

def savej(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,indent=2,default=lambda x:x.item() if isinstance(x,np.generic) else str(x)),encoding='utf-8')
def rootdir():
 p=Path(__file__).resolve();return p.parent.parent if p.parent.name.lower()=='code' else p.parent

def discover(root,strict):
 base=root/'Data';dirs=[(base/'BSR'/'BSDS500'/'data'/'images'/s,'BSDS500') for s in ('train','val','test')]+[(base/'misc','USC-SIPI')]
 out=[];counts={}
 for folder,src in dirs:
  if not folder.exists():
   if strict:raise FileNotFoundError(str(folder))
   continue
  exts=('*.jpg','*.jpeg') if src=='BSDS500' else ('*.tif','*.tiff')
  fs=sorted(set(p for ext in exts for p in folder.glob(ext)));counts[str(folder)]=len(fs);out.extend((str(p),src,None) for p in fs)
 if strict and (sum(v for k,v in counts.items() if 'BSDS500' in k)!=500 or sum(v for k,v in counts.items() if 'misc' in k)!=39):raise RuntimeError(f'Expected 500+39 real images: {counts}')
 return out,counts

def synth(side):
 y,x=np.indices((side,side));r=np.random.default_rng(117)
 return [('synthetic_'+n,'synthetic',np.asarray(a,dtype=np.uint8)) for n,a in [
 ('zeros',np.zeros((side,side))),('ones',np.ones((side,side))),('checker',(x+y)%2),('stripes',(x//8)%2),
 ('rings',(((x-side/2)**2+(y-side/2)**2)//160)%2),('random',r.integers(0,2,(side,side))),('disc',((x-side/2)**2+(y-side/2)**2)<(side/4)**2)]]
def read(path,side):
 with Image.open(path) as im:a=np.asarray(im.convert('L').resize((side,side),Image.Resampling.BILINEAR))
 return (a<128).astype(np.uint8)

def shift(a,dx,dy,fill):
 h,w=a.shape;o=np.full((h,w),fill,dtype=np.float64);xa=max(0,dx);xb=min(w,w+dx);ya=max(0,dy);yb=min(h,h+dy)
 if xa<xb and ya<yb:o[ya:yb,xa:xb]=a[ya-dy:yb-dy,xa-dx:xb-dx]
 return o

def blur(a,r):
 if r==0:return a
 return np.asarray(Image.fromarray(np.uint8(np.clip(a*255,0,255))).filter(ImageFilter.GaussianBlur(r)),dtype=np.float64)/255

def fiducial(side,seed=777):
 # fixed public fiducial: NOT a cryptographic authenticator
 r=np.random.default_rng(seed);f=np.zeros((side,side),dtype=np.uint8);w=max(3,side//16)
 f[:w,:w]=r.integers(0,2,(w,w));f[:w,-w:]=r.integers(0,2,(w,w));f[-w:,:w]=r.integers(0,2,(w,w));f[-w:,-w:]=r.integers(0,2,(w,w))
 mask=np.zeros((side,side),dtype=bool)
 for yy in (slice(0,w),slice(side-w,side)):
  for xx in (slice(0,w),slice(side-w,side)):mask[yy,xx]=True
 return f,mask

def physical(E,P,td,tc,rng,dx=0,dy=0,noise=0,gain=0,br=0,fdamage=False,ref_override=None):
 ref=E if ref_override is None else ref_override
 R=np.where(ref,td,tc).astype(float);D=np.where(P,tc,td).astype(float)
 F,mask=fiducial(E.shape[0]);# fiducial printed on the presented layer, independently of content
 D[mask]=np.where(F[mask],tc,td)
 if fdamage:D[mask]=tc
 if dx or dy:D=shift(D,dx,dy,tc)
 if br:R=blur(R,br);D=blur(D,br)
 I=R*D
 if gain:I*=max(.01,1+rng.normal(0,gain))
 if noise:I+=rng.normal(0,noise,I.shape)
 return np.clip(I,0,1)

def estimate_shift(I,E,td,tc,radius,mask):
 # INSTRUMENTED oracle-like registration: assumes reference E is known digitally.
 # Candidate score uses fiducial positions only, not content pixels.
 F,_=fiducial(E.shape[0]);R=np.where(E,td,tc).astype(float);D=np.where(F,tc,td).astype(float)
 scores=[]
 for dy in range(-radius,radius+1):
  for dx in range(-radius,radius+1):
   pred=R*shift(D,dx,dy,tc)
   # Compare fiducial only, with global gain normalization
   a=pred[mask];b=I[mask];g=np.dot(a,b)/(np.dot(a,a)+1e-12)
   err=float(np.mean((g*a-b)**2));scores.append((err,abs(dx)+abs(dy),dx,dy))
 scores.sort();return scores[0][2],scores[0][3],scores[0][0]

def compensated_score(I,E,td,tc,dx,dy,mask,threshold,trim):
 # Correct for known illumination and registered image geometry; exclude shifted boundaries.
 h,w=E.shape;R=np.where(E,td,tc);baseline=td*tc
 valid=np.ones((h,w),dtype=bool)&~mask
 edge=max(abs(dx),abs(dy))+2
 if edge:valid[:edge,:]=False;valid[-edge:,:]=False;valid[:,:edge]=False;valid[:,-edge:]=False
 # Estimate gain using median of nonfiducial pixels (assumes sparse tampering)
 med=float(np.median(I[valid])) if np.any(valid) else baseline
 gain=baseline/max(med,1e-9);gain=float(np.clip(gain,.4,2.5))
 residual=np.abs(I*gain-baseline)
 vals=residual[valid]
 if not len(vals):return 0.,0.,0
 # Trim extreme residuals only for robust calibration, not for detection.
 frac=float(np.mean(vals>threshold));peak=float(np.quantile(vals,.999))
 return peak,frac,int(frac>trim)

def forge(E,rng,attack,strength,sub):
 P=E.copy();n=P.size;h,w=P.shape;t=max(1,round(strength*n))
 if attack=='random_flip':P.flat[rng.choice(n,min(t,n),replace=False)]^=1
 elif attack=='localized_block':
  a=min(h,max(1,int(math.ceil(math.sqrt(t)))));y=int(rng.integers(0,h-a+1));x=int(rng.integers(0,w-a+1));P[y:y+a,x:x+a]^=1
 elif attack=='ink_add':P.flat[rng.choice(n,min(t,n),replace=False)]=1
 elif attack=='ink_remove':P.flat[rng.choice(n,min(t,n),replace=False)]=0
 elif attack=='single_pixel':P.flat[int(rng.integers(n))]^=1
 elif attack=='substitution':P=sub.copy()
 elif attack in ('exact_copy','reference_swap','fiducial_damage'):pass
 else:raise ValueError(attack)
 return P

def crypto():
 msg=b'F7|issuer|reference-id|expected-hash|nonce';d={'sha256_tamper_detected':hashlib.sha256(msg).digest()!=hashlib.sha256(msg+b'changed').digest(),'ml_dsa':'NOT_EXECUTED','physical_reference_authenticated':False,'trust_note':'Trusted reference is a provisioning assumption, not proved by optical fiducials or a digital signature.'}
 try:
  from pqcrypto.sign import ml_dsa_65 as m
  if not all(callable(getattr(m,x,None)) for x in ('generate_keypair','sign','verify')):d['reason']='ML-DSA API unavailable';return d
  pk,sk=m.generate_keypair();sig=m.sign(sk,msg)
  try:v=m.verify(pk,msg,sig);valid=v is None or v is True
  except Exception:valid=False
  try:v=m.verify(pk,msg+b'changed',sig);tamper=v is False
  except Exception:tamper=True
  d.update(ml_dsa='ELECTRONIC_PASS' if valid and tamper else 'ELECTRONIC_FAILED',valid=valid,tamper_rejected=tamper)
 except Exception as e:d['reason']=f'{type(e).__name__}: {e}'
 return d

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for name,typ,default in [('image-limit',int,0),('side',int,128),('trials',int,30),('optical-samples',int,30),('seed',int,20261107),('registration-radius',int,2),('t-dark',float,.15),('t-clear',float,.85),('noise-sd',float,.012),('gain-sd',float,.015)]:ap.add_argument('--'+name,type=typ,default=default)
 ap.add_argument('--strict-data',action='store_true');ap.add_argument('--thresholds',default='.03,.06,.10');ap.add_argument('--fractions',default='0,.0001,.001');ap.add_argument('--strengths',default='.001,.01,.05')
 args=ap.parse_args()
 if args.side<32 or args.trials<1 or args.registration_radius<0 or not 0<args.t_dark<args.t_clear<=1:ap.error('Invalid dimensions, optical coefficients, or trial count')
 thresholds=[float(v) for v in args.thresholds.split(',')];fractions=[float(v) for v in args.fractions.split(',')];strengths=[float(v) for v in args.strengths.split(',')]
 if any(v<0 or v>=1 for v in fractions) or any(v<=0 for v in thresholds) or any(v<=0 or v>1 for v in strengths):ap.error('Invalid threshold/fraction/strength')
 root=rootdir();out=root/'Results'/'F7_Complete'
 for p in ('configuration','mathematical_validation','reports','optical_simulation','cryptographic_audit','figures'):(out/p).mkdir(parents=True,exist_ok=True)
 files,counts=discover(root,args.strict_data)
 if args.image_limit>0:files=files[:args.image_limit]
 samples=files+synth(args.side);savej(out/'configuration'/'run.json',dict(vars(args),dataset_counts=counts,images=len(samples),python=platform.python_version(),numpy=np.__version__))
 savej(out/'mathematical_validation'/'claims.json',{'physical_operator':'I=T_reference*T_presented with fiducials and nuisance','registration':'digital fiducial-only least squares search followed by simulated mechanical repositioning and re-exposure; not unaided human alignment','trusted_reference':'external assumption; issuer origin is NOT proven by optical patterns','known_content':'attacker knowing expected content can manufacture a matching layer','perfect_copy':'indistinguishable from original under same optical observation','misregistration_vs_tamper':'If legitimate and forged observation distributions overlap, no observation-only rule can achieve both zero false rejects and zero false accepts.','edge_caveat':'Boundary exclusion creates a blind region and must be reported','content_secrecy':'NOT PROVIDED: public expected-image comparison differs from secret sharing','post_quantum':'ML-DSA audit, if available, is electronic only'})
 rng=np.random.default_rng(args.seed);mask=fiducial(args.side)[1]
 attack_fields=['image','source','attack','strength','trial','threshold','fraction_cutoff','actual_content_changes','reference_compromised','registration_dx','registration_dy','estimated_dx','estimated_dy','registration_correct','max_deviation_q999','fraction_above','rejected']
 optical_fields=['image','condition','threshold','fraction_cutoff','true_dx','true_dy','estimated_dx','estimated_dy','registration_correct','fraction_above','false_reject']
 af=open(out/'reports'/'attacks_trials.csv','w',newline='',encoding='utf-8');aw=csv.DictWriter(af,fieldnames=attack_fields);aw.writeheader()
 of=open(out/'reports'/'optical_trials.csv','w',newline='',encoding='utf-8');ow=csv.DictWriter(of,fieldnames=optical_fields);ow.writeheader()
 stats={};ostats={};recon=[];atotal=0;ototal=0;start=time.time()
 for idx,(name,source,arr) in enumerate(samples):
  E=read(name,args.side) if arr is None else arr;sub=np.roll(E,1,axis=1) if idx else 1-E
  recon.append({'image':name,'source':source,'ideal_matching_fraction':1.,'reference_public':True,'pixels':E.size})
  if idx<10:
   Image.fromarray(np.uint8(E*255)).save(out/'figures'/f'{idx:03d}_expected.png')
   I=physical(E,E,args.t_dark,args.t_clear,rng);Image.fromarray(np.uint8(I*255)).save(out/'figures'/f'{idx:03d}_matched_transmission.png')
  for attack in ATTACKS:
   for strength in strengths:
    for trial in range(args.trials):
     P=forge(E,rng,attack,strength,sub);changed=int(np.count_nonzero(E!=P));compromised=attack=='reference_swap'
     ref_override=P if compromised else None
     # Random registration nuisance on both honest and malicious trials.
     dx=int(rng.integers(-1,2));dy=int(rng.integers(-1,2))
     I=physical(E,P,args.t_dark,args.t_clear,rng,dx=dx,dy=dy,noise=args.noise_sd,gain=args.gain_sd,fdamage=attack=='fiducial_damage',ref_override=ref_override)
     ex,ey,_=estimate_shift(I,E if not compromised else P,args.t_dark,args.t_clear,args.registration_radius,mask)
     # Simulated physical re-positioning of the presented layer, followed by a fresh exposure.
     I=physical(E,P,args.t_dark,args.t_clear,rng,dx=dx-ex,dy=dy-ey,noise=args.noise_sd,gain=args.gain_sd,fdamage=attack=='fiducial_damage',ref_override=ref_override)
     for threshold in thresholds:
      peak,frac,_=compensated_score(I,E,args.t_dark,args.t_clear,ex,ey,mask,threshold,0)
      for cutoff in fractions:
       rejected=int(frac>cutoff);row=dict(image=name,source=source,attack=attack,strength=strength,trial=trial,threshold=threshold,fraction_cutoff=cutoff,actual_content_changes=changed,reference_compromised=int(compromised),registration_dx=dx,registration_dy=dy,estimated_dx=ex,estimated_dy=ey,registration_correct=int((dx,dy)==(ex,ey)),max_deviation_q999=peak,fraction_above=frac,rejected=rejected)
       aw.writerow(row);atotal+=1;key=(attack,strength,threshold,cutoff);v=stats.setdefault(key,[0,0,0,0,0]);v[0]+=1;v[1]+=rejected;v[2]+=int(changed>0);v[3]+=int(rejected and changed>0);v[4]+=int((dx,dy)==(ex,ey))
  if idx<args.optical_samples:
   for cond in CONDITIONS:
    dx=1 if cond in ('shift_x1','shift_xy1','shift_blur') else 0;dy=1 if cond in ('shift_y1','shift_xy1') else 0
    ns=args.noise_sd*(2 if cond=='high_noise' else 1) if cond in ('noise','high_noise','shift_blur','shift_x1','shift_y1','shift_xy1','blur','fiducial_occlusion') else 0
    gain=args.gain_sd*2 if cond=='gain' else 0;br=.7 if cond in ('blur','shift_blur') else 0
    I=physical(E,E,args.t_dark,args.t_clear,rng,dx=dx,dy=dy,noise=ns,gain=gain,br=br,fdamage=cond=='fiducial_occlusion')
    ex,ey,_=estimate_shift(I,E,args.t_dark,args.t_clear,args.registration_radius,mask)
    # Fresh exposure after modeled mechanical correction; residual errors remain.
    I=physical(E,E,args.t_dark,args.t_clear,rng,dx=dx-ex,dy=dy-ey,noise=ns,gain=gain,br=br,fdamage=cond=='fiducial_occlusion')
    for threshold in thresholds:
     peak,frac,_=compensated_score(I,E,args.t_dark,args.t_clear,ex,ey,mask,threshold,0)
     for cutoff in fractions:
      rej=int(frac>cutoff);ow.writerow(dict(image=name,condition=cond,threshold=threshold,fraction_cutoff=cutoff,true_dx=dx,true_dy=dy,estimated_dx=ex,estimated_dy=ey,registration_correct=int((dx,dy)==(ex,ey)),fraction_above=frac,false_reject=rej));ototal+=1
      key=(cond,threshold,cutoff);v=ostats.setdefault(key,[0,0,0]);v[0]+=1;v[1]+=rej;v[2]+=int((dx,dy)==(ex,ey))
  if (idx+1)%50==0:print(f'Processed {idx+1}/{len(samples)} images; attack-threshold records {atotal}',flush=True)
 af.close();of.close()
 with open(out/'reports'/'attack_summary.csv','w',newline='',encoding='utf-8') as f:
  w=csv.writer(f);w.writerow(['attack','strength','threshold','fraction_cutoff','trials','reject_rate','changed_rate','reject_given_change','registration_accuracy'])
  for key,(n,r,c,d,a) in sorted(stats.items()):w.writerow([*key,n,r/n,c/n,d/c if c else 'NA',a/n])
 with open(out/'reports'/'optical_summary.csv','w',newline='',encoding='utf-8') as f:
  w=csv.writer(f);w.writerow(['condition','threshold','fraction_cutoff','trials','false_reject_rate','registration_accuracy'])
  for key,(n,r,a) in sorted(ostats.items()):w.writerow([*key,n,r/n,a/n])
 with open(out/'reports'/'reconstruction.csv','w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=recon[0].keys());w.writeheader();w.writerows(recon)
 audit=crypto();savej(out/'cryptographic_audit'/'electronic_issuance.json',audit)
 verdict={'physical_forward':'SIMULATED_MULTIPLICATIVE_TRANSMISSION','fiducial_registration':'DIGITAL_INSTRUMENTED_ALIGNMENT_ONLY','registration_tolerance':'EMPIRICAL_THRESHOLD_DEPENDENT','content_integrity':'CONDITIONAL_ON_TRUSTED_EXPECTED_IMAGE_AND_NOISE_MODEL','known_content_origin_authentication':'FAILED_MATCHING_LAYER_CAN_BE_REPRINTED','reference_origin_authentication':'ASSUMED_EXTERNAL_NOT_IMPLEMENTED','reference_swap':'OUTSIDE_TRUST_MODEL_AND_DEFEATS_COMPARISON','exact_copy_resistance':'IMPOSSIBLE_STATIC_OBSERVATION','single_share_secrecy':'NOT_PROVIDED','human_only_authentication':'NOT_ESTABLISHED','post_quantum_optical_authentication':'NOT_ESTABLISHED','ml_dsa':audit['ml_dsa'],'physical_hardware':'NOT_TESTED','human_study':'NOT_PERFORMED'}
 savej(out/'reports'/'verdict.json',verdict)
 result={'output':str(out),'images_processed':len(samples),'real_images_processed':len(files),'attack_threshold_records':atotal,'optical_threshold_records':ototal,'errors':0,'elapsed_seconds':round(time.time()-start,2),'results':verdict}
 savej(out/'reports'/'summary.json',result);print(json.dumps(result,indent=2))
if __name__=='__main__':main()
