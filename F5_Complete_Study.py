#!/usr/bin/env python3
"""F5: Trust-Bound Optical Comparison and Impossibility Study.

Research outcome, not a claimed secure human-only PQ optical protocol.
F5 replaces secret-reference VC with an independently trusted, *public* expected
image and a full-field optical mismatch-comparison hypothesis. A trusted
reference is mandatory; no secrecy or authenticity is inferred from a printed
pattern alone. A digital XOR is an IDEAL OBSERVER surrogate, NOT a demonstrated
passive transparency operator. Cryptographic signing is an independent electronic
control, not optical verification.

Run:
 python F5_Complete_Study.py --image-limit 0 --side 128 --trials 30 --optical-samples 30 --strict-data
Requires numpy pillow. Optional pqcrypto for electronic ML-DSA.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,math,platform,sys,time
from pathlib import Path
from datetime import datetime,timezone
import numpy as np
from PIL import Image,ImageFilter
ROOT=Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')

def jwrite(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,indent=2,default=str),encoding='utf-8')
def cwrite(p,rows):
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
  seen.add(digest);out.append((rel,'sipi' if rel.startswith('misc/') else 'bsds500'))
 out.sort()
 if strict and missing:raise FileNotFoundError(f'{len(missing)} missing; first {missing[0]}')
 if strict and limit==0 and len(out)!=539:raise ValueError(f'Expected 539 canonical real images; found {len(out)}')
 return out[:limit] if limit else out
def synthetic(side):
 y,x=np.indices((side,side));c=(side-1)/2
 return [('checker',((x+y)%2).astype('uint8')),('stripes',((x//4)%2).astype('uint8')),('circle',(((x-c)**2+(y-c)**2)<(side/3)**2).astype('uint8')),('symbol_H',(((x>side//5)&(x<side//3)&(y>side//6)&(y<5*side//6))|((x>2*side//3)&(x<4*side//5)&(y>side//6)&(y<5*side//6))|((abs(y-side//2)<2)&(x>side//5)&(x<4*side//5))).astype('uint8')),('random',np.random.default_rng(19).integers(0,2,(side,side),dtype='uint8')),('all_white',np.zeros((side,side),dtype='uint8')),('all_black',np.ones((side,side),dtype='uint8'))]
def load_image(p,side,threshold):
 with Image.open(p) as im:
  im=im.convert('L');im.thumbnail((side,side),Image.Resampling.LANCZOS)
  return (np.asarray(im,dtype='uint8')<threshold).astype('uint8')
def issue_vc(m,rng):
 a=rng.integers(0,2,size=m.shape,dtype='uint8');R=np.stack((a,1-a),axis=-1)
 b=a^m;D=np.stack((b,1-b),axis=-1)
 return R,D
def vc_decode(R,D):return (np.sum(R|D,axis=-1)==2).astype('uint8')
def recover_reference(D,m):
 a=D[...,0]^m;return np.stack((a,1-a),axis=-1)
def optical_mismatch_ideal(expected,presented):return np.bitwise_xor(expected,presented)
def mismatch_channels(expected,presented):
 # Two directional comparisons: new black pixels and removed black pixels.
 return ((1-expected)&presented),(expected&(1-presented))
def exact_spot_miss(N,t,k):
 if t==0:return 1.
 if k>N-t:return 0.
 return math.exp(math.lgamma(N-t+1)-math.lgamma(k+1)-math.lgamma(N-t-k+1)-math.lgamma(N+1)+math.lgamma(k+1)+math.lgamma(N-k+1))
def mathematical_audit():
 # Exhaustively test two-subpixel Naor-Shamir basis and known-content recovery.
 records=[]
 for m in (0,1):
  for a in (0,1):
   R=np.array([a,1-a],dtype=np.uint8);D=np.array([a^m,1-(a^m)],dtype=np.uint8)
   rr=np.array([D[0]^m,1-(D[0]^m)],dtype=np.uint8)
   records.append(dict(m=m,random_bit=a,reference_recovered=bool(np.array_equal(R,rr)),decoded=int(np.sum(R|D)==2)))
 # Universal statement for deterministic, uniquely-decodable reference under known (M,D).
 # This is an algebraic conditional, NOT an impossibility theorem for all optical schemes.
 return {'basis_cases':records,'known_content_reference_recovery_all':all(x['reference_recovered'] for x in records),
 'conditional_inversion_lemma':'If R is a unique solution of Decode(R,D)=M for known M,D, R is recoverable by exhaustive search. This does not apply to non-unique or computationally hard inverse maps.',
 'static_exact_copy_lemma':'Any deterministic verifier observing identical physical inputs accepts a perfect copy exactly as it accepts the original.',
 'trusted_reference_necessity':'Without an independently authenticated expectation or secret/challenge, acceptance of a visible pattern alone cannot identify its issuer.',
 'optical_operator_warning':'XOR and directional mismatches are ideal digital observer models; ordinary passive OR stacking does not compute XOR.'}
def audit_electronic(m):
 payload=hashlib.sha256(m.tobytes()).digest();changed=bytearray(m.tobytes());changed[0]^=1
 out={'sha256_tamper_detected':hashlib.sha256(bytes(changed)).digest()!=payload,'ml_dsa':'NOT_EXECUTED','optical_signature_verification':False}
 try:
  from pqcrypto.sign import ml_dsa_65 as mod
  if not all(callable(getattr(mod,x,None)) for x in ('generate_keypair','sign','verify')):
   out['ml_dsa']='API_UNAVAILABLE';return out
  pk,sk=mod.generate_keypair();sig=mod.sign(sk,payload)
  result=mod.verify(pk,payload,sig)
  # pqcrypto verify convention: None means success; some implementations return True.
  good=(result is None or result is True)
  try:
   bad=mod.verify(pk,hashlib.sha256(bytes(changed)).digest(),sig)
   tamper_rejected=not (bad is None or bad is True)
  except Exception:tamper_rejected=True
  out.update(ml_dsa='EXECUTED',valid_signature_verified=good,tampered_payload_rejected=tamper_rejected)
 except Exception as e:out.update(ml_dsa='UNAVAILABLE_OR_ERROR',detail=f'{type(e).__name__}: {e}')
 return out
def forge(m,kind,strength,rng,other=None):
 n=m.size;t=max(1,round(n*strength));out=m.copy();flat=out.ravel()
 if kind=='random_flip':idx=rng.choice(n,size=min(t,n),replace=False);flat[idx]^=1
 elif kind=='block':
  h,w=m.shape;side=max(1,round(math.sqrt(t)));yy=int(rng.integers(0,max(1,h-side+1)));xx=int(rng.integers(0,max(1,w-side+1)))
  out[yy:yy+side,xx:xx+side]^=1
 elif kind=='add_ink':
  idx=np.flatnonzero(flat==0)
  if len(idx):flat[rng.choice(idx,size=min(t,len(idx)),replace=False)]=1
 elif kind=='remove_ink':
  idx=np.flatnonzero(flat==1)
  if len(idx):flat[rng.choice(idx,size=min(t,len(idx)),replace=False)]=0
 elif kind=='swap':
  if other is not None and other.shape==m.shape:out=other.copy()
  else:out=1-m
 elif kind=='exact_copy':pass
 elif kind=='reference_compromise':idx=rng.choice(n,size=min(t,n),replace=False);flat[idx]^=1
 elif kind=='targeted_single':flat[int(rng.integers(n))]^=1
 else:raise ValueError(kind)
 return out

def optical_sim(m,rng,mode):
 h,w=m.shape
 if mode=='horizontal_shift':return np.roll(m,1,axis=1)
 if mode=='vertical_shift':return np.roll(m,1,axis=0)
 if mode=='noise':
  out=m.copy();idx=rng.choice(m.size,size=max(1,round(.005*m.size)),replace=False);out.ravel()[idx]^=1;return out
 if mode=='blur':
  return (np.asarray(Image.fromarray((1-m)*255).filter(ImageFilter.GaussianBlur(.8)))<128).astype('uint8')
 if mode=='rotation':return np.rot90(m,1) if h==w else np.roll(m,1,axis=0)
 raise ValueError(mode)
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--image-limit',type=int,default=0);p.add_argument('--side',type=int,default=128);p.add_argument('--trials',type=int,default=30);p.add_argument('--optical-samples',type=int,default=30);p.add_argument('--strict-data',action='store_true');p.add_argument('--seed',type=int,default=20261107);p.add_argument('--threshold',type=int,default=128);p.add_argument('--checks',default='16,64,256,1024');p.add_argument('--output',type=Path,default=None)
 args=p.parse_args();start=time.monotonic();rng=np.random.default_rng(args.seed)
 root=args.root;out=args.output or root/'Results'/'F5_Complete';data=root/'Data';manifest=root/'Data_Inspection'/'file_manifest.csv'
 checks=sorted(set(int(x) for x in args.checks.split(',') if x.strip()));assert all(k>0 for k in checks)
 real=discover(data,manifest,args.image_limit,args.strict_data)
 images=[(name,load_image(data/name,args.side,args.threshold),'real') for name,_ in real]+[(name,arr,'synthetic') for name,arr in synthetic(args.side)]
 if not images:raise RuntimeError('No images')
 jwrite(out/'configuration'/'run.json',dict(command=sys.argv,seed=args.seed,real_images=len(real),images=len(images),platform=platform.platform(),numpy=np.__version__,date=datetime.now(timezone.utc).isoformat(),optical_model='IDEAL_DIGITAL_MISMATCH_NOT_VALIDATED_PHYSICAL_OPTICS'))
 mathaudit=mathematical_audit();jwrite(out/'mathematical_validation'/'exact_cases.json',mathaudit)
 attack_kinds=['random_flip','block','add_ink','remove_ink','swap','targeted_single','exact_copy','reference_compromise']
 strengths=[.001,.01,.05]
 trialpath=out/'reports'/'attacks_trials.csv';trialpath.parent.mkdir(parents=True,exist_ok=True)
 summary={};recon=[];optical=[];counter=0;errors=[];sample_count=0
 with trialpath.open('w',newline='',encoding='utf-8-sig') as f:
  fields=['image','kind','strength','trial','checks','modified_pixels','ideal_full_field_detected','spot_detected','theoretical_spot_detection','trusted_reference_required','attack_assumption']
  writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
  for ii,(name,m,typ) in enumerate(images):
   try:
    R,D=issue_vc(m,rng);decoded=vc_decode(R,D);recovered=recover_reference(D,m)
    recon.append(dict(image=name,type=typ,height=m.shape[0],width=m.shape[1],ideal_accuracy=float(np.mean(decoded==m)),known_content_reference_recovered=bool(np.array_equal(R,recovered)),pixel_expansion=2))
    if sample_count<8:
     (out/'figures').mkdir(parents=True,exist_ok=True)
     changed=forge(m,'block',.01,rng);mask=optical_mismatch_ideal(m,changed)
     Image.fromarray((1-m)*255).save(out/'figures'/f'{sample_count:03d}_expected.png')
     Image.fromarray((1-changed)*255).save(out/'figures'/f'{sample_count:03d}_forged.png')
     Image.fromarray(mask*255).save(out/'figures'/f'{sample_count:03d}_ideal_mismatch.png')
     sample_count+=1
    for kind in attack_kinds:
     for strength in strengths:
      for trial in range(args.trials):
       other=images[int(rng.integers(len(images)))][1] if kind=='swap' else None
       presented=forge(m,kind,strength,rng,other)
       t=int(np.count_nonzero(optical_mismatch_ideal(m,presented)));N=m.size
       for k in checks:
        kk=min(k,N);idx=rng.choice(N,size=kk,replace=False)
        spotted=bool(np.any(m.ravel()[idx]!=presented.ravel()[idx]))
        ideal=t>0
        theory=1-exact_spot_miss(N,t,kk)
        assumption='reference_compromised' if kind=='reference_compromise' else ('copy_equivalence' if kind=='exact_copy' else 'trusted_expected_image')
        writer.writerow(dict(image=name,kind=kind,strength=strength,trial=trial,checks=kk,modified_pixels=t,ideal_full_field_detected=int(ideal),spot_detected=int(spotted),theoretical_spot_detection=theory,trusted_reference_required=1,attack_assumption=assumption));counter+=1
        key=(kind,strength,kk);v=summary.setdefault(key,[0,0,0,0.,0]);v[0]+=1;v[1]+=int(ideal);v[2]+=int(spotted);v[3]+=theory;v[4]+=t
    if ii<args.optical_samples:
     for mode in ('horizontal_shift','vertical_shift','noise','blur','rotation'):
      pert=optical_sim(m,rng,mode);optical.append(dict(image=name,mode=mode,mismatch_fraction=float(np.mean(m!=pert)),ideal_false_rejection=int(np.any(m!=pert))))
    if (ii+1)%50==0:print(f'Processed {ii+1}/{len(images)} images; attack/check records {counter}',flush=True)
   except Exception as e:
    errors.append(dict(image=name,error=f'{type(e).__name__}: {e}'))
    if args.strict_data:raise
 cwrite(out/'reports'/'reconstruction.csv',recon);cwrite(out/'reports'/'optical_summary.csv',optical)
 sums=[]
 for (kind,strength,k),v in sorted(summary.items()):
  sums.append(dict(kind=kind,strength=strength,checks=k,trials=v[0],ideal_full_field_detection_rate=v[1]/v[0],spot_detection_rate=v[2]/v[0],mean_exact_spot_detection_probability=v[3]/v[0],mean_modified_pixels=v[4]/v[0]))
 cwrite(out/'reports'/'attack_summary.csv',sums);cwrite(out/'reports'/'errors.csv',errors)
 e_audit=audit_electronic(images[0][1]);jwrite(out/'cryptographic_audit'/'electronic_issuance.json',e_audit)
 verdict={'classical_basis_single_share_privacy':'PROVEN_FOR_CONTENT_BASIS_ONLY','ideal_reconstruction':'PASSED' if all(r['ideal_accuracy']==1 for r in recon) else 'FAILED',
 'known_content_reference_secrecy':'FAILED_EXACT_RECOVERY_FOR_CLASSICAL_BASIS',
 'F5_reference_model':'INDEPENDENTLY_TRUSTED_PUBLIC_EXPECTED_IMAGE_NO_SECRET_REFERENCE',
 'ideal_full_field_mismatch_detection':'EXACT_FOR_NONZERO_BINARY_CONTENT_CHANGE_UNDER_IDEAL_DIGITAL_XOR',
 'physical_passive_overlay_XOR':'NOT_ESTABLISHED',
 'human_only_optical_verification':'NOT_ESTABLISHED',
 'origin_authentication':'REQUIRES_INDEPENDENTLY_AUTHENTICATED_TRUST_ANCHOR',
 'exact_copy_resistance':'IMPOSSIBLE_FOR_IDENTICAL_STATIC_OBSERVATION',
 'post_quantum_optical_authentication':'NOT_ESTABLISHED',
 'ml_dsa_electronic_issuance':e_audit['ml_dsa'],
 'physical_transparency_study':'NOT_PERFORMED','human_observer_study':'NOT_PERFORMED',
 'conditional_result':'F5 detects all actual binary mismatches under an ideal full-field comparator and trusted expectation; it does not realize that comparator as unaided optics or authenticate provenance.'}
 jwrite(out/'reports'/'verdict.json',verdict)
 result=dict(output=str(out),images_processed=len(recon),real_images_processed=sum(x['type']=='real' for x in recon),adversarial_check_trials=counter,optical_trials=len(optical),errors=len(errors),elapsed_seconds=round(time.monotonic()-start,2),results=verdict)
 jwrite(out/'reports'/'summary.json',result);print(json.dumps(result,indent=2))
if __name__=='__main__':main()
