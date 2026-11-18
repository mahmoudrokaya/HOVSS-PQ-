#!/usr/bin/env python3
"""F1 full computational study: exhaustive theory, images, attacks, optical perturbations.

Research baseline, NOT a post-quantum authenticated visual secret-sharing protocol.
Python 3.10+, numpy and Pillow. No writes to source data. Runs all experiments
in one command and writes a consolidated verdict with explicit failed properties.
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib.util, json, math, platform, sys, time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from PIL import Image, ImageFilter

HERE=Path(__file__).resolve().parent
DEFAULT_ROOT=Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')

def save_json(p,x):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(x,indent=2,ensure_ascii=False,default=str),encoding='utf-8')
def save_csv(p,rows):
    p.parent.mkdir(parents=True,exist_ok=True)
    if not rows:return
    keys=list(dict.fromkeys(k for r in rows for k in r))
    with p.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(rows)
def digest(a):return hashlib.sha256(np.ascontiguousarray(a).tobytes()).hexdigest()
def encode(secret,rng):
    bit=rng.integers(0,2,size=secret.shape,dtype=np.uint8)
    ref=np.stack((1-bit,bit),axis=-1)
    dist=np.where(secret[...,None]==0,ref,1-ref).astype(np.uint8)
    return ref,dist
def overlay(ref,dist):return np.bitwise_or(ref,dist)
def metrics(secret,ref,dist):
    s=overlay(ref,dist); blacks=s.sum(-1); expected=1+secret
    return {'reconstruction_exact_fraction':float(np.mean(blacks==expected)),
            'white_mean_black_subpixels':float(blacks[secret==0].mean()) if np.any(secret==0) else None,
            'black_mean_black_subpixels':float(blacks[secret==1].mean()) if np.any(secret==1) else None,
            'normalized_contrast':float((blacks[secret==1].mean()-blacks[secret==0].mean())/2) if np.any(secret==0) and np.any(secret==1) else None,
            'black_fraction':float(secret.mean())}
def enumerate_theory():
    bases={0:np.array([[1,0],[1,0]],dtype=np.uint8),1:np.array([[1,0],[0,1]],dtype=np.uint8)}
    rows=[]; single=[]; conditional=[]; secrecy={}
    for secret in (0,1):
      for perm in (0,1):
        b=bases[secret][:,[0,1] if perm==0 else [1,0]]
        target=np.bitwise_or(b[0],b[1]); valid=0; ref_fixed=0
        for mask in range(16):
          flips=np.array([(mask>>k)&1 for k in range(4)],dtype=np.uint8).reshape(2,2)
          modified=b^flips
          if np.array_equal(overlay(modified[0],modified[1]),target):
            valid+=1
            if np.array_equal(modified[0],b[0]):ref_fixed+=1
        for share in (0,1):
          for sub in (0,1):
            z=b.copy();z[share,sub]^=1
            invisible=bool(np.array_equal(overlay(z[0],z[1]),target))
            single.append({'secret':secret,'permutation':perm,'share':share,'subpixel':sub,'invisible':invisible,
                           'reference_bit':int(b[0,sub]),'distributed_bit':int(b[1,sub])})
        rows.append({'secret':secret,'permutation':perm,'valid_joint_bitflip_masks':valid,
                     'valid_masks_reference_unchanged':ref_fixed})
    for share in (0,1):
      dist=[]
      for secret in (0,1):
        outcomes=[tuple(map(int,bases[secret][share,[0,1] if perm==0 else [1,0]])) for perm in (0,1)]
        dist.append(dict(Counter(outcomes)))
      secrecy[f'share_{share+1}_perfect_single_pixel_privacy']=dist[0]==dist[1]
    # For fixed ref and arbitrary dist, every position where ref=1 is optically masked.
    # There are two such positions per original 2x2 basis block across the two shares;
    # for a fixed protected ref, one of the two distributed subpixels is masked.
    return {'basis':{str(k):v.tolist() for k,v in bases.items()},'mask_enumeration':rows,
            'single_flip_cases':single,'invisible_single_flips':sum(x['invisible'] for x in single),
            'total_single_flips':len(single),'single_share_privacy':secrecy,
            'theorems':[
              {'id':'T1','claim':'Under Boolean OR, a change to the distributed share at any position where reference=1 is invisible.',
               'status':'PROVEN','proof':'For b in {0,1}, 1 OR b = 1.'},
              {'id':'T2','claim':'Every canonical (2,2) reference block has exactly one masked distributed subpixel.',
               'status':'PROVEN','proof':'Both canonical reference patterns contain one black subpixel.'},
              {'id':'T3','claim':'Unrestricted integrity of every distributed-share bit is impossible with fixed OR reference.',
               'status':'PROVEN','proof':'T1 and T2 construct an invisible single-bit modification for every pixel.'},
              {'id':'T4','claim':'A signature verified only offline authenticates the physical optical overlay without any trusted reference or verification channel.',
               'status':'NOT_ESTABLISHED','proof':'An offline signature check is not a function of the optical observation; no coupling is specified.'},
              {'id':'T5','claim':'A public-target-only optical observer can authenticate the original issuer against complete share replacement.',
               'status':'IMPOSSIBLE_UNDER_STATED_MODEL','proof':'An attacker can run the public sharing algorithm on the same target and provide a new valid-looking pair.'}
            ]}
def synthetic(side):
    y,x=np.indices((side,side)); c=(side-1)/2
    out=[('checker',((x+y)%2).astype(np.uint8)),('stripes',((x//4)%2).astype(np.uint8)),
         ('circle',(((x-c)**2+(y-c)**2)<(side/3)**2).astype(np.uint8)),
         ('symbol_H',(((x>side//5)&(x<side//3)&(y>side//6)&(y<5*side//6))|((x>2*side//3)&(x<4*side//5)&(y>side//6)&(y<5*side//6))|((abs(y-side//2)<2)&(x>side//5)&(x<4*side//5))).astype(np.uint8)),
         ('random',np.random.default_rng(19).integers(0,2,(side,side),dtype=np.uint8)),
         ('all_white',np.zeros((side,side),dtype=np.uint8)),('all_black',np.ones((side,side),dtype=np.uint8))]
    return out
def discover(data_root,manifest,limit):
    if not manifest.is_file():return [],'missing_manifest'
    with manifest.open(encoding='utf-8-sig',newline='') as f: rows=list(csv.DictReader(f))
    buckets=defaultdict(list); seen=set()
    for r in rows:
        rel=r.get('relative_path','').replace('\\','/')
        if not (rel.startswith('BSR/BSDS500/data/images/') or rel.startswith('misc/')):continue
        if Path(rel).suffix.lower() not in ('.jpg','.jpeg','.tif','.tiff','.png'):continue
        p=data_root/Path(rel)
        if not p.is_file():continue
        # canonical only, and avoid exact duplicate copies if any
        sha=r.get('sha256') or rel
        if sha in seen:continue
        seen.add(sha)
        if rel.startswith('misc/'):split='sipi'
        else:
            parts=rel.split('/')
            split=parts[4] if len(parts)>4 else 'unknown'
        buckets[split].append((rel,split,sha))
    for b in buckets.values():b.sort()
    selected=[]
    while any(buckets.values()) and (limit==0 or len(selected)<limit):
        for key in sorted(buckets):
            if buckets[key] and (limit==0 or len(selected)<limit):selected.append(buckets[key].pop(0))
    return selected,'ok'
def load_binary(path,side,threshold):
    with Image.open(path) as im:
        im=im.convert('L'); im.thumbnail((side,side),Image.Resampling.LANCZOS)
        a=np.asarray(im,dtype=np.uint8)
    return (a<threshold).astype(np.uint8)
def save_preview(path,secret,ref,dist,forged=None):
    h,w=secret.shape
    panels=[secret,ref.reshape(h,2*w),dist.reshape(h,2*w),overlay(ref,dist).reshape(h,2*w)]
    if forged is not None:panels.append(overlay(ref,forged).reshape(h,2*w))
    pw=2*w*3;ph=h*3
    canvas=Image.new('L',(pw*len(panels),ph),255)
    for i,a in enumerate(panels):
        im=Image.fromarray((1-a)*255,'L').resize((pw,ph),Image.Resampling.NEAREST)
        canvas.paste(im,(i*pw,0))
    path.parent.mkdir(parents=True,exist_ok=True);canvas.save(path)
def simulate_attack(kind,ref,dist,rng,strength):
    d=dist.copy();h,w,_=d.shape
    if kind=='random_flip':
        n=max(1,round(d.size*strength));idx=rng.choice(d.size,size=min(n,d.size),replace=False)
        d.reshape(-1)[idx]^=1
    elif kind in ('ink_addition','ink_removal'):
        positions=np.flatnonzero((d==0 if kind=='ink_addition' else d==1).reshape(-1))
        if len(positions):
            idx=rng.choice(positions,size=min(len(positions),max(1,round(d.size*strength))),replace=False)
            d.reshape(-1)[idx]=1 if kind=='ink_addition' else 0
    elif kind=='random_block':
        n=max(1,round(h*w*strength));idx=rng.choice(h*w,size=min(n,h*w),replace=False)
        d.reshape(-1,2)[idx]=rng.integers(0,2,size=(len(idx),2),dtype=np.uint8)
    elif kind=='whole_share_random':d=rng.integers(0,2,size=d.shape,dtype=np.uint8)
    elif kind=='masked_adaptive':
        # An attacker able to inspect the protected reference can flip ONLY masked bits.
        # This is a diagnostic upper-bound adversary, NOT allowed in protected-reference model.
        positions=np.flatnonzero((ref==1).reshape(-1));n=max(1,round(d.size*strength))
        idx=rng.choice(positions,size=min(n,len(positions)),replace=False);d.reshape(-1)[idx]^=1
    elif kind=='blind_reference_guess':
        # Guess the reference pattern independently, and attack guessed-black locations.
        guess=rng.integers(0,2,size=(h,w),dtype=np.uint8)
        sub=np.stack((1-guess,guess),axis=-1)
        positions=np.flatnonzero((sub==1).reshape(-1));n=max(1,round(d.size*strength))
        idx=rng.choice(positions,size=min(n,len(positions)),replace=False);d.reshape(-1)[idx]^=1
    else:raise ValueError(kind)
    return d
def attack_experiment(secret,ref,dist,rng,trials,strengths):
    base=overlay(ref,dist);rows=[]
    for kind in ('random_flip','ink_addition','ink_removal','random_block','whole_share_random','blind_reference_guess','masked_adaptive'):
      for strength in (strengths if kind not in ('whole_share_random',) else [1.0]):
        for t in range(trials):
          d=simulate_attack(kind,ref,dist,rng,strength)
          modified=np.count_nonzero(d!=dist)
          changed=np.count_nonzero(overlay(ref,d)!=base)
          pix_changed=np.count_nonzero(np.any(overlay(ref,d)!=base,axis=-1))
          rows.append({'attack':kind,'strength':strength,'trial':t,'modified_subpixels':int(modified),
                       'changed_overlay_subpixels':int(changed),'changed_overlay_pixels':int(pix_changed),
                       'exact_overlay_invisible':bool(modified>0 and changed==0),
                       'changed_overlay_fraction':float(changed/base.size),
                       'changed_pixel_fraction':float(pix_changed/secret.size),
                       'attacker_knowledge':'reference_known_DIAGNOSTIC' if kind=='masked_adaptive' else 'reference_unknown'})
    return rows
def shift_overlay(ref,dist,dy,dx):
    # shifted dist, white (0) outside. A digital misregistration surrogate.
    h,w2=dist.shape[0],dist.shape[1]*2
    a=ref.reshape(h,w2);b=dist.reshape(h,w2)
    shifted=np.zeros_like(b)
    sy0=max(0,-dy);sy1=min(h,h-dy);sx0=max(0,-dx);sx1=min(w2,w2-dx)
    if sy1>sy0 and sx1>sx0:shifted[sy0+dy:sy1+dy,sx0+dx:sx1+dx]=b[sy0:sy1,sx0:sx1]
    return np.bitwise_or(a,shifted)
def optical_experiment(ref,dist,rng,noise_levels,shifts,blur_radii):
    base=overlay(ref,dist).reshape(ref.shape[0],ref.shape[1]*2)
    rows=[]
    for dy,dx in shifts:
      shifted=shift_overlay(ref,dist,dy,dx)
      for radius in blur_radii:
        im=Image.fromarray(((1-shifted)*255).astype(np.uint8),'L')
        if radius>0:im=im.filter(ImageFilter.GaussianBlur(radius=radius))
        gray=np.asarray(im,dtype=np.float32)/255.0
        for sigma in noise_levels:
          noisy=np.clip(gray+rng.normal(0,sigma,size=gray.shape),0,1)
          # black = transmitted intensity < 0.5
          observed=(noisy<0.5).astype(np.uint8)
          rows.append({'shift_y_subpixels':dy,'shift_x_subpixels':dx,'blur_radius':radius,
                       'gaussian_noise_sigma':sigma,'overlay_bit_error_fraction':float(np.mean(observed!=base)),
                       'observed_black_fraction':float(observed.mean())})
    return rows
def hash_audit(secret,ref,dist):
    # This experiment is intentionally separated from visual authentication.
    original=hashlib.sha256(secret.tobytes()+ref.tobytes()+dist.tobytes()).hexdigest()
    modified=dist.copy();modified.reshape(-1)[0]^=1
    altered=hashlib.sha256(secret.tobytes()+ref.tobytes()+modified.tobytes()).hexdigest()
    visual_equal=bool(np.array_equal(overlay(ref,dist),overlay(ref,modified)))
    return {'hash_detects_modified_share':original!=altered,
            'same_optical_overlay_after_first_flip':visual_equal,
            'cryptographic_to_optical_binding_established':False,
            'note':'Hash comparison requires an electronic verifier; it is not an unaided optical authentication mechanism.'}
def aggregate(rows,group_keys,metrics):
    groups=defaultdict(list)
    for r in rows:groups[tuple(r.get(k) for k in group_keys)].append(r)
    out=[]
    for key,items in sorted(groups.items(),key=lambda z:str(z[0])):
        record={k:v for k,v in zip(group_keys,key)};record['n']=len(items)
        for m in metrics:
            v=[float(r[m]) for r in items if r.get(m) is not None]
            record[m+'_mean']=float(np.mean(v)) if v else None
            record[m+'_std']=float(np.std(v,ddof=1)) if len(v)>1 else None
        out.append(record)
    return out
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--experiments-root',type=Path,default=DEFAULT_ROOT)
    p.add_argument('--data-root',type=Path);p.add_argument('--manifest',type=Path);p.add_argument('--output',type=Path)
    p.add_argument('--image-limit',type=int,default=0,help='0 = all 539 canonical images')
    p.add_argument('--side',type=int,default=128);p.add_argument('--threshold',type=int,default=128)
    p.add_argument('--trials',type=int,default=30);p.add_argument('--seed',type=int,default=20261107)
    p.add_argument('--preview-count',type=int,default=12)
    p.add_argument('--optical-samples',type=int,default=30,help='Real images for registration/noise tests; 0 = all')
    p.add_argument('--strict-data',action='store_true',help='Fail if manifest or images missing')
    args=p.parse_args()
    if args.side<16 or not 1<=args.threshold<=255 or args.trials<1 or args.image_limit<0 or args.optical_samples<0:p.error('Invalid parameters')
    start=time.time();root=args.experiments_root
    data=args.data_root or root/'Data';manifest=args.manifest or root/'Data_Inspection'/'file_manifest.csv'
    output=args.output or root/'Results'/'F1_Complete'
    output.mkdir(parents=True,exist_ok=True)
    save_json(output/'configuration'/'run_config.json',{'args':vars(args),'python':sys.version,'numpy':np.__version__,'pillow':Image.__version__,'platform':platform.platform(),'generated_utc':datetime.now(timezone.utc).isoformat()})
    theory=enumerate_theory();save_json(output/'mathematical_validation'/'theory.json',theory)
    save_csv(output/'mathematical_validation'/'single_bit_counterexamples.csv',theory['single_flip_cases'])
    chosen,status=discover(data,manifest,args.image_limit)
    if args.strict_data and (status!='ok' or not chosen):raise RuntimeError('Missing canonical image manifest or images')
    cases=[('synthetic/'+name,'synthetic','synthetic',a,'') for name,a in synthetic(args.side)]
    errors=[]
    for rel,split,sha in chosen:
      try:cases.append((rel,'sipi' if split=='sipi' else 'bsds500',split,load_binary(data/rel,args.side,args.threshold),sha))
      except Exception as exc:errors.append({'image':rel,'error':repr(exc)})
    if args.strict_data and errors:raise RuntimeError(f'{len(errors)} image loading errors; inspect reports')
    recon=[];attacks=[];optical=[];audit=[]
    strength_levels=(0.001,0.01,0.05)
    for i,(name,source,split,secret,sha) in enumerate(cases):
        # Stable independent per-image seeds, irrespective of ordering or image limit
        imgseed=int.from_bytes(hashlib.sha256((str(args.seed)+'|'+name).encode()).digest()[:8],'big')
        rng=np.random.default_rng(imgseed);ref,dist=encode(secret,rng)
        m=metrics(secret,ref,dist)
        recon.append({'image':name,'source':source,'split':split,'height':secret.shape[0],'width':secret.shape[1],
                      'source_sha256':sha,'binary_sha256':digest(secret),'share_ref_sha256':digest(ref),
                      'share_dist_sha256':digest(dist),**m})
        for a in attack_experiment(secret,ref,dist,rng,args.trials,strength_levels):attacks.append({'image':name,'source':source,'split':split,**a})
        if i<args.preview_count:
            forged=simulate_attack('masked_adaptive',ref,dist,rng,0.05)
            save_preview(output/'figures'/f'{i:03d}_{source}.png',secret,ref,dist,forged)
        if i==0:audit.append(hash_audit(secret,ref,dist))
        if i<7 or (source!='synthetic' and sum(r['source']!='synthetic' for r in recon)<=args.optical_samples) or (args.optical_samples==0):
            for r in optical_experiment(ref,dist,rng,(0.0,0.05,0.15),((0,0),(0,1),(1,0),(1,1)),(0.0,0.7)):
                optical.append({'image':name,'source':source,**r})
        if (i+1)%100==0:print(f'Processed {i+1}/{len(cases)} images',flush=True)
    save_csv(output/'reports'/'reconstruction.csv',recon)
    save_csv(output/'reports'/'attacks_trials.csv',attacks)
    save_csv(output/'reports'/'optical_trials.csv',optical)
    save_csv(output/'reports'/'attack_summary.csv',aggregate(attacks,['source','attack','strength','attacker_knowledge'],['exact_overlay_invisible','changed_overlay_fraction','changed_pixel_fraction','modified_subpixels']))
    save_csv(output/'reports'/'optical_summary.csv',aggregate(optical,['source','shift_y_subpixels','shift_x_subpixels','blur_radius','gaussian_noise_sigma'],['overlay_bit_error_fraction']))
    save_csv(output/'reports'/'reconstruction_summary.csv',aggregate(recon,['source','split'],['reconstruction_exact_fraction','normalized_contrast','black_fraction']))
    save_csv(output/'reports'/'errors.csv',errors)
    save_json(output/'reports'/'hash_binding_audit.json',audit)
    invisible=theory['invisible_single_flips'];total=theory['total_single_flips']
    verdict={'framework':'F1 - exhaustive optical feasibility baseline',
      'dataset_status':status,'real_images':sum(r['source']!='synthetic' for r in recon),
      'synthetic_images':sum(r['source']=='synthetic' for r in recon),
      'image_errors':len(errors),'attack_trial_rows':len(attacks),'optical_trial_rows':len(optical),
      'single_flip_invisible':invisible,'single_flip_total':total,
      'privacy_exact_for_original_basis':all(theory['single_share_privacy'].values()),
      'all_images_exact_reconstruction':all(r['reconstruction_exact_fraction']==1 for r in recon),
      'full_share_integrity_under_OR':'FAIL - proven invisible masked modifications',
      'origin_authentication_under_total_substitution':'FAIL - absent independent authenticated trust anchor',
      'post_quantum_optical_authentication':'NOT IMPLEMENTED',
      'human_detection':'NOT TESTED - requires participants and ethics protocol',
      'physical_robustness':'DIGITAL SURROGATE ONLY - no physical measurements',
      'cryptographic_binding':'NOT ESTABLISHED - SHA-256 audit is not optical verification',
      'interpretation':'Do not infer human detectability from pixel-level differences or post-quantum security from hashes.',
      'duration_seconds':round(time.time()-start,3)}
    save_json(output/'reports'/'verdict.json',verdict)
    readme='''F1 COMPLETE COMPUTATIONAL STUDY\n================================\nRead reports/verdict.json first.\n\nThis run evaluates the canonical Naor-Shamir (2,2) baseline. It is NOT a completed\npost-quantum authenticated visual-secret-sharing construction.\n\nmathematical_validation/theory.json: exact basis-level proofs and enumeration.\nreports/reconstruction.csv: image-wise exact reconstruction and contrast.\nreports/attacks_trials.csv: individual attack trials, including reference-known\n  diagnostic adaptive attacks, which are OUTSIDE the protected-reference threat model.\nreports/attack_summary.csv: aggregate attack results.\nreports/optical_trials.csv: digital shift, blur, and noise surrogates.\nreports/hash_binding_audit.json: why offline hashing is not optical verification.\nfigures/: reconstruction panels (target, reference, distributed, overlay, attacked overlay).\n\nLIMITATIONS: No authenticated optical anchor is constructed, no lattice/ML-DSA\ncryptography, no quantum security proof, no physical transparency tests, no human study.\nA meaningful next architectural iteration must address these gaps rather than\nclaiming a complete F1 scheme.\n'''
    (output/'README.txt').write_text(readme,encoding='utf-8')
    print(json.dumps(verdict,indent=2));print('OUTPUT:',output)
if __name__=='__main__':main()
