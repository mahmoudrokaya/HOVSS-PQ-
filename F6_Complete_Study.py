#!/usr/bin/env python3
"""F6: Complementary-transmission differential optical comparison study.
Computational physical forward model only: no physical/human verification claimed.
Requires numpy, Pillow. Python >=3.10.
"""
import argparse,csv,hashlib,json,math,os,platform,time
from pathlib import Path
import numpy as np
from PIL import Image,ImageFilter

ATTACKS=('random_flip','localized_block','ink_add','ink_remove','single_pixel','substitution','exact_copy','reference_compromise')

def save_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,default=lambda v: v.item() if isinstance(v,np.generic) else str(v)),encoding='utf-8')

def resolve_root(code):
    p=Path(code).resolve()
    return p.parent.parent if p.parent.name.lower()=='code' else p.parent

def discover(root,strict):
    base=root/'Data'
    folders=[(base/'BSR'/'BSDS500'/'data'/'images'/s,'BSDS500') for s in ('train','val','test')]+[(base/'misc','USC-SIPI')]
    files=[];counts={}
    for folder,source in folders:
        if not folder.exists():
            if strict: raise FileNotFoundError(f'Missing canonical dataset directory: {folder}')
            continue
        patterns=('*.jpg','*.jpeg') if source=='BSDS500' else ('*.tif','*.tiff')
        found=sorted({p for pat in patterns for p in folder.glob(pat)})
        counts[str(folder)]=len(found)
        files.extend((p,source) for p in found)
    if strict and (sum(v for k,v in counts.items() if 'BSDS500' in k)!=500 or sum(v for k,v in counts.items() if 'misc' in k)!=39):
        raise RuntimeError(f'Expected 500 BSDS500 + 39 USC-SIPI images, found {counts}')
    return files,counts

def synthetic(side):
    y,x=np.indices((side,side));r=np.random.default_rng(91)
    return [('synthetic_'+n,a.astype(np.uint8)) for n,a in [
        ('zeros',np.zeros((side,side))),('ones',np.ones((side,side))),
        ('checker',(x+y)%2),('stripes',(x//8)%2),('rings',((x-side/2)**2+(y-side/2)**2)//160%2),
        ('random',r.integers(0,2,(side,side))),('disc',((x-side/2)**2+(y-side/2)**2)<(side/4)**2)]]

def read_image(path,side):
    with Image.open(path) as im:
        a=np.asarray(im.convert('L').resize((side,side),Image.Resampling.BILINEAR),dtype=np.uint8)
    return (a<128).astype(np.uint8)

def transmission(E,P,td,tc):
    # E=1 => dark reference, P=1 => clear complementary presented layer
    return np.where(E,td,tc)*np.where(P,tc,td)

def shift(a,dx,dy,fill):
    out=np.full_like(a,fill,dtype=np.float64)
    h,w=a.shape
    xa=max(0,dx);xb=min(w,w+dx);ya=max(0,dy);yb=min(h,h+dy)
    if xb>xa and yb>ya:out[ya:yb,xa:xb]=a[ya-dy:yb-dy,xa-dx:xb-dx]
    return out

def blur(a,radius):
    if radius==0:return a
    return np.asarray(Image.fromarray(np.uint8(np.clip(a*255,0,255))).filter(ImageFilter.GaussianBlur(radius)),dtype=np.float64)/255.

def physical_forward(E,P,td,tc,rng,noise=0.,dx=0,dy=0,blur_radius=0.,gain_sd=0.,misregistration=True):
    ref=np.where(E,td,tc).astype(float)
    pres=np.where(P,tc,td).astype(float)
    if misregistration and (dx or dy):pres=shift(pres,dx,dy,tc)
    if blur_radius:
        ref=blur(ref,blur_radius);pres=blur(pres,blur_radius)
    I=ref*pres
    if gain_sd:I*=max(0.,1+rng.normal(0,gain_sd))
    if noise:I+=rng.normal(0,noise,I.shape)
    return np.clip(I,0,1)

def score(I,baseline,threshold):
    delta=np.abs(I-baseline)
    return float(np.max(delta)),float(np.mean(delta>threshold)),int(np.any(delta>threshold))

def forge(E,rng,attack,strength,sub=None):
    P=E.copy();h,w=P.shape;n=P.size
    t=max(1,round(n*strength))
    if attack=='random_flip':
        ix=rng.choice(n,size=min(n,t),replace=False);P.flat[ix]^=1
    elif attack=='localized_block':
        a=max(1,math.ceil(math.sqrt(t)));y=int(rng.integers(0,max(1,h-a+1)));x=int(rng.integers(0,max(1,w-a+1)));P[y:y+a,x:x+a]^=1
    elif attack=='ink_add':
        ix=rng.choice(n,size=min(n,t),replace=False);P.flat[ix]=1
    elif attack=='ink_remove':
        ix=rng.choice(n,size=min(n,t),replace=False);P.flat[ix]=0
    elif attack=='single_pixel':P.flat[int(rng.integers(n))]^=1
    elif attack=='substitution':P=(sub if sub is not None else 1-E).copy()
    elif attack in ('exact_copy','reference_compromise'):pass
    else:raise ValueError(attack)
    return P

def theoretical(td,tc):
    b=td*tc;bright=tc*tc;dark=td*td
    return {'reference_clear_transmission':tc,'reference_dark_transmission':td,'legitimate_baseline':b,
            'E0_P1_bright_mismatch':bright,'E1_P0_dark_mismatch':dark,
            'minimum_mismatch_contrast':min(bright-b,b-dark),
            'contrast_asymmetry':(bright-b)/(b-dark) if b>dark else None,
            'transmission_identity':'I(E,P)=T_R(E)*T_P(P); I(E,E)=td*tc for either E value',
            'indistinguishable_exact_copy':'YES','known_content_forgery':'P=E always passes; provenance impossible without independent trust'}

def crypto_audit():
    d={'sha256_binding':'PASS_DIGITAL_ONLY','ml_dsa':'NOT_EXECUTED','reason':None}
    msg=b'F6|issuer|content|reference|nonce';digest=hashlib.sha256(msg).digest()
    d['sha256_tamper_detected']=digest!=hashlib.sha256(msg+b'changed').digest()
    try:
        from pqcrypto.sign import ml_dsa_65 as m
        if not all(callable(getattr(m,x,None)) for x in ('generate_keypair','sign','verify')):
            d['reason']='Installed pqcrypto ML-DSA-65 does not expose expected API';return d
        pk,sk=m.generate_keypair();sig=m.sign(sk,msg)
        try:
            result=m.verify(pk,msg,sig)
            valid=(result is None or result is True)
        except Exception:valid=False
        try:
            changed=m.verify(pk,msg+b'changed',sig)
            rejected=(changed is False)
        except Exception:rejected=True
        d.update(ml_dsa='ELECTRONIC_PASS' if valid and rejected else 'ELECTRONIC_FAILED',valid=valid,tamper_rejected=rejected)
    except Exception as exc:d['reason']=f'{type(exc).__name__}: {exc}'
    return d

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--image-limit',type=int,default=0)
    ap.add_argument('--side',type=int,default=128)
    ap.add_argument('--trials',type=int,default=30)
    ap.add_argument('--optical-samples',type=int,default=30)
    ap.add_argument('--strict-data',action='store_true')
    ap.add_argument('--seed',type=int,default=20261107)
    ap.add_argument('--t-dark',type=float,default=.15)
    ap.add_argument('--t-clear',type=float,default=.85)
    ap.add_argument('--thresholds',default='0.03,0.06,0.10')
    ap.add_argument('--strengths',default='0.001,0.01,0.05')
    ap.add_argument('--noise-sd',type=float,default=.012)
    ap.add_argument('--gain-sd',type=float,default=.015)
    args=ap.parse_args()
    if not (0<args.t_dark<args.t_clear<=1):ap.error('Require 0 < t-dark < t-clear <= 1')
    if args.side<16 or args.trials<1:ap.error('Require side>=16 and trials>=1')
    thresholds=[float(x) for x in args.thresholds.split(',')];strengths=[float(x) for x in args.strengths.split(',')]
    if any(x<=0 or x>=1 for x in strengths) or any(x<=0 for x in thresholds):ap.error('Invalid strengths/thresholds')
    root=resolve_root(__file__);out=root/'Results'/'F6_Complete'
    for s in ('configuration','mathematical_validation','reports','optical_simulation','cryptographic_audit','figures'):(out/s).mkdir(parents=True,exist_ok=True)
    files,counts=discover(root,args.strict_data)
    if args.image_limit>0:files=files[:args.image_limit]
    samples=[(str(p),source,None) for p,source in files]+[(name,'synthetic',a) for name,a in synthetic(args.side)]
    save_json(out/'configuration'/'run.json',dict(vars(args),dataset_counts=counts,root=str(root),python=platform.python_version(),numpy=np.__version__,images=len(samples)))
    th=theoretical(args.t_dark,args.t_clear)
    save_json(out/'mathematical_validation'/'transmission_identity.json',th)
    b=th['legitimate_baseline'];rng=np.random.default_rng(args.seed)
    # Analytic impossibility: any bounded nuisance set containing an attack perturbation makes perfect discrimination impossible.
    save_json(out/'mathematical_validation'/'identifiability.json',{
      'statement':'If legitimate and adversarial observation sets intersect, no deterministic observation-only rule can perfectly distinguish them.',
      'proof':'For y in intersection, a decision rule must assign the same output to the same y under both hypotheses.',
      'exact_copy':'Same E and same optical P yields identical observation.',
      'known_content':'Attacker able to print P=E passes even without recovering a hidden VC reference.',
      'reference_swap':'If attacker controls both expected reference and presented layer, matching counterfeit pairs pass.',
      'physical_claim':'Transmission product is a physically motivated intensity model, not a measured prototype.'})
    fields=['image','source','attack','strength','trial','threshold','actual_changes','physical_noise','max_deviation','fraction_above','rejected','ideal_mismatch']
    af=open(out/'reports'/'attacks_trials.csv','w',newline='',encoding='utf-8');aw=csv.DictWriter(af,fieldnames=fields);aw.writeheader()
    ofields=['image','condition','threshold','changed','max_deviation','fraction_above','false_reject']
    of=open(out/'reports'/'optical_trials.csv','w',newline='',encoding='utf-8');ow=csv.DictWriter(of,fieldnames=ofields);ow.writeheader()
    summary={};opt_summary={};recon=[];total=0;opt_total=0;start=time.time()
    for index,(name,source,arr) in enumerate(samples):
        E=arr if arr is not None else read_image(Path(name),args.side)
        n=E.size
        genuine=physical_forward(E,E,args.t_dark,args.t_clear,rng)
        recon.append({'image':name,'source':source,'pixels':n,'ideal_matching_pixels':n,'baseline_mean':float(genuine.mean())})
        if index<12:
            Image.fromarray((E*255).astype('uint8')).save(out/'figures'/f'{index:03d}_expected.png')
            Image.fromarray(np.uint8(np.clip(genuine*255,0,255))).save(out/'figures'/f'{index:03d}_legitimate_overlay.png')
        for attack in ATTACKS:
            for strength in strengths:
                for trial in range(args.trials):
                    sub=None
                    if attack=='substitution':sub=(1-E) if index==0 else (np.roll(E,1,axis=1))
                    P=forge(E,rng,attack,strength,sub)
                    changes=int(np.count_nonzero(P!=E))
                    # Reference compromise: both printed layers are changed consistently, so compare against altered reference.
                    actual_E=P if attack=='reference_compromise' else E
                    I=physical_forward(actual_E,P,args.t_dark,args.t_clear,rng,noise=args.noise_sd,gain_sd=args.gain_sd)
                    for threshold in thresholds:
                        mx,frac,rej=score(I,b,threshold)
                        row=dict(image=name,source=source,attack=attack,strength=strength,trial=trial,threshold=threshold,actual_changes=changes,
                                 physical_noise=1,max_deviation=mx,fraction_above=frac,rejected=rej,ideal_mismatch=int(changes>0))
                        aw.writerow(row);total+=1
                        key=(attack,strength,threshold)
                        z=summary.setdefault(key,[0,0,0,0]);z[0]+=1;z[1]+=rej;z[2]+=int(changes>0);z[3]+=int(rej and changes>0)
        if index<args.optical_samples:
            conds=[('ideal',0,0,0,0,0),('sensor_noise',0,0,0,args.noise_sd,args.gain_sd),
                   ('high_noise',0,0,0,args.noise_sd*2,args.gain_sd*2),
                   ('shift_x1',1,0,0,args.noise_sd,args.gain_sd),('shift_y1',0,1,0,args.noise_sd,args.gain_sd),
                   ('blur_0.7',0,0,.7,args.noise_sd,args.gain_sd),('shift_blur',1,1,.7,args.noise_sd,args.gain_sd)]
            for cname,dx,dy,br,ns,gs in conds:
                I=physical_forward(E,E,args.t_dark,args.t_clear,rng,noise=ns,dx=dx,dy=dy,blur_radius=br,gain_sd=gs)
                for threshold in thresholds:
                    mx,frac,rej=score(I,b,threshold)
                    ow.writerow(dict(image=name,condition=cname,threshold=threshold,changed=0,max_deviation=mx,fraction_above=frac,false_reject=rej))
                    opt_total+=1
                    key=(cname,threshold);z=opt_summary.setdefault(key,[0,0]);z[0]+=1;z[1]+=rej
        if (index+1)%50==0:print(f'Processed {index+1}/{len(samples)} images; attack records {total}',flush=True)
    af.close();of.close()
    with open(out/'reports'/'attack_summary.csv','w',newline='',encoding='utf-8') as f:
        w=csv.writer(f);w.writerow(['attack','strength','threshold','trials','rejection_rate','changed_rate','rejection_given_change'])
        for (a,s,t),(num,rej,changed,det) in sorted(summary.items()):w.writerow([a,s,t,num,rej/num,changed/num,det/changed if changed else 'NA'])
    with open(out/'reports'/'optical_summary.csv','w',newline='',encoding='utf-8') as f:
        w=csv.writer(f);w.writerow(['condition','threshold','trials','false_reject_rate'])
        for (a,t),(num,rej) in sorted(opt_summary.items()):w.writerow([a,t,num,rej/num])
    with open(out/'reports'/'reconstruction.csv','w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=recon[0].keys());w.writeheader();w.writerows(recon)
    audit=crypto_audit();save_json(out/'cryptographic_audit'/'electronic_issuance.json',audit)
    verdict={'ideal_transmission_identity':'PROVEN_ALGEBRAICALLY','complementary_layer_physics':'MODEL_OF_MULTIPLICATIVE_INTENSITY_NOT_HARDWARE_VALIDATED',
      'full_field_difference_signal':'NONZERO_FOR_ANY_BINARY_MISMATCH_IN_IDEAL_MODEL',
      'noise_robustness':'EMPIRICALLY_SIMULATED_THRESHOLD_DEPENDENT',
      'perfect_sensitivity_and_zero_false_rejection':'NOT_ESTABLISHED_AND_IMPOSSIBLE_FOR_OVERLAPPING_OBSERVATION_SETS',
      'known_content_origin_authentication':'FAILED_PUBLIC_REFERENCE_CAN_BE_COPIED',
      'reference_origin_trust':'ASSUMED_EXTERNAL_NOT_ESTABLISHED',
      'exact_copy_resistance':'IMPOSSIBLE_FOR_IDENTICAL_OPTICAL_OBSERVATION',
      'human_only_verification':'NOT_ESTABLISHED_NO_OBSERVER_STUDY',
      'post_quantum_optical_authentication':'NOT_ESTABLISHED',
      'physical_prototype':'NOT_BUILT',
      'mldsa_electronic_issuance':audit['ml_dsa'],
      'scope':'Computational comparison of physically motivated multiplicative transmission with simulated nuisance; no physical or human security proof.'}
    save_json(out/'reports'/'verdict.json',verdict)
    result={'output':str(out),'images_processed':len(samples),'real_images_processed':len(files),'adversarial_threshold_records':total,
            'optical_threshold_records':opt_total,'errors':0,'elapsed_seconds':round(time.time()-start,2),'results':verdict}
    save_json(out/'reports'/'summary.json',result);print(json.dumps(result,indent=2))
if __name__=='__main__':main()
