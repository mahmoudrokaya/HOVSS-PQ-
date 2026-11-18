#!/usr/bin/env python3
"""EOW C11: simulation-only optical robustness for classical two-subpixel OR-VSS.

Run with --dataset PATH --c10 ../Results/EOW_C10 --strict-c10.
Requires Pillow and NumPy. Source images only; MATLAB annotations are excluded.
Simulates geometric/photometric perturbations of a single share, using pixel-
level optical OR and an explicit ideal-registration reference. Reports fidelity,
false rejection, attack detection and false acceptance, with exact denominators.
Not a human study, physical prototype, or security-qualified construction.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,math,random,sys,time,zipfile
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
import numpy as np
from PIL import Image,ImageFilter,ImageEnhance,ImageOps

EXT={'.jpg','.jpeg','.png','.bmp','.tif','.tiff','.webp'}
CONDITIONS=('ideal','shift_1','shift_2','rotate_1','rotate_3',
            'scale_098','scale_102','blur_08','blur_15',
            'contrast_070','brightness_080','noise_010','noise_030')
def dump(p,v):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(v,indent=2,sort_keys=True,default=str)+'\n',encoding='utf-8')
def csvout(p,rows,fields):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def audit(path):
    if path is None:return {'status':'NOT_PROVIDED'}
    p=Path(path)
    try:
        if p.is_dir():
            matches=list(p.glob('reports/verdict.json'))+list(p.glob('EOW_C10/reports/verdict.json'))
            if matches:
                b=matches[0].read_bytes()
                return {'status':'LOADED','source':str(matches[0]),'sha256':hashlib.sha256(b).hexdigest(),'verdict':json.loads(b)}
        if p.is_file() and zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as z:
                names=[n for n in z.namelist() if n.endswith('EOW_C10/reports/verdict.json')]
                if names:
                    b=z.read(names[0])
                    return {'status':'LOADED','source':str(p),'member':names[0],'sha256':hashlib.sha256(b).hexdigest(),'verdict':json.loads(b)}
    except (OSError,ValueError,KeyError,json.JSONDecodeError) as e:
        return {'status':'INVALID','source':str(p),'error':str(e)}
    return {'status':'MISSING_VERDICT','source':str(p)}
def load_secret(path,side):
    with Image.open(path) as src:
        im=ImageOps.exif_transpose(src).convert('L')
    original=im.size
    im.thumbnail((side,side),Image.Resampling.BILINEAR)
    x=np.asarray(im,dtype=np.uint8)
    return x>=128,original
def encode(secret,rng):
    h,w=secret.shape
    flips=rng.integers(0,2,size=(h,w),dtype=np.uint8)
    a=np.zeros((h,w,2),dtype=np.uint8)
    b=np.zeros_like(a)
    ys,xs=np.indices((h,w))
    a[ys,xs,flips]=1
    b[ys,xs,flips ^ secret.astype(np.uint8)]=1
    return a.reshape(h,w*2),b.reshape(h,w*2)
def perturb(share,condition,rng):
    # Binary share: 1=opaque/black. Geometric transforms fill transparent/white (0).
    im=Image.fromarray(np.uint8(255*(1-share)),mode='L')
    w,h=im.size
    if condition.startswith('shift_'):
        d=int(condition.split('_')[1])
        im=im.transform((w,h),Image.Transform.AFFINE,(1,0,-d,0,1,0),
                        resample=Image.Resampling.NEAREST,fillcolor=255)
    elif condition.startswith('rotate_'):
        angle=float(condition.split('_')[1])
        im=im.rotate(angle,resample=Image.Resampling.BILINEAR,expand=False,fillcolor=255)
    elif condition.startswith('scale_'):
        fac=int(condition.split('_')[1])/100
        new=(max(1,round(w*fac)),max(1,round(h*fac)))
        temp=im.resize(new,Image.Resampling.BILINEAR)
        canvas=Image.new('L',(w,h),255)
        canvas.paste(temp,((w-new[0])//2,(h-new[1])//2))
        im=canvas
    elif condition.startswith('blur_'):
        rad=int(condition.split('_')[1])/10
        im=im.filter(ImageFilter.GaussianBlur(rad))
    elif condition.startswith('contrast_'):
        im=ImageEnhance.Contrast(im).enhance(int(condition.split('_')[1])/100)
    elif condition.startswith('brightness_'):
        im=ImageEnhance.Brightness(im).enhance(int(condition.split('_')[1])/100)
    elif condition.startswith('noise_'):
        sigma=int(condition.split('_')[1])/100
        arr=np.asarray(im,dtype=np.float32)
        arr=np.clip(arr+rng.normal(0,sigma*255,arr.shape),0,255).astype(np.uint8)
        im=Image.fromarray(arr,mode='L')
    elif condition!='ideal':raise ValueError('Unknown condition '+condition)
    return np.asarray(im,dtype=np.uint8)<128
def decoded(a,b):
    h,w=a.shape
    stacked=np.logical_or(a,b).reshape(h,w//2,2)
    # A classical OR VSS reconstruction: 2 black subpixels => black secret.
    return stacked.all(axis=2)
def metrics(reference,observed):
    mismatch=np.count_nonzero(reference!=observed)
    return int(mismatch),int(reference.size),float(1-mismatch/reference.size)
def flip_content(b,secret,rng):
    # Modify a single subpixel of B so that decoded secret changes.
    y=int(rng.integers(0,secret.shape[0]))
    x=int(rng.integers(0,secret.shape[1]))
    modified=b.copy()
    pair=modified[y,2*x:2*x+2]
    # Black pixel: turn black subpixel white; white pixel: turn white subpixel black.
    index=int(np.flatnonzero(pair==bool(secret[y,x]))[0])
    modified[y,2*x+index]=not modified[y,2*x+index]
    return modified,(y,x)
def test():
    rng=np.random.default_rng(42)
    for h,w in [(1,1),(3,5),(8,8)]:
        for val in (False,True):
            secret=np.full((h,w),val,dtype=bool)
            a,b=encode(secret,rng)
            assert np.array_equal(decoded(a,b),secret)
            b2,_=flip_content(b,secret,rng)
            assert np.count_nonzero(b!=b2)==1
            assert np.count_nonzero(decoded(a,b2)!=secret)==1
            assert np.array_equal(perturb(b,'ideal',rng),b.astype(bool))
    return {'vss_reconstruction':'PASS','single_subpixel_attack_changes_one_secret_pixel':'PASS',
            'ideal_perturbation_identity':'PASS'}
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dataset',type=Path,required=True)
    ap.add_argument('--c10',type=Path,default=Path('../Results/EOW_C10'))
    ap.add_argument('--strict-c10',action='store_true')
    ap.add_argument('--output',type=Path,default=Path('../Results/EOW_C11'))
    ap.add_argument('--max-side',type=int,default=128)
    ap.add_argument('--limit',type=int,help='Pilot only: first N images')
    ap.add_argument('--seed',type=int,default=20261115)
    ap.add_argument('--threshold',type=float,default=0.99,
                    help='Pixel reconstruction agreement needed to accept; default 0.99')
    ap.add_argument('--conditions',nargs='+',choices=CONDITIONS,default=list(CONDITIONS))
    args=ap.parse_args()
    if not args.dataset.is_dir():ap.error('Dataset directory not found')
    if args.max_side<1 or args.limit is not None and args.limit<1:ap.error('Invalid image size or limit')
    if not 0<=args.threshold<=1:ap.error('threshold must be in [0,1]')
    upstream=audit(args.c10)
    if args.strict_c10 and upstream['status']!='LOADED':ap.error('C10 verdict not found')
    selftests=test()
    files=sorted((x for x in args.dataset.rglob('*') if x.is_file() and x.suffix.lower() in EXT),
                 key=lambda x:x.relative_to(args.dataset).as_posix().lower())
    if args.limit:files=files[:args.limit]
    if not files:ap.error('No standard image files found; .mat annotations are intentionally excluded')
    rng=np.random.default_rng(args.seed)
    out=args.output
    rows=[];errors=[];hashes=Counter()
    t0=time.perf_counter()
    for index,p in enumerate(files,1):
        name=p.relative_to(args.dataset).as_posix()
        try:
            sha=hashlib.sha256(p.read_bytes()).hexdigest()
            hashes[sha]+=1
            secret,original=load_secret(p,args.max_side)
            a,b=encode(secret,rng)
            if not np.array_equal(decoded(a,b),secret):raise AssertionError('IDEAL_RECONSTRUCTION_FAILED')
            attack_b,attack_pixel=flip_content(b,secret,rng)
            ideal=decoded(a,b)
            for condition in args.conditions:
                t1=time.perf_counter()
                perturbed=perturb(b,condition,rng)
                observed=decoded(a,perturbed)
                benign_errors,total,benign_agreement=metrics(ideal,observed)
                tampered=perturb(attack_b,condition,rng)
                observed_attack=decoded(a,tampered)
                attack_errors,_,attack_agreement=metrics(ideal,observed_attack)
                # Compare to clean, trusted image; not a human optical protocol.
                benign_accepted=benign_agreement>=args.threshold
                attack_accepted=attack_agreement>=args.threshold
                rows.append({'file':name,'sha256':sha,'condition':condition,
                    'width':secret.shape[1],'height':secret.shape[0],
                    'source_width':original[0],'source_height':original[1],
                    'pixels':total,'benign_mismatch':benign_errors,
                    'benign_agreement':round(benign_agreement,10),
                    'benign_accepted':int(benign_accepted),
                    'false_rejection':int(not benign_accepted),
                    'attack_pixel_y':attack_pixel[0],'attack_pixel_x':attack_pixel[1],
                    'attack_mismatch':attack_errors,
                    'attack_agreement':round(attack_agreement,10),
                    'attack_accepted':int(attack_accepted),
                    'attack_detected':int(not attack_accepted),
                    'elapsed_seconds':round(time.perf_counter()-t1,6)})
        except Exception as e:
            errors.append({'file':name,'error_type':type(e).__name__,'message':str(e)[:300]})
        if index%50==0:print(f'{index}/{len(files)} images processed',flush=True)
    elapsed=time.perf_counter()-t0
    fields=['file','sha256','condition','width','height','source_width','source_height',
            'pixels','benign_mismatch','benign_agreement','benign_accepted',
            'false_rejection','attack_pixel_y','attack_pixel_x','attack_mismatch',
            'attack_agreement','attack_accepted','attack_detected','elapsed_seconds']
    csvout(out/'reports'/'image_condition_results.csv',rows,fields)
    csvout(out/'reports'/'failed_inputs.csv',errors,['file','error_type','message'])
    condition_summary=[]
    for c in args.conditions:
        subset=[r for r in rows if r['condition']==c]
        n=len(subset)
        if n==0:continue
        condition_summary.append({'condition':c,'images':n,
          'total_pixels':sum(r['pixels'] for r in subset),
          'mean_benign_agreement':sum(r['benign_agreement'] for r in subset)/n,
          'pooled_pixel_error_rate':sum(r['benign_mismatch'] for r in subset)/sum(r['pixels'] for r in subset),
          'false_rejections':sum(r['false_rejection'] for r in subset),
          'false_rejection_rate':sum(r['false_rejection'] for r in subset)/n,
          'attacks_tested':n,'attacks_detected':sum(r['attack_detected'] for r in subset),
          'attack_detection_rate':sum(r['attack_detected'] for r in subset)/n,
          'attacks_accepted':sum(r['attack_accepted'] for r in subset),
          'false_acceptance_rate':sum(r['attack_accepted'] for r in subset)/n})
    cf=['condition','images','total_pixels','mean_benign_agreement','pooled_pixel_error_rate',
        'false_rejections','false_rejection_rate','attacks_tested','attacks_detected',
        'attack_detection_rate','attacks_accepted','false_acceptance_rate']
    csvout(out/'reports'/'condition_summary.csv',condition_summary,cf)
    dump(out/'reports'/'c10_source_audit.json',upstream)
    dump(out/'reports'/'self_tests.json',{'passed':len(selftests),'total':len(selftests),'checks':selftests})
    dump(out/'configuration'/'run.json',{
      'experiment':'EOW_C11','timestamp_utc':datetime.now(timezone.utc).isoformat(),
      'dataset':str(args.dataset.resolve()),'c10':str(args.c10),'seed':args.seed,
      'max_side':args.max_side,'threshold':args.threshold,'conditions':args.conditions,
      'limit':args.limit,'python':sys.version.split()[0],
      'numpy':np.__version__,'pillow':Image.__version__})
    summary={'selected_source_images':len(files),
             'processed_source_images':len({r['file'] for r in rows}),
             'failed_source_images':len(errors),'image_condition_records':len(rows),
             'duplicate_extra_sha256':sum(v-1 for v in hashes.values() if v>1),
             'conditions':len(args.conditions),'elapsed_seconds':round(elapsed,3),
             'threshold':args.threshold,'c10_source_status':upstream['status'],
             'research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION'}
    dump(out/'reports'/'summary.json',summary)
    dump(out/'reports'/'model_assumptions.json',{
      'source_files':'standard image files only; .mat segmentation annotations excluded',
      'share_generation':'fresh randomized two-subpixel classical (2,2) OR VSS',
      'ideal_reconstruction':'pixelwise OR, both black subpixels interpreted as black',
      'perturbation':'simulation of B share only; A remains perfectly aligned',
      'geometry':'shift, rotation and scale use specified image interpolation and white fill',
      'photometry':'blur, contrast, brightness and additive Gaussian noise; threshold 128',
      'reference':'trusted original reconstruction is assumed available to software',
      'acceptance':'full-image agreement >= threshold; NOT a human-verifiable rule',
      'attack':'one B subpixel flipped so exactly one decoded secret pixel changes under ideal overlay',
      'attack_strength':'nonadaptive baseline; not an optimal adaptive adversary',
      'confounding':'at 99% image agreement a one-pixel attack is typically accepted even ideally',
      'statistical_unit':'one image per condition; no independence claimed across conditions or duplicates',
      'limitations':'no physical printing, scanner capture, registration algorithm, or human participants',
      'enrollment':'ML-DSA-65 not retested; C08 is separate',
      'references':['https://doi.org/10.1007/BFb0053419',
                    'https://doi.org/10.6028/NIST.FIPS.204']})
    gates=[
      {'gate':'execution','status':'PASS' if rows and not errors else 'PARTIAL' if rows else 'FAIL'},
      {'gate':'ideal_reconstruction','status':'PASS_TESTED_ONLY' if rows else 'NOT_TESTED'},
      {'gate':'optical_integrity','status':'NOT_QUALIFIED'},
      {'gate':'physical_robustness','status':'NOT_TESTED'},
      {'gate':'human_verification','status':'NOT_ESTABLISHED'},
      {'gate':'post_quantum_enrollment','status':'UPSTREAM_ONLY'}]
    csvout(out/'reports'/'feasibility_gates.csv',gates,['gate','status'])
    dump(out/'reports'/'verdict.json',{'execution':gates[0]['status'],
         'research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION',
         'simulation_only':True,'human_optical_verification':'NOT_ESTABLISHED',
         'physical_prototype':'NOT_TESTED','cryptographic_enrollment':'NOT_RETESTED'})
    lines=['# EOW C11 — Simulated Optical Robustness','',
           f"Processed {summary['processed_source_images']}/{len(files)} source images across {len(args.conditions)} conditions.",
           f"Agreement acceptance threshold: {args.threshold:.4f}.",
           f"Elapsed time: {elapsed:.2f} s.",'',
           '| Condition | Images | Benign pixel error | False rejection | Attack acceptance |',
           '|---|---:|---:|---:|---:|']
    for s in condition_summary:
        lines.append(f"| {s['condition']} | {s['images']} | {s['pooled_pixel_error_rate']:.5f} | {s['false_rejection_rate']:.5f} | {s['false_acceptance_rate']:.5f} |")
    lines+=['','## Interpretation',
      'The comparison uses a trusted clean image and a software pixel-agreement rule. This is not unaided human optical verification.',
      'A single-pixel content change can pass a 99% whole-image agreement threshold even with no perturbation. This is an intentionally weak illustrative verifier, not a proposed secure design.',
      'Benign distortion may cause false rejection, while distortion may also mask content changes. Results are simulation-only and depend on image size and threshold.',
      'No print/scan, real transparency alignment, human observer, or post-quantum cryptographic operation was performed.',
      '','## References',
      '- Naor and Shamir, Visual Cryptography: https://doi.org/10.1007/BFb0053419',
      '- NIST FIPS 204: https://doi.org/10.6028/NIST.FIPS.204']
    (out/'reports'/'scientific_report.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2))
    return 0 if rows and not errors else 2
if __name__=='__main__':raise SystemExit(main())
