#!/usr/bin/env python3
"""EOW_C12: constrained architecture comparison, NOT security qualification.

Requires numpy, Pillow. Uses actual source images, randomized classical 2x OR-VSS
and benign perturbations. Compares (1) relaxed whole-image reference matching,
(2) strict exact reconstruction, (3) bounded registration+strict comparison,
(4) electronic SHA-256 image-reference comparison (not unaided optical).
All candidates require a trusted reference; none qualifies as human-only optical
authentication. Attack model: one changed B subpixel causing a changed decoded
pixel under ideal alignment. SHA-256 is not a signature; C08 is upstream only.
"""
import argparse,csv,hashlib,json,time,zipfile,sys
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
import numpy as np
from PIL import Image,ImageOps,ImageFilter,ImageEnhance

EXT={'.jpg','.jpeg','.png','.bmp','.tif','.tiff','.webp'}
CONDS=('ideal','shift_1','shift_2','rotate_1','blur_08','contrast_070','noise_030')
CANDIDATES=('reference_99','reference_exact','registration_exact','digital_digest')
def save(p,x):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(x,indent=2,sort_keys=True,default=str)+'\n',encoding='utf-8')
def table(p,rows,fields):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
def upstream(path):
    p=Path(path)
    try:
        if p.is_dir():
            hits=list(p.glob('reports/verdict.json'))+list(p.glob('EOW_C11/reports/verdict.json'))
            if hits:
                raw=hits[0].read_bytes()
                return {'status':'LOADED','source':str(hits[0]),'sha256':hashlib.sha256(raw).hexdigest(),'verdict':json.loads(raw)}
        if p.is_file() and zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as z:
                hits=[n for n in z.namelist() if n.endswith('EOW_C11/reports/verdict.json')]
                if hits:
                    raw=z.read(hits[0])
                    return {'status':'LOADED','source':str(p),'member':hits[0],'sha256':hashlib.sha256(raw).hexdigest(),'verdict':json.loads(raw)}
    except Exception as e:
        return {'status':'INVALID','reason':str(e)}
    return {'status':'MISSING','source':str(p)}
def secret_from_file(path,side):
    with Image.open(path) as f: im=ImageOps.exif_transpose(f).convert('L')
    im.thumbnail((side,side),Image.Resampling.BILINEAR)
    return np.asarray(im,dtype=np.uint8)>=128
def shares(s,rng):
    h,w=s.shape
    bit=rng.integers(0,2,(h,w),dtype=np.uint8)
    yy,xx=np.indices((h,w))
    a=np.zeros((h,w,2),dtype=np.uint8)
    b=np.zeros_like(a)
    a[yy,xx,bit]=1
    b[yy,xx,bit^s.astype(np.uint8)]=1
    return a.reshape(h,w*2).astype(bool),b.reshape(h,w*2).astype(bool)
def decode(a,b):
    h,w=a.shape
    return np.logical_or(a,b).reshape(h,w//2,2).all(axis=2)
def change_one(a,b,s,rng):
    y=int(rng.integers(0,s.shape[0]));x=int(rng.integers(0,s.shape[1]))
    c=b.copy()
    pair=c[y,2*x:2*x+2]
    k=int(np.flatnonzero(pair==bool(s[y,x]))[0])
    c[y,2*x+k]=~c[y,2*x+k]
    assert np.count_nonzero(decode(a,c)!=s)==1
    return c
def distort(b,condition,rng):
    im=Image.fromarray(np.uint8(255*(~b)),mode='L')
    w,h=im.size
    if condition=='shift_1':
        im=im.transform((w,h),Image.Transform.AFFINE,(1,0,-1,0,1,0),
                        resample=Image.Resampling.NEAREST,fillcolor=255)
    elif condition=='shift_2':
        im=im.transform((w,h),Image.Transform.AFFINE,(1,0,-2,0,1,0),
                        resample=Image.Resampling.NEAREST,fillcolor=255)
    elif condition=='rotate_1':
        im=im.rotate(1,resample=Image.Resampling.BILINEAR,expand=False,fillcolor=255)
    elif condition=='blur_08':
        im=im.filter(ImageFilter.GaussianBlur(.8))
    elif condition=='contrast_070':
        im=ImageEnhance.Contrast(im).enhance(.7)
    elif condition=='noise_030':
        x=np.asarray(im,dtype=np.float32)
        im=Image.fromarray(np.clip(x+rng.normal(0,7.65,x.shape),0,255).astype(np.uint8))
    elif condition!='ideal':raise ValueError(condition)
    return np.asarray(im)<128
def shift(arr,dx):
    out=np.zeros_like(arr)
    if dx>0:out[:,dx:]=arr[:,:-dx]
    elif dx<0:out[:,:dx]=arr[:,-dx:]
    else:out[:]=arr
    return out
def agreement(a,b):return 1-np.count_nonzero(a!=b)/a.size
def assess(candidate,a,observed_b,reference,ref_digest):
    if candidate=='digital_digest':
        # Electronic reference comparison only: no optical/human verification.
        reconstructed=decode(a,observed_b)
        digest=hashlib.sha256(np.packbits(reconstructed.reshape(-1)).tobytes()).digest()
        return digest==ref_digest,agreement(reconstructed,reference)
    if candidate=='registration_exact':
        # Bounded horizontal search, NOT oracle access to true displacement.
        scores=[agreement(decode(a,shift(observed_b,dx)),reference) for dx in (-2,-1,0,1,2)]
        best=max(scores)
        return best==1.,best
    reconstruction=decode(a,observed_b)
    score=agreement(reconstruction,reference)
    if candidate=='reference_99':return score>=.99,score
    if candidate=='reference_exact':return score==1.,score
    raise ValueError(candidate)
def selftests():
    rng=np.random.default_rng(9)
    for n in (1,7,64):
        for val in (False,True):
            s=np.full((3,n),val,dtype=bool)
            a,b=shares(s,rng)
            assert np.array_equal(decode(a,b),s)
            c=change_one(a,b,s,rng)
            assert np.count_nonzero(decode(a,c)!=s)==1
            assert np.array_equal(distort(b,'ideal',rng),b)
            assert np.array_equal(shift(shift(b,1),-1)[:,:-1],b[:,:-1])
    return {'reconstruction':'PASS','content_change':'PASS','ideal_identity':'PASS','shift_inverse_interior':'PASS'}
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dataset',type=Path,required=True)
    ap.add_argument('--c11',type=Path,default=Path('../Results/EOW_C11'))
    ap.add_argument('--strict-c11',action='store_true')
    ap.add_argument('--output',type=Path,default=Path('../Results/EOW_C12'))
    ap.add_argument('--max-side',type=int,default=128)
    ap.add_argument('--limit',type=int)
    ap.add_argument('--seed',type=int,default=20261115)
    ap.add_argument('--max-frr',type=float,default=.05)
    ap.add_argument('--max-far',type=float,default=.05)
    ap.add_argument('--conditions',nargs='+',choices=CONDS,default=list(CONDS))
    args=ap.parse_args()
    if not args.dataset.is_dir():ap.error('Dataset directory not found')
    if args.max_side<1 or args.limit is not None and args.limit<1:ap.error('Invalid max-side or limit')
    if not 0<=args.max_frr<=1 or not 0<=args.max_far<=1:ap.error('Rates must be within [0,1]')
    prior=upstream(args.c11)
    if args.strict_c11 and prior['status']!='LOADED':ap.error('C11 verdict unavailable')
    checks=selftests()
    paths=sorted((p for p in args.dataset.rglob('*') if p.is_file() and p.suffix.lower() in EXT),
                 key=lambda p:p.relative_to(args.dataset).as_posix().lower())
    if args.limit:paths=paths[:args.limit]
    if not paths:ap.error('No standard image files found')
    rng=np.random.default_rng(args.seed)
    rows=[];fail=[];hashes=Counter()
    start=time.perf_counter()
    for idx,p in enumerate(paths,1):
        name=p.relative_to(args.dataset).as_posix()
        try:
            sha=hashlib.sha256(p.read_bytes()).hexdigest()
            hashes[sha]+=1
            s=secret_from_file(p,args.max_side)
            a,b=shares(s,rng)
            assert np.array_equal(decode(a,b),s)
            bad=change_one(a,b,s,rng)
            ref_digest=hashlib.sha256(np.packbits(s.reshape(-1)).tobytes()).digest()
            for condition in args.conditions:
                # Independent noise realizations for benign and attack; same condition.
                good_obs=distort(b,condition,rng)
                bad_obs=distort(bad,condition,rng)
                for candidate in CANDIDATES:
                    t0=time.perf_counter()
                    accept_good,score_good=assess(candidate,a,good_obs,s,ref_digest)
                    accept_bad,score_bad=assess(candidate,a,bad_obs,s,ref_digest)
                    rows.append({'file':name,'sha256':sha,'condition':condition,
                      'candidate':candidate,'pixels':int(s.size),
                      'benign_accepted':int(accept_good),'false_rejection':int(not accept_good),
                      'attack_accepted':int(accept_bad),'attack_detected':int(not accept_bad),
                      'benign_agreement':round(score_good,10),
                      'attack_agreement':round(score_bad,10),
                      'seconds':round(time.perf_counter()-t0,7)})
        except Exception as e:
            fail.append({'file':name,'error_type':type(e).__name__,'message':str(e)[:250]})
        if idx%50==0:print(f'{idx}/{len(paths)} images processed',flush=True)
    out=args.output
    fields=['file','sha256','condition','candidate','pixels','benign_accepted',
            'false_rejection','attack_accepted','attack_detected','benign_agreement',
            'attack_agreement','seconds']
    table(out/'reports'/'candidate_image_results.csv',rows,fields)
    table(out/'reports'/'failed_inputs.csv',fail,['file','error_type','message'])
    aggregates=[]
    for candidate in CANDIDATES:
        for condition in args.conditions:
            sub=[r for r in rows if r['candidate']==candidate and r['condition']==condition]
            if not sub:continue
            n=len(sub);frr=sum(r['false_rejection'] for r in sub)/n
            far=sum(r['attack_accepted'] for r in sub)/n
            aggregates.append({'candidate':candidate,'condition':condition,'images':n,
              'false_rejections':sum(r['false_rejection'] for r in sub),
              'false_rejection_rate':frr,
              'accepted_attacks':sum(r['attack_accepted'] for r in sub),
              'false_acceptance_rate':far,
              'mean_benign_agreement':sum(r['benign_agreement'] for r in sub)/n,
              'mean_attack_agreement':sum(r['attack_agreement'] for r in sub)/n,
              'mean_evaluation_seconds':sum(r['seconds'] for r in sub)/n,
              'both_operational_gates':int(frr<=args.max_frr and far<=args.max_far)})
    af=['candidate','condition','images','false_rejections','false_rejection_rate',
        'accepted_attacks','false_acceptance_rate','mean_benign_agreement',
        'mean_attack_agreement','mean_evaluation_seconds','both_operational_gates']
    table(out/'reports'/'candidate_condition_summary.csv',aggregates,af)
    ranks=[]
    for candidate in CANDIDATES:
        sub=[r for r in aggregates if r['candidate']==candidate]
        # Candidate must meet BOTH rates for EVERY condition, not merely average.
        good=sum(x['both_operational_gates'] for x in sub)
        ranks.append({'candidate':candidate,'conditions_passed':good,
                      'conditions_total':len(sub),
                      'all_operational_gates':int(good==len(sub)),
                      'human_only_optical':0,
                      'privacy_qualified':0,
                      'security_qualified':0,
                      'mean_false_rejection_rate':sum(x['false_rejection_rate'] for x in sub)/len(sub),
                      'mean_false_acceptance_rate':sum(x['false_acceptance_rate'] for x in sub)/len(sub)})
    ranks.sort(key=lambda r:(-r['conditions_passed'],r['mean_false_rejection_rate']+r['mean_false_acceptance_rate']))
    rf=['candidate','conditions_passed','conditions_total','all_operational_gates',
        'human_only_optical','privacy_qualified','security_qualified',
        'mean_false_rejection_rate','mean_false_acceptance_rate']
    table(out/'reports'/'architecture_comparison.csv',ranks,rf)
    elapsed=time.perf_counter()-start
    summary={'selected_images':len(paths),'processed_images':len(set(r['file'] for r in rows)),
      'failed_images':len(fail),'candidate_image_condition_records':len(rows),
      'duplicate_extra_sha256':sum(n-1 for n in hashes.values() if n>1),
      'conditions':len(args.conditions),'candidates':len(CANDIDATES),
      'elapsed_seconds':round(elapsed,3),'c11_source_status':prior['status'],
      'max_false_rejection_rate':args.max_frr,'max_false_acceptance_rate':args.max_far,
      'research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION'}
    save(out/'reports'/'summary.json',summary)
    save(out/'reports'/'c11_source_audit.json',prior)
    save(out/'reports'/'self_tests.json',{'passed':len(checks),'total':len(checks),'checks':checks})
    save(out/'configuration'/'run.json',{'experiment':'EOW_C12',
      'timestamp_utc':datetime.now(timezone.utc).isoformat(),
      'dataset':str(args.dataset.resolve()),'c11':str(args.c11),
      'max_side':args.max_side,'limit':args.limit,'seed':args.seed,
      'conditions':args.conditions,'candidates':CANDIDATES,
      'max_frr':args.max_frr,'max_far':args.max_far,
      'python':sys.version.split()[0],'numpy':np.__version__,'pillow':Image.__version__})
    save(out/'reports'/'model_assumptions.json',{
      'dataset':'actual standard image files; MATLAB annotation files excluded',
      'secret':'grayscale threshold 128; resize longest side <= max-side',
      'encoding':'randomized 2-subpixel classical OR VSS',
      'benign':'B share perturbed; A ideal; no actual print/scan',
      'attack':'one changed B subpixel that changes one reconstructed pixel ideally',
      'trusted_reference':'ALL four candidates use original trusted binary image; this is NOT unaided human verification',
      'reference_99':'software full-image agreement >= 0.99',
      'reference_exact':'software full-image agreement == 1',
      'registration_exact':'software maximizes agreement across horizontal shifts -2..2 then requires exact match; bounded search only',
      'digital_digest':'software SHA-256 comparison of decoded image against trusted digest; NOT an authenticated signature or optical method',
      'fairness':'same encoded shares and attacked share for each candidate; noise independently sampled for benign and malicious examples',
      'operational_gate':'FRR<=max-frr AND FAR<=max-far for EACH condition, never reward reject-all',
      'statistical_scope':'one attack per image per condition, not adaptive optimal adversary; no confidence claim',
      'privacy':'NOT established by this experiment; see C07',
      'post_quantum':'NOT retested; see C08; SHA-256 alone does not authenticate issuer',
      'optical_human':'NOT established; trusted electronic reference makes all candidates unsuitable as pure human optical schemes',
      'physical':'NOT tested',
      'references':['https://doi.org/10.1007/BFb0053419',
                    'https://doi.org/10.6028/NIST.FIPS.204']})
    save(out/'reports'/'verdict.json',{
      'execution':'PASS' if rows and not fail else 'PARTIAL' if rows else 'FAIL',
      'research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION',
      'qualified_candidate_count':0,
      'architecture_optimization':'COMPARATIVE_BASELINES_ONLY',
      'human_optical_verification':'NOT_ESTABLISHED',
      'physical_robustness':'NOT_TESTED',
      'post_quantum_enrollment':'UPSTREAM_ONLY'})
    gates=[{'gate':'execution','status':'PASS' if rows and not fail else 'PARTIAL'},
      {'gate':'dual_operational_gate','status':'EVALUATED_NOT_SECURITY_QUALIFICATION'},
      {'gate':'information_theoretic_privacy','status':'NOT_TESTED'},
      {'gate':'human_only_optical_integrity','status':'NOT_ESTABLISHED'},
      {'gate':'physical_robustness','status':'NOT_TESTED'},
      {'gate':'issuer_binding','status':'UPSTREAM_C08_ONLY'}]
    table(out/'reports'/'feasibility_gates.csv',gates,['gate','status'])
    lines=['# EOW C12 — Constrained Architecture Comparison','',
      f"Processed {summary['processed_images']}/{len(paths)} images; {len(args.conditions)} conditions; {len(CANDIDATES)} candidates.",
      f"Operational thresholds: FRR <= {args.max_frr:.3f}, FAR <= {args.max_far:.3f}.",
      '','| Candidate | Passed conditions | Mean FRR | Mean attack acceptance | Human-only optical |',
      '|---|---:|---:|---:|---|']
    for r in ranks:
        lines.append(f"| {r['candidate']} | {r['conditions_passed']}/{r['conditions_total']} | {r['mean_false_rejection_rate']:.4f} | {r['mean_false_acceptance_rate']:.4f} | No |")
    lines+=['','## Scientific interpretation','',
      'This experiment compares explicit architectural baselines, not a new security-qualified visual authentication construction.',
      'All four candidates rely on a trusted digital reference image or digest. The digital digest is neither an ML-DSA signature nor a human optical method.',
      'The bounded-registration candidate tests a narrow engineering improvement, not a general geometric registration solution.',
      'An architecture is not credited for detecting attacks when it rejects legitimate samples. Both FRR and FAR must satisfy the configured limits in each condition.',
      'One changed subpixel is not an adaptive optimal attacker; security must be re-tested against C09-style adaptive strategies and stronger modifications.',
      'Privacy, physical optical performance, unaided human verification, and post-quantum issuer binding remain separate unresolved or upstream questions.',
      '','## References','',
      '- Naor and Shamir, Visual Cryptography: https://doi.org/10.1007/BFb0053419',
      '- NIST FIPS 204: https://doi.org/10.6028/NIST.FIPS.204']
    (out/'reports'/'scientific_report.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2))
    return 0 if rows and not fail else 2
if __name__=='__main__':raise SystemExit(main())
