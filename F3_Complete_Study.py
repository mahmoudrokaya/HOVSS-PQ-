#!/usr/bin/env python3
"""F3-HCOA: complete reproducible *computational feasibility audit*.

Tests protected-reference challenge authentication, joint OR feasibility, attacks,
image reconstruction, digital optical perturbations, and electronic PQ issuance.
Does NOT claim a proven secure optical authenticator or human/physical results.

Python 3.10+; numpy, Pillow; optional pqcrypto.
Example:
 python F3_Complete_Study.py --image-limit 0 --side 128 --trials 30 --optical-samples 30 --strict-data
"""
from __future__ import annotations
import argparse,csv,hashlib,json,math,platform,sys,time,itertools
from pathlib import Path
from collections import Counter,defaultdict
from datetime import datetime,timezone
import numpy as np
from PIL import Image,ImageFilter

DEFAULT_ROOT=Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')

def jdump(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,default=str),encoding='utf-8')
def csvdump(path,rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    if not rows: path.write_text('',encoding='utf-8');return
    cols=list(dict.fromkeys(k for r in rows for k in r))
    with path.open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=cols);w.writeheader();w.writerows(rows)
def hash_array(x):return hashlib.sha256(np.ascontiguousarray(x).tobytes()).hexdigest()

def discover(root,manifest,limit,strict):
    if not manifest.is_file():
        if strict:raise FileNotFoundError(manifest)
        return []
    with manifest.open(encoding='utf-8-sig',newline='') as f: rows=list(csv.DictReader(f))
    result=[];seen=set();missing=[]
    for row in rows:
        rel=row.get('relative_path','').replace('\\','/')
        if not (rel.startswith('BSR/BSDS500/data/images/') or rel.startswith('misc/')):continue
        if Path(rel).suffix.lower() not in ('.jpg','.jpeg','.tiff','.tif','.png'):continue
        p=root/Path(rel)
        if not p.is_file():missing.append(rel);continue
        digest=row.get('sha256') or rel
        if digest in seen:continue
        seen.add(digest)
        split='sipi' if rel.startswith('misc/') else rel.split('/')[4]
        result.append((rel,split,digest))
    result.sort(key=lambda a:(a[1],a[0]))
    if strict and missing:raise FileNotFoundError(f'{len(missing)} missing; first {missing[0]}')
    if strict and limit==0 and len(result)!=539:raise ValueError(f'Expected 539 canonical real images, found {len(result)}')
    return result[:limit] if limit else result

def synthetic(side):
    y,x=np.indices((side,side));c=(side-1)/2
    return [('checker',((x+y)%2).astype(np.uint8)),('stripes',((x//4)%2).astype(np.uint8)),
            ('circle',(((x-c)**2+(y-c)**2)<(side/3)**2).astype(np.uint8)),
            ('symbol_H',(((x>side//5)&(x<side//3)&(y>side//6)&(y<5*side//6))|((x>2*side//3)&(x<4*side//5)&(y>side//6)&(y<5*side//6))|((abs(y-side//2)<2)&(x>side//5)&(x<4*side//5))).astype(np.uint8)),
            ('random',np.random.default_rng(19).integers(0,2,(side,side),dtype=np.uint8)),
            ('all_white',np.zeros((side,side),dtype=np.uint8)),('all_black',np.ones((side,side),dtype=np.uint8))]
def load_image(path,side,threshold):
    with Image.open(path) as im:
        im=im.convert('L');im.thumbnail((side,side),Image.Resampling.LANCZOS)
        return (np.asarray(im,dtype=np.uint8)<threshold).astype(np.uint8)

# Content: standard Naor-Shamir 2-out-of-2, one randomly permuted 2-cell pair per bit.
# Audit: independent random optical challenge (R_a,D_a) and trusted enrolled overlay E_a.
# The audit-only rule cannot bind content changes: this is tested, not hidden.
def issue(m,rng,audit_density=0.25):
    n=len(m);a=rng.integers(0,2,n,dtype=np.uint8)
    R=np.stack((a,1-a),axis=1)
    D=np.stack((a^m,1-(a^m)),axis=1).astype(np.uint8)
    k=max(1,math.ceil(n*audit_density))
    ra=rng.integers(0,2,(k,2),dtype=np.uint8)
    da=rng.integers(0,2,(k,2),dtype=np.uint8)
    expected=ra|da
    return R,D,ra,da,expected

def decode(R,D):
    overlay=R|D
    weights=overlay.sum(axis=1)
    return (weights==2).astype(np.uint8),np.isin(weights,[1,2]),overlay

def audit_accept(ra,da,expected,tolerance=0):
    return float(np.mean((ra|da)!=expected))<=tolerance

def joint_theory():
    # Exhaust all deterministic 1-bit, 2-cell-per-share encoders with exactly
    # two equally likely issuance outcomes for each content value. 120^2 choices
    # of unordered distinct (R,D) pairs from 16 possible share-pair states,
    # each state is (R0,R1,D0,D1). Strong perfect privacy requires equal
    # marginals for both shares. Decode by an overlay-only rule with disjoint
    # supports. This is a necessary finite feasibility check, not universal impossibility.
    states=[]
    for bits in itertools.product((0,1),repeat=4):
        r=bits[:2];d=bits[2:];states.append((r,d,tuple(int(x|y) for x,y in zip(r,d))))
    pairs=list(itertools.combinations(range(16),2))
    marg={}
    for p in pairs:
        marg[p]=(Counter(states[i][0] for i in p),Counter(states[i][1] for i in p),frozenset(states[i][2] for i in p))
    equal_marg_pairs=0;perfect_overlay_encoders=0;examples=[]
    for p0 in pairs:
        mr0,md0,ov0=marg[p0]
        for p1 in pairs:
            mr1,md1,ov1=marg[p1]
            if mr0!=mr1 or md0!=md1:continue
            equal_marg_pairs+=1
            if ov0.isdisjoint(ov1):
                perfect_overlay_encoders+=1
                if len(examples)<3:examples.append({'zero_states':p0,'one_states':p1})
    # Fundamental optical locality counterexample: a disjoint audit region
    # stays unchanged if an adversary edits only content share cells.
    return {'enumeration':'2-subpixel R and D; exactly two equiprobable states per content bit',
            'share_pair_states':16,'two_state_choices_per_bit':len(pairs),
            'candidate_pairs_checked':len(pairs)**2,
            'both_single_share_marginals_equal':equal_marg_pairs,
            'perfect_overlay_decodable_and_private':perfect_overlay_encoders,
            'examples':examples,
            'proven_static_copy_limit':'A perfect physical copy yields the same optical observation under a static deterministic verifier.',
            'proven_disjoint_audit_locality':'Changing content-share cells does not alter the optical result of untouched disjoint audit cells.',
            'scope_warning':'Finite enumeration does not prove impossibility for larger blocks, other operators, or physically coupled materials.'}

def exact_reference_recovery():
    rows=[]
    for m,a in itertools.product((0,1),repeat=2):
        r=(a,1-a);d=(a^m,1-(a^m))
        candidates=[(b,1-b) for b in (0,1) if (b^m,1-(b^m))==d]
        rows.append({'content':m,'reference':r,'distributed':d,'candidate_reference_count':len(candidates),'recovered':candidates[0]==r})
    return rows

def challenge_leakage():
    # For one independent audit cell, ra,da uniform. E=ra OR da is enrolled
    # and may be visible to an adversary. Exact conditional guessing probability.
    # If da=0, ra=E; if da=1, E=1 regardless of ra. The distributed audit cell
    # alone reveals zero about ra, but public E reduces its entropy.
    joint=Counter()
    for ra,da in itertools.product((0,1),repeat=2):joint[(da,ra|da,ra)]+=0.25
    views=defaultdict(Counter)
    for (da,e,ra),p in joint.items():views[(da,e)][ra]+=p
    pguess=sum(max(c.values()) for c in views.values())
    return {'per_audit_cell_pguess_given_D_and_public_enrolled_E':pguess,
            'per_audit_cell_average_min_entropy_bits':-math.log2(pguess),
            'pguess_given_D_only':0.5,
            'warning':'This is a one-cell independent audit toy model, not a forgery-security bound. Public E also allows accepted changes at masked positions.'}

def attack_variant(name,R,D,ra,da,m,rng,strength,other=None):
    dc=D.copy();ac=da.copy();n=len(m);k=max(1,round(n*strength))
    if name=='random_flip':
        ix=rng.choice(dc.size,size=min(k,dc.size),replace=False);dc.flat[ix]^=1
    elif name=='ink_addition':
        ix=np.flatnonzero(dc==0);ix=rng.choice(ix,size=min(k,len(ix)),replace=False);dc.flat[ix]=1
    elif name=='ink_removal':
        ix=np.flatnonzero(dc==1);ix=rng.choice(ix,size=min(k,len(ix)),replace=False);dc.flat[ix]=0
    elif name=='block_replace':
        ix=rng.choice(n,size=min(k,n),replace=False);dc[ix]=rng.integers(0,2,(len(ix),2),dtype=np.uint8)
    elif name=='audit_only_corruption':
        ix=rng.choice(ac.size,size=min(k,ac.size),replace=False);ac.flat[ix]^=1
    elif name=='content_only_valid_forgery':
        # Known m and D imply R. Replace selected content blocks by the other
        # valid content bit, while keeping all audit cells unchanged.
        ix=rng.choice(n,size=min(k,n),replace=False)
        dc[ix]=1-dc[ix]
    elif name=='masked_reference_aware':
        ix=np.flatnonzero(R==1);ix=rng.choice(ix,size=min(k,len(ix)),replace=False);dc.flat[ix]^=1
    elif name=='full_random':
        dc=rng.integers(0,2,dc.shape,dtype=np.uint8)
        ac=rng.integers(0,2,ac.shape,dtype=np.uint8)
    elif name=='cross_issuance':
        if other is None:raise ValueError('Need other issuance')
        dc=other[0].copy();ac=other[1].copy()
    elif name=='exact_copy':pass
    else:raise ValueError(name)
    return dc,ac

def image_tile(a):
    n=len(a);cols=max(1,math.ceil(math.sqrt(n)));rows=math.ceil(n/cols);pad=rows*cols-n
    return np.pad(a,((0,pad),(0,0))).reshape(rows,cols,2).reshape(rows,cols*2)

def optical(R,D,ra,da,rng):
    # Digital surrogate: 1x2 subpixel tiles; compare content and audit overlay.
    base=image_tile(R|D);ref=image_tile(R);dist=image_tile(D)
    audit_base=image_tile(ra|da);audit_ref=image_tile(ra);audit_dist=image_tile(da)
    results=[]
    for region,b,r,d in [('content',base,ref,dist),('audit',audit_base,audit_ref,audit_dist)]:
        for dy,dx in [(0,0),(0,1),(1,0),(1,1),(0,2)]:
            shifted=np.zeros_like(d)
            if dy<d.shape[0] and dx<d.shape[1]:shifted[dy:,dx:]=d[:d.shape[0]-dy,:d.shape[1]-dx]
            results.append({'region':region,'condition':'translation','dy':dy,'dx':dx,'overlay_error':float(np.mean((r|shifted)!=b))})
        for sigma in [0.5,1.0]:
            blur=np.asarray(Image.fromarray((d*255).astype('uint8')).filter(ImageFilter.GaussianBlur(sigma)))>=128
            results.append({'region':region,'condition':'blur','sigma':sigma,'overlay_error':float(np.mean((r|blur.astype('uint8'))!=b))})
        for prob in [0.001,0.01]:
            noise=rng.random(d.shape)<prob
            results.append({'region':region,'condition':'binary_noise','probability':prob,'overlay_error':float(np.mean((r|(d^noise.astype('uint8')))!=b))})
        for angle in [0.5,1.0]:
            rot=np.asarray(Image.fromarray((d*255).astype('uint8')).rotate(angle,resample=Image.Resampling.BILINEAR,fillcolor=0))>=128
            results.append({'region':region,'condition':'rotation','degrees':angle,'overlay_error':float(np.mean((r|rot.astype('uint8'))!=b))})
    return results

def save_fig(path,m,R,D,ra,da,forged=None):
    path.parent.mkdir(parents=True,exist_ok=True)
    content=[image_tile(R),image_tile(D),image_tile(R|D)]
    if forged is not None:content.append(image_tile(R|forged))
    maxh=max(x.shape[0] for x in content);pad=lambda a:np.pad(a,((0,maxh-a.shape[0]),(0,0)),constant_values=0)
    Image.fromarray((255*(1-np.concatenate([pad(x) for x in content],axis=1))).astype('uint8')).save(path)
    a=[image_tile(ra),image_tile(da),image_tile(ra|da)]
    ah=max(x.shape[0] for x in a)
    Image.fromarray((255*(1-np.concatenate([np.pad(x,((0,ah-x.shape[0]),(0,0))) for x in a],axis=1))).astype('uint8')).save(path.with_name(path.stem+'_audit.png'))

def crypto_audit(m,R,D,ra,da):
    payload=b'F3-HCOA-v1|'+m.tobytes()+R.tobytes()+D.tobytes()+ra.tobytes()+da.tobytes()
    altered=bytearray(payload);altered[-1]^=1
    report={'sha256_original':hashlib.sha256(payload).hexdigest(),
            'sha256_changed':hashlib.sha256(altered).hexdigest(),
            'digest_detects_change':hashlib.sha256(payload).digest()!=hashlib.sha256(altered).digest(),
            'ml_dsa_status':'NOT_EXECUTED','optical_signature_verification':'NOT_IMPLEMENTED',
            'warning':'Electronic issuance signatures cannot be validated by optical OR alone.'}
    try:
        from pqcrypto.sign import ml_dsa_65
        names=[x for x in ('generate_keypair','sign','verify') if not callable(getattr(ml_dsa_65,x,None))]
        if names:
            report['ml_dsa_status']='API_UNAVAILABLE';report['missing_api']=names
        else:
            pk,sk=ml_dsa_65.generate_keypair();sig=ml_dsa_65.sign(sk,payload)
            def verify(msg):
                # pqcrypto variants may return True or None on successful verification.
                try:
                    outcome=ml_dsa_65.verify(pk,msg,sig)
                    return outcome is None or outcome is True
                except Exception:return False
            report.update({'ml_dsa_status':'EXECUTED','algorithm':'ML-DSA-65',
                           'signature_bytes':len(sig),'public_key_bytes':len(pk),
                           'valid_message_accepted':verify(payload),'tampered_message_rejected':not verify(bytes(altered))})
    except (ImportError,AttributeError,TypeError,ValueError,RuntimeError) as e:
        report['ml_dsa_status']='UNAVAILABLE_OR_ERROR';report['ml_dsa_error']=str(e)
    return report

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=DEFAULT_ROOT)
    ap.add_argument('--data',type=Path)
    ap.add_argument('--manifest',type=Path)
    ap.add_argument('--out',type=Path)
    ap.add_argument('--image-limit',type=int,default=0)
    ap.add_argument('--side',type=int,default=128)
    ap.add_argument('--threshold',type=int,default=128)
    ap.add_argument('--trials',type=int,default=30)
    ap.add_argument('--optical-samples',type=int,default=30)
    ap.add_argument('--audit-density',type=float,default=0.25)
    ap.add_argument('--seed',type=int,default=20261107)
    ap.add_argument('--strict-data',action='store_true')
    args=ap.parse_args()
    if args.side<8 or args.trials<1 or args.optical_samples<0 or not 0<args.audit_density<=1:ap.error('Invalid side/trials/optical-samples/audit-density')
    root=args.root;data=args.data or root/'Data';manifest=args.manifest or root/'Data_Inspection'/'file_manifest.csv';out=args.out or root/'Results'/'F3_Complete'
    started=time.monotonic();out.mkdir(parents=True,exist_ok=True)
    cfg={'version':'F3-HCOA-v1','utc':datetime.now(timezone.utc).isoformat(),
         'arguments':vars(args),'python':sys.version,'numpy':np.__version__,'pillow':Image.__version__,
         'dataset_root':str(data),'manifest':str(manifest),
         'important':'This is a feasibility and falsification benchmark, not a proven optical authentication system.'}
    jdump(out/'configuration'/'run.json',cfg)
    theory=joint_theory();reference=exact_reference_recovery();leakage=challenge_leakage()
    jdump(out/'mathematical_validation'/'joint_search.json',theory)
    jdump(out/'mathematical_validation'/'reference_recovery.json',reference)
    jdump(out/'mathematical_validation'/'challenge_leakage.json',leakage)
    real=discover(data,manifest,args.image_limit,args.strict_data)
    inputs=[(rel,split,lambda p=data/Path(rel):load_image(p,args.side,args.threshold)) for rel,split,_ in real]
    inputs.extend((name,'synthetic',lambda arr=arr:arr) for name,arr in synthetic(args.side))
    rng=np.random.default_rng(args.seed)
    recon=[];attacks=[];opts=[];fig_count=0;crypto=None;errors=[]
    modes=['random_flip','ink_addition','ink_removal','block_replace','audit_only_corruption',
           'content_only_valid_forgery','masked_reference_aware','full_random','cross_issuance','exact_copy']
    strengths=[0.001,0.01,0.05]
    for idx,(name,split,loader) in enumerate(inputs):
        try:
            img=loader();m=img.ravel();n=len(m)
            R,D,ra,da,E=issue(m,rng,args.audit_density)
            decoded,valid,Y=decode(R,D)
            if not np.array_equal(decoded,m) or not valid.all() or not audit_accept(ra,da,E):
                raise AssertionError('Honest reconstruction failure')
            recon.append({'image':name,'split':split,'height':img.shape[0],'width':img.shape[1],
                          'content_bits':n,'audit_cells':len(ra)*2,
                          'ideal_accuracy':float(np.mean(decoded==m)),
                          'honest_audit_accepted':True,'effective_subpixels_per_content_bit':float((2*n+2*len(ra))/n),
                          'source_sha256':hash_array(img)})
            if crypto is None:crypto=crypto_audit(m,R,D,ra,da)
            # Fresh independently issued second credential; same original content
            # is a particularly important cross-issuance substitution challenge.
            _,D2,_,da2,_=issue(m,rng,args.audit_density)
            for mode in modes:
                for strength in strengths:
                    for trial in range(args.trials):
                        forged,fa=attack_variant(mode,R,D,ra,da,m,rng,strength,(D2,da2))
                        dm,vv,yy=decode(R,forged)
                        content_changed=bool(np.any(dm!=m))
                        optical_changed=bool(np.any(yy!=Y))
                        audit_error=float(np.mean((ra|fa)!=E))
                        audit_ok=audit_error==0
                        # An intentionally weak audit-only rule and a stringent
                        # expected-content+audit surrogate, never a human result.
                        attacks.append({'image':name,'split':split,'mode':mode,'strength':strength,'trial':trial,
                                        'content_changed':int(content_changed),'overlay_changed':int(optical_changed),
                                        'content_error_rate':float(np.mean(dm!=m)),
                                        'invalid_content_block_rate':float(np.mean(~vv)),
                                        'audit_overlay_error_rate':audit_error,
                                        'audit_only_accept':int(audit_ok),
                                        'content_and_audit_accept':int(audit_ok and not content_changed and bool(vv.all())),
                                        'unauthorized_content_accepted_by_audit_only':int(content_changed and audit_ok),
                                        'exact_overlay_invisible':int(not optical_changed and audit_ok)})
            if idx<args.optical_samples:
                for row in optical(R,D,ra,da,rng):opts.append({'image':name,'split':split,**row})
            if fig_count<12:
                forged,_=attack_variant('content_only_valid_forgery',R,D,ra,da,m,rng,0.05)
                save_fig(out/'figures'/f'{fig_count:02d}_{Path(name).stem[:35]}.png',m,R,D,ra,da,forged)
                fig_count+=1
        except Exception as e:
            errors.append({'image':name,'error':repr(e)})
            if args.strict_data:raise
        if (idx+1)%50==0:print(f'Processed {idx+1}/{len(inputs)} images; attack trials {len(attacks)}',flush=True)
    csvdump(out/'reports'/'reconstruction.csv',recon)
    csvdump(out/'reports'/'attacks_trials.csv',attacks)
    csvdump(out/'reports'/'optical_trials.csv',opts)
    csvdump(out/'reports'/'errors.csv',errors)
    groups=defaultdict(list)
    for a in attacks:groups[(a['mode'],a['strength'])].append(a)
    summary=[]
    metrics=['content_changed','overlay_changed','content_error_rate','invalid_content_block_rate',
             'audit_overlay_error_rate','audit_only_accept','content_and_audit_accept',
             'unauthorized_content_accepted_by_audit_only','exact_overlay_invisible']
    for (mode,strength),rows in sorted(groups.items()):
        summary.append({'mode':mode,'strength':strength,'trials':len(rows),**{x+'_mean':float(np.mean([r[x] for r in rows])) for x in metrics}})
    csvdump(out/'reports'/'attack_summary.csv',summary)
    ogroups=defaultdict(list)
    for row in opts:ogroups[(row['region'],row['condition'],row.get('dx',''),row.get('dy',''),row.get('sigma',''),row.get('probability',''),row.get('degrees',''))].append(row['overlay_error'])
    csvdump(out/'reports'/'optical_summary.csv',[
        {'region':k[0],'condition':k[1],'dx':k[2],'dy':k[3],'sigma':k[4],'probability':k[5],
         'degrees':k[6],'samples':len(v),'mean_overlay_error':float(np.mean(v))} for k,v in sorted(ogroups.items())])
    jdump(out/'cryptographic_audit'/'electronic_issuance.json',crypto or {'status':'NO_IMAGES'})
    forged=[a for a in attacks if a['mode']=='content_only_valid_forgery' and a['content_changed']]
    verdict={'single_share_content_secrecy':'PROVEN_FOR_CONTENT_BASIS_ONLY',
             'full_share_privacy':'IDEAL_CONTENT_SECRECY_FOR_THIS_INDEPENDENT_AUDIT_CANDIDATE_ONLY',
             'ideal_reconstruction':'PASSED' if recon and not errors else 'FAILED_OR_INCOMPLETE',
             'known_content_reference_recovery':'FAILED_ALL_ENUMERATED_CASES',
             'audit_only_content_binding':'FAILED' if any(a['audit_only_accept'] for a in forged) else 'NOT_DEMONSTRATED',
             'static_exact_copy_resistance':'IMPOSSIBLE_FOR_IDENTICAL_OPTICAL_COPY',
             'human_only_optical_origin_authentication':'NOT_ESTABLISHED',
             'post_quantum_optical_authentication':'NOT_ESTABLISHED',
             'human_observer_study':'NOT_PERFORMED','physical_transparency_study':'NOT_PERFORMED',
             'cryptographic_issuance':'ELECTRONIC_ONLY_IF_EXECUTED',
             'interpretation':'Disjoint audit patterns are an explicit falsification candidate; a successful F3 joint optical content-binding encoder has not been constructed.'}
    jdump(out/'reports'/'verdict.json',verdict)
    report={'output':str(out),'images_processed':len(recon),'real_images_processed':sum(x['split']!='synthetic' for x in recon),
            'adversarial_trials':len(attacks),'optical_trials':len(opts),'errors':len(errors),
            'elapsed_seconds':round(time.monotonic()-started,2),'results':verdict,
            'theory':{'candidate_encoders_checked':theory['candidate_pairs_checked'],
                      'perfect_overlay_decodable_and_private':theory['perfect_overlay_decodable_and_private']},
            'challenge_leakage':leakage}
    jdump(out/'reports'/'summary.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in ('theory','challenge_leakage')},indent=2))

if __name__=='__main__':main()
