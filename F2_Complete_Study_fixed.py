#!/usr/bin/env python3
"""F2 complete computational evaluation of balanced differential visual shares.

Python >=3.10; numpy, Pillow. Reads the canonical BSDS500/USC-SIPI image
manifest; never changes source data. This is an experimental optical-code
baseline, NOT a proven human-only or post-quantum authentication scheme.

Run: python F2_Complete_Study.py --image-limit 0 --side 128 --trials 30
"""
from __future__ import annotations
import argparse, csv, hashlib, json, math, platform, sys, time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from PIL import Image, ImageFilter

HERE=Path(__file__).resolve().parent
DEFAULT_ROOT=Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')

def write_json(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(obj,indent=2,ensure_ascii=False,default=str),encoding='utf-8')
def write_csv(p,rows):
    p.parent.mkdir(parents=True,exist_ok=True)
    if not rows:
        p.write_text('',encoding='utf-8');return
    keys=list(dict.fromkeys(k for row in rows for k in row))
    with p.open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(rows)
def sha(arr):return hashlib.sha256(np.ascontiguousarray(arr).tobytes()).hexdigest()
def synthetic(side):
    y,x=np.indices((side,side));c=(side-1)/2
    return [('checker',((x+y)%2).astype(np.uint8)),('stripes',((x//4)%2).astype(np.uint8)),
            ('circle',(((x-c)**2+(y-c)**2)<(side/3)**2).astype(np.uint8)),
            ('symbol_H',(((x>side//5)&(x<side//3)&(y>side//6)&(y<5*side//6))|((x>2*side//3)&(x<4*side//5)&(y>side//6)&(y<5*side//6))|((abs(y-side//2)<2)&(x>side//5)&(x<4*side//5))).astype(np.uint8)),
            ('random',np.random.default_rng(19).integers(0,2,(side,side),dtype=np.uint8)),
            ('all_white',np.zeros((side,side),dtype=np.uint8)),('all_black',np.ones((side,side),dtype=np.uint8))]
def discover(root,manifest,limit,strict):
    if not manifest.exists():
        if strict:raise FileNotFoundError(f'Missing manifest: {manifest}')
        return [],{'missing_manifest':True}
    with manifest.open(encoding='utf-8-sig',newline='') as f: rows=list(csv.DictReader(f))
    candidates=[];seen=set();missing=[]
    for r in rows:
        rel=r.get('relative_path','').replace('\\','/')
        if not (rel.startswith('BSR/BSDS500/data/images/') or rel.startswith('misc/')):continue
        if Path(rel).suffix.lower() not in ('.jpg','.jpeg','.tif','.tiff','.png'):continue
        p=root/Path(rel)
        if not p.is_file():missing.append(rel);continue
        h=r.get('sha256') or rel
        if h in seen:continue
        seen.add(h)
        if rel.startswith('misc/'):split='sipi'
        else:split=rel.split('/')[4]
        candidates.append((rel,split,h))
    candidates.sort(key=lambda a:(a[1],a[0]))
    if strict and missing:raise FileNotFoundError(f'{len(missing)} canonical images missing; first: {missing[0]}')
    if strict and limit==0 and len(candidates)!=539:raise ValueError(f'Expected 539 canonical images, found {len(candidates)}')
    if limit:candidates=candidates[:limit]
    return candidates,{'available':len(candidates),'missing':missing[:30],'missing_count':len(missing)}
def load_binary(path,side,threshold):
    with Image.open(path) as im:
        im=im.convert('L');im.thumbnail((side,side),Image.Resampling.LANCZOS)
        return (np.asarray(im,dtype=np.uint8)<threshold).astype(np.uint8)

def parity_graph(n,rate,degree,seed):
    """Sparse public parity graph. Each parity bit XORs 'degree' data bits."""
    r=max(1,int(math.ceil(n*rate))) if rate>0 else 0
    rng=np.random.default_rng(seed);degree=min(n,max(1,degree))
    return np.stack([rng.choice(n,size=degree,replace=False) for _ in range(r)]) if r else np.zeros((0,degree),dtype=np.int32)
def make_code(m,graph):
    p=np.bitwise_xor.reduce(m[graph],axis=1) if len(graph) else np.empty(0,dtype=np.uint8)
    return np.concatenate([m,p])
def syndrome(z,n,graph):
    if not len(graph):return np.empty(0,dtype=np.uint8)
    return np.bitwise_xor(np.bitwise_xor.reduce(z[:n][graph],axis=1),z[n:])
def permutation(n,r,layout,seed):
    """Index at each physical cell; layout is invertible and reproducible."""
    if layout=='L1':return np.random.default_rng(seed).permutation(n+r)
    if layout=='L2':
        # motif bands: interleave parity at approximately regular intervals
        if not r:return np.arange(n)
        data=list(range(n));par=list(range(n,n+r));out=[]
        for j in range(r):
            end=round((j+1)*n/r);start=round(j*n/r)
            out.extend(data[start:end]);out.append(par[j])
        return np.asarray(out,dtype=np.int64)
    if layout=='L3':
        # each parity cell near the data bits to which it is linked only in
        # a coarse contiguous layout; graph itself remains globally sparse.
        if not r:return np.arange(n)
        out=[];start=0
        for j in range(r):
            end=round((j+1)*n/r);out.extend(range(start,end));out.append(n+j);start=end
        return np.asarray(out,dtype=np.int64)
    raise ValueError(layout)
def encode_visual(v,rng):
    """Balanced differential 4-subpixel VC, both shares uniform conditional on bit."""
    a=rng.integers(0,2,size=len(v),dtype=np.uint8)
    b=rng.integers(0,2,size=len(v),dtype=np.uint8)
    R=np.stack([a,1-a,b,1-b],axis=1).astype(np.uint8)
    D=np.empty_like(R)
    zero=(v==0)
    D[zero,0]=a[zero];D[zero,1]=1-a[zero]
    D[zero,2]=1-b[zero];D[zero,3]=b[zero]
    D[~zero,0]=1-a[~zero];D[~zero,1]=a[~zero]
    D[~zero,2]=b[~zero];D[~zero,3]=1-b[~zero]
    return R,D
def decode_overlay(R,D):
    Y=np.bitwise_or(R,D)
    left=Y[:,:2].sum(axis=1);right=Y[:,2:].sum(axis=1)
    valid=((left==1)&(right==2))|((left==2)&(right==1))
    bits=(left==2).astype(np.uint8)
    return bits,valid,Y

def exhaustive_theory():
    outcomes={};flips=[];privacy={}
    for bit in (0,1):
        patterns=[]
        for a in (0,1):
            for b in (0,1):
                R,D=encode_visual(np.array([bit],dtype=np.uint8),np.random.default_rng(0)) if False else (None,None)
                R=np.array([a,1-a,b,1-b],dtype=np.uint8)
                D=np.array([a,1-a,1-b,b] if bit==0 else [1-a,a,b,1-b],dtype=np.uint8)
                y=R|D;left=int(y[:2].sum());right=int(y[2:].sum())
                assert (left,right)==((1,2) if bit==0 else (2,1))
                patterns.append({'a':a,'b':b,'R':R.tolist(),'D':D.tolist(),'overlay':y.tolist()})
                for side in ('R','D'):
                    for j in range(4):
                        rr=R.copy();dd=D.copy()
                        if side=='R':rr[j]^=1
                        else:dd[j]^=1
                        yy=rr|dd
                        l=int(yy[:2].sum());r=int(yy[2:].sum())
                        flips.append({'bit':bit,'a':a,'b':b,'side':side,'subpixel':j,
                                      'overlay_unchanged':bool(np.array_equal(yy,y)),
                                      'decoded_valid':(l,r) in ((1,2),(2,1)),
                                      'decoded_bit':int(l==2) if (l,r) in ((1,2),(2,1)) else None})
        outcomes[str(bit)]=patterns
    for share in ('R','D'):
        c0=Counter(tuple(p[share]) for p in outcomes['0'])
        c1=Counter(tuple(p[share]) for p in outcomes['1'])
        privacy[share]=c0==c1
    # Known z and D uniquely determine R for each of the 8 configurations.
    recovered=all(next(p['R'] for p in outcomes[str(bit)] if p['D']==p0['D'])==p0['R']
                  for bit in (0,1) for p0 in outcomes[str(bit)])
    invisible=sum(x['overlay_unchanged'] for x in flips)
    return {'basis_patterns':outcomes,'single_bit_flips':flips,'single_bit_flips_total':len(flips),
            'invisible_single_bit_flips':invisible,'single_share_privacy_exact':privacy,
            'known_codeword_reference_recovery_exact':recovered,
            'propositions':[
                {'id':'F2-P1','status':'PROVEN','statement':'Both single shares are uniform and independent of the encoded bit under independent uniform a,b.'},
                {'id':'F2-P2','status':'PROVEN','statement':'Correctly issued blocks decode exactly from the (1,2) or (2,1) pair weights.'},
                {'id':'F2-P3','status':'PROVEN','statement':'Given the encoded bit and distributed block, the reference block is uniquely determined.'},
                {'id':'F2-P4','status':'PROVEN','statement':'Static local OR overlays cannot propagate a local share edit to an untouched distant optical cell.'},
                {'id':'F2-P5','status':'NOT_ESTABLISHED','statement':'Digital parity syndrome or an offline ML-DSA signature is verified by an unaided human observing only the optical overlay.'}
            ]}

def attack(D,R,v,n,graph,mode,strength,rng):
    d=D.copy();k=max(1,round(len(d)*strength))
    if mode=='random_flip':
        ix=rng.choice(len(d)*4,size=min(k,len(d)*4),replace=False)
        d.flat[ix]^=1
    elif mode=='ink_addition':
        ix=np.flatnonzero(d==0);ix=rng.choice(ix,size=min(k,len(ix)),replace=False);d.flat[ix]=1
    elif mode=='ink_removal':
        ix=np.flatnonzero(d==1);ix=rng.choice(ix,size=min(k,len(ix)),replace=False);d.flat[ix]=0
    elif mode=='block_replace':
        ix=rng.choice(len(d),size=min(k,len(d)),replace=False);d[ix]=rng.integers(0,2,(len(ix),4),dtype=np.uint8)
    elif mode=='whole_share_random':d=rng.integers(0,2,size=d.shape,dtype=np.uint8)
    elif mode=='masked_reference_aware':
        ix=np.flatnonzero(R==1);ix=rng.choice(ix,size=min(k,len(ix)),replace=False);d.flat[ix]^=1
    elif mode=='known_codeword_valid_flip':
        # A2: recover R from D and known codeword; force a different VALID
        # bit in k cells using a legal four-subpixel encoding with same R.
        ix=rng.choice(len(d),size=min(k,len(d)),replace=False)
        for i in ix:
            a=int(R[i,0]);b=int(R[i,2]);new=int(v[i]^1)
            d[i]=[a,1-a,1-b,b] if new==0 else [1-a,a,b,1-b]
    elif mode=='known_codeword_consistent_forgery':
        # A2: recover R and replace content+parity with a fresh valid codeword.
        # This is a legitimate mathematical codeword but not authorized issuance.
        if n==0:return d
        z=v.copy();z[:n]^=np.uint8(1)
        if len(graph):z[n:]=np.bitwise_xor.reduce(z[:n][graph],axis=1)
        a=R[:,0];b=R[:,2];zero=z==0
        d[zero,0]=a[zero];d[zero,1]=1-a[zero];d[zero,2]=1-b[zero];d[zero,3]=b[zero]
        d[~zero,0]=1-a[~zero];d[~zero,1]=a[~zero];d[~zero,2]=b[~zero];d[~zero,3]=1-b[~zero]
    else:raise ValueError(mode)
    return d

def image_tile(arr):
    # Four subpixels rendered as a 2x2 tile for each codeword bit.
    h,w=arr.shape[:2];return arr.reshape(h,w,2,2).transpose(0,2,1,3).reshape(h*2,w*2)
def optical_trials(R,D,side,rng):
    # Physically rasterize in 2x2 tiles. Pad to rectangular codeword layout.
    n=len(R);cols=max(1,int(math.ceil(math.sqrt(n))));rows=int(math.ceil(n/cols));pad=rows*cols-n
    rr=np.pad(R,((0,pad),(0,0)),constant_values=0).reshape(rows,cols,4)
    dd=np.pad(D,((0,pad),(0,0)),constant_values=0).reshape(rows,cols,4)
    ref=image_tile(rr);dist=image_tile(dd);base=ref|dist
    results=[]
    for shift in ((0,0),(1,0),(0,1),(1,1),(2,0)):
        dy,dx=shift
        shifted=np.zeros_like(dist)
        ys=slice(dy,None);xs=slice(dx,None)
        shifted[ys,xs]=dist[:dist.shape[0]-dy if dy else None,:dist.shape[1]-dx if dx else None]
        overlay=ref|shifted
        results.append({'condition':'translation','dx':dx,'dy':dy,'pixel_disagreement':float(np.mean(base!=overlay))})
    for sigma in (0.5,1.0):
        im=Image.fromarray((dist*255).astype(np.uint8),'L').filter(ImageFilter.GaussianBlur(sigma))
        blurred=(np.asarray(im)>=128).astype(np.uint8)
        results.append({'condition':'blur','sigma':sigma,'pixel_disagreement':float(np.mean(base!=(ref|blurred)))})
    for prob in (0.001,0.01):
        noise=rng.random(dist.shape)<prob
        altered=dist^noise.astype(np.uint8)
        results.append({'condition':'binary_noise','probability':prob,'pixel_disagreement':float(np.mean(base!=(ref|altered)))})
    for angle in (0.5,1.0):
        im=Image.fromarray((dist*255).astype(np.uint8),'L').rotate(angle,resample=Image.Resampling.BILINEAR,fillcolor=0)
        rotated=(np.asarray(im)>=128).astype(np.uint8)
        results.append({'condition':'rotation','degrees':angle,'pixel_disagreement':float(np.mean(base!=(ref|rotated)))})
    return results

def save_visual(path,m,R,D,forged=None):
    path.parent.mkdir(parents=True,exist_ok=True)
    n=len(R);cols=max(1,int(math.ceil(math.sqrt(n))));rows=int(math.ceil(n/cols));pad=rows*cols-n
    def tiled(a):return image_tile(np.pad(a,((0,pad),(0,0))).reshape(rows,cols,4))
    items=[tiled(R),tiled(D),tiled(R|D)]
    if forged is not None:items.append(tiled(R|forged))
    canvas=np.concatenate(items,axis=1)
    Image.fromarray((255*(1-canvas)).astype(np.uint8),'L').save(path)

def electronic_binding_audit(m,R,D):
    """Electronic binding and optional actual ML-DSA-65 via pqcrypto."""
    payload=m.tobytes()+R.tobytes()+D.tobytes()
    original=hashlib.sha256(payload).hexdigest()
    changed=D.copy();changed.flat[0]^=1
    changed_hash=hashlib.sha256(m.tobytes()+R.tobytes()+changed.tobytes()).hexdigest()
    result={'sha256_original':original,'sha256_after_flip':changed_hash,
            'digital_digest_detects_flip':original!=changed_hash,
            'ml_dsa_implemented':False,'post_quantum_origin_authentication':'NOT_IMPLEMENTED',
            'human_optical_signature_verification':'NOT_IMPLEMENTED',
            'explanation':'Electronic signature validation is NOT human optical signature validation.'}
    try:
        from pqcrypto.sign import ml_dsa_65
        keygen = getattr(ml_dsa_65, 'generate_keypair', None)
        if keygen is None:
            result['ml_dsa_note'] = (
                'Installed pqcrypto.sign.ml_dsa_65 has no generate_keypair(). '
                'Electronic ML-DSA audit skipped; all optical experiments continue. '
                'Check module path and reinstall the official pqcrypto distribution.'
            )
        else:
            pk, sk = keygen()
            signature = ml_dsa_65.sign(sk, payload)
            def verify(msg):
                try:
                    outcome = ml_dsa_65.verify(pk, msg, signature)
                    # Some implementations signal success by returning None;
                    # official pqcrypto returns a bool. Only explicit False fails.
                    return outcome is not False
                except Exception:
                    return False
            valid_original = verify(payload)
            valid_tampered = verify(m.tobytes()+R.tobytes()+changed.tobytes())
            result.update({
                'ml_dsa_implemented': bool(valid_original and not valid_tampered),
                'ml_dsa_algorithm': 'ML-DSA-65',
                'signature_length_bytes': len(signature),
                'public_key_length_bytes': len(pk),
                'original_signature_valid': valid_original,
                'tampered_signature_valid': valid_tampered,
                'post_quantum_origin_authentication':
                    'ELECTRONIC_ONLY' if valid_original and not valid_tampered else 'AUDIT_FAILED'
            })
            if not valid_original or valid_tampered:
                result['ml_dsa_note'] = 'ML-DSA audit failed its positive/negative controls.'
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        result['ml_dsa_note'] = (
            'Optional ML-DSA audit unavailable (' + type(exc).__name__ + ': ' + str(exc) + '). '
            'All non-cryptographic experiments continue.'
        )
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=DEFAULT_ROOT)
    ap.add_argument('--data',type=Path,default=None)
    ap.add_argument('--manifest',type=Path,default=None)
    ap.add_argument('--out',type=Path,default=None)
    ap.add_argument('--image-limit',type=int,default=0,help='0=all 539 canonical real images')
    ap.add_argument('--side',type=int,default=128)
    ap.add_argument('--threshold',type=int,default=128)
    ap.add_argument('--trials',type=int,default=30)
    ap.add_argument('--optical-samples',type=int,default=30)
    ap.add_argument('--parity-rate',type=float,default=0.125)
    ap.add_argument('--parity-degree',type=int,default=7)
    ap.add_argument('--seed',type=int,default=20261107)
    ap.add_argument('--strict-data',action='store_true')
    ap.add_argument('--layouts',default='L1,L2,L3')
    ap.add_argument('--figures',type=int,default=12)
    args=ap.parse_args()
    if not 0<=args.parity_rate<=2 or args.side<8 or args.trials<1 or args.optical_samples<0:ap.error('Invalid numeric parameters')
    root=args.root;data=args.data or root/'Data';manifest=args.manifest or root/'Data_Inspection'/'file_manifest.csv';out=args.out or root/'Results'/'F2_Complete'
    layouts=[s.strip() for s in args.layouts.split(',') if s.strip()]
    if not layouts or any(x not in ('L1','L2','L3') for x in layouts):ap.error('layouts must be from L1,L2,L3')
    start=time.time();rng=np.random.default_rng(args.seed)
    theory=exhaustive_theory();write_json(out/'mathematical_validation'/'theory.json',theory)
    files,discovery=discover(data,manifest,args.image_limit,args.strict_data)
    records=[(f'synthetic/{name}','synthetic',m,None) for name,m in synthetic(args.side)]
    for rel,split,h in files:records.append((rel,split,None,h))
    reconstruction=[];attacks=[];optical=[];integrity=[];figures=0;failures=[];digest_audit=None
    modes=('random_flip','ink_addition','ink_removal','block_replace','whole_share_random','masked_reference_aware','known_codeword_valid_flip','known_codeword_consistent_forgery')
    strengths=(0.001,0.01,0.05)
    for idx,(rel,split,provided,source_sha) in enumerate(records):
        try:
            m2=provided if provided is not None else load_binary(data/Path(rel),args.side,args.threshold)
            m=m2.reshape(-1);n=len(m);graph=parity_graph(n,args.parity_rate,args.parity_degree,args.seed+idx)
            z=make_code(m,graph);r=len(graph)
            for layout in layouts:
                perm=permutation(n,r,layout,args.seed+idx)
                v=z[perm];R,D=encode_visual(v,rng)
                bits,valid,Y=decode_overlay(R,D)
                inverse=np.argsort(perm);decoded=bits[inverse];orig_error=float(np.mean(decoded[:n]!=m))
                rec={'image':rel,'split':split,'layout':layout,'height':m2.shape[0],'width':m2.shape[1],
                     'data_bits':n,'parity_bits':r,'effective_expansion':4*(n+r)/n,
                     'source_sha256':source_sha or sha(m2),'image_black_fraction':float(m.mean()),
                     'exact_reconstruction':bool(np.array_equal(bits,v)),
                     'reconstruction_bit_error':orig_error,'invalid_block_fraction':float(np.mean(~valid)),
                     'syndrome_nonzero':int(syndrome(decoded,n,graph).sum()),
                     'overlay_black_fraction':float(Y.mean())}
                reconstruction.append(rec)
                if digest_audit is None:digest_audit=electronic_binding_audit(m,R,D)
                if figures<args.figures:
                    forged=attack(D,R,v,n,graph,'known_codeword_valid_flip',0.01,rng)
                    save_visual(out/'figures'/f'{figures:03d}_{layout}.png',m2,R,D,forged);figures+=1
                for mode in modes:
                    ss=(1.0,) if mode in ('whole_share_random','known_codeword_consistent_forgery') else strengths
                    for strength in ss:
                        for trial in range(args.trials):
                            attacked=attack(D,R,v,n,graph,mode,strength,rng)
                            b2,valid2,y2=decode_overlay(R,attacked)
                            zd=b2[inverse];syn=syndrome(zd,n,graph)
                            changed=int(np.count_nonzero(attacked!=D))
                            overlay_changed=int(np.count_nonzero(y2!=Y))
                            content_changed=int(np.count_nonzero(zd[:n]!=m))
                            attacks.append({'image':rel,'split':split,'layout':layout,'mode':mode,'strength':strength,
                                'trial':trial,'changed_share_subpixels':changed,'overlay_changed_subpixels':overlay_changed,
                                'overlay_exactly_unchanged':overlay_changed==0,
                                'invalid_blocks':int(np.count_nonzero(~valid2)),
                                'invalid_block_detection':bool(np.any(~valid2)),
                                'syndrome_weight':int(syn.sum()),'digital_syndrome_detection':bool(np.any(syn)),
                                'content_changed_bits':content_changed,'content_forgery':content_changed>0,
                                'digital_composite_detection':bool(np.any(~valid2) or np.any(syn)),
                                'attacker_knows_reference':mode in ('masked_reference_aware','known_codeword_valid_flip','known_codeword_consistent_forgery'),
                                'human_detected':None})
                # Explicit non-adversarial parity codeword transitions and unchanged optical motif
                if layout==layouts[0]:
                    altered=m.copy();altered[0]^=1
                    other=make_code(altered,graph)
                    integrity.append({'image':rel,'codeword_valid_after_reencoding':bool(not np.any(syndrome(other,n,graph))),
                                      'content_changed':True,'offline_signature_automatically_revalidated':False,
                                      'static_printed_parity_auto_recomputes':False})
                if idx<args.optical_samples:
                    for item in optical_trials(R,D,args.side,rng):optical.append({'image':rel,'split':split,'layout':layout,**item})
        except Exception as exc:
            failures.append({'image':rel,'error':repr(exc)})
            if args.strict_data:raise
        if (idx+1)%50==0:print(f'Processed {idx+1}/{len(records)} images; attack trials {len(attacks)}',flush=True)
    write_csv(out/'reports'/'reconstruction.csv',reconstruction)
    write_csv(out/'reports'/'attacks_trials.csv',attacks)
    write_csv(out/'reports'/'optical_trials.csv',optical)
    write_csv(out/'coding_integrity'/'codeword_transitions.csv',integrity)
    write_csv(out/'reports'/'errors.csv',failures)
    groups=defaultdict(list)
    for row in attacks:groups[(row['layout'],row['mode'],row['strength'])].append(row)
    agg=[]
    for (layout,mode,strength),rows in sorted(groups.items()):
        agg.append({'layout':layout,'mode':mode,'strength':strength,'trials':len(rows),
                    'exactly_invisible_rate':float(np.mean([r['overlay_exactly_unchanged'] for r in rows])),
                    'digital_composite_detection_rate':float(np.mean([r['digital_composite_detection'] for r in rows])),
                    'digital_syndrome_detection_rate':float(np.mean([r['digital_syndrome_detection'] for r in rows])),
                    'invalid_block_detection_rate':float(np.mean([r['invalid_block_detection'] for r in rows])),
                    'content_forgery_rate':float(np.mean([r['content_forgery'] for r in rows])),
                    'mean_changed_overlay_subpixels':float(np.mean([r['overlay_changed_subpixels'] for r in rows]))})
    write_csv(out/'reports'/'attack_summary.csv',agg)
    optical_groups=defaultdict(list)
    for row in optical:
        key=(row['layout'],row['condition'],row.get('dx'),row.get('dy'),row.get('sigma'),row.get('probability'),row.get('degrees'))
        optical_groups[key].append(row['pixel_disagreement'])
    optagg=[]
    for key,vals in optical_groups.items():
        optagg.append({'layout':key[0],'condition':key[1],'dx':key[2],'dy':key[3],'sigma':key[4],
                       'probability':key[5],'degrees':key[6],'samples':len(vals),'mean_pixel_disagreement':float(np.mean(vals))})
    write_csv(out/'reports'/'optical_summary.csv',optagg)
    write_json(out/'cryptographic_audit'/'electronic_binding.json',digest_audit or {'status':'no_images'})
    config={'generated_utc':datetime.now(timezone.utc).isoformat(),'python':sys.version,'numpy':np.__version__,
            'pillow':Image.__version__,'platform':platform.platform(),'command':sys.argv,'seed':args.seed,
            'root':str(root),'data':str(data),'manifest':str(manifest),'out':str(out),'side':args.side,
            'threshold':args.threshold,'trials':args.trials,'optical_samples':args.optical_samples,
            'parity_rate':args.parity_rate,'parity_degree':args.parity_degree,'layouts':layouts,
            'discovery':discovery,'real_images_selected':len(files),'synthetic_images':7,
            'warning':'Digital optical detector is not a human participant. ML-DSA is optional and electronic only.'}
    write_json(out/'configuration'/'run.json',config)
    verdict={'framework':'F2 balanced differential shares + static sparse parity + spatial layouts',
             'elapsed_seconds':round(time.time()-start,2),'images_processed':len({r['image'] for r in reconstruction}),
             'real_images_processed':len({r['image'] for r in reconstruction if r['split']!='synthetic'}),
             'reconstruction_records':len(reconstruction),'adversarial_trials':len(attacks),
             'optical_trials':len(optical),'errors':len(failures),
             'results':{
                 'single_share_privacy': 'PROVEN_FOR_IDEAL_ENCODING' if all(theory['single_share_privacy_exact'].values()) else 'FAILED',
                 'ideal_reconstruction':'PASSED' if reconstruction and all(r['exact_reconstruction'] for r in reconstruction) else 'FAILED_OR_NOT_TESTED',
                 'known_codeword_reference_secrecy':'FAILED' if theory['known_codeword_reference_recovery_exact'] else 'NOT_ESTABLISHED',
                 'detect_every_physical_modification':'FAILED' if theory['invisible_single_bit_flips'] else 'NOT_ESTABLISHED',
                 'digital_parity_integrity':'MEASURED_NOT_ORIGIN_AUTHENTICATION',
                 'human_only_integrity':'NOT_ESTABLISHED',
                 'post_quantum_optical_origin_authentication':'NOT_ESTABLISHED_EVEN_IF_ELECTRONIC_ML_DSA_AVAILABLE',
                 'physical_transparency_testing':'NOT_PERFORMED'},
             'limitations':['Static optical motifs do not calculate a parity syndrome.',
                            'A valid different codeword can be substituted by a reference-aware attacker.',
                            'Digital optical differences are not human detection rates.',
                            'ML-DSA-65 is optional via pqcrypto and, when available, verifies electronically only.',
                            'Pixel expansion and print/registration sensitivity must be assessed against F1.']}
    write_json(out/'reports'/'verdict.json',verdict)
    (out/'README.txt').write_text('F2 complete computational study.\nMain report: reports/verdict.json\n'
        'Results: reports/reconstruction.csv, reports/attacks_trials.csv, reports/attack_summary.csv, '
        'reports/optical_summary.csv.\nTheory: mathematical_validation/theory.json\n'
        'Not a post-quantum or human-only authenticated protocol.\n',encoding='utf-8')
    print(json.dumps({'output':str(out),**{k:verdict[k] for k in ('images_processed','real_images_processed','adversarial_trials','optical_trials','errors','elapsed_seconds')},'results':verdict['results']},indent=2))
    if failures:sys.exit(2)
if __name__=='__main__':main()
