#!/usr/bin/env python3
"""F8.01: reproducible, read-only source-data and environment audit for HOVSS-PQ.

Run from Experiments/Code, or pass --root. Requires Pillow for image validation.
Does not modify source images, existing F1-F7 outputs, or the Python environment.
Only writes to Results/F8_01. This is infrastructure validation, not a security proof.
"""
from __future__ import annotations
import argparse, collections, csv, hashlib, importlib, importlib.metadata
import json, os, platform, random, re, sys, time, traceback
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ROOT = Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')
BSDS_PARTITIONS = ('train', 'val', 'test')
REAL_EXPECTED = {'BSDS500': 500, 'USC-SIPI': 39}
SYNTHETIC_NAMES = ('all_white','all_black','checkerboard','vertical_stripes',
                   'horizontal_stripes','center_square','letter_A')

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def sha256(path, chunk=1024*1024):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(chunk), b''):
            h.update(block)
    return h.hexdigest()

def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()

def write_json(path, data):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8') as f:
        json.dump(data,f,indent=2,ensure_ascii=False,default=str)

def write_csv(path, rows, columns):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=columns,extrasaction='ignore');w.writeheader();w.writerows(rows)

def rel(path,root):
    return path.relative_to(root).as_posix()

def dataset_files(root):
    bsds=root/'Data'/'BSR'/'BSDS500'/'data'/'images'
    misc=root/'Data'/'misc'
    out=[]; problems=[]
    for split in BSDS_PARTITIONS:
        folder=bsds/split
        if not folder.is_dir():
            problems.append(f'Missing BSDS500 directory: {folder}');continue
        for p in sorted(folder.iterdir(),key=lambda x:x.name.lower()):
            if p.is_file() and p.suffix.lower() in ('.jpg','.jpeg','.png','.tif','.tiff'):
                out.append((p,'BSDS500',split))
    if not misc.is_dir():
        problems.append(f'Missing USC-SIPI directory: {misc}')
    else:
        for p in sorted(misc.iterdir(),key=lambda x:x.name.lower()):
            if p.is_file() and p.suffix.lower() in ('.tiff','.tif'):
                out.append((p,'USC-SIPI','unassigned'))
    return out,problems

def validate_image(path, root, source, original_split, Image, side, compute_hash):
    item={'relative_path':rel(path,root),'source':source,'original_split':original_split,
          'filename':path.name,'size_bytes':path.stat().st_size,'sha256':None,
          'image_mode':None,'width':None,'height':None,'status':'OK','error':'',
          'normalized_sha256':None,'normalized_black_fraction':None}
    try:
        if compute_hash:item['sha256']=sha256(path)
        with Image.open(path) as im:
            im.verify()
        with Image.open(path) as im:
            item['image_mode']=im.mode;item['width'],item['height']=im.size
            if im.width<1 or im.height<1:raise ValueError('Empty image dimensions')
            # Explicit deterministic baseline: grayscale, bicubic resize, threshold 128.
            normalized=im.convert('L').resize((side,side),resample=Image.Resampling.BICUBIC)
            binary=normalized.point(lambda x:255 if x>=128 else 0,mode='L')
            raw=binary.tobytes()
            item['normalized_sha256']=digest_bytes(raw)
            item['normalized_black_fraction']=round(sum(v==0 for v in raw)/len(raw),8)
    except Exception as exc:
        item['status']='ERROR';item['error']=f'{type(exc).__name__}: {exc}'
    return item

def synthetic_images(side, Image):
    from PIL import ImageDraw, ImageFont
    result={}
    for name in SYNTHETIC_NAMES:
        im=Image.new('L',(side,side),255)
        draw=ImageDraw.Draw(im)
        if name=='all_black':draw.rectangle((0,0,side-1,side-1),fill=0)
        elif name=='checkerboard':
            for y in range(side):
                for x in range(side):
                    if (x+y)%2==0:im.putpixel((x,y),0)
        elif name=='vertical_stripes':
            for x in range(side):
                if (x//max(1,side//16))%2==0:draw.line((x,0,x,side-1),fill=0)
        elif name=='horizontal_stripes':
            for y in range(side):
                if (y//max(1,side//16))%2==0:draw.line((0,y,side-1,y),fill=0)
        elif name=='center_square':
            q=side//4;draw.rectangle((q,q,side-q-1,side-q-1),fill=0)
        elif name=='letter_A':
            # Geometry, not a system-font-dependent glyph.
            draw.line([(int(.18*side),int(.84*side)),(int(.5*side),int(.13*side)),
                       (int(.82*side),int(.84*side))],fill=0,width=max(1,side//10),joint='curve')
            draw.line((int(.31*side),int(.60*side),int(.69*side),int(.60*side)),fill=0,width=max(1,side//12))
        result[name]=im
    return result

def group_partition(records,seed):
    """Preserve BSDS native train/val/test; group identical normalized images.

    Native test > val > train priority prevents a duplicate in development from
    contaminating held-out test. USC-SIPI is deterministically allocated 23/8/8
    approximately, with duplicate groups kept intact. Synthetic = diagnostic only.
    """
    rng=random.Random(seed)
    records=[r for r in records if r['status']=='OK']
    priority={'train':0,'val':1,'test':2}
    groups=collections.defaultdict(list)
    for r in records:groups[r['normalized_sha256']].append(r)
    # Build connected groups by identical normalized content, not by filenames.
    for digest,members in sorted(groups.items()):
        bsds=[r for r in members if r['source']=='BSDS500']
        if bsds:
            split=max((r['original_split'] for r in bsds),key=lambda x:priority[x])
            for r in members:r['assigned_split']=split
    unassigned=[(d,m) for d,m in groups.items() if 'assigned_split' not in m[0]]
    unassigned.sort(key=lambda x:x[0]);rng.shuffle(unassigned)
    total=sum(len(m) for _,m in unassigned)
    desired={'train':round(total*.60),'val':round(total*.20)}
    desired['test']=total-desired['train']-desired['val']
    assigned=collections.Counter()
    for _,members in unassigned:
        split=max(('train','val','test'),key=lambda k:(desired[k]-assigned[k], {'train':2,'val':1,'test':0}[k]))
        for r in members:r['assigned_split']=split
        assigned[split]+=len(members)
    return groups

def audit_modules():
    result={}
    for name in ('PIL','numpy','scipy','matplotlib','pandas','pytest','pqcrypto','cryptography'):
        package={'PIL':'Pillow'}.get(name,name)
        entry={'installed':False,'version':None,'error':None}
        try:
            spec=importlib.util.find_spec(name)
            entry['installed']=spec is not None
            if entry['installed']:
                try:entry['version']=importlib.metadata.version(package)
                except importlib.metadata.PackageNotFoundError:entry['version']='unknown'
        except Exception as exc:entry['error']=str(exc)
        result[name]=entry
    # Non-invasive interface check only. Do not claim signature verification.
    ml={'module_importable':False,'generate_keypair':False,'sign':False,'verify':False,
        'sign_verify_executed':False,'status':'NOT_EXECUTED'}
    try:
        m=importlib.import_module('pqcrypto.sign.ml_dsa_65')
        ml.update(module_importable=True,generate_keypair=callable(getattr(m,'generate_keypair',None)),
                  sign=callable(getattr(m,'sign',None)),verify=callable(getattr(m,'verify',None)))
        ml['status']='API_PRESENT_NOT_EXECUTED' if all(ml[k] for k in ('generate_keypair','sign','verify')) else 'API_INCOMPLETE'
    except Exception as exc:ml['error']=f'{type(exc).__name__}: {exc}'
    result['ml_dsa_65']=ml
    return result

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--root',type=Path,default=None,help='Experiments project root (auto-detect from script when omitted)')
    parser.add_argument('--output',type=Path,default=None,help='Output folder; default Results/F8_01')
    parser.add_argument('--side',type=int,default=128)
    parser.add_argument('--seed',type=int,default=20261114)
    parser.add_argument('--image-limit',type=int,default=0,help='0 means all real images; synthetic always included')
    parser.add_argument('--strict-data',action='store_true',help='Fail if dataset counts, source paths, or image checks fail')
    parser.add_argument('--no-hash',action='store_true',help='Skip source-file SHA-256; normalized hashes still computed')
    parser.add_argument('--write-synthetic',action='store_true',help='Export deterministic synthetic PNGs into output')
    args=parser.parse_args(argv)
    if args.side<16 or args.image_limit<0:parser.error('--side must be >=16 and --image-limit >=0')
    script_root=Path(__file__).resolve().parent.parent
    root=(args.root or (script_root if (script_root/'Data').is_dir() else DEFAULT_ROOT)).resolve()
    output=(args.output or root/'Results'/'F8_01').resolve()
    if not root.is_dir():parser.error(f'Project root not found: {root}')
    if not (root/'Data').is_dir():parser.error(f'Data directory missing: {root / "Data"}')
    if output==root or output==root/'Data':parser.error('Refusing to overwrite project root or Data')
    started=time.perf_counter();errors=[]
    try:
        from PIL import Image
        pillow_version=importlib.metadata.version('Pillow')
    except ImportError:
        parser.error('Pillow is required for image validation: python -m pip install Pillow')
    inputs,missing=dataset_files(root);errors.extend(missing)
    if args.image_limit:inputs=inputs[:args.image_limit]
    records=[]
    for i,(p,source,split) in enumerate(inputs,1):
        rec=validate_image(p,root,source,split,Image,args.side,not args.no_hash)
        records.append(rec)
        if rec['status']!='OK':errors.append(f'{rec["relative_path"]}: {rec["error"]}')
        if i%100==0:print(f'Validated {i}/{len(inputs)} real images',flush=True)
    groups=group_partition(records,args.seed)
    synthetic=synthetic_images(args.side,Image)
    synth_records=[]
    for name,im in synthetic.items():
        raw=im.tobytes()
        synth_records.append({'relative_path':f'SYNTHETIC/{name}.png','source':'SYNTHETIC',
          'original_split':'diagnostic','assigned_split':'diagnostic','filename':f'{name}.png',
          'size_bytes':len(raw),'sha256':None,'image_mode':'L','width':args.side,'height':args.side,
          'status':'OK','error':'','normalized_sha256':digest_bytes(raw),
          'normalized_black_fraction':round(sum(v==0 for v in raw)/len(raw),8)})
    if args.write_synthetic:
        dest=output/'synthetic';dest.mkdir(parents=True,exist_ok=True)
        for name,im in synthetic.items():im.save(dest/f'{name}.png')
    all_records=records+synth_records
    counts=collections.Counter(r['source'] for r in records if r['status']=='OK')
    splits=collections.Counter(r['assigned_split'] for r in records if r['status']=='OK')
    duplicates=[]
    for digest,members in sorted(groups.items()):
        if len(members)>1:
            duplicates.append({'normalized_sha256':digest,'count':len(members),
               'paths':[r['relative_path'] for r in members],
               'original_splits':sorted(set(r['original_split'] for r in members)),
               'assigned_split':members[0]['assigned_split']})
    source_hash_groups=collections.defaultdict(list)
    for r in records:
        if r['sha256']:source_hash_groups[r['sha256']].append(r['relative_path'])
    exact_dups=[v for v in source_hash_groups.values() if len(v)>1]
    expected_ok=all(counts.get(k,0)==v for k,v in REAL_EXPECTED.items())
    valid=not errors and (expected_ok if args.image_limit==0 else True)
    environment={'generated_utc':utc_now(),'python':sys.version,'python_executable':sys.executable,
      'platform':platform.platform(),'machine':platform.machine(),'pillow_version':pillow_version,
      'packages':audit_modules()}
    config={'root':str(root),'output':str(output),'side':args.side,'seed':args.seed,
      'image_limit':args.image_limit,'strict_data':args.strict_data,'hash_source_files':not args.no_hash,
      'write_synthetic':args.write_synthetic,'normalization':'Pillow L + bicubic resize + threshold 128',
      'split_policy':'BSDS native split, normalized-duplicate groups promoted to test > val > train; USC-SIPI deterministic 60/20/20; synthetic diagnostic-only'}
    summary={'generated_utc':utc_now(),'real_images_found':len(records),
      'real_images_valid':sum(r['status']=='OK' for r in records),'synthetic_images':len(synth_records),
      'total_valid_images':sum(r['status']=='OK' for r in records)+len(synth_records),
      'by_source':dict(counts),'by_split':dict(splits),
      'normalized_duplicate_groups':len(duplicates),'source_byte_duplicate_groups':len(exact_dups),
      'errors':len(errors),'expected_full_benchmark_counts_met':expected_ok if not args.image_limit else None,
      'data_audit_passed':valid,'elapsed_seconds':round(time.perf_counter()-started,3),
      'security_claim':'NONE: dataset/environment validation only'}
    write_json(output/'configuration'/'run.json',config)
    write_json(output/'configuration'/'environment.json',environment)
    write_csv(output/'reports'/'dataset_manifest.csv',all_records,
      ['relative_path','source','original_split','assigned_split','filename','size_bytes','sha256',
       'image_mode','width','height','status','error','normalized_sha256','normalized_black_fraction'])
    write_json(output/'reports'/'splits.json',{'seed':args.seed,
      'train':[r['relative_path'] for r in records if r.get('assigned_split')=='train'],
      'val':[r['relative_path'] for r in records if r.get('assigned_split')=='val'],
      'test':[r['relative_path'] for r in records if r.get('assigned_split')=='test'],
      'diagnostic':[r['relative_path'] for r in synth_records]})
    write_json(output/'reports'/'duplicate_groups.json',{'normalized':duplicates,'exact_source':exact_dups})
    write_json(output/'reports'/'scan_errors.json',errors)
    write_json(output/'reports'/'summary.json',summary)
    write_json(output/'reports'/'verdict.json',{'dataset_environment': 'PASS' if valid else 'FAIL',
      'cryptographic_issuance':'NOT_TESTED','confidentiality':'NOT_TESTED',
      'optical_authentication':'NOT_TESTED','physical_validation':'NOT_PERFORMED',
      'human_validation':'NOT_PERFORMED'})
    (output/'README.txt').write_text('F8_01 dataset and environment audit.\n'+
       'This run does not establish confidentiality, authentication, physical or human security.\n'+
       'Use reports/dataset_manifest.csv and reports/splits.json in subsequent F8 programs.\n',encoding='utf-8')
    print(json.dumps({'output':str(output),**summary},indent=2))
    if args.strict_data and not valid:return 2
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except KeyboardInterrupt:print('Interrupted',file=sys.stderr);sys.exit(130)
    except Exception:traceback.print_exc();sys.exit(1)
