#!/usr/bin/env python3
"""EOW_C13: reproducible <=5% source-pixel changes, regenerated consistent VSS artifacts.

SIMULATION ONLY. This does not modify existing files or fabricate physical captures.
Input can be a recursive source-image folder or the prior C13 ideal-reference folder.
Related files are REGENERATED, never independently perturbed or silently falsified.
"""
import argparse,csv,hashlib,json,math,random,sys,io,collections
from pathlib import Path
import numpy as np
from PIL import Image,ImageOps,ImageDraw
try:
 from reportlab.pdfgen import canvas
 from reportlab.lib.units import mm
except ImportError:
 canvas=None
EXT={'.jpg','.jpeg','.png','.bmp','.tif','.tiff','.webp','.gif','.ico','.icns','.ppm','.pgm','.pbm','.pnm','.tga','.dds','.psd','.jp2','.j2k','.pcx','.sgi','.eps','.apng','.heic','.heif','.avif','.qoi','.exr','.hdr','.svg','.dcm','.dicom'}
# Pillow is format-driven; these extensions are hints only. Unsupported formats are
# recorded explicitly. Optional: pillow-heif, cairosvg, pydicom, imagecodecs.
try:
 import pillow_heif
 pillow_heif.register_heif_opener()
except ImportError:pass
DERIVED={'share_A_preview.png','share_B_preview.png','ideal_aligned_overlay_preview.png','ideal_decoded_secret.png','reference_binary_secret.png','comparison_guide.png'}
def is_derived(p):
    n=p.name.lower()
    return n in {x.lower() for x in DERIVED}|{'source_original_resized.png',
        'share_a_print_100pct.pdf','share_b_print_100pct.pdf'} or n.startswith('ideal_') or n.startswith('share_')

def inspect_image(p):
    """Inspect contents, not just filename extension; no destructive conversion."""
    if p.suffix.lower()=='.svg':
        try:
            import cairosvg
            return Image.open(io.BytesIO(cairosvg.svg2png(url=str(p))))
        except ImportError:raise RuntimeError('SVG requires pip install cairosvg')
    if p.suffix.lower() in {'.dcm','.dicom'}:
        try:import pydicom
        except ImportError:raise RuntimeError('DICOM requires pip install pydicom')
        ds=pydicom.dcmread(str(p));a=np.asarray(ds.pixel_array,dtype=np.float32)
        if a.ndim>2:a=a[0]  # first frame only
        a=a-np.min(a);mx=float(np.max(a))
        return Image.fromarray(np.uint8(255*a/mx) if mx>0 else np.zeros(a.shape,dtype=np.uint8))
    with Image.open(p) as im:
        im.seek(0)  # first frame for animated/multipage images
        return ImageOps.exif_transpose(im).copy()

def discover(root,include_derived=False):
    """Recursively inspect every file; prefer original sources in C13 sample folders."""
    found=[];fail=[];inventory=[]
    for p in sorted(root.rglob('*'),key=lambda x:x.as_posix().casefold()):
        if not p.is_file():continue
        rel=p.relative_to(root)
        if any(part.startswith('.') for part in rel.parts):continue
        if not include_derived and is_derived(p) and p.name!='source_resized_color.png':
            inventory.append({'path':rel.as_posix(),'classification':'related_derived_file','format':'','size':'','reason':'regenerated_from_source'})
            continue
        # Skip PDF and other arbitrary docs: images can be embedded in documents,
        # but this program never silently rasterizes a multipage research PDF.
        if p.suffix.lower() in {'.pdf','.docx','.pptx','.xlsx','.zip','.json','.csv','.md','.txt'}:
            inventory.append({'path':rel.as_posix(),'classification':'non_image_or_document','format':'','size':'','reason':'not_an_independent_raster_image'})
            continue
        try:
            im=inspect_image(p)
            fmt=im.format or p.suffix.lower().lstrip('.') or 'unknown'
            wh=f'{im.width}x{im.height}'
            im.close()
            # For C13 prior outputs, only source_resized_color.png is the input,
            # not both source variants or derived references.
            if p.name=='source_original_resized.png' and (p.parent/'source_resized_color.png').exists():
                continue
            sid=p.stem+'_'+hashlib.sha256(rel.as_posix().encode()).hexdigest()[:8]
            found.append((sid,p))
            inventory.append({'path':rel.as_posix(),'classification':'processable_image','format':fmt,'size':wh,'reason':'first_frame'})
        except Exception as e:
            classification='unreadable_image' if p.suffix.lower() in EXT else 'non_image_or_unsupported'
            inventory.append({'path':rel.as_posix(),'classification':classification,'format':'','size':'','reason':str(e)[:180]})
            if classification=='unreadable_image':fail.append({'file':rel.as_posix(),'error':str(e)[:180]})
    return found,inventory,fail

def change_pixels(image,rng,rate):
    """Exactly ceil(rate*N) RGB pixel locations at most, guaranteed changed."""
    a=np.asarray(image.convert('RGB'),dtype=np.uint8).copy()
    h,w,_=a.shape;n=h*w
    k=min(n,math.floor(n*rate)) # <=5%, including tiny images
    if k==0:return image.convert('RGB'),0
    chosen=rng.choice(n,k,replace=False)
    flat=a.reshape(-1,3)
    # Minor local RGB jitter, but exactly k pixels change by >=1 intensity.
    offsets=rng.integers(-12,13,size=(k,3),dtype=np.int16)
    offsets[:,0]=np.where(offsets[:,0]==0,1,offsets[:,0])
    old=flat[chosen].astype(np.int16)
    changed=np.clip(old+offsets,0,255).astype(np.uint8)
    # Saturation corner case: force one channel to move one level.
    stuck=np.all(changed==flat[chosen],axis=1)
    changed[stuck,0]=np.where(flat[chosen[stuck],0]==255,254,flat[chosen[stuck],0]+1)
    flat[chosen]=changed
    return Image.fromarray(a,'RGB'),k

def encode(secret,rng):
    h,w=secret.shape
    bits=rng.integers(0,2,(h,w),dtype=np.uint8)
    yy,xx=np.indices((h,w))
    a=np.zeros((h,w,2),dtype=bool);b=np.zeros_like(a)
    a[yy,xx,bits]=True
    b[yy,xx,bits^secret.astype(np.uint8)]=True
    return a.reshape(h,w*2),b.reshape(h,w*2)

def preview(bits,cell=8):
    h,w=bits.shape;pad=6*cell
    im=Image.new('RGB',(w*cell+2*pad,h*cell+2*pad),'white');d=ImageDraw.Draw(im)
    for y,x in zip(*np.nonzero(bits)):
        x0=pad+x*cell;y0=pad+y*cell
        d.rectangle((x0,y0,x0+cell-1,y0+cell-1),fill='black')
    # Marker centers exactly 3 subpixels outside payload, consistent with PDFs.
    for x in (pad-3*cell,pad+(w+3)*cell):
        for y in (pad-3*cell,pad+(h+3)*cell):
            d.line((x-2*cell,y,x+2*cell,y),fill='black',width=max(1,cell//5))
            d.line((x,y-2*cell,x,y+2*cell),fill='black',width=max(1,cell//5))
    return im

def pdf(path,bits,subpixel_mm):
    if canvas is None:raise RuntimeError('Install reportlab: python -m pip install reportlab')
    h,w=bits.shape
    if w*subpixel_mm+24>210 or h*subpixel_mm+24>297:
        raise ValueError('Image exceeds A4; decrease --max-side or --subpixel-mm')
    c=canvas.Canvas(str(path),pagesize=(210*mm,297*mm))
    c.setTitle('EOW_C13 simulated share - print at 100 percent')
    x0=(210-w*subpixel_mm)/2;y0=(297-h*subpixel_mm)/2
    c.setFillColorRGB(0,0,0)
    for y,x in zip(*np.nonzero(bits)):
        c.rect((x0+x*subpixel_mm)*mm,(y0+(h-1-y)*subpixel_mm)*mm,subpixel_mm*mm,subpixel_mm*mm,fill=1,stroke=0)
    c.setLineWidth(.3*mm)
    for x in (x0-3*subpixel_mm,x0+(w+3)*subpixel_mm):
        for y in (y0-3*subpixel_mm,y0+(h+3)*subpixel_mm):
            c.line((x-2*subpixel_mm)*mm,y*mm,(x+2*subpixel_mm)*mm,y*mm)
            c.line(x*mm,(y-2*subpixel_mm)*mm,x*mm,(y+2*subpixel_mm)*mm)
    bx=x0;by=y0-7
    c.line(bx*mm,by*mm,(bx+10)*mm,by*mm)
    for x in (bx,bx+10):c.line(x*mm,(by-1)*mm,x*mm,(by+1)*mm)
    c.setFont('Helvetica',8);c.drawString(bx*mm,(by-3)*mm,'10 mm')
    c.save()

def guide(color,reference,decoded):
    # comparison panel with explicit simulation labeling in filename/README.
    scale=4
    imgs=[color.resize((color.width*scale,color.height*scale)),
          reference.convert('RGB').resize((reference.width*scale,reference.height*scale),Image.Resampling.NEAREST),
          decoded.convert('RGB').resize((decoded.width*scale,decoded.height*scale),Image.Resampling.NEAREST)]
    height=max(i.height for i in imgs);width=sum(i.width for i in imgs)+24
    out=Image.new('RGB',(width,height+32),'white');d=ImageDraw.Draw(out)
    x=0
    for im,label in zip(imgs,('Perturbed source','Binary reference','Ideal decoded')):
        out.paste(im,(x,32));d.text((x+2,8),label,fill='black');x+=im.width+12
    return out

def run(args):
    root=args.input.resolve();out=args.output.resolve()
    if not root.is_dir():raise ValueError('Input directory not found')
    if out==root or root in out.parents:raise ValueError('Output must be outside input tree to avoid recursive ingestion')
    if not 0<=args.max_distortion<=.05:raise ValueError('--max-distortion must be between 0 and 0.05')
    if args.max_side<1 or args.subpixel_mm<=0:raise ValueError('Invalid dimensions')
    sources,inventory,discovery_fail=discover(root,args.include_derived)
    if args.limit:sources=sources[:args.limit]
    if not sources:raise ValueError('No eligible source images found')
    out.mkdir(parents=True,exist_ok=True)
    records=[];fail=[];metrics=[]
    with (out/'input_inventory.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['path','classification','format','size','reason']);w.writeheader();w.writerows(inventory)
    tree=collections.Counter(row['classification'] for row in inventory)
    (out/'input_structure.json').write_text(json.dumps({'root':str(root),'files_inspected':len(inventory),
        'classification_counts':dict(tree),'processable_images':len(sources),
        'source_directories':sorted({str(p.parent.relative_to(root)) for _,p in sources}),
        'discovery_warnings':discovery_fail},indent=2)+'\n',encoding='utf-8')
    for sid,p in sources:
        try:
            data=p.read_bytes();original_hash=hashlib.sha256(data).hexdigest()
            with inspect_image(p) as src:base=src.convert('RGB')
            base.thumbnail((args.max_side,args.max_side),Image.Resampling.LANCZOS)
            seed=int.from_bytes(hashlib.sha256(f'{args.seed}|{p.relative_to(root).as_posix()}'.encode()).digest()[:8],'big')
            rng=np.random.default_rng(seed)
            rate=float(rng.uniform(0,args.max_distortion)) if args.random_rate else args.max_distortion
            perturbed,k=change_pixels(base,rng,rate)
            arr0=np.asarray(base);arr1=np.asarray(perturbed)
            count=int(np.count_nonzero(np.any(arr0!=arr1,axis=2)))
            assert count==k and count/base.width/base.height<=.05+1e-12
            secret=np.asarray(perturbed.convert('L'))<128
            a,b=encode(secret,rng)
            decoded=(a|b).reshape(secret.shape[0],secret.shape[1],2).all(axis=2)
            assert np.array_equal(decoded,secret)
            # Mirror input subdirectories within samples; preserve traceable identity.
            folder=out/'samples'/p.relative_to(root).parent/sid
            folder.mkdir(parents=True,exist_ok=True)
            base.save(folder/'source_original_resized.png')
            perturbed.save(folder/'source_resized_color.png')
            Image.fromarray(np.uint8(secret)*0+np.uint8(~secret)*255,'L').save(folder/'reference_binary_secret.png')
            Image.fromarray(np.uint8(~decoded)*255,'L').save(folder/'ideal_decoded_secret.png')
            preview(a).save(folder/'share_A_preview.png');preview(b).save(folder/'share_B_preview.png')
            preview(a|b).save(folder/'ideal_aligned_overlay_preview.png')
            guide(perturbed,Image.fromarray(np.uint8(~secret)*255,'L'),Image.fromarray(np.uint8(~decoded)*255,'L')).save(folder/'comparison_guide.png')
            pdf(folder/'share_A_PRINT_100pct.pdf',a,args.subpixel_mm)
            pdf(folder/'share_B_PRINT_100pct.pdf',b,args.subpixel_mm)
            metrics.append({'sample':sid,'source_relative_path':p.relative_to(root).as_posix(),
              'source_sha256':original_hash,'output_relative_folder':folder.relative_to(out).as_posix(),'binary_width':secret.shape[1],'binary_height':secret.shape[0],
              'source_pixel_count':base.width*base.height,'distorted_pixel_count':count,
              'distortion_fraction':count/(base.width*base.height),
              'binary_secret_changed_pixels':int(np.count_nonzero((np.asarray(base.convert('L'))<128)!=secret)),
              'ideal_reconstruction_pixel_errors':0,'ideal_reconstruction_agreement':1.0,
              'physical_captures':0,'experiment_type':'SIMULATED_MINOR_SOURCE_DISTORTION'})
            records.append({'sample_id':sid,'source':p.relative_to(root).as_posix(),
              'source_sha256':original_hash,'share_A_pdf':(folder/'share_A_PRINT_100pct.pdf').relative_to(out).as_posix(),
              'share_B_pdf':(folder/'share_B_PRINT_100pct.pdf').relative_to(out).as_posix(),
              'reference':(folder/'ideal_aligned_overlay_preview.png').relative_to(out).as_posix(),
              'capture_path':None,'corners_px':None,'capture_status':'NOT_CAPTURED'})
        except Exception as e:fail.append({'sample':sid,'source':str(p),'error':f'{type(e).__name__}: {e}'})
    fields=['sample','source_relative_path','source_sha256','output_relative_folder','binary_width','binary_height',
            'source_pixel_count','distorted_pixel_count','distortion_fraction',
            'binary_secret_changed_pixels','ideal_reconstruction_pixel_errors',
            'ideal_reconstruction_agreement','physical_captures','experiment_type']
    with (out/'ideal_metrics.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(metrics)
    with (out/'failed_inputs.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['sample','source','error']);w.writeheader();w.writerows(fail)
    (out/'captures_TEMPLATE.json').write_text(json.dumps({'schema':'EOW_C13_MINOR_DISTORTION_SIMULATION_V1','records':records},indent=2)+'\n',encoding='utf-8')
    summary={'input':str(root),'output':str(out),'discovered':len(sources),'completed':len(metrics),
      'failed':len(fail),'inspected_files':len(inventory),'source_directories':len({str(p.parent.relative_to(root)) for _,p in sources}),'discovery_warnings':len(discovery_fail),'seed':args.seed,'max_distortion_fraction':args.max_distortion,
      'rate_selection':'uniform_random_0_to_max' if args.random_rate else 'fixed_max',
      'all_distortion_fractions_at_most_5_percent':all(r['distortion_fraction']<=.05 for r in metrics),
      'physical_captures':0,'research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    (out/'README.md').write_text('''# EOW_C13 — Simulated minor source distortion reference

**SIMULATION ONLY. No physical print, overlay photograph, or human trial was performed.**

This package mirrors the input hierarchy within `samples/<relative/subfolder>/<ID>/` contains two A4
print PDFs, A/B previews, ideal overlay, binary secret, decoded secret, resized
color source, and comparison guide. `source_original_resized.png` additionally
preserves the pre-distortion baseline. `ideal_metrics.csv` and
`captures_TEMPLATE.json` are regenerated consistently.

Only the resized source color image is randomly perturbed, at no more than 5% of
pixel locations. The color adjustment per selected pixel is at most 12 levels
per channel. A/B shares, ideal overlay, reference, PDFs, and metrics are
**regenerated from the same perturbed image**, not corrupted independently.
A single image pixel may change without changing the binary secret; this is
reported separately. The 0% ideal reconstruction error is a mathematical
property of digital OR-VSS with perfect alignment, not measured robustness.

The original input folder is not modified. PDFs are for future real printing at
100% actual size. Captures are blank until real photographs are collected.

Reference: Naor and Shamir, Visual Cryptography, https://doi.org/10.1007/BFb0053419
''',encoding='utf-8')
    print(json.dumps(summary,indent=2))
    return 0 if metrics and not fail else 2

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',type=Path,required=True,help='Recursive source-image folder OR extracted prior C13 ideal-reference folder')
    ap.add_argument('--output',type=Path,required=True,help='New output folder OUTSIDE the input folder')
    ap.add_argument('--max-distortion',type=float,default=.05,help='Maximum fraction of altered pixel locations, 0..0.05')
    ap.add_argument('--random-rate',action='store_true',help='Randomize fraction independently per image in [0,max-distortion]')
    ap.add_argument('--max-side',type=int,default=64)
    ap.add_argument('--subpixel-mm',type=float,default=1.)
    ap.add_argument('--limit',type=int,default=0,help='0 = all images')
    ap.add_argument('--seed',type=int,default=20261116)
    ap.add_argument('--include-derived',action='store_true',help='Also treat share/overlay previews as independent sources (usually not recommended)')
    a=ap.parse_args()
    try:return run(a)
    except (ValueError,RuntimeError) as e:ap.error(str(e))
if __name__=='__main__':sys.exit(main())
