#!/usr/bin/env python3
"""EOW C13 physical pilot assistant: print, capture, annotate, record, evaluate.

Real-world printing, physical alignment and camera positioning require a person.
The program never fabricates physical observations or claims print success.

Install: python -m pip install numpy Pillow opencv-python
Optional Windows PDF printing: SumatraPDF.exe (https://www.sumatrapdfreader.org/).

Examples:
 python EOW_C13_Physical_Pilot_Assistant.py --root PILOT status
 python EOW_C13_Physical_Pilot_Assistant.py --root PILOT print --sample all
 python EOW_C13_Physical_Pilot_Assistant.py --root PILOT print --sample 0001 --execute --printer "My Printer"
 python EOW_C13_Physical_Pilot_Assistant.py --root PILOT capture --sample 0001 --repeat 1 --camera 0
 python EOW_C13_Physical_Pilot_Assistant.py --root PILOT annotate --sample 0001 --repeat 1
 python EOW_C13_Physical_Pilot_Assistant.py --root PILOT record --sample 0001
 python EOW_C13_Physical_Pilot_Assistant.py --root PILOT evaluate
"""
import argparse,csv,hashlib,json,os,shutil,subprocess,sys
from datetime import datetime
from pathlib import Path

COLUMNS=['sample_id','print_date','printer_model','film_type','print_setting','calibration_bar_mm','bar_scale_error_pct','alignment_time_sec','visual_reconstruction_yes_partial_no','lighting','camera_model','capture_file','repeat_capture_file','notes']

def load(root):
    p=root/'captures.json'
    if not p.exists():raise FileNotFoundError(f'Missing {p}; extract the pilot ZIP first')
    obj=json.loads(p.read_text(encoding='utf-8'))
    if obj.get('schema')!='EOW_C13_CAPTURE_V1':raise ValueError('Unexpected capture manifest schema')
    return obj

def write_json(path,obj):
    path.write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')

def choose(data,selector):
    records=data['records']
    if selector=='all':return records
    matches=[r for r in records if r['sample_id']==selector or r['sample_id'].startswith(selector+'_')]
    if len(matches)!=1:raise ValueError(f'Sample {selector!r} not uniquely found. Available: {[r["sample_id"] for r in records]}')
    return matches

def safe_path(root,rel):
    p=(root/rel).resolve()
    if not p.is_relative_to(root.resolve()):raise ValueError('Path outside pilot root')
    return p

def observations(root,data):
    p=root/'pilot_observations.csv'
    existing={}
    if p.exists():
        with p.open(newline='',encoding='utf-8-sig') as f:
            existing={r['sample_id']:r for r in csv.DictReader(f)}
    return {r['sample_id']:{k:existing.get(r['sample_id'],{}).get(k,'') for k in COLUMNS} for r in data['records']}

def save_observations(root,rows):
    with (root/'pilot_observations.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=COLUMNS);w.writeheader();w.writerows(rows.values())

def status(root,data,args):
    rows=observations(root,data)
    for r in data['records']:
        sid=r['sample_id'];o=rows[sid]
        print(f'{sid}: bar={o["calibration_bar_mm"] or "unmeasured"} mm; '
              f'capture={r.get("capture_path") or "none"}; corners={"yes" if r.get("corners_px") else "no"}; '
              f'visual={o["visual_reconstruction_yes_partial_no"] or "unrecorded"}')
    print('No physical action is inferred from files alone.')

def print_cmd(root,data,args):
    recs=choose(data,args.sample)
    jobs=[]
    for r in recs:
        for key in ('share_a_pdf','share_b_pdf'):
            path=safe_path(root,r[key]);
            if not path.exists():raise FileNotFoundError(path)
            jobs.append(path)
    print('PDFs for actual-size transparent-film printing:')
    for path in jobs:print(' ',path)
    print('MANDATORY: compatible transparent film; print at 100% / Actual Size; '
          'disable fit/shrink; verify 10 mm scale bar with a physical ruler. '
          'The script cannot verify printer scaling or physically align sheets.')
    if not args.execute:
        print('DRY RUN: no print jobs submitted. Add --execute to use SumatraPDF on Windows.')
        return
    if sys.platform!='win32':raise RuntimeError('Automated printing supported only on Windows with SumatraPDF')
    exe=args.sumatra or shutil.which('SumatraPDF.exe') or shutil.which('SumatraPDF')
    if not exe:raise RuntimeError('Install SumatraPDF or supply --sumatra path')
    for path in jobs:
        command=[str(exe),'-silent','-print-settings','noscale']
        command+=['-print-to',args.printer] if args.printer else ['-print-to-default']
        command.append(str(path))
        print('Submitting:',path.name)
        subprocess.run(command,check=True,timeout=90)
    print('Jobs submitted to print system; successful physical printing and 100% scale NOT verified.')

def cv2_module():
    try:import cv2;return cv2
    except ImportError as e:raise RuntimeError('Install OpenCV: python -m pip install opencv-python') from e

def capture(root,data,args):
    cv2=cv2_module();r=choose(data,args.sample)[0];sid=r['sample_id']
    camera=cv2.VideoCapture(args.camera,cv2.CAP_DSHOW if sys.platform=='win32' else cv2.CAP_ANY)
    if not camera.isOpened():raise RuntimeError('Camera unavailable; alternatively take a phone photo and use import-photo')
    camera.set(cv2.CAP_PROP_FRAME_WIDTH,1920);camera.set(cv2.CAP_PROP_FRAME_HEIGHT,1080)
    print('Position camera perpendicular to the PHYSICAL stacked transparencies with even lighting.')
    print('Ensure all four registration crosses visible. SPACE: save photo; ESC: cancel.')
    folder=root/'captures';folder.mkdir(exist_ok=True)
    dest=folder/f'{sid}_overlay_r{args.repeat}.png'
    try:
        while True:
            ok,frame=camera.read()
            if not ok:raise RuntimeError('Camera frame unavailable')
            cv2.imshow('EOW C13 REAL physical overlay — SPACE capture / ESC cancel',frame)
            key=cv2.waitKey(30)&255
            if key==27:print('Capture cancelled');return
            if key==32:
                if not cv2.imwrite(str(dest),frame):raise RuntimeError('Unable to write capture')
                break
    finally:
        camera.release();cv2.destroyAllWindows()
    register_capture(root,data,r,dest,args.repeat)
    print('Saved REAL camera image:',dest)
    print('Next: annotate --sample',args.sample,'--repeat',args.repeat)

def register_capture(root,data,r,path,repeat):
    if repeat==1:
        r['capture_path']=path.relative_to(root).as_posix()
        r['corners_px']=None
        r['capture_timestamp']=datetime.now().astimezone().isoformat()
    else:
        repeats=r.setdefault('repeat_captures',[])
        repeats[:]=[v for v in repeats if v['repeat']!=repeat]
        repeats.append({'repeat':repeat,'capture_path':path.relative_to(root).as_posix(),
                        'corners_px':None,'capture_timestamp':datetime.now().astimezone().isoformat()})
    write_json(root/'captures.json',data)
    rows=observations(root,data);field='capture_file' if repeat==1 else 'repeat_capture_file'
    rows[r['sample_id']][field]=path.relative_to(root).as_posix()
    save_observations(root,rows)

def import_photo(root,data,args):
    r=choose(data,args.sample)[0];source=Path(args.file).expanduser().resolve()
    if not source.is_file():raise FileNotFoundError(source)
    if source.suffix.lower() not in ('.jpg','.jpeg','.png','.tif','.tiff','.bmp','.webp'):
        raise ValueError('Unsupported image extension')
    folder=root/'captures';folder.mkdir(exist_ok=True)
    dest=folder/f'{r["sample_id"]}_overlay_r{args.repeat}{source.suffix.lower()}'
    if source!=dest.resolve():shutil.copy2(source,dest)
    register_capture(root,data,r,dest,args.repeat)
    print('Imported photo (user-supplied, physical origin not independently verified):',dest)

def get_capture(r,repeat):
    if repeat==1:return r
    matches=[x for x in r.get('repeat_captures',[]) if x['repeat']==repeat]
    if len(matches)!=1:raise ValueError('Repeat photo missing')
    return matches[0]

def annotate(root,data,args):
    cv2=cv2_module();r=choose(data,args.sample)[0];entry=get_capture(r,args.repeat)
    if not entry.get('capture_path'):raise ValueError('Capture not registered; use capture or import-photo')
    path=safe_path(root,entry['capture_path'])
    frame=cv2.imread(str(path))
    if frame is None:raise ValueError('Could not decode photo')
    points=[];win='Click marker CENTERS TL, TR, BR, BL | R reset | ENTER save | ESC cancel'
    def click(event,x,y,flags,param):
        if event==cv2.EVENT_LBUTTONDOWN and len(points)<4:points.append([int(x),int(y)])
    cv2.namedWindow(win,cv2.WINDOW_NORMAL);cv2.setMouseCallback(win,click)
    try:
        while True:
            view=frame.copy()
            for i,(x,y) in enumerate(points):
                cv2.circle(view,(x,y),7,(0,0,255),-1)
                cv2.putText(view,['TL','TR','BR','BL'][i],(x+10,y-10),cv2.FONT_HERSHEY_SIMPLEX,.9,(0,0,255),2)
            cv2.imshow(win,view)
            k=cv2.waitKey(30)&255
            if k==27:print('Annotation cancelled');return
            if k in (ord('r'),ord('R')):points.clear()
            if k in (13,10) and len(points)==4:break
    finally:cv2.destroyAllWindows()
    # Reject degenerate quadrilaterals and unexpected order.
    cross=[]
    for i in range(4):
        x1,y1=points[i];x2,y2=points[(i+1)%4];x3,y3=points[(i+2)%4]
        cross.append((x2-x1)*(y3-y2)-(y2-y1)*(x3-x2))
    if any(abs(x)<10 for x in cross) or not (all(x>0 for x in cross) or all(x<0 for x in cross)):
        raise ValueError('Invalid/degenerate marker order; expected TL, TR, BR, BL')
    entry['corners_px']=points
    write_json(root/'captures.json',data)
    print('Saved corners:',points)

def ask(prompt,default=''):
    s=input(f'{prompt}'+(f' [{default}]' if default else '')+': ').strip()
    return s or default

def record(root,data,args):
    r=choose(data,args.sample)[0];sid=r['sample_id']
    rows=observations(root,data);row=rows[sid]
    print('Record ACTUAL observations; leave unknown values blank. No values are inferred.')
    for key,prompt in [('print_date','Print date (YYYY-MM-DD)'),('printer_model','Printer model'),
                       ('film_type','Transparent film/media type'),('print_setting','Print settings (e.g. actual size)'),
                       ('calibration_bar_mm','Physically measured 10 mm calibration bar length (mm)'),
                       ('alignment_time_sec','Physical alignment time (seconds)'),
                       ('visual_reconstruction_yes_partial_no','Unaided visual reconstruction (yes/partial/no)'),
                       ('lighting','Lighting setup'),('camera_model','Camera model'),('notes','Notes')]:
        value=ask(prompt,row.get(key,''))
        if key in ('calibration_bar_mm','alignment_time_sec') and value:
            try:
                v=float(value)
                if not (0<v<10000):raise ValueError()
            except ValueError:raise ValueError(f'Invalid positive numeric value for {key}')
        if key=='visual_reconstruction_yes_partial_no' and value and value.lower() not in ('yes','partial','no'):
            raise ValueError('Visual reconstruction must be yes, partial or no')
        row[key]=value
    if row['calibration_bar_mm']:
        row['bar_scale_error_pct']=f'{(float(row["calibration_bar_mm"])-10)/10*100:.4f}'
    else:row['bar_scale_error_pct']=''
    r.update({'printer_model':row['printer_model'] or None,'print_media':row['film_type'] or None,
              'print_scale_percent':float(row['calibration_bar_mm'])/10*100 if row['calibration_bar_mm'] else None,
              'overlay_method':'manual registration using printed cross centers',
              'lighting':row['lighting'] or None,'camera_model':row['camera_model'] or None})
    save_observations(root,rows);write_json(root/'captures.json',data)
    print('Recorded:',sid,'calibration error % =',row['bar_scale_error_pct'] or 'not measured')

def evaluate(root,data,args):
    cv2=cv2_module();import numpy as np
    out=root/'reports';out.mkdir(exist_ok=True)
    rows=[];errors=[]
    for r in data['records']:
        entries=[(1,r)]+[(v['repeat'],v) for v in r.get('repeat_captures',[])]
        for repeat,e in entries:
            if not e.get('capture_path') or not e.get('corners_px'):continue
            try:
                path=safe_path(root,e['capture_path'])
                ideal_path=safe_path(root,r['ideal_overlay_png'])
                if path.resolve()==ideal_path.resolve():raise ValueError('Ideal overlay is not a physical capture')
                photo=cv2.imread(str(path));reference=cv2.imread(str(ideal_path),cv2.IMREAD_GRAYSCALE)
                if photo is None or reference is None:raise ValueError('Capture or reference cannot be read')
                pts=np.asarray(e['corners_px'],dtype=np.float32)
                target=np.asarray(r['png_layout']['registration_corners_px'],dtype=np.float32)
                if pts.shape!=(4,2):raise ValueError('Expected four corners')
                h,w=reference.shape
                H=cv2.getPerspectiveTransform(pts,target)
                rect=cv2.warpPerspective(cv2.cvtColor(photo,cv2.COLOR_BGR2GRAY),H,(w,h),
                                         flags=cv2.INTER_LINEAR,borderValue=255)
                x0,y0,x1,y1=map(int,r['png_layout']['payload_box_px'])
                actual=rect[y0:y1,x0:x1];expected=reference[y0:y1,x0:x1]<128
                metrics={f'pixel_error_t{t}':float(np.mean((actual<t)!=expected)) for t in (96,128,160)}
                white=actual[~expected];black=actual[expected]
                contrast=float(np.mean(white)-np.mean(black)) if len(white) and len(black) else None
                rect_path=root/'rectified'/f'{r["sample_id"]}_r{repeat}.png';rect_path.parent.mkdir(exist_ok=True)
                cv2.imwrite(str(rect_path),rect)
                rows.append({'sample_id':r['sample_id'],'repeat':repeat,'capture_file':e['capture_path'],
                             'capture_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                             'payload_pixels':int(expected.size),'white_minus_black_intensity':contrast,
                             **metrics})
            except Exception as exc:errors.append({'sample_id':r['sample_id'],'repeat':repeat,'error':str(exc)})
    fields=['sample_id','repeat','capture_file','capture_sha256','payload_pixels',
            'pixel_error_t96','pixel_error_t128','pixel_error_t160','white_minus_black_intensity']
    with (out/'physical_pilot_measurements.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
    write_json(out/'physical_pilot_evaluation.json',{
        'captures_evaluated':len(rows),'errors':errors,'measured_results':rows,
        'note':'Physical provenance depends on operator-supplied photos. These are reference-based software image-quality measurements, not human-only authentication.',
        'research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION'})
    print('Measured real/user-supplied captures:',len(rows),'errors:',len(errors))
    for row in rows:print(row['sample_id'],'repeat',row['repeat'],'error t128',f'{row["pixel_error_t128"]:.4f}')
    if not rows:print('No capture with complete coordinates; no physical measurements claimed.')

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--root',type=Path,required=True,help='Extracted EOW_C13_Three_Sample_Physical_Pilot folder')
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('status')
    x=sub.add_parser('print');x.add_argument('--sample',default='all');x.add_argument('--execute',action='store_true');x.add_argument('--printer');x.add_argument('--sumatra')
    x=sub.add_parser('capture');x.add_argument('--sample',required=True);x.add_argument('--repeat',type=int,default=1);x.add_argument('--camera',type=int,default=0)
    x=sub.add_parser('import-photo');x.add_argument('--sample',required=True);x.add_argument('--repeat',type=int,default=1);x.add_argument('--file',required=True)
    x=sub.add_parser('annotate');x.add_argument('--sample',required=True);x.add_argument('--repeat',type=int,default=1)
    x=sub.add_parser('record');x.add_argument('--sample',required=True)
    sub.add_parser('evaluate')
    a=p.parse_args();root=a.root.expanduser().resolve();data=load(root)
    if a.command=='status':status(root,data,a)
    elif a.command=='print':print_cmd(root,data,a)
    elif a.command=='capture':capture(root,data,a)
    elif a.command=='import-photo':import_photo(root,data,a)
    elif a.command=='annotate':annotate(root,data,a)
    elif a.command=='record':record(root,data,a)
    elif a.command=='evaluate':evaluate(root,data,a)
if __name__=='__main__':
    try:main()
    except (OSError,ValueError,RuntimeError,subprocess.CalledProcessError) as e:
        print('ERROR:',e,file=sys.stderr);sys.exit(2)
