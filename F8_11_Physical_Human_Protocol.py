#!/usr/bin/env python3
"""F8_11: preregistrable physical human-overlay feasibility protocol.

This tool PREPARES physical stimuli, randomization, printable transparency artwork,
blinded response sheets and an analysis pipeline. It does NOT perform physical
experiments, generate human decisions, or certify issuer authenticity.

Python >=3.10. Dependencies: numpy, pillow. Optional: scipy for statistics.

Examples:
 python F8_11_Physical_Human_Protocol.py prepare --root "D:\\48\\481\\New Papers\\Nature_Idea\\Experiments" --strict-data --images 12 --trials-per-condition 2 --seed 20261114
 python F8_11_Physical_Human_Protocol.py analyze --root "D:\\48\\481\\New Papers\\Nature_Idea\\Experiments" --responses "D:\\responses.csv"
 python F8_11_Physical_Human_Protocol.py self-test

Important: never give participants the private answer key. Obtain applicable
ethics approval and consent before recruiting participants or collecting data.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, math, random, statistics, sys
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
from PIL import Image, ImageDraw

DEFAULT_ROOT=Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')
CONDITIONS=('aligned','shift_1mm','shift_2mm','illumination_low','fabrication_defect')
ATTACKS=('legitimate','single_subpixel','content_flip','known_content_reissue','exact_copy')
RESPONSE_FIELDS=('participant_id','trial_id','decision','decision_seconds','confidence_1_to_5','notes')
KEY_FIELDS=('trial_id','stimulus_id','image_id','split','condition','presentation','content_changed','share_changed','replay','attack_applicable','reference_policy','pairing_id')

def write_json(path,obj):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(obj,indent=2,ensure_ascii=False,sort_keys=True)+'\n',encoding='utf-8')

def write_csv(path,fields,rows):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)

def read_csv(path):
 with path.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

def sha256(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()

def wilson(k,n):
 if not n:return [None,None]
 z=1.959963984540054;p=k/n;den=1+z*z/n
 mid=(p+z*z/(2*n))/den
 half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
 return [round(max(0,mid-half),6),round(min(1,mid+half),6)]

def ns(secret,rng):
 r=rng.integers(0,2,secret.shape,dtype=np.uint8)
 a=np.stack((r,1-r),axis=-1).astype(np.uint8)
 b=np.stack((np.where(secret==0,r,1-r),np.where(secret==0,1-r,r)),axis=-1).astype(np.uint8)
 return a,b

def decode(a,b):
 o=np.bitwise_or(a,b)
 return np.bitwise_and(o[...,0],o[...,1]).astype(np.uint8)

def load_manifest(root,strict):
 manifest=root/'Results'/'F8_01'/'reports'/'dataset_manifest.csv'
 if not manifest.is_file():raise FileNotFoundError('Missing F8_01 dataset manifest: '+str(manifest))
 rows=read_csv(manifest);items=[];errors=[]
 for row in rows:
  if row.get('status')!='OK':continue
  rel=row['relative_path'].replace('\\','/');src=row.get('source','')
  path=(root/'Results'/'F8_01'/'synthetic'/Path(rel).name) if src=='SYNTHETIC' else root/Path(rel)
  if not path.is_file():errors.append('missing: '+str(path));continue
  if strict and src!='SYNTHETIC' and row.get('sha256') and sha256(path)!=row['sha256']:
   errors.append('sha256 mismatch: '+str(path));continue
  split=row.get('assigned_split','unknown')
  items.append({'id':rel,'path':path,'source':src,'split':split})
 if strict and errors:raise ValueError('Dataset integrity failures: '+str(errors[:10]))
 if not items:raise ValueError('No available F8_01 images')
 return items,errors

def load_binary(path,side):
 with Image.open(path) as im:
  a=np.asarray(im.convert('L').resize((side,side),Image.Resampling.BICUBIC),dtype=np.uint8)
 return (a<128).astype(np.uint8)

def altered_pair(kind,secret,a,b,rng):
 aa=a.copy();bb=b.copy()
 if kind=='single_subpixel':
  y=int(rng.integers(secret.shape[0]));x=int(rng.integers(secret.shape[1]));k=int(rng.integers(2));aa[y,x,k]^=1
 elif kind=='content_flip':
  y=int(rng.integers(secret.shape[0]));x=int(rng.integers(secret.shape[1]));s=secret[y:y+1,x:x+1]^1
  ca,cb=ns(s,rng);aa[y,x]=ca[0,0];bb[y,x]=cb[0,0]
 elif kind=='known_content_reissue':aa,bb=ns(secret,rng)
 return aa,bb

def render_share(share,path,cell_px,quiet_px,registration=True):
 """Black=opaque, white=transparent in RGBA; print black on clear film.

 Pixel registration fiducials are OUTSIDE the share area and identical on both
 layers. The transparent PNG is artwork, not proof of physical print accuracy.
 """
 h,w,k=share.shape
 if k!=2:raise ValueError('Expected 2 subpixels per secret pixel')
 width=w*2*cell_px+2*quiet_px;height=h*cell_px+2*quiet_px
 im=Image.new('RGBA',(width,height),(255,255,255,0));d=ImageDraw.Draw(im)
 for y in range(h):
  for x in range(w):
   for s in range(2):
    if share[y,x,s]:
     xx=quiet_px+(2*x+s)*cell_px;yy=quiet_px+y*cell_px
     d.rectangle((xx,yy,xx+cell_px-1,yy+cell_px-1),fill=(0,0,0,255))
 if registration:
  # Fiducials in margins; do not count as security features.
  m=max(2,cell_px//3)
  for xx,yy in ((quiet_px//2,quiet_px//2),(width-quiet_px//2,quiet_px//2),(quiet_px//2,height-quiet_px//2),(width-quiet_px//2,height-quiet_px//2)):
   d.line((xx-m,yy,xx+m,yy),fill=(0,0,0,255),width=1)
   d.line((xx,yy-m,xx,yy+m),fill=(0,0,0,255),width=1)
 path.parent.mkdir(parents=True,exist_ok=True);im.save(path)
 return width,height

def prepare(args):
 root=args.root;out=args.output or root/'Results'/'F8_11'
 if args.side<8 or args.images<1 or args.trials_per_condition<1 or args.cell_px<2:raise ValueError('Invalid preparation parameters')
 items,errors=load_manifest(root,args.strict_data)
 # Do not select held-out test images for an exploratory pilot.
 pool=[x for x in items if x['split'] in ('val','validation','diagnostic')]
 if not pool:raise ValueError('No validation/diagnostic images available for pilot')
 r=random.Random(args.seed);r.shuffle(pool);pool=pool[:args.images]
 if args.strict_data and len(pool)<args.images:raise ValueError('Insufficient pilot images')
 public=out/'public';private=out/'private_DO_NOT_SHARE_WITH_PARTICIPANTS'
 stim_dir=public/'stimuli';rows=[];key=[];stimuli=[];seedroot=args.seed
 for i,item in enumerate(pool):
  secret=load_binary(item['path'],args.side)
  for repetition in range(args.trials_per_condition):
   rng=np.random.default_rng(int.from_bytes(hashlib.sha256(f'{seedroot}|{item["id"]}|{repetition}'.encode()).digest()[:8],'big'))
   a,b=ns(secret,rng)
   for attack in ATTACKS:
    aa,bb=altered_pair(attack,secret,a,b,rng)
    changed_share=bool(np.any(aa!=a) or np.any(bb!=b))
    changed_content=bool(np.any(decode(aa,bb)!=decode(a,b)))
    for cond in CONDITIONS:
     sid=f'S{i:03d}_R{repetition:02d}_{attack}_{cond}'
     # All physical perturbations are PROCEDURAL instructions; the artwork
     # intentionally remains identical. Never misrepresent rendered PNG as
     # physical perturbation data.
     p1=stim_dir/sid/'share_A.png';p2=stim_dir/sid/'share_B.png'
     render_share(aa,p1,args.cell_px,args.quiet_px)
     render_share(bb,p2,args.cell_px,args.quiet_px)
     stimuli.append({'stimulus_id':sid,'share_A':str(p1.relative_to(public)),'share_B':str(p2.relative_to(public)),
                     'condition':cond,'handling_instruction':condition_instruction(cond)})
     key.append({'trial_id':'','stimulus_id':sid,'image_id':item['id'],'split':item['split'],
                 'condition':cond,'presentation':attack,'content_changed':int(changed_content),
                 'share_changed':int(changed_share),'replay':int(attack=='exact_copy'),
                 'attack_applicable':1,'reference_policy':'no independently trusted expected reference',
                 'pairing_id':f'{i}:{repetition}'})
 # A stimulus is one blinded trial; observers should not see filenames with attack labels.
 # Copy artwork to opaque IDs, then delete descriptive public stimulus paths.
 opaque=public/'blinded_artwork';opaque.mkdir(parents=True,exist_ok=True)
 schedule=[]
 import shutil
 for idx,(s,k) in enumerate(zip(stimuli,key)):
  tid=f'T{idx+1:06d}';src=public/s['share_A'];src2=public/s['share_B']
  dest=opaque/tid;dest.mkdir(parents=True,exist_ok=True)
  shutil.move(str(src),str(dest/'A.png'));shutil.move(str(src2),str(dest/'B.png'))
  k['trial_id']=tid
  schedule.append({'trial_id':tid,'share_A':f'blinded_artwork/{tid}/A.png','share_B':f'blinded_artwork/{tid}/B.png',
                   'condition':s['condition'],'handling_instruction':s['handling_instruction']})
 shutil.rmtree(stim_dir)
 # One fixed random order per participant, generated by a seed; no allocation
 # of participant identifiers or responses is fabricated.
 r.shuffle(schedule)
 write_csv(public/'master_blinded_schedule.csv',list(schedule[0]),schedule)
 write_csv(private/'answer_key.csv',KEY_FIELDS,key)
 write_csv(public/'response_template.csv',RESPONSE_FIELDS,[])
 write_json(public/'fabrication_specifications.json',{
  'status':'ARTWORK_ONLY_NOT_FABRICATED','share_type':'Classical 2-of-2 Naor-Shamir OR baseline',
  'cell_size_px':args.cell_px,'quiet_margin_px':args.quiet_px,'artwork_resolution_dpi':args.dpi,
  'nominal_subpixel_mm_at_dpi':round(25.4*args.cell_px/args.dpi,4),
  'substrate':'clear transparency film; specify batch and printer model in physical log',
  'printer_instruction':'print at 100% scale with no fit-to-page, scaling, antialiasing or interpolation; black opaque ink',
  'alignment':'overlay A and B using fiducials in margin; do not show the answer key',
  'quality_control':'measure physical pitch, transparency, contrast, registration error and printing defects using external measurements',
  'physical_conditions':{c:condition_instruction(c) for c in CONDITIONS},
  'warning':'Digital artwork and nominal DPI do not establish fabricated tolerances or human performance'})
 write_json(public/'protocol.json',{
  'title':'F8_11 preregistered pilot: unaided human classification of overlaid shares',
  'research_question':'Can human observers distinguish legitimate from unauthorized overlays under realistic alignment/fabrication error, without electronic verification or attacker-controlled references?',
  'status':'PLANNED_NOT_EXECUTED','human_data_collected':False,'ethics':'Approval and informed consent required before recruitment',
  'primary_outcomes':['FAR for unauthorized presentations','FRR for legitimate presentations'],
  'secondary_outcomes':['decision time','confidence','content-changing vs share-only distinction','replay acceptance'],
  'participant_instruction':'Overlay two clear physical films. Answer ACCEPT if you judge this to be an authorized issued presentation; otherwise REJECT. Choose UNSURE if you cannot decide. Do not use electronic verification.',
  'critical_validity_warning':'Without a trusted enrolled expected optical reference or a human-verifiable issuer-bound feature, observer judgments cannot establish issuer authenticity. Exact-copy/replay is observationally identical to the original.',
  'design':'within-observer repeated measures; random order; conceal labels and answer key; counterbalance using make-schedule',
  'blinding':'An independent custodian stores private key; no answer key in participant workspace',
  'handling':'Randomize trial order per participant; document illumination lux, observer distance, vision aids, substrate batch, print scale, alignment measurement, handling and training',
  'decision_policy':'UNSURE counted as reject for acceptance rate, and also reported separately; preregister before data collection',
  'provisional_targets':{'FRR_max':0.05,'content_change_FAR_max':0.05},
  'design_limitations':['No optical PQ issuer authentication constructed','Naor-Shamir OR artwork is a baseline, not the polarization physical candidate','Attack names are hidden from observers but content differences may not be perceptible','Exact copies are indistinguishable without an external freshness challenge','No fabricated or measured observations are generated']})
 write_json(private/'preparation_audit.json',{'seed':args.seed,'selected_images':len(pool),'trials_per_condition':args.trials_per_condition,
  'conditions':list(CONDITIONS),'attacks':list(ATTACKS),'trial_count':len(key),'dataset_errors':errors,
  'selected_splits':dict(Counter(x['split'] for x in pool)),
  'selected_ids':[x['id'] for x in pool],'human_data_collected':False})
 print(json.dumps({'status':'PREPARED_NOT_EXECUTED','output':str(out),'blinded_trials':len(key),'images':len(pool),
                   'public':str(public),'private_answer_key':str(private/'answer_key.csv')},indent=2))

def condition_instruction(c):
 return {'aligned':'Align both fiducial sets as closely as possible; measure offset.',
         'shift_1mm':'Introduce measured 1.0 mm horizontal offset, record actual offset.',
         'shift_2mm':'Introduce measured 2.0 mm horizontal offset, record actual offset.',
         'illumination_low':'Use preregistered low-illumination setting; measure lux.',
         'fabrication_defect':'Use separately fabricated documented defect specimen; record defect map; do NOT simulate as physical.'}[c]

def make_schedule(args):
 root=args.root;out=args.output or root/'Results'/'F8_11'
 master=read_csv(out/'public'/'master_blinded_schedule.csv')
 if not master:raise ValueError('Prepare first; no schedule')
 if args.max_trials<1:raise ValueError('max-trials must be positive')
 if not args.participant_id or any(c in args.participant_id for c in '/\\'):
  raise ValueError('Provide a pseudonymous participant ID without path separators')
 rng=random.Random(int.from_bytes(hashlib.sha256(f'{args.seed}|{args.participant_id}'.encode()).digest()[:8],'big'))
 rng.shuffle(master)
 # Balanced allocation across attack types and perturbation conditions,
 # using the PRIVATE key only inside the coordinator's computer.
 key={r['trial_id']:r for r in read_csv(out/'private_DO_NOT_SHARE_WITH_PARTICIPANTS'/'answer_key.csv')}
 bins=defaultdict(list)
 for entry in master:
  k=key[entry['trial_id']]
  bins[(k['presentation'],k['condition'])].append(entry)
 chosen=[]
 while len(chosen)<min(args.max_trials,len(master)) and any(bins.values()):
  labels=list(bins);rng.shuffle(labels)
  for label in labels:
   if bins[label] and len(chosen)<args.max_trials:chosen.append(bins[label].pop())
 rng.shuffle(chosen);master=chosen
 p=out/'public'/'participant_schedules'/f'{args.participant_id}.csv'
 write_csv(p,list(master[0]),master)
 print('Blinded schedule:',p)

def analyze(args):
 out=args.output or args.root/'Results'/'F8_11';keyfile=out/'private_DO_NOT_SHARE_WITH_PARTICIPANTS'/'answer_key.csv'
 if not keyfile.is_file():raise FileNotFoundError('Missing private answer key; run prepare first')
 if not args.responses or not args.responses.is_file():raise FileNotFoundError('Provide a real, completed response CSV via --responses')
 key={x['trial_id']:x for x in read_csv(keyfile)}
 rows=read_csv(args.responses)
 if not rows:raise ValueError('Response file is empty: no human data analyzed')
 seen=set();data=[];problems=[]
 for n,row in enumerate(rows,2):
  pid=row.get('participant_id','').strip();tid=row.get('trial_id','').strip();dec=row.get('decision','').strip().upper()
  if not pid or not tid:problems.append(f'line {n}: participant_id/trial_id missing');continue
  if (pid,tid) in seen:problems.append(f'line {n}: duplicate participant/trial');continue
  seen.add((pid,tid))
  if tid not in key:problems.append(f'line {n}: unknown trial ID');continue
  if dec not in ('ACCEPT','REJECT','UNSURE'):problems.append(f'line {n}: decision must be ACCEPT, REJECT or UNSURE');continue
  try:
   sec=float(row['decision_seconds']) if row.get('decision_seconds','').strip() else None
   conf=int(row['confidence_1_to_5']) if row.get('confidence_1_to_5','').strip() else None
   if sec is not None and (not math.isfinite(sec) or sec<=0):raise ValueError('decision_seconds must be positive finite')
   if conf is not None and conf not in range(1,6):raise ValueError('confidence must be 1..5')
  except (ValueError,KeyError) as e:problems.append(f'line {n}: {e}');continue
  k=key[tid];data.append({**k,'participant_id':pid,'decision':dec,'accepted':int(dec=='ACCEPT'),
                           'decision_seconds':sec,'confidence':conf})
 if problems:raise ValueError('Invalid responses; nothing analyzed. Examples: '+'; '.join(problems[:15]))
 groups=defaultdict(list)
 for d in data:
  # Report legitimate FRR, unauthorized FAR, content-changing FAR, share-only FAR, replay.
  attack=d['presentation'];cond=d['condition']
  outcome='FRR' if attack=='legitimate' else 'replay_acceptance' if attack=='exact_copy' else 'content_change_FAR' if d['content_changed']=='1' else 'share_only_FAR'
  groups[(cond,outcome)].append(d)
  groups[('ALL',outcome)].append(d)
 report=[]
 for (cond,outcome),arr in sorted(groups.items()):
  n=len(arr);accept=sum(d['accepted'] for d in arr)
  k=n-accept if outcome=='FRR' else accept
  report.append({'condition':cond,'outcome':outcome,'n_responses':n,'n_participants':len(set(d['participant_id'] for d in arr)),
                 'n_images':len(set(d['image_id'] for d in arr)),'events':k,'rate':round(k/n,6),
                 'wilson_low':wilson(k,n)[0],'wilson_high':wilson(k,n)[1],
                 'unsure_count':sum(d['decision']=='UNSURE' for d in arr),
                 'mean_decision_seconds':round(statistics.mean(d['decision_seconds'] for d in arr if d['decision_seconds'] is not None),3) if any(d['decision_seconds'] is not None for d in arr) else ''})
 result=out/'analysis';write_csv(result/'human_outcome_summary.csv',list(report[0]),report)
 write_json(result/'analysis_report.json',{'status':'OBSERVED_RESPONSES_ANALYZED','responses':len(data),
  'participants':len(set(d['participant_id'] for d in data)),
  'images':len(set(d['image_id'] for d in data)),
  'complete_design':len(data)==len(key)*len(set(d['participant_id'] for d in data)),
  'analysis_limitations':['Wilson intervals treat repeated responses as independent; descriptive only.','Participant and image crossed random effects / two-way cluster bootstrap required for confirmatory inference.','A human decision on these baseline overlays is not cryptographic issuer authentication.','Exact copy cannot be rejected without an independent freshness mechanism.','Ethics approval and physical logs must be independently verified.'],
  'primary_results':report,'physical_data_verified':False,'ethics_approval_verified':False})
 print(json.dumps({'status':'ANALYZED_REAL_RESPONSES','responses':len(data),'participants':len(set(d['participant_id'] for d in data)),
                   'summary':str(result/'human_outcome_summary.csv'),'warning':'Do not claim physical validation or issuer authentication from this software alone'},indent=2))

def self_test():
 rng=np.random.default_rng(13)
 for side in (8,16):
  for v in (0,1):
   secret=np.full((side,side),v,dtype=np.uint8);a,b=ns(secret,rng)
   assert np.array_equal(decode(a,b),secret)
   aa,bb=altered_pair('content_flip',secret,a,b,rng)
   assert np.count_nonzero(decode(aa,bb)!=secret)==1
   assert not np.array_equal(a,aa) or not np.array_equal(b,bb)
 assert wilson(0,0)==[None,None]
 assert wilson(5,10)[0]<0.5<wilson(5,10)[1]
 print('SELF_TEST_PASS: secret sharing, forced content change, confidence intervals')

def main():
 p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
 sub=p.add_subparsers(dest='command',required=True)
 for cmd in ('prepare','make-schedule','analyze','self-test'):
  q=sub.add_parser(cmd)
  if cmd!='self-test':
   q.add_argument('--root',type=Path,default=DEFAULT_ROOT)
   q.add_argument('--output',type=Path)
  if cmd=='prepare':
   q.add_argument('--strict-data',action='store_true');q.add_argument('--images',type=int,default=12)
   q.add_argument('--side',type=int,default=32,help='Pilot crop/resize resolution; NOT F8_09 full-resolution comparison')
   q.add_argument('--trials-per-condition',type=int,default=2)
   q.add_argument('--cell-px',type=int,default=8);q.add_argument('--quiet-px',type=int,default=24)
   q.add_argument('--dpi',type=int,default=300);q.add_argument('--seed',type=int,default=20261114)
  elif cmd=='make-schedule':
   q.add_argument('--participant-id',required=True);q.add_argument('--seed',type=int,default=20261114);q.add_argument('--max-trials',type=int,default=40)
  elif cmd=='analyze':q.add_argument('--responses',type=Path,required=True)
 args=p.parse_args()
 if args.command=='self-test':self_test()
 elif args.command=='prepare':prepare(args)
 elif args.command=='make-schedule':make_schedule(args)
 else:analyze(args)

if __name__=='__main__':main()
