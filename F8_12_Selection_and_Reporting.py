#!/usr/bin/env python3
"""F8_12: Evidence-gated selection and reporting for HOVSS-PQ.

Python >=3.10, standard library only; optional matplotlib for PNG figures.
Reads existing Results/F8_01..F8_11 and Results/F8_09_REVISED.
Never treats simulation, a prepared physical protocol, or a digital signature as
proof of human-only post-quantum optical issuer authentication.

Examples:
 python F8_12_Selection_and_Reporting.py --strict-data
 python F8_12_Selection_and_Reporting.py --root "D:\\48\\481\\New Papers\\Nature_Idea\\Experiments" --strict-data
 python F8_12_Selection_and_Reporting.py --self-test
"""
from __future__ import annotations
import argparse, csv, hashlib, json, math, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')
MODELS = ('or','public_anchor','trusted_stack','trusted_layers','polarization','signed_digital')
OPTICAL = ('or','public_anchor','trusted_stack','trusted_layers','polarization')
ATTACKS = ('single_subpixel','known_content_reissue','public_anchor_rebinding',
           'full_share_substitution','adaptive_optical_search','exact_copy',
           'signed_record_tamper','signed_share_replacement')
REFS = {
 'Naor-Shamir visual cryptography':'https://doi.org/10.1007/BFb0053419',
 'NIST FIPS 204 ML-DSA':'https://doi.org/10.6028/NIST.FIPS.204',
 'WMA Declaration of Helsinki':'https://www.wma.net/policies-post/wma-declaration-of-helsinki/'
}

def read_json(p):
 with p.open(encoding='utf-8-sig') as f:return json.load(f)

def write_json(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(json.dumps(obj,indent=2,ensure_ascii=False,sort_keys=True,allow_nan=False)+'\n',encoding='utf-8')

def read_csv(p):
 with p.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

def write_csv(p,rows,fields):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)

def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def number(x):
 try:
  v=float(x)
  return v if math.isfinite(v) else None
 except (TypeError,ValueError):return None

def fraction(rows, numerator='accepted',denominator='n'):
 n=sum(int(float(r.get(denominator,0) or 0)) for r in rows)
 k=sum(int(float(r.get(numerator,0) or 0)) for r in rows)
 return (k/n if n else None,n,k)

def fmt(x):return 'N/A' if x is None else f'{x:.2%}'

def collect(root,strict):
 paths={
  'F8_01_dataset':root/'Results/F8_01/reports/dataset_manifest.csv',
  'F8_02_verdict':root/'Results/F8_02/reports/verdict.json',
  'F8_03_verdict':root/'Results/F8_03/reports/verdict.json',
  'F8_04_verdict':root/'Results/F8_04/reports/verdict.json',
  'F8_05_verdict':root/'Results/F8_05/reports/verdict.json',
  'F8_06_verdict':root/'Results/F8_06/reports/verdict.json',
  'F8_07_verdict':root/'Results/F8_07/reports/verdict.json',
  'F8_07_crypto':root/'Results/F8_07/reports/dependency_audit_crypto.json',
  'F8_08_verdict':root/'Results/F8_08/reports/verdict.json',
  'F8_09_revised_verdict':root/'Results/F8_09_REVISED/reports/verdict.json',
  'F8_09_revised_summary':root/'Results/F8_09_REVISED/reports/summary.json',
  'F8_09_revised_attack_summary':root/'Results/F8_09_REVISED/reports/attack_summary.csv',
  'F8_10_verdict':root/'Results/F8_10/reports/verdict.json',
  'F8_10_robustness':root/'Results/F8_10/reports/robustness_summary.csv',
  'F8_10_summary':root/'Results/F8_10/reports/summary.json',
  'F8_11_preparation':root/'Results/F8_11/private_DO_NOT_SHARE_WITH_PARTICIPANTS/preparation_audit.json',
 }
 required=('F8_01_dataset','F8_07_verdict','F8_09_revised_verdict','F8_09_revised_summary',
           'F8_09_revised_attack_summary','F8_10_verdict','F8_10_robustness','F8_11_preparation')
 absent=[k for k in required if not paths[k].is_file()]
 if strict and absent:raise FileNotFoundError('Missing mandatory evidence: '+', '.join(f'{k}={paths[k]}' for k in absent))
 provenance=[];data={}
 for k,p in paths.items():
  exists=p.is_file()
  provenance.append({'evidence':k,'path':str(p),'present':exists,'sha256':digest(p) if exists else '', 'required':k in required})
  if exists:
   try:data[k]=read_csv(p) if p.suffix=='.csv' else read_json(p)
   except (OSError,ValueError,UnicodeError,csv.Error) as e:
    if strict:raise ValueError(f'Cannot parse {p}: {e}') from e
    data[k+'_parse_error']=str(e)
 return data,provenance,absent

def aggregate_f9(rows,threshold=0.02,split='test'):
 groups=defaultdict(list)
 for r in rows:
  if r.get('split')!=split or r.get('model') not in MODELS:continue
  t=number(r.get('threshold'))
  if t is None or abs(t-threshold)>1e-9:continue
  if r.get('attack_applicable','1') in ('0','false','False'):continue
  groups[(r['model'],r['attack'])].append(r)
 out=[]
 for (model,attack),rr in sorted(groups.items()):
  rate,n,k=fraction(rr)
  content,_,_=fraction(rr,'content_forgery_accept')
  share,_,_=fraction(rr,'share_forgery_accept')
  out.append({'model':model,'attack':attack,'split':split,'threshold':threshold,'n':n,'accepted':k,
              'acceptance_rate':round(rate,8) if rate is not None else '',
              'content_forgery_acceptance_rate':round(content,8) if content is not None else '',
              'share_forgery_acceptance_rate':round(share,8) if share is not None else '',
              'source_rows':len(rr),'scope':'F8_09_REVISED computational surrogate; not a human result'})
 return out

def aggregate_f10(rows):
 # Preserve each perturbation and severity: do not pool incompatible calibrated thresholds.
 out=[]
 for r in rows:
  if r.get('model') not in MODELS:continue
  if r.get('attack') not in ('legitimate','content_flip','single_subpixel','exact_copy'):continue
  if r.get('severity') not in ('1.0','1','0.0','0'):continue
  out.append({'model':r['model'],'attack':r['attack'],'perturbation':r.get('perturbation',''),
              'severity':r.get('severity',''),'n':r.get('n',''),
              'acceptance_rate':r.get('acceptance_rate',''),
              'threshold':r.get('threshold',''),
              'image_bootstrap_low':r.get('image_bootstrap_low',''),
              'image_bootstrap_high':r.get('image_bootstrap_high','')})
 return out

def select_gates(data):
 v7=data.get('F8_07_verdict',{})
 v9=data.get('F8_09_revised_verdict',{})
 v10=data.get('F8_10_verdict',{})
 prep=data.get('F8_11_preparation',{})
 real_crypto=(v7.get('execution')=='PASS' and v7.get('ml_dsa_electronic_audit')=='PASS')
 comp=(v9.get('execution')=='PASS' and v10.get('execution')=='PASS')
 human=bool(prep.get('human_data_collected') is True)
 gates=[
  {'gate':'G1 Dataset and computational pipeline','status':'PASS' if comp and data.get('F8_01_dataset') else 'NOT_VERIFIED',
   'basis':'F8_01 manifest, F8_09_REVISED and F8_10 execution verdicts'},
  {'gate':'G2 Electronic post-quantum issuer signatures','status':'PASS_ELECTRONIC_ONLY' if real_crypto else 'NOT_VERIFIED',
   'basis':'F8_07 actual ML-DSA-65 verification; no optical issuer binding implied'},
  {'gate':'G3 Perfect secrecy of complete proposed construction','status':'NOT_ESTABLISHED',
   'basis':'Classical baseline privacy does not prove secrecy of public anchors, references or full system'},
  {'gate':'G4 Human-observable issuer-bound authentication','status':'NOT_ESTABLISHED',
   'basis':'No demonstrated optical encoding of issuer authorization; electronic signature alone is insufficient'},
  {'gate':'G5 Physical optical fabrication and tolerance','status':'NOT_MEASURED',
   'basis':'F8_10 perturbations are simulated; F8_11 is a preparation protocol'},
  {'gate':'G6 Human-observer discrimination','status':'DATA_PRESENT_REQUIRES_REVIEW' if human else 'NOT_PERFORMED',
   'basis':'F8_11 preparation audit; presence of responses alone is not evidence of success'},
  {'gate':'G7 Static exact-copy replay prevention','status':'NOT_ESTABLISHED',
   'basis':'Exact copies cannot be distinguished by static optical observations or signatures without freshness'},
  {'gate':'G8 Complete HOVSS-PQ feasibility','status':'NOT_ESTABLISHED',
   'basis':'G3–G7 are not satisfied; do not infer full feasibility from G1 or G2'}]
 return gates

def candidate_matrix():
 return [
  {'candidate':'A Public lattice-derived anchor','optical_model':'public_anchor','electronic_pq_signature':'NOT_INHERENT',
   'human_only_issuer_auth':'NOT_ESTABLISHED','trusted_reference':'NONE','status':'NEGATIVE_CONTROL',
   'critical_limitation':'Public recomputation allows rebinding; optical issuer authenticity absent'},
  {'candidate':'B Protected enrolled reference','optical_model':'trusted_stack / trusted_layers',
   'electronic_pq_signature':'SEPARATE_CONTROL_ONLY','human_only_issuer_auth':'NOT_ESTABLISHED',
   'trusted_reference':'REQUIRED','status':'CONDITIONAL_RESEARCH_CANDIDATE',
   'critical_limitation':'Reference substitution/custody; trusted_layers is an ideal digital comparator'},
  {'candidate':'C Jones polarization differential','optical_model':'polarization',
   'electronic_pq_signature':'SEPARATE_CONTROL_ONLY','human_only_issuer_auth':'NOT_ESTABLISHED',
   'trusted_reference':'NO_ISSUER_BOUND_PHYSICAL_REFERENCE_DEMONSTRATED',
   'status':'CONDITIONAL_RESEARCH_CANDIDATE',
   'critical_limitation':'Threshold robustness fails under blur/translation/fabrication surrogate'},
  {'candidate':'D ML-DSA electronic verifier','optical_model':'signed_digital',
   'electronic_pq_signature':'DEMONSTRATED_F8_07','human_only_issuer_auth':'NOT_APPLICABLE',
   'trusted_reference':'DIGITAL_PUBLIC_KEY_TRUST','status':'ELECTRONIC_POSITIVE_CONTROL',
   'critical_limitation':'Requires electronic verification; not human-only optical authentication'}]

def make_figures(out,f9,f10):
 try:
  import matplotlib
  matplotlib.use('Agg')
  import matplotlib.pyplot as plt
 except ImportError:return {'status':'SKIPPED','reason':'matplotlib unavailable'}
 figdir=out/'figures';figdir.mkdir(parents=True,exist_ok=True)
 # Visualizations are descriptive and labelled with their exact scope.
 fig,ax=plt.subplots(figsize=(11,5))
 selected=['single_subpixel','adaptive_optical_search','exact_copy']
 for j,attack in enumerate(selected):
  rates=[]
  for m in MODELS:
   rr=next((r for r in f9 if r['model']==m and r['attack']==attack),None)
   rates.append(float(rr['acceptance_rate']) if rr and rr['acceptance_rate']!='' else float('nan'))
  ax.plot(range(len(MODELS)),rates,marker='o',label=attack.replace('_',' '))
 ax.set_xticks(range(len(MODELS)),MODELS,rotation=25,ha='right');ax.set_ylim(-0.05,1.05)
 ax.set_ylabel('Acceptance rate');ax.set_title('F8_09_REVISED: held-out test, threshold 0.02 (simulation)')
 ax.legend();fig.tight_layout();fig.savefig(figdir/'f9_heldout_attack_acceptance.png',dpi=180);plt.close(fig)
 fig,ax=plt.subplots(figsize=(10,5))
 cases=['ideal','blur','translation','fabrication_dropout','combined']
 vals=[];labels=[]
 for condition in cases:
  rr=[r for r in f10 if r['model']=='polarization' and r['attack']=='content_flip' and
      r['perturbation']==condition and str(r['severity']) in ('1','1.0')]
  if rr:
   vals.append(float(rr[0]['acceptance_rate']));labels.append(condition)
 if vals:
  ax.bar(labels,vals);ax.set_ylim(0,1.05);ax.set_ylabel('Attack acceptance rate')
  ax.set_title('F8_10: polarization content flip, max severity (simulation)')
  ax.tick_params(axis='x',rotation=20);fig.tight_layout();fig.savefig(figdir/'f10_polarization_robustness.png',dpi=180)
 plt.close(fig)
 return {'status':'CREATED','files':[str(p) for p in sorted(figdir.glob('*.png'))]}

def report_markdown(gates,candidates,f9,f10,provenance,summary):
 lines=['# HOVSS-PQ: Evidence-Gated Selection and Reporting','',
  '**Status:** Computational experiments completed; complete HOVSS-PQ feasibility NOT ESTABLISHED.','',
  '## Evidence and reproducibility','',
  f"- Dataset images reported by F8_09_REVISED: {summary.get('images_processed','not verified')}",
  f"- F8_09_REVISED trial records: {summary.get('records','not verified')}",
  '- Primary full-image benchmark: F8_09_REVISED, not the superseded F8_09.',
  '- F8_07 executes real electronic ML-DSA; F8_09_REVISED uses an ideal digital control.',
  '- F8_10 uses numerical perturbations, not calibrated physical measurements.',
  '- F8_11 produces protocol materials; no human performance is inferred from preparation.', '',
  '## Feasibility gates','', '| Gate | Status | Basis |','|---|---|---|']
 for g in gates:lines.append('| '+ ' | '.join(g[k].replace('|','/') for k in ('gate','status','basis'))+' |')
 lines+=['','## Candidate selection (no security-certified winner)','',
          '| Candidate | Classification | Primary limitation |','|---|---|---|']
 for c in candidates:lines.append('| '+ ' | '.join(c[k].replace('|','/') for k in ('candidate','status','critical_limitation'))+' |')
 lines+=['','**Selection rule:** No candidate passes all required security and physical-human gates. '
         'Candidate C remains a research direction for optical distinguishability, B for reference-dependent '
         'verification, A a negative control, and D a digital positive control. '
         'No ranking of full-system security is justified.','','## Selected held-out attack acceptance rates',
         '','F8_09_REVISED, `split=test`, threshold 0.02. Rates are computational, not human observations.','',
         '| Model | Single-subpixel | Adaptive search | Exact copy |','|---|---:|---:|---:|']
 lookup={(r['model'],r['attack']):r for r in f9}
 for m in MODELS:
  rates=[]
  for a in ('single_subpixel','adaptive_optical_search','exact_copy'):
   r=lookup.get((m,a));rates.append(fmt(number(r['acceptance_rate'])) if r else 'N/A')
  lines.append('| '+m+' | '+' | '.join(rates)+' |')
 lines+=['','## Interpretation and unresolved work','',
  '1. Validate whole-construction confidentiality including references and public side information.',
  '2. Specify and prove a secure issuer-to-optical binding, or narrow the claim to electronic authentication.',
  '3. Measure actual fabricated optical specimens and predefine operating tolerances.',
  '4. Obtain applicable ethics approval, conduct blinded human studies, and analyze actual responses.',
  '5. Address reference custody and static replay/freshness limitations.',
  '6. Avoid equating an ideal digital layer comparator with unaided human verification.',
  '', '## References','']
 for name,url in REFS.items():lines.append(f'- {name}: {url}')
 lines+=['','## Evidence inventory','', '| Source | Present | SHA-256 |','|---|---|---|']
 for p in provenance:lines.append(f"| {p['evidence']} | {p['present']} | `{p['sha256'][:16]}` |")
 return '\n'.join(lines)+'\n'

def self_test():
 sample=[{'model':'or','attack':'single_subpixel','split':'test','threshold':'0.02','n':'3','accepted':'2','content_forgery_accept':'1','share_forgery_accept':'2','attack_applicable':'1'},
         {'model':'or','attack':'single_subpixel','split':'test','threshold':'0.02','n':'2','accepted':'1','content_forgery_accept':'0','share_forgery_accept':'1','attack_applicable':'1'},
         {'model':'or','attack':'single_subpixel','split':'val','threshold':'0.02','n':'9','accepted':'9','attack_applicable':'1'},
         {'model':'or','attack':'single_subpixel','split':'test','threshold':'0.05','n':'9','accepted':'9','attack_applicable':'1'}]
 a=aggregate_f9(sample)
 assert len(a)==1 and a[0]['n']==5 and a[0]['accepted']==3
 assert abs(a[0]['acceptance_rate']-.6)<1e-9
 assert a[0]['content_forgery_acceptance_rate']==.2
 assert select_gates({})[-1]['status']=='NOT_ESTABLISHED'
 assert not number('NaN') and number('0.02')==.02
 print('SELF-TEST PASS: split isolation, threshold isolation, weighted aggregation, evidence gates')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--root',type=Path,default=ROOT)
 p.add_argument('--output',type=Path,default=None)
 p.add_argument('--strict-data',action='store_true')
 p.add_argument('--threshold',type=float,default=.02)
 p.add_argument('--evaluation-split',default='test')
 p.add_argument('--self-test',action='store_true')
 args=p.parse_args()
 if args.self_test:self_test();return
 if args.threshold<0:p.error('--threshold must be nonnegative')
 data,provenance,missing=collect(args.root,args.strict_data)
 out=args.output or args.root/'Results/F8_12';out.mkdir(parents=True,exist_ok=True)
 f9=aggregate_f9(data.get('F8_09_revised_attack_summary',[]),args.threshold,args.evaluation_split)
 f10=aggregate_f10(data.get('F8_10_robustness',[]))
 gates=select_gates(data);candidates=candidate_matrix()
 summary9=data.get('F8_09_revised_summary',{})
 checks={'full_image_count_546':summary9.get('images_processed')==546,
         'revised_trial_count_294840':summary9.get('records')==294840,
         'f9_heldout_rows_present':bool(f9),
         'f10_robustness_rows_present':bool(f10),
         'f11_human_data_collected':data.get('F8_11_preparation',{}).get('human_data_collected') is True,
         'real_ml_dsa_electronic_audit':data.get('F8_07_verdict',{}).get('ml_dsa_electronic_audit')=='PASS'}
 if args.strict_data and not all(checks[k] for k in ('full_image_count_546','revised_trial_count_294840','f9_heldout_rows_present','f10_robustness_rows_present','real_ml_dsa_electronic_audit')):
  raise ValueError('Mandatory validation checks failed: '+str({k:v for k,v in checks.items() if not v and k!='f11_human_data_collected'}))
 write_csv(out/'reports/evidence_provenance.csv',provenance,['evidence','path','present','sha256','required'])
 write_csv(out/'reports/feasibility_gates.csv',gates,['gate','status','basis'])
 write_csv(out/'reports/candidate_matrix.csv',candidates,['candidate','optical_model','electronic_pq_signature','human_only_issuer_auth','trusted_reference','status','critical_limitation'])
 write_csv(out/'reports/f9_heldout_comparison.csv',f9,['model','attack','split','threshold','n','accepted','acceptance_rate','content_forgery_acceptance_rate','share_forgery_acceptance_rate','source_rows','scope'])
 write_csv(out/'reports/f10_robustness_extract.csv',f10,['model','attack','perturbation','severity','n','acceptance_rate','threshold','image_bootstrap_low','image_bootstrap_high'])
 figure=make_figures(out,f9,f10)
 (out/'reports/scientific_report.md').write_text(report_markdown(gates,candidates,f9,f10,provenance,summary9),encoding='utf-8')
 write_json(out/'reports/model_assumptions.json',{
  'no_full_system_winner':'No candidate passes all confidentiality, issuer-authenticity, physical, human and replay gates.',
  'dataset':'F8_01 manifest; F8_09_REVISED is authoritative benchmark',
  'signature':'F8_07 actual ML-DSA-65 electronic verification only; F8_09 idealized digital control',
  'physical':'F8_10 numerical perturbations only; F8_11 prepared stimuli only',
  'human':'No empirical human performance is inferred from preparation; user-collected observations require independent audit',
  'statistical':'Aggregated rates are descriptive, not independent Bernoulli trials; source-specific cluster bootstrap is in original files',
  'selection':'Noncompensatory security feasibility gates; no arbitrary weighted score can compensate for missing issuer binding',
  'provenance':'SHA-256 of each loaded evidence file recorded; missing optional stages explicitly disclosed'})
 write_json(out/'configuration/run.json',{'root':str(args.root),'output':str(out),'strict_data':args.strict_data,
            'threshold':args.threshold,'evaluation_split':args.evaluation_split})
 status='PASS_WITH_UNRESOLVED_SECURITY_GATES' if not missing else 'INCOMPLETE_EVIDENCE'
 verdict={'execution':status,'full_hovss_pq_feasibility':'NOT_ESTABLISHED',
          'candidate_selection':'NO_SECURITY_QUALIFIED_WINNER',
          'physical_human_verification':'NOT_ESTABLISHED',
          'real_electronic_ml_dsa':'PASS' if checks['real_ml_dsa_electronic_audit'] else 'NOT_VERIFIED',
          'checks':checks,'missing_required_evidence':missing,'figures':figure}
 write_json(out/'reports/verdict.json',verdict)
 write_json(out/'reports/summary.json',{'gates':len(gates),'candidates':len(candidates),'f9_comparison_rows':len(f9),
           'f10_extract_rows':len(f10),'evidence_files_present':sum(p['present'] for p in provenance),
           'evidence_files_expected':len(provenance),'verdict':verdict['execution']})
 print(json.dumps({'output':str(out),'verdict':verdict['execution'],'selection':verdict['candidate_selection'],
                   'gates':len(gates),'f9_rows':len(f9),'f10_rows':len(f10),'figures':figure['status']},indent=2))

if __name__=='__main__':main()
