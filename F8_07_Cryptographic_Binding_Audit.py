#!/usr/bin/env python3
"""F8_07: ML-DSA issuer-to-optical binding audit (research; no optical auth claim).

No secret keys or full signatures are saved. All outputs are reproducible in
structure and attack selection, while real ML-DSA key generation is randomized.
Compatible with pqcrypto 1.0.0 (keygen/sign/verify) and older
pqcrypto 0.x (generate_keypair/sign/verify) where installed.
"""
from __future__ import annotations
import argparse, csv, hashlib, importlib, importlib.metadata, json, os, platform, random, sys, time
from pathlib import Path

DEFAULT_ROOT = Path(r'D:\48\481\New Papers\Nature_Idea\Experiments')
DOMAIN = b'HOVSS-PQ:F8-07:ISSUANCE:V1\x00'
CONTEXT = b'HOVSS-PQ-F8-07'

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def sha(data): return hashlib.sha256(data).hexdigest()

def bits(rng, n): return ''.join(str(rng.randrange(2)) for _ in range(n))

def make_record(secret, shares, anchor, issuer, issuance_id):
    return {'schema':'HOVSS-PQ-F8-07-v1', 'issuer_id':issuer, 'issuance_id':issuance_id,
            'secret_sha256':sha(secret.encode()), 'share_commitments':[sha(x.encode()) for x in shares],
            'anchor_commitment':sha(anchor.encode()), 'access_structure':'2-of-2',
            'optical_model':'OR-baseline', 'reference_policy':'no-independent-anchor'}

def encoded_record(record): return DOMAIN + canonical(record)

def resolve_backend():
    info={'module':'pqcrypto.sign.ml_dsa_65', 'available':False,'api':None,'version':None,'error':None}
    try:
        info['version']=importlib.metadata.version('pqcrypto')
        mod=importlib.import_module('pqcrypto.sign.ml_dsa_65')
        keygen=getattr(mod,'keygen',None) or getattr(mod,'generate_keypair',None)
        sign=getattr(mod,'sign',None); verify=getattr(mod,'verify',None)
        if not callable(keygen) or not callable(sign) or not callable(verify):
            info['error']='Missing callable keygen/generate_keypair, sign, or verify'
            return None,info
        info.update(available=True,api=('keygen' if hasattr(mod,'keygen') else 'generate_keypair'))
        return (keygen,sign,verify),info
    except Exception as exc:
        info['error']=type(exc).__name__+': '+str(exc)
        return None,info

def verify_ok(fn,pk,msg,sig,context_support):
    try:
        if context_support: result=fn(pk,msg,sig,CONTEXT)
        else: result=fn(pk,msg,sig)
        # pqcrypto 1.0 returns None on success, 0.x returns bool
        return result is None or result is True
    except Exception:
        return False

def sign_message(fn,sk,msg,context_support):
    return fn(sk,msg,CONTEXT) if context_support else fn(sk,msg)

def negotiate(backend):
    keygen,sign,verify=backend
    pk,sk=keygen()
    msg=encoded_record({'test':'API negotiation'})
    for use_ctx in (True,False):
        try:
            sig=sign_message(sign,sk,msg,use_ctx)
            if verify_ok(verify,pk,msg,sig,use_ctx):
                return {'pk':pk,'sk':sk,'sign':sign,'verify':verify,'context_support':use_ctx,
                        'signature_size':len(sig),'public_key_size':len(pk)}
        except (TypeError,ValueError):
            continue
    raise RuntimeError('ML-DSA keygen/sign/verify round trip failed; no fallback permitted')

def sha_share(s): return sha(s.encode())

def visual_or(a,b): return ''.join('1' if x=='1' or y=='1' else '0' for x,y in zip(a,b))

def csv_write(path,rows,fields):
    with path.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)

def write_json(path,obj): path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=DEFAULT_ROOT)
    p.add_argument('--trials',type=int,default=100)
    p.add_argument('--secret-pixels',type=int,default=4)
    p.add_argument('--seed',type=int,default=20261114)
    p.add_argument('--strict-data',action='store_true',help='Require existing F8_01 through F8_06 result folders')
    p.add_argument('--require-ml-dsa',action='store_true',help='Exit nonzero if real ML-DSA cannot be executed')
    args=p.parse_args(argv)
    if not (1<=args.secret_pixels<=4096) or not (1<=args.trials<=100000): p.error('invalid size/trials')
    root=args.root.expanduser(); results=root/'Results'; out=results/'F8_07'
    for part in ('configuration','mathematical_validation','reports','logs'): (out/part).mkdir(parents=True,exist_ok=True)
    dep={f'F8_{i:02d}':(results/f'F8_{i:02d}').is_dir() for i in range(1,7)}
    if args.strict_data and not all(dep.values()):
        print('ERROR: --strict-data missing prerequisite result folders: '+', '.join(k for k,v in dep.items() if not v),file=sys.stderr)
        return 2
    write_json(out/'configuration'/'run.json',{'root':str(root),'trials':args.trials,'secret_pixels':args.secret_pixels,'seed':args.seed,'strict_data':args.strict_data,'require_ml_dsa':args.require_ml_dsa})
    write_json(out/'reports'/'dependency_audit.json',dep)
    backend,backend_info=resolve_backend(); crypto=None; crypto_error=None
    if backend:
        try:
            crypto=negotiate(backend)
            backend_info.update(context_support=crypto['context_support'],signature_size=crypto['signature_size'],public_key_size=crypto['public_key_size'],roundtrip=True)
        except Exception as exc:
            crypto_error=type(exc).__name__+': '+str(exc);backend_info.update(roundtrip=False,error=crypto_error)
    write_json(out/'reports'/'dependency_audit_crypto.json',backend_info)
    if args.require_ml_dsa and crypto is None:
        write_json(out/'reports'/'verdict.json',{'status':'BLOCKED','reason':'Real ML-DSA unavailable','backend':backend_info})
        print('BLOCKED: real ML-DSA backend unavailable. See dependency_audit_crypto.json',file=sys.stderr)
        return 3
    rng=random.Random(args.seed); rows=[]; witnesses=[]
    attacks=['unaltered','modify_secret_commitment','modify_share_commitment','modify_anchor_commitment',
             'change_issuer','change_issuance_id','change_access_structure','swap_record',
             'replace_share_without_rebinding','public_rebinding','exact_copy']
    # An issuer signature is an electronic control; the passive visual observer does not see its validity.
    for t in range(args.trials):
        secret=bits(rng,args.secret_pixels)
        a=bits(rng,args.secret_pixels)
        b=bits(rng,args.secret_pixels)
        anchor=bits(rng,args.secret_pixels)
        rec=make_record(secret,[a,b],anchor,'issuer-A',f'issue-{t:06d}')
        msg=encoded_record(rec)
        sig=sign_message(crypto['sign'],crypto['sk'],msg,crypto['context_support']) if crypto else None
        original_obs=visual_or(a,b)
        for attack in attacks:
            forged=json.loads(json.dumps(rec)); fa,fb=a,b
            if attack=='modify_secret_commitment': forged['secret_sha256']=sha((secret+'1').encode())
            elif attack=='modify_share_commitment': forged['share_commitments'][0]=sha((a+'1').encode())
            elif attack=='modify_anchor_commitment': forged['anchor_commitment']=sha((anchor+'1').encode())
            elif attack=='change_issuer': forged['issuer_id']='attacker'
            elif attack=='change_issuance_id': forged['issuance_id']='replay-'+str(t)
            elif attack=='change_access_structure': forged['access_structure']='1-of-2'
            elif attack=='swap_record':
                forged=make_record(bits(rng,args.secret_pixels),[bits(rng,args.secret_pixels),bits(rng,args.secret_pixels)],bits(rng,args.secret_pixels),'issuer-B',f'foreign-{t}')
            elif attack=='replace_share_without_rebinding':
                fa=('1' if a[0]=='0' else '0')+a[1:]
            elif attack=='public_rebinding':
                fa=('1' if a[0]=='0' else '0')+a[1:]
                forged['share_commitments'][0]=sha_share(fa)
                forged['anchor_commitment']=sha((anchor+'public').encode())
            # Copy: same message, same presentation, same signature; replay defense needs external state.
            message_valid=encoded_record(forged)==msg
            electronic_sig_valid=(verify_ok(crypto['verify'],crypto['pk'],encoded_record(forged),sig,crypto['context_support']) if crypto else None)
            # Enrolled issuance record and committed share bytes are digitally checked here.
            commitment_consistent=forged['share_commitments']==[sha_share(fa),sha_share(fb)]
            digital_accept=(bool(electronic_sig_valid) and commitment_consistent) if crypto else None
            passive_optical_equal=visual_or(fa,fb)==original_obs
            # Rebinding is locally recomputable but cannot be signed without issuer private key.
            public_rebinding_consistent=commitment_consistent
            row={'trial':t,'attack':attack,'signed_message_unchanged':int(message_valid),
                 'signature_valid':('' if electronic_sig_valid is None else int(electronic_sig_valid)),
                 'share_commitments_match':int(commitment_consistent),
                 'digital_accept':('' if digital_accept is None else int(digital_accept)),
                 'passive_or_equal':int(passive_optical_equal),
                 'public_rebinding_consistent':int(public_rebinding_consistent)}
            rows.append(row)
            if len(witnesses)<60 and attack not in ('unaltered','exact_copy') and (passive_optical_equal or (electronic_sig_valid and not commitment_consistent)):
                witnesses.append({'trial':t,'attack':attack,'original_share_0':a,'presented_share_0':fa,
                                  'original_or':original_obs,'presented_or':visual_or(fa,fb),
                                  'signature_valid':electronic_sig_valid,'commitments_match':commitment_consistent})
    fields=list(rows[0]);csv_write(out/'reports'/'attack_metrics.csv',rows,fields)
    summaries=[]
    for attack in attacks:
        subset=[r for r in rows if r['attack']==attack]
        def rate(k):
            vals=[int(r[k]) for r in subset if r[k]!='']
            return (sum(vals)/len(vals)) if vals else None
        summaries.append({'attack':attack,'trials':len(subset),'signature_valid_rate':rate('signature_valid'),
                          'digital_accept_rate':rate('digital_accept'),
                          'passive_or_equivalence_rate':rate('passive_or_equal'),
                          'public_rebinding_consistency_rate':rate('public_rebinding_consistent')})
    csv_write(out/'reports'/'attack_summary.csv',summaries,list(summaries[0]))
    write_json(out/'mathematical_validation'/'counterexamples.json',witnesses)
    tests={'canonical_key_order':canonical({'b':2,'a':1})==canonical({'a':1,'b':2}),
           'domain_separation':encoded_record({'x':1}).startswith(DOMAIN),
           'share_commitment_change':sha_share('0')!=sha_share('1'),
           'optical_or_masking':visual_or('1','0')==visual_or('1','1'),
           'optical_or_change':visual_or('0','0')!=visual_or('1','0'),
           'attack_row_count':len(rows)==len(attacks)*args.trials}
    if crypto:
        tests['real_ml_dsa_roundtrip']=verify_ok(crypto['verify'],crypto['pk'],encoded_record({'test':1}),
            sign_message(crypto['sign'],crypto['sk'],encoded_record({'test':1}),crypto['context_support']),crypto['context_support'])
        tests['real_ml_dsa_tamper_rejected']=not verify_ok(crypto['verify'],crypto['pk'],encoded_record({'test':2}),
            sign_message(crypto['sign'],crypto['sk'],encoded_record({'test':1}),crypto['context_support']),crypto['context_support'])
    write_json(out/'reports'/'self_tests.json',tests)
    model={'ml_dsa':'FIPS 204 implementation via external pqcrypto only when roundtrip succeeds',
           'canonicalization':'domain-separated deterministic UTF-8 JSON; this serialization is an experimental protocol, not a standard',
           'signed_fields':'issuer, issuance ID, secret digest, share commitments, anchor commitment, access structure, optical model, reference policy',
           'verification':'electronic signature + share-commitment checks; not optical-only',
           'visual_control':'unauthenticated OR of two binary share strings; no protected issuer-dependent visual witness',
           'limitations':['no physical fabrication','no human study','no trusted enrollment mechanism','no replay database','no signature keys written to disk','no proof of optical issuer authentication','SHA-256 commitments alone do not establish perfect secrecy of low-entropy secrets'],
           'sources':['https://doi.org/10.6028/NIST.FIPS.204','https://pypi.org/project/pqcrypto/']}
    write_json(out/'reports'/'model_assumptions.json',model)
    verdict={'execution':'PASS' if all(tests.values()) else 'FAIL',
             'ml_dsa_electronic_audit':'PASS' if crypto and tests.get('real_ml_dsa_roundtrip') and tests.get('real_ml_dsa_tamper_rejected') else 'NOT_EXECUTED',
             'optical_issuer_authentication':'NOT_ESTABLISHED',
             'physical_human_verification':'NOT_PERFORMED',
             'claim':'A valid electronic signature does not become human-observable authentication without an independently justified optical binding.',
             'backend':backend_info}
    write_json(out/'reports'/'verdict.json',verdict)
    write_json(out/'reports'/'summary.json',{'trials':args.trials,'attacks':attacks,'records':len(rows),'results':summaries,'self_tests':tests,'verdict':verdict})
    print(json.dumps({'output':str(out),'records':len(rows),'ml_dsa':verdict['ml_dsa_electronic_audit'],
                      'execution':verdict['execution'],'optical_authentication':verdict['optical_issuer_authentication']},indent=2))
    return 0 if verdict['execution']=='PASS' else 1

if __name__=='__main__': sys.exit(main())
