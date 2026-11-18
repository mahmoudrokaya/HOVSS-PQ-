#!/usr/bin/env python3
"""EOW_C08: real OpenSSL ML-DSA-65 enrollment signatures and adversarial audit.

Requires OpenSSL >=3.5 with ML-DSA-65 provider. No simulation fallback.
Keys are TEST-ONLY, generated fresh per run, and never included in the ZIP.
The trusted public-key fingerprint is pinned out of band. A signed digest
binds the issued share bytes, enrollment identifier, and issuance metadata.
Electronic verification != unaided human optical authentication.
"""
from __future__ import annotations
import argparse, base64, csv, hashlib, json, os, shutil, subprocess, sys, tempfile, zipfile
from datetime import datetime, timezone
from pathlib import Path

DOMAIN="HOVSS-PQ-EOW/ENROLLMENT/v1"
ALG="ML-DSA-65"

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
def sha(x):
    return hashlib.sha256(x).hexdigest()
def save(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n",encoding="utf-8")
def command(openssl,*args,ok=True):
    r=subprocess.run([openssl,*map(str,args)],capture_output=True,text=True)
    if ok and r.returncode:
        raise RuntimeError("OpenSSL command failed: "+r.stderr.strip())
    return r
def make_key(openssl,priv,pub):
    command(openssl,"genpkey","-algorithm",ALG,"-out",priv)
    command(openssl,"pkey","-in",priv,"-pubout","-out",pub)
def sign(openssl,priv,msg):
    with tempfile.TemporaryDirectory() as d:
        d=Path(d); (d/"msg").write_bytes(msg)
        command(openssl,"pkeyutl","-sign","-inkey",priv,"-in",d/"msg","-out",d/"sig")
        return (d/"sig").read_bytes()
def verify(openssl,pub,msg,sig):
    with tempfile.TemporaryDirectory() as d:
        d=Path(d); (d/"msg").write_bytes(msg); (d/"sig").write_bytes(sig)
        r=command(openssl,"pkeyutl","-verify","-pubin","-inkey",pub,
                  "-in",d/"msg","-sigfile",d/"sig",ok=False)
        return r.returncode==0
def record(share,issuer="Issuer-A",eid="enroll-001",revision=1,subject="test-document-001"):
    return {"domain":DOMAIN,"algorithm":ALG,"issuer":issuer,
            "enrollment_id":eid,"revision":revision,"subject_id":subject,
            "share_sha256":sha(share),"share_size":len(share)}
def check_bundle(openssl,record_,sig,share,pub,trusted_pub_hash,
                 expected_issuer="Issuer-A",expected_eid="enroll-001",
                 min_revision=1,allowed_eids=None):
    # All binding fields are authenticated by the signature.
    if sha(pub.read_bytes()) != trusted_pub_hash:
        return False,"UNTRUSTED_PUBLIC_KEY"
    if record_.get("domain")!=DOMAIN or record_.get("algorithm")!=ALG:
        return False,"DOMAIN_OR_ALGORITHM"
    if record_.get("issuer")!=expected_issuer:
        return False,"ISSUER_IDENTITY"
    if record_.get("enrollment_id")!=expected_eid:
        return False,"ENROLLMENT_IDENTITY"
    if allowed_eids is not None and record_["enrollment_id"] not in allowed_eids:
        return False,"REVOKED_OR_UNKNOWN_ENROLLMENT"
    if not isinstance(record_.get("revision"),int) or record_["revision"]<min_revision:
        return False,"STALE_REVISION"
    if record_.get("share_sha256")!=sha(share) or record_.get("share_size")!=len(share):
        return False,"SHARE_BINDING"
    if not verify(openssl,pub,canonical(record_),sig):
        return False,"INVALID_SIGNATURE"
    return True,"ACCEPT"
def upstream(source):
    if not source:
        return {"status":"NOT_PROVIDED"}
    p=Path(source)
    if p.is_dir():
        candidates=list(p.glob("reports/verdict.json"))+list(p.glob("EOW_C07/reports/verdict.json"))
        if candidates:
            data=candidates[0].read_bytes()
            return {"status":"LOADED","source":str(candidates[0]),"sha256":sha(data),
                    "verdict":json.loads(data)}
    elif p.is_file() and zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            matches=[x for x in z.namelist() if x.endswith("EOW_C07/reports/verdict.json")]
            if matches:
                data=z.read(matches[0])
                return {"status":"LOADED","source":str(p),"member":matches[0],
                        "sha256":sha(data),"verdict":json.loads(data)}
    return {"status":"MISSING_VERDICT","source":str(p)}
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openssl",default="openssl",help="OpenSSL 3.5+ executable or absolute path")
    ap.add_argument("--c07",type=Path)
    ap.add_argument("--strict-c07",action="store_true")
    ap.add_argument("--root",type=Path)
    ap.add_argument("--output",type=Path)
    args=ap.parse_args()
    exe=shutil.which(args.openssl)
    if not exe:
        ap.error("OpenSSL executable not found. Install OpenSSL >=3.5 with ML-DSA support.")
    version=command(exe,"version").stdout.strip()
    root=args.root or Path(__file__).resolve().parent.parent
    out=args.output or root/"Results"/"EOW_C08"
    rep=out/"reports"
    source=upstream(args.c07 or root/"Results"/"EOW_C07")
    if args.strict_c07 and source["status"]!="LOADED":
        ap.error("C07 verdict not found. Provide --c07 folder or ZIP.")
    cases=[]
    # All test keys are ephemeral; output contains only the issuer public key.
    with tempfile.TemporaryDirectory(prefix="eow_c08_keys_") as td:
        tmp=Path(td); private=tmp/"issuer_private.pem"; public=tmp/"issuer_public.pem"
        other_private=tmp/"other_private.pem"; other_public=tmp/"other_public.pem"
        try:
            make_key(exe,private,public)
            make_key(exe,other_private,other_public)
        except RuntimeError as exc:
            ap.error("ML-DSA-65 unavailable in this OpenSSL build: "+str(exc))
        share=b"EOW-C08 synthetic issued share bytes; not a real secret or production material."
        changed=share+b" malicious alteration"
        rec=record(share)
        sig=sign(exe,private,canonical(rec))
        pinned=sha(public.read_bytes())
        # Tests include tampering, replay/version, rogue key, substituted issuer,
        # stolen public key, and unsigned/invalid enrollment.
        variants=[
            ("legitimate",rec,sig,share,public,1,None,True),
            ("modified_share",rec,sig,changed,public,1,None,False),
            ("modified_record",{**rec,"subject_id":"substituted"},sig,share,public,1,None,False),
            ("modified_digest",{**rec,"share_sha256":"0"*64},sig,share,public,1,None,False),
            ("modified_issuer",{**rec,"issuer":"Issuer-B"},sig,share,public,1,None,False),
            ("modified_enrollment_id",{**rec,"enrollment_id":"enroll-999"},sig,share,public,1,None,False),
            ("modified_revision",{**rec,"revision":2},sig,share,public,1,None,False),
            ("truncated_signature",rec,sig[:len(sig)//2],share,public,1,None,False),
            ("random_signature",rec,os.urandom(len(sig)),share,public,1,None,False),
            ("rogue_public_key",rec,sig,share,other_public,1,None,False),
            ("rogue_signature",rec,sign(exe,other_private,canonical(rec)),share,public,1,None,False),
            ("stale_revision",rec,sig,share,public,2,None,False),
            ("revoked_enrollment",rec,sig,share,public,1,set(),False),
            ("exact_replay",rec,sig,share,public,1,None,True),
        ]
        for name,r,s,b,p,min_rev,allow,expected in variants:
            accepted,reason=check_bundle(exe,r,s,b,p,pinned,
                                         min_revision=min_rev,allowed_eids=allow)
            cases.append({"case":name,"expected_accept":expected,
                          "observed_accept":accepted,"reason":reason,
                          "test_pass":accepted==expected})
        # A valid signature on a different share is valid ONLY when the signed
        # record is replaced as well: issuer-authorized reissuance, not forgery.
        authorized_record=record(changed,eid="enroll-002",revision=2)
        authorized_sig=sign(exe,private,canonical(authorized_record))
        accepted,reason=check_bundle(exe,authorized_record,authorized_sig,changed,public,pinned,
                                     expected_eid="enroll-002",min_revision=2)
        cases.append({"case":"authorized_reissuance","expected_accept":True,
                      "observed_accept":accepted,"reason":reason,
                      "test_pass":accepted})
        # Copying a genuine issuer's public key into an untrusted bundle is NOT
        # key substitution when fingerprint is pinned, but a valid signed record
        # can be replayed unless a trusted external state rejects it.
        (out/"artifacts").mkdir(parents=True,exist_ok=True)
        (out/"artifacts"/"issuer_public_TEST_ONLY.pem").write_bytes(public.read_bytes())
        save(out/"artifacts"/"enrollment_record_TEST_ONLY.json",rec)
        (out/"artifacts"/"enrollment_signature_TEST_ONLY.bin").write_bytes(sig)
        save(out/"artifacts"/"trust_anchor_TEST_ONLY.json",{
            "algorithm":ALG,"public_key_pem_sha256":pinned,
            "warning":"Pinned by experiment harness; production requires authenticated distribution"})
        signature_bytes=len(sig)
        public_bytes=len(public.read_bytes())
    if not all(x["test_pass"] for x in cases):
        status="FAIL"
    else:
        status="PASS"
    save(out/"configuration"/"run.json",{
        "experiment":"EOW_C08","timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "openssl_version":version,"openssl_executable":exe,
        "algorithm":ALG,"upstream_status":source["status"],
        "private_key_retained":False})
    save(rep/"c07_source_audit.json",source)
    save(rep/"self_tests.json",{"passed":sum(x["test_pass"] for x in cases),
                               "total":len(cases),"cases":cases})
    with (rep/"adversarial_cases.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(cases[0]))
        w.writeheader();w.writerows(cases)
    save(rep/"model_assumptions.json",{
        "signature_algorithm":ALG,
        "implementation":"OpenSSL provider native ML-DSA-65 (not simulated)",
        "signed_payload":"Canonical UTF-8 JSON with domain, algorithm, issuer, enrollment id, revision, subject id, SHA-256 digest and size of issued share",
        "trust":"Verifier independently pins issuer public-key PEM SHA-256; no PKI or certificate validation modeled",
        "freshness":"External minimum revision or revocation list; exact replay otherwise accepted",
        "privacy":"Only digest of synthetic share is signed; hashing does not guarantee confidentiality of low-entropy secrets",
        "key_lifecycle":"Ephemeral test private keys; no production key storage, revocation or secure issuance",
        "scope":"Electronic record authentication only; no passive optical verification, no physical binding to printed share, no human study",
        "sources":["https://doi.org/10.6028/NIST.FIPS.204",
                   "https://docs.openssl.org/3.5/man1/openssl-pkeyutl/"]})
    gates=[
        {"gate":"real_mldsa65_sign_verify","status":status,"evidence":f"{len(cases)} adversarial tests"},
        {"gate":"signed_record_tamper_detection","status":"PASS_TESTED_ONLY" if status=="PASS" else "FAIL","evidence":"modified fields and signature rejected"},
        {"gate":"share_digest_binding","status":"PASS_TESTED_ONLY" if status=="PASS" else "FAIL","evidence":"changed bytes rejected"},
        {"gate":"issuer_key_pinning","status":"PASS_TESTED_ONLY" if status=="PASS" else "FAIL","evidence":"rogue key rejected"},
        {"gate":"replay_without_external_state","status":"FAIL_STATIC_REPLAY","evidence":"exact replay accepted"},
        {"gate":"human_optical_issuer_authentication","status":"NOT_ESTABLISHED","evidence":"No human optical verifier"},
        {"gate":"physical_share_binding","status":"NOT_ESTABLISHED","evidence":"No trusted physical-to-digital measurement"},
        {"gate":"confidentiality","status":"NOT_EVALUATED","evidence":"No privacy game"},
    ]
    with (rep/"feasibility_gates.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=["gate","status","evidence"])
        w.writeheader();w.writerows(gates)
    verdict={
        "execution":status,
        "electronic_enrollment_authenticity":"PASS_TESTED_ONLY" if status=="PASS" else "FAIL",
        "optical_integrity":"UNRESOLVED",
        "human_optical_issuer_authentication":"NOT_ESTABLISHED",
        "research_verdict":"NO_SECURITY_QUALIFIED_CONSTRUCTION",
        "universal_impossibility_theorem":"NOT_CLAIMED"}
    save(rep/"verdict.json",verdict)
    summary={"execution":status,"openssl_version":version,
             "algorithm":ALG,"tests_passed":sum(x["test_pass"] for x in cases),
             "tests_total":len(cases),"signature_bytes":signature_bytes,
             "public_key_pem_bytes":public_bytes,"c07_source_status":source["status"],
             "electronic_enrollment_authenticity":verdict["electronic_enrollment_authenticity"],
             "research_verdict":verdict["research_verdict"]}
    save(rep/"summary.json",summary)
    report=["# EOW_C08 — Real ML-DSA-65 Enrollment Audit","",
            f"**Execution:** {status}; **tests:** {summary['tests_passed']}/{len(cases)}.",
            f"**OpenSSL:** {version}.",
            f"**Signature size:** {signature_bytes} bytes.","",
            "## Adversarial cases","",
            "| Case | Expected | Observed | Reason |",
            "|---|---|---|---|"]
    for c in cases:
        report.append(f"| {c['case']} | {c['expected_accept']} | {c['observed_accept']} | {c['reason']} |")
    report+=["","## Security boundary","",
             "A verified signature binds the *digital* enrollment record and its issued-share digest to the pinned issuer key.",
             "It does not establish that a physical transparency is the signed share, that an unaided observer authenticates the issuer, or that OR-stacking forgery resistance is achieved.",
             "A trusted external revocation/freshness state is necessary to reject an exact replay when freshness is required.",
             "Private keys are temporary TEST-ONLY keys and are not exported.","",
             "## References","",
             "- [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)",
             "- [OpenSSL pkeyutl ML-DSA documentation](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/)"]
    (rep/"scientific_report.md").write_text("\n".join(report)+"\n",encoding="utf-8")
    print(json.dumps(summary,indent=2))
    return 0 if status=="PASS" else 1
if __name__=="__main__":
    raise SystemExit(main())
