#!/usr/bin/env python3
"""EOW_C07 — exact finite-domain privacy–integrity feasibility investigation.

NOT a proof of universal impossibility. Models classical two-subpixel (2,2)
visual secret sharing, independent uniformly random OR challenge masks, and
several exact observer/custody views. An enrolled expected response is computed
from the legitimate second share and the challenge mask. The verifier's
comparison is an IDEAL computational surrogate, not demonstrated human vision.

Python 3.10+; standard library only.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import itertools
import json
import math
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REFERENCES = {
    "visual_cryptography": "https://doi.org/10.1007/BFb0053419",
    "ml_dsa": "https://doi.org/10.6028/NIST.FIPS.204",
}

def save_json(p, x):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(x, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def save_csv(p, rows, cols):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

def bit(x, i):
    return (x >> i) & 1

def fmt(x, n):
    return "".join(str(bit(x, i)) for i in range(n))

def shares(secret, pad, n):
    a = b = 0
    for i in range(n):
        v = bit(pad, i)
        a |= (1 << (2*i+v))
        b |= (1 << (2*i+(v ^ bit(secret, i))))
    return a, b

def content(a, b, n):
    x = a | b
    return tuple(bit(x, 2*i) + bit(x, 2*i+1) for i in range(n))

def optical(b, mask, n, observer):
    x = b | mask
    if observer == "exact_or":
        return x
    if observer == "black_count":
        return tuple(bit(x, 2*i) + bit(x, 2*i+1) for i in range(n))
    raise ValueError(observer)

def tv(x, y):
    nx, ny = sum(x.values()), sum(y.values())
    return sum(abs(x.get(k,0)/nx - y.get(k,0)/ny) for k in x.keys() | y.keys())/2

def entropy(probs):
    return -sum(p*math.log2(p) for p in probs if p > 0)

def info_stats(joint, n):
    """Exact empirical distribution under uniform secret/pad/mask.

    Returns I(S;V), maximum pairwise TV, and optimal MAP guessing probability.
    """
    totals = Counter()
    by_secret = {s:Counter() for s in range(1 << n)}
    by_view = {}
    for (s,v), count in joint.items():
        totals[v] += count
        by_secret[s][v] += count
        by_view.setdefault(v,Counter())[s] += count
    N = sum(joint.values())
    ps = Counter()
    for (s,v), count in joint.items():
        ps[s] += count
    h_s = entropy([x/N for x in ps.values()])
    h_cond = sum((sum(c.values())/N)*entropy([x/sum(c.values()) for x in c.values()])
                 for c in by_view.values())
    map_success = sum(max(c.values()) for c in by_view.values())/N
    max_tv = max((tv(by_secret[a],by_secret[b])
                  for a,b in itertools.combinations(range(1<<n),2)), default=0.0)
    return {"mutual_information_bits":round(h_s-h_cond,12),
            "secret_entropy_bits":round(h_s,12),
            "conditional_entropy_bits":round(h_cond,12),
            "max_pairwise_tv":round(max_tv,12),
            "map_secret_guess_probability":round(map_success,12),
            "observations":N,
            "distinct_views":len(totals)}

def privacy(n, observer):
    width=2*n
    views = (
        "public_A",
        "public_A_mask",
        "public_A_expected",
        "public_A_mask_expected",
        "public_A_B",
        "B_only",
        "B_mask",
        "B_expected",
        "B_mask_expected",
        "A_B_mask_expected",
    )
    joint={v:Counter() for v in views}
    for s,pad,mask in itertools.product(range(1<<n),range(1<<n),range(1<<width)):
        a,b=shares(s,pad,n)
        expected=optical(b,mask,n,observer)
        vmap={
            "public_A":(a,),
            "public_A_mask":(a,mask),
            "public_A_expected":(a,expected),
            "public_A_mask_expected":(a,mask,expected),
            "public_A_B":(a,b),
            "B_only":(b,),
            "B_mask":(b,mask),
            "B_expected":(b,expected),
            "B_mask_expected":(b,mask,expected),
            "A_B_mask_expected":(a,b,mask,expected),
        }
        for name,view in vmap.items():
            joint[name][(s,view)]+=1
    return [{"observer":observer,"view":name,**info_stats(joint[name],n)} for name in views]

def integrity(n, observer):
    """Exact attack enumeration for each enrolled (S,pad).

    Adversary knows A and B, commits to B' before uniform private challenge.
    Optimal precommit success is the maximum over content-changing B'.
    Also records public-mask vulnerability and conditional masking structure.
    """
    width=2*n
    masks=range(1<<width)
    results=[]
    examples=[]
    for s,pad in itertools.product(range(1<<n),repeat=2):
        a,b=shares(s,pad,n)
        baseline=content(a,b,n)
        candidates=[x for x in range(1<<width) if content(a,x,n)!=baseline]
        success=[]
        public_vulnerable=0
        for altered in candidates:
            accepted=sum(optical(altered,m,n,observer)==optical(b,m,n,observer)
                         for m in masks)
            success.append((accepted,altered))
        best_count,best_b=max(success,default=(0,b))
        for m in masks:
            if any(optical(x,m,n,observer)==optical(b,m,n,observer) for x in candidates):
                public_vulnerable+=1
        if best_count and len(examples)<10:
            passing=next(m for m in masks
                         if optical(best_b,m,n,observer)==optical(b,m,n,observer))
            examples.append({
                "observer":observer,"secret":fmt(s,n),"pad":fmt(pad,n),
                "share_A":fmt(a,width),"legitimate_B":fmt(b,width),
                "modified_B":fmt(best_b,width),"passing_mask":fmt(passing,width),
                "legitimate_content":baseline,"modified_content":content(a,best_b,n),
                "passing_masks":best_count,"total_masks":1<<width})
        results.append({
            "observer":observer,"secret":fmt(s,n),"pad":fmt(pad,n),
            "eligible_content_changing":len(candidates),
            "best_accepted_masks":best_count,"challenge_count":1<<width,
            "optimal_precommit_success":best_count/(1<<width),
            "public_vulnerable_masks":public_vulnerable,
            "public_vulnerable_fraction":public_vulnerable/(1<<width),
        })
    return results,examples

def adversary_views(n, observer):
    """Demonstrate exposure tradeoff for one- and two-pixel masks.

    Quantify how many replacement B values are indistinguishable from legitimate
    B for each mask under each observer; no assumption of restricted codebook.
    """
    width=2*n
    rows=[]
    for mask in range(1<<width):
        collisions=[]
        for b in range(1<<width):
            signature=optical(b,mask,n,observer)
            collisions.append(sum(optical(x,mask,n,observer)==signature
                                  for x in range(1<<width))-1)
        rows.append({
            "observer":observer,"mask":fmt(mask,width),
            "opaque_positions":mask.bit_count(),
            "mean_alternative_shares":sum(collisions)/len(collisions),
            "worst_alternative_shares":max(collisions),
            "injective_on_all_binary_shares":all(c==0 for c in collisions),
        })
    return rows

def load_upstream(source):
    if source is None:
        return {"status":"NOT_PROVIDED"}
    p=Path(source)
    if p.is_dir():
        candidates=list(p.glob("reports/verdict.json"))+list(p.glob("EOW_C06/reports/verdict.json"))
        if not candidates:
            return {"status":"MISSING_VERDICT","source":str(p)}
        data=candidates[0].read_bytes()
        return {"status":"LOADED","source":str(candidates[0]),
                "sha256":hashlib.sha256(data).hexdigest(),
                "verdict":json.loads(data)}
    if p.is_file() and zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            names=[n for n in z.namelist() if n.endswith("EOW_C06/reports/verdict.json")]
            if not names:
                return {"status":"MISSING_VERDICT","source":str(p)}
            data=z.read(names[0])
            return {"status":"LOADED","source":str(p),"member":names[0],
                    "sha256":hashlib.sha256(data).hexdigest(),
                    "verdict":json.loads(data)}
    return {"status":"MISSING_VERDICT","source":str(p)}

def tests():
    checks={}
    for n in (1,2,3):
        for s,p in itertools.product(range(1<<n),repeat=2):
            a,b=shares(s,p,n)
            assert content(a,b,n)==tuple(1+bit(s,i) for i in range(n))
    checks["classical_reconstruction"]="PASS"
    for n in (1,2,3):
        for s,p in itertools.product(range(1<<n),repeat=2):
            a,b=shares(s,p,n)
            assert sum(bit(a,2*i)+bit(a,2*i+1) for i in range(n))==n
            assert sum(bit(b,2*i)+bit(b,2*i+1) for i in range(n))==n
    checks["share_weight"]="PASS"
    assert optical(0,3,1,"exact_or")==3
    checks["or_semantics"]="PASS"
    assert optical(1,2,1,"black_count")==(2,)
    checks["black_count_semantics"]="PASS"
    assert tv(Counter({0:2,1:2}),Counter({0:1,1:1}))==0
    checks["tv_normalization"]="PASS"
    x=Counter({(0,(0,)):1,(1,(1,)):1})
    assert info_stats(x,1)["mutual_information_bits"]==1
    checks["mutual_information_full_leak"]="PASS"
    x=Counter({(0,(0,)):1,(0,(1,)):1,(1,(0,)):1,(1,(1,)):1})
    assert info_stats(x,1)["mutual_information_bits"]==0
    checks["mutual_information_zero_leak"]="PASS"
    assert optical(0,3,1,"exact_or")==optical(1,3,1,"exact_or")
    checks["opaque_mask_collision"]="PASS"
    assert optical(0,0,1,"exact_or")!=optical(1,0,1,"exact_or")
    checks["transparent_mask_distinguishes"]="PASS"
    return checks

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bits",type=int,default=3,help="Secret pixels; 1..3")
    ap.add_argument("--c06",type=Path,help="C06 results folder or ZIP")
    ap.add_argument("--strict-c06",action="store_true")
    ap.add_argument("--root",type=Path,help="Experiments root")
    ap.add_argument("--output",type=Path,help="Override output directory")
    args=ap.parse_args()
    if not 1<=args.bits<=3:
        ap.error("Exact enumeration supports --bits 1..3")
    root=args.root or Path(__file__).resolve().parent.parent
    out=args.output or root/"Results"/"EOW_C07"
    rep=out/"reports"
    upstream=load_upstream(args.c06 or root/"Results"/"EOW_C06")
    if args.strict_c06 and upstream["status"]!="LOADED":
        ap.error("C06 verdict not found; specify --c06 path or ZIP")
    checks=tests()
    priv=[]
    attacks=[]
    masks=[]
    examples=[]
    for observer in ("exact_or","black_count"):
        priv.extend(privacy(args.bits,observer))
        rows,ex=integrity(args.bits,observer)
        attacks.extend(rows)
        examples.extend(ex)
        masks.extend(adversary_views(args.bits,observer))
    save_json(out/"configuration"/"run.json",{
        "experiment":"EOW_C07","timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "bits":args.bits,"python":sys.version.split()[0],
        "upstream":upstream["status"],"output":str(out)})
    save_json(rep/"c06_source_audit.json",upstream)
    save_json(rep/"self_tests.json",{"passed":len(checks),"total":len(checks),"checks":checks})
    save_csv(rep/"privacy_information.csv",priv,[
        "observer","view","mutual_information_bits","secret_entropy_bits",
        "conditional_entropy_bits","max_pairwise_tv",
        "map_secret_guess_probability","observations","distinct_views"])
    save_csv(rep/"optimal_integrity_attacks.csv",attacks,[
        "observer","secret","pad","eligible_content_changing",
        "best_accepted_masks","challenge_count","optimal_precommit_success",
        "public_vulnerable_masks","public_vulnerable_fraction"])
    save_csv(rep/"mask_collision_audit.csv",masks,[
        "observer","mask","opaque_positions","mean_alternative_shares",
        "worst_alternative_shares","injective_on_all_binary_shares"])
    save_json(rep/"content_changing_counterexamples.json",examples)
    save_json(rep/"model_assumptions.json",{
        "secret_distribution":"Uniform over all n-bit secrets",
        "share_generation":"Uniform pad, standard 2-subpixel classical (2,2) OR VSS",
        "challenge_distribution":"Uniform over all 2n-bit binary masks",
        "attack":"Attacker knows original A,B; commits B' before challenge; exhaustive over content-changing B'",
        "privacy_views":"Explicitly listed in privacy_information.csv; all are information-theoretic toy views",
        "enrollment":"Trusted reference O(B,mask) available to ideal verifier; no human verification shown",
        "observer_models":["exact_or","black_count"],
        "important_distinctions":[
            "Privacy of a public share is different from privacy after witness compromise",
            "Mutual information, TV, and guessing probability measure different leakage aspects",
            "Attacker knows original shares in integrity game, but privacy games examine separately defined views",
            "Public-mask vulnerability is not an optimal precommit success probability",
            "Static exact-copy replay is outside content-changing integrity; freshness depends on application",
            "No real physical optics, fabrication, human experiment, or ML-DSA",
            "Small finite domains do not imply general impossibility",
        ],"references":REFERENCES})
    # Interpret each mandatory gate conservatively.
    public=[r for r in priv if r["view"]=="public_A"]
    exposure=[r for r in priv if r["view"]=="public_A_mask_expected"]
    worst=max(r["optimal_precommit_success"] for r in attacks)
    gates=[
        {"gate":"correctness","status":"PASS_TOY","evidence":"9/9 unit tests and exact classical reconstruction"},
        {"gate":"public_one_share_privacy","status":"PASS_TOY" if all(r["max_pairwise_tv"]==0 for r in public) else "FAIL_TOY",
         "evidence":str(max(r["max_pairwise_tv"] for r in public))},
        {"gate":"exposed_enrollment_privacy","status":"FAIL_TOY" if any(r["max_pairwise_tv"]>0 for r in exposure) else "PASS_TOY",
         "evidence":str(max(r["max_pairwise_tv"] for r in exposure))},
        {"gate":"content_integrity","status":"FAIL_TOY" if worst>0 else "PASS_TESTED_ONLY",
         "evidence":str(worst)},
        {"gate":"human_optical_verification","status":"NOT_ESTABLISHED","evidence":"No human participant study"},
        {"gate":"post_quantum_issuer_binding","status":"NOT_TESTED","evidence":"No ML-DSA implementation"},
        {"gate":"physical_robustness","status":"NOT_TESTED","evidence":"No calibrated optical perturbation"},
        {"gate":"freshness","status":"APPLICATION_DEPENDENT","evidence":"No live-presentation state machine"},
    ]
    save_csv(rep/"feasibility_gates.csv",gates,["gate","status","evidence"])
    verdict={
        "execution":"PASS","research_verdict":"NO_SECURITY_QUALIFIED_CONSTRUCTION",
        "universal_impossibility_theorem":"NOT_CLAIMED",
        "conditional_finding":"Under tested OR-based enrolled reference and uniform private masks, optimal precommitted content-changing forgeries exist and enrollment disclosure leaks information.",
        "recommended_next_action":"Architecture decision before interpreting C08 electronic issuer authentication as optical integrity",
        "human_study":False,"ml_dsa_executed":False}
    save_json(rep/"verdict.json",verdict)
    summary={"bits":args.bits,"self_tests_passed":len(checks),
             "privacy_rows":len(priv),"attack_instances":len(attacks),
             "mask_audit_rows":len(masks),"counterexamples":len(examples),
             "c06_source_status":upstream["status"],
             "worst_optimal_precommit_success":worst,
             "max_enrollment_exposure_tv":max(r["max_pairwise_tv"] for r in exposure),
             "research_verdict":verdict["research_verdict"]}
    save_json(rep/"summary.json",summary)
    report=[
        "# EOW_C07 — Privacy–Integrity Feasibility Diagnostic","",
        "**Research verdict:** NO_SECURITY_QUALIFIED_CONSTRUCTION.",
        "**Scope:** exact finite-domain computational experiment, not a universal impossibility theorem.","",
        "## Principal findings","",
        f"- Public one-share privacy max TV: {max(r['max_pairwise_tv'] for r in public):.6g}.",
        f"- Enrollment-exposure max TV: {max(r['max_pairwise_tv'] for r in exposure):.6g}.",
        f"- Worst optimal precommitted content-changing forgery probability: {worst:.6g}.",
        "- Secret/pad/challenge enumerated exhaustively for the selected domain.",
        "- Human verification and post-quantum issuer binding remain untested.","",
        "## Per-view information leakage","",
        "| Observer | View | I(S;V) bits | Max TV | MAP guess |",
        "|---|---|---:|---:|---:|"]
    for r in priv:
        report.append("| {} | {} | {:.6g} | {:.6g} | {:.6g} |".format(
            r["observer"],r["view"],r["mutual_information_bits"],
            r["max_pairwise_tv"],r["map_secret_guess_probability"]))
    report.extend(["","## Interpretation","",
        "A protected witness may provide an ideal integrity comparison while its disclosure leaks the secret. An OR mask hides modified subpixels, creating content-changing collisions. These are conditional findings for the specified construction and exposure views.",
        "An exact comparator is not evidence of unaided human optical authentication. Electronic ML-DSA enrollment does not by itself provide a passive optical issuer check.",
        "","## Sources","",
        "- [Naor and Shamir, Visual Cryptography](https://doi.org/10.1007/BFb0053419)",
        "- [NIST FIPS 204, ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)"])
    (rep/"scientific_report.md").write_text("\n".join(report)+"\n",encoding="utf-8")
    print(json.dumps(summary,indent=2))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
