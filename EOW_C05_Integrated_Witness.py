#!/usr/bin/env python3
"""EOW_C05: falsification-oriented integrated optical witness experiment.

Three candidate mechanisms, all TOY MODELS:
  detached_tag: a publicly transferable tag independent of the protected data.
  distributed_tag: per-pixel secret-key-masked parity tags, still transplantable.
  private_spatial_probe: protected spatial mask and enrolled expected OR pattern;
      requires a trusted, private expected response (ideal comparator).

Classical Naor-Shamir (2,2) shares are generated with two subpixels per pixel.
This is NOT a physical implementation, human study, ML-DSA verification, or
post-quantum optical-authentication proof. Python 3.10+, stdlib only.
"""
from __future__ import annotations
import argparse, csv, hashlib, itertools, json, random, sys, zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

MODELS = ("detached_tag", "distributed_tag", "private_spatial_probe")
OBSERVERS = ("exact_or", "per_pixel_black_count")
REFS = {
    "Naor-Shamir": "https://doi.org/10.1007/BFb0053419",
    "NIST-FIPS-204": "https://doi.org/10.6028/NIST.FIPS.204",
}

def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def bit(x, i):
    return (x >> i) & 1

def bitstr(x, n):
    return "".join(str(bit(x, i)) for i in range(n))

def encode(s, pad, n):
    a = b = 0
    for i in range(n):
        for j in range(2):
            v = int(j == bit(pad, i))
            a |= v << (2*i+j)
            b |= (v ^ bit(s, i)) << (2*i+j)
    return a, b

def visible(a, b, n):
    return tuple(((a | b) >> (2*i) & 1) + ((a | b) >> (2*i+1) & 1) for i in range(n))

def observation(data, mask, n, observer):
    x = data | mask
    if observer == "exact_or":
        return x
    return tuple(bit(x, 2*i) + bit(x, 2*i+1) for i in range(n))

def parity(x):
    return x.bit_count() & 1

def distributed_tag(b, key, otp, n):
    # The tag at every pixel depends on its local data bits and a secret mask.
    # Independent OTP bits make the public tag statistically independent of B.
    result = 0
    for i in range(n):
        local = (b >> (2*i)) & 3
        k = (key >> (2*i)) & 3
        t = parity(local & k) ^ bit(otp, i)
        result |= t << i
    return result

def make_enrollment(model, a, b, n, key, otp, probe):
    if model == "detached_tag":
        return {"tag": otp, "mask": 0, "expected": 0, "key": key, "otp": otp}
    if model == "distributed_tag":
        return {"tag": distributed_tag(b, key, otp, n),
                "mask": 0, "expected": 0, "key": key, "otp": otp}
    # A private mask is an enrolled optical layer; the expected response is
    # trusted and private. This comparator is NOT automatically human-readable.
    return {"tag": 0, "mask": probe, "expected": b | probe,
            "key": key, "otp": otp}

def accepts(model, enrolled, submitted_b, submitted_tag, n, observer):
    if model in ("detached_tag", "distributed_tag"):
        # Human checks ONLY tag; no trusted way to recompute keyed data binding.
        return submitted_tag == enrolled["tag"]
    return observation(submitted_b, enrolled["mask"], n, observer) == observation(
        enrolled["expected"], 0, n, observer)

def privacy_tv(distributions):
    keys = list(distributions)
    if len(keys) < 2:
        return 0.0
    tv = 0.0
    for i in range(len(keys)):
        for j in range(i+1, len(keys)):
            x, y = distributions[keys[i]], distributions[keys[j]]
            nx, ny = sum(x.values()), sum(y.values())
            tv = max(tv, sum(abs(x.get(k,0)/nx-y.get(k,0)/ny)
                              for k in x.keys() | y.keys()) / 2)
    return tv

def privacy_audit(n):
    """Exact secrecy for PUBLIC view (A, public tag), and private compromise.

    Key/OTP are uniformly sampled over finite domains; private mask is not
    disclosed. For the probe model, public tag is constant. Compromise views
    include both shares, so TV=1 by construction and are labeled accordingly.
    """
    domain = 1 << n
    views = {}
    for model in MODELS:
        public = {s: Counter() for s in range(domain)}
        compromised = {s: Counter() for s in range(domain)}
        for s, pad, key, otp in itertools.product(range(domain), repeat=4):
            a, b = encode(s, pad, n)
            e = make_enrollment(model, a, b, n, key, otp, 0)
            public[s][(a, e["tag"])] += 1
            # Full compromise includes the second share B, which is intentionally
            # outside the allowed public threat view.
            compromised[s][(a, b, e["tag"], key, otp)] += 1
        views[model] = {
            "public_A_and_tag_max_tv": privacy_tv(public),
            "compromised_A_B_key_otp_max_tv": privacy_tv(compromised),
            "public_view": "A and published tag only; B and private enrollment excluded",
            "compromised_view": "A,B,key,OTP; deliberately exposes reconstruction pair",
        }
    return views

def run_attacks(n, seed):
    # Deterministic exact enumeration of (secret,pad, replacement B, keys, probes)
    # with multiple enrollment randomizations. The randomizations are not a
    # security parameter and must not be interpreted as cryptographic strength.
    width = 2*n
    domain = 1 << n
    mask_width = (1 << width)-1
    rng = random.Random(seed)
    rows, examples = [], []
    for model in MODELS:
        for observer in OBSERVERS:
            counters = Counter()
            for s in range(domain):
                for pad in range(domain):
                    a, b = encode(s, pad, n)
                    # Four predeclared independent enrollment states.
                    for rep in range(4):
                        key = rng.randrange(1 << width)
                        otp = rng.randrange(domain)
                        probe = rng.randrange(1 << width)
                        e = make_enrollment(model, a, b, n, key, otp, probe)
                        assert accepts(model, e, b, e["tag"], n, observer)
                        counters["legitimate"] += 1
                        for replacement in range(1 << width):
                            if replacement == b:
                                continue
                            counters["modified"] += 1
                            content_changed = visible(a, replacement, n) != visible(a, b, n)
                            if content_changed:
                                counters["visible_changed"] += 1
                            # Attacker can transplant the public tag intact.
                            ok = accepts(model, e, replacement, e["tag"], n, observer)
                            if ok:
                                counters["accepted_modified"] += 1
                                if content_changed:
                                    counters["accepted_visible_changed"] += 1
                                    if len(examples) < 12:
                                        examples.append({
                                            "model":model, "observer":observer,
                                            "secret":bitstr(s,n), "A":bitstr(a,width),
                                            "B":bitstr(b,width),
                                            "replacement_B":bitstr(replacement,width),
                                            "probe_mask":bitstr(e["mask"],width),
                                            "public_tag":bitstr(e["tag"],n),
                                            "note":"Accepted modified share with changed OR reconstruction"
                                        })
                        # exact copy always accepted; this is not anti-replay.
                        assert accepts(model, e, b, e["tag"], n, observer)
                        counters["exact_copy_accepted"] += 1
                        # A one-bit perturbation of the trusted mask is modeled
                        # as an alignment/defect surrogate, not physical tolerance.
                        altered_mask = dict(e)
                        altered_mask["mask"] ^= 1
                        if model == "private_spatial_probe":
                            counters["mask_defect_cases"] += 1
                            if not accepts(model, altered_mask, b, e["tag"], n, observer):
                                counters["mask_defect_rejected"] += 1
            row = {"model":model,"observer":observer,"bits":n, **counters}
            row["accepted_visible_fraction"] = (
                counters["accepted_visible_changed"]/counters["visible_changed"]
                if counters["visible_changed"] else 0.0)
            rows.append(row)
    return rows, examples

def probe_coverage(n):
    """For a fixed B, characterize OR mask blind spots exactly.

    If probe bit is 1, corresponding B bit is hidden. If probe bit is 0,
    exact OR reveals that bit. Black-count observation may have more collisions.
    """
    width=2*n
    out=[]
    for observer in OBSERVERS:
        for mask in range(1 << width):
            collisions=0
            content_collisions=0
            for b in range(1 << width):
                baseline=observation(b,mask,n,observer)
                for candidate in range(1 << width):
                    if candidate != b and observation(candidate,mask,n,observer)==baseline:
                        collisions += 1
                        if candidate != b:
                            content_collisions += 1
            out.append({"observer":observer,"mask":bitstr(mask,width),
                        "hidden_positions":mask.bit_count(),
                        "ordered_collisions":collisions,
                        "nonidentical_collisions":content_collisions})
    return out

def source_audit(c04):
    if not c04:
        return {"status":"NOT_PROVIDED"}
    p=Path(c04)
    if p.is_dir():
        candidates=[p/"reports"/"verdict.json",p/"EOW_C04"/"reports"/"verdict.json"]
        for c in candidates:
            if c.is_file():
                return {"status":"LOADED","path":str(c),"sha256":sha(c.read_bytes()),
                        "verdict":json.loads(c.read_text(encoding="utf-8"))}
        return {"status":"MISSING_VERDICT","path":str(p)}
    if p.is_file() and zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            names=[x for x in z.namelist() if x.endswith("EOW_C04/reports/verdict.json")]
            if names:
                data=z.read(names[0])
                return {"status":"LOADED","path":str(p),"member":names[0],
                        "sha256":sha(data),"verdict":json.loads(data)}
    return {"status":"MISSING_VERDICT","path":str(p)}

def self_tests():
    checks={}
    for n in (1,2,3):
        for s in range(1<<n):
            for pad in range(1<<n):
                a,b=encode(s,pad,n)
                assert all(bit(a,2*i)+bit(a,2*i+1)==1 for i in range(n))
                assert all(bit(b,2*i)+bit(b,2*i+1)==1 for i in range(n))
                assert visible(a,b,n)==tuple(1+bit(s,i) for i in range(n))
    checks["classical_vss_reconstruction"]="PASS"
    checks["optical_or_noninjective"]="PASS" if (0|1)==(1|0) else "FAIL"
    assert distributed_tag(0,0,0,2)==0
    checks["distributed_tag_determinism"]="PASS"
    e=make_enrollment("distributed_tag",0,1,2,0,0,0)
    assert accepts("distributed_tag",e,2,e["tag"],2,"exact_or")
    checks["tag_transplantation_counterexample"]="PASS"
    e=make_enrollment("private_spatial_probe",0,1,1,0,0,0)
    assert accepts("private_spatial_probe",e,1,0,1,"exact_or")
    assert not accepts("private_spatial_probe",e,0,0,1,"exact_or")
    checks["probe_clear_detects_changed_bit"]="PASS"
    e=make_enrollment("private_spatial_probe",0,1,1,0,0,3)
    assert accepts("private_spatial_probe",e,0,0,1,"exact_or")
    checks["probe_black_mask_hides_all"]="PASS"
    assert privacy_tv({0:Counter({0:2,1:2}),1:Counter({0:1,1:1})})==0
    checks["tv_normalization"]="PASS"
    return checks

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bits",type=int,default=2,help="Secret pixels, 1..3")
    parser.add_argument("--root",type=Path,help="Experiments root")
    parser.add_argument("--output",type=Path,help="Override results output directory")
    parser.add_argument("--c04",type=Path,help="C04 directory or ZIP")
    parser.add_argument("--strict-c04",action="store_true")
    parser.add_argument("--seed",type=int,default=20261115)
    args=parser.parse_args()
    if not 1 <= args.bits <= 3:
        parser.error("--bits must be between 1 and 3 (exact enumeration)")
    root=args.root or Path(__file__).resolve().parent.parent
    output=args.output or root/"Results"/"EOW_C05"
    reports=output/"reports"
    audit=source_audit(args.c04 or (root/"Results"/"EOW_C04"))
    if args.strict_c04 and audit["status"]!="LOADED":
        parser.error("C04 evidence not found or unreadable; use --c04")
    checks=self_tests()
    write_json(output/"configuration"/"run.json",{
        "experiment":"EOW_C05","timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "bits":args.bits,"seed":args.seed,"python":sys.version.split()[0],
        "output":str(output),"upstream_status":audit["status"]})
    write_json(reports/"c04_source_audit.json",audit)
    write_json(reports/"self_tests.json",{"passed":len(checks),"total":len(checks),"checks":checks})
    privacy=privacy_audit(args.bits)
    rows,examples=run_attacks(args.bits,args.seed)
    coverage=probe_coverage(args.bits)
    write_csv(reports/"attack_enumeration.csv",rows,[
        "model","observer","bits","legitimate","modified","visible_changed",
        "accepted_modified","accepted_visible_changed","accepted_visible_fraction",
        "exact_copy_accepted","mask_defect_cases","mask_defect_rejected"])
    write_csv(reports/"probe_collision_audit.csv",coverage,[
        "observer","mask","hidden_positions","ordered_collisions","nonidentical_collisions"])
    write_json(reports/"privacy_exact.json",privacy)
    write_json(reports/"content_changing_counterexamples.json",examples)
    assumptions={
        "models":{
            "detached_tag":"Public tag can be copied independently of share B",
            "distributed_tag":"Each tag bit is parity(B_pixel & secret_mask_pixel) XOR independent OTP; tag is publicly visible, verification compares the tag only",
            "private_spatial_probe":"Private OR mask and trusted expected OR observation; no human recognition established",
        },
        "attack":"Exhaustive arbitrary replacement of B with A fixed; unchanged tag copied; 4 deterministic seeded enrollment states per secret/pad",
        "observer_models":list(OBSERVERS),
        "confidentiality":"Exact public view (A,tag), with uniform pad/key/OTP; private state excluded; full compromise includes both shares",
        "limitations":[
            "No physical optics, perceptual data, electronic ML-DSA or anti-replay",
            "No theorem for arbitrary n; random enrollment states in attack study are not exhaustive",
            "The spatial probe relies on a trusted expected response and ideal comparison",
            "Private OR masks may leak protected B if revealed; mask custody not solved",
            "Tag comparison is not an integrated content authentication mechanism even when tags are spatially distributed",
            "Privacy view assumes public A and tag, not public B plus tag or compromised enrollment",
            "Probe defect is a logical bit flip, not calibrated misregistration",
        ],
        "references":REFS
    }
    write_json(reports/"model_assumptions.json",assumptions)
    gates=[]
    for model in MODELS:
        relevant=[r for r in rows if r["model"]==model]
        worst=max(r["accepted_visible_changed"] for r in relevant)
        gates += [
            {"model":model,"gate":"public_view_privacy","status":"PASS_TOY_VIEW" if privacy[model]["public_A_and_tag_max_tv"]==0 else "FAIL_TOY_VIEW","evidence":privacy[model]["public_A_and_tag_max_tv"]},
            {"model":model,"gate":"content_changing_integrity","status":"FAIL_TOY_MODEL" if worst else "PASS_TESTED_ONLY","evidence":worst},
            {"model":model,"gate":"human_only_optical_authentication","status":"NOT_ESTABLISHED","evidence":"No human observations"},
            {"model":model,"gate":"post_quantum_issuer_binding","status":"NOT_TESTED","evidence":"No ML-DSA execution"},
            {"model":model,"gate":"replay_resistance","status":"FAIL_STATIC_REPLAY","evidence":"Exact copy accepted"},
            {"model":model,"gate":"physical_robustness","status":"NOT_ESTABLISHED","evidence":"Only toy mask-bit perturbation"},
        ]
    write_csv(reports/"feasibility_gates.csv",gates,["model","gate","status","evidence"])
    verdict={"execution":"PASS","construction":"NO_SECURITY_QUALIFIED_CONSTRUCTION",
             "candidate":"private_spatial_probe_AS_IDEAL_OR_CONTROL_ONLY",
             "reason":"Distributed public tags are transplantable; private OR probes have collisions, trusted-state and perceptual gaps.",
             "human_data_collected":False,"ml_dsa_tested":False}
    write_json(reports/"verdict.json",verdict)
    summary={"bits":args.bits,"self_tests_passed":len(checks),
             "attack_rows":len(rows),"probe_rows":len(coverage),
             "privacy_models":len(privacy),"counterexamples":len(examples),
             "c04_status":audit["status"],"verdict":verdict["construction"]}
    write_json(reports/"summary.json",summary)
    lines=["# EOW_C05 Integrated Witness — Scientific Report","",
           "**Verdict: NO_SECURITY_QUALIFIED_CONSTRUCTION.**","",
           "This is an exact small-domain and seeded-enrollment computational experiment, not a physical or human verification study.","",
           "## Models","",
           "1. Detached tag: a separable control.","2. Distributed keyed parity tags: tags depend on local B data but are checked only against their original public values, allowing transplantation.",
           "3. Private spatial OR probe: a protected mask and trusted expected observation; ideal comparator, not a demonstrated unaided human operation.","",
           "## Attack enumeration","",
           "| Model | Observer | Accepted visible-content changes | Visible-content changes |",
           "|---|---|---:|---:|"]
    for r in rows:
        lines.append("| {} | {} | {} | {} |".format(
            r["model"],r["observer"],r["accepted_visible_changed"],r["visible_changed"]))
    lines += ["","## Privacy","",
              "Public observations are limited to share A and the published tag; no private witness state is exposed."]
    for model,v in privacy.items():
        lines.append("- {}: public TV = {}; full-compromise TV = {}.".format(
            model,v["public_A_and_tag_max_tv"],v["compromised_A_B_key_otp_max_tv"]))
    lines += ["","## Interpretation","",
              "Spatial distribution of keyed tags does not prevent an attacker from transplanting unchanged public tags while modifying the share data.",
              "A private OR probe can detect some alterations but necessarily masks selected subpixels and suffers collisions; exact and black-count observers may differ.",
              "No mechanism here establishes simultaneous confidentiality, optical issuer authenticity, robust human verification, and replay resistance.",
              "","## References","",
              "- [Naor and Shamir, Visual Cryptography](https://doi.org/10.1007/BFb0053419)",
              "- [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)"]
    (reports/"scientific_report.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps(summary,indent=2))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
