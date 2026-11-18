#!/usr/bin/env python3
"""EOW_C10: honest image-level benchmark of classical OR-VSS and OR-mask witnesses.

Requires Pillow: python -m pip install Pillow
Optional MATLAB .mat input: python -m pip install scipy numpy
No images are fabricated or silently substituted. Unsupported/corrupt files
are reported. Each decoded source is binarized, then a fresh random (2,2)
classical VSS share pair is generated. A one-subpixel content-changing attack
is tested against random hidden masks; this is an ATTACK BASELINE, not a
security-qualified optical verifier or a human study.

Privacy is not inferred from visual statistics on a finite dataset; refer to
C07's distributional games. Electronic enrollment is not re-run; refer to C08.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, math, random, statistics, sys, time, tracemalloc, zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

IMAGE_EXT={".jpg",".jpeg",".png",".bmp",".tif",".tiff",".webp"}
MAT_EXT={".mat"}
def write_json(p,x):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(x,indent=2,sort_keys=True,default=str)+"\n",encoding="utf-8")
def write_csv(p,rows,cols):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=cols,extrasaction="ignore")
        w.writeheader();w.writerows(rows)
def audit_upstream(p):
    if p is None: return {"status":"NOT_PROVIDED"}
    p=Path(p)
    if p.is_dir():
        matches=list(p.glob("reports/verdict.json"))+list(p.glob("EOW_C09/reports/verdict.json"))
        if matches:
            raw=matches[0].read_bytes()
            return {"status":"LOADED","source":str(matches[0]),
                    "sha256":hashlib.sha256(raw).hexdigest(),"verdict":json.loads(raw)}
    elif p.is_file() and zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            matches=[n for n in z.namelist() if n.endswith("EOW_C09/reports/verdict.json")]
            if matches:
                raw=z.read(matches[0])
                return {"status":"LOADED","source":str(p),"member":matches[0],
                        "sha256":hashlib.sha256(raw).hexdigest(),"verdict":json.loads(raw)}
    return {"status":"MISSING_VERDICT","source":str(p)}
def discover(folder,include_mat):
    extensions=IMAGE_EXT | (MAT_EXT if include_mat else set())
    return sorted((p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in extensions),
                  key=lambda p:p.relative_to(folder).as_posix().lower())
def load_binary(path,max_side,mat_key=None):
    from PIL import Image,ImageOps
    if path.suffix.lower()==".mat":
        try:
            import numpy as np
            from scipy.io import loadmat
        except ImportError as e:
            raise RuntimeError("MAT_REQUIRES_SCIPY_AND_NUMPY") from e
        data=loadmat(path)
        if mat_key:
            if mat_key not in data: raise ValueError("MAT_KEY_NOT_FOUND")
            arr=data[mat_key]
        else:
            arrays=[(k,v) for k,v in data.items()
                    if not k.startswith("__") and isinstance(v,np.ndarray)
                    and v.ndim in (2,3) and np.issubdtype(v.dtype,np.number)]
            if len(arrays)!=1:
                raise ValueError("MAT_AMBIGUOUS_ARRAYS:"+",".join(k for k,_ in arrays))
            arr=arrays[0][1]
        if arr.ndim==3:
            if arr.shape[-1] in (1,3,4): arr=arr.mean(axis=-1)
            else: raise ValueError("MAT_UNSUPPORTED_SHAPE")
        if arr.ndim!=2 or arr.size==0: raise ValueError("MAT_UNSUPPORTED_SHAPE")
        arr=np.asarray(arr,dtype=np.float64)
        if not np.isfinite(arr).all(): raise ValueError("MAT_NONFINITE")
        lo,hi=float(arr.min()),float(arr.max())
        if hi>lo: arr=(arr-lo)*255/(hi-lo)
        else: arr=np.full_like(arr,255 if hi>0 else 0)
        im=Image.fromarray(arr.astype("uint8"),"L")
    else:
        with Image.open(path) as original:
            im=ImageOps.exif_transpose(original).convert("L")
    original_size=im.size
    im.thumbnail((max_side,max_side),Image.Resampling.BILINEAR)
    width,height=im.size
    # Fixed threshold, reported explicitly; no data-dependent threshold leakage.
    pixels=im.tobytes()
    bits=bytes(int(x>=128) for x in pixels)
    return bits,width,height,original_size
def make_shares(secret,rng):
    # 0 (white) => same one-black subpixel patterns; 1 (black) => complementary.
    a=bytearray(2*len(secret));b=bytearray(2*len(secret))
    for i,s in enumerate(secret):
        r=rng.getrandbits(1)
        a[2*i+r]=1
        b[2*i+(r^s)]=1
    return a,b
def reconstruct(a,b):
    return bytes(int((a[2*i]|b[2*i])+(a[2*i+1]|b[2*i+1])==2)
                 for i in range(len(a)//2))
def attack(a,b,i):
    """Flip B's one white subpixel to black: guarantees changed OR content
    for a WHITE pixel, while for a BLACK pixel flip its black subpixel to
    white, which guarantees a changed OR content. Only one B bit changes.
    """
    changed=bytearray(b)
    j=2*i
    if a[j]==b[j]:  # white secret; black-count 1 -> 2
        target=j if b[j]==0 else j+1
        changed[target]=1
    else:           # black secret; black-count 2 -> 1
        target=j if b[j]==1 else j+1
        changed[target]=0
    return changed,target
def verify_single_pixel(b,b2,position,mask,observer):
    i=position//2
    j=2*i
    x=(b[j]|mask[0],b[j+1]|mask[1])
    y=(b2[j]|mask[0],b2[j+1]|mask[1])
    return x==y if observer=="exact_or" else sum(x)==sum(y)
def wilson(k,n,z=1.96):
    if n==0:return (None,None)
    p=k/n; den=1+z*z/n
    mid=(p+z*z/(2*n))/den
    rad=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return (max(0,mid-rad),min(1,mid+rad))
def tests():
    rng=random.Random(5)
    for s in (bytes([0]),bytes([1]),bytes([0,1,1,0]),bytes([1]*64)):
        a,b=make_shares(s,rng)
        assert reconstruct(a,b)==s
        for i in range(len(s)):
            b2,pos=attack(a,b,i)
            assert sum(x!=y for x,y in zip(b,b2))==1
            assert reconstruct(a,b2)!=s
            for observer in ("exact_or","black_count"):
                accept=[verify_single_pixel(b,b2,pos,(m&1,(m>>1)&1),observer)
                        for m in range(4)]
                assert sum(accept)==2, (s,i,observer,accept)
    return {"vss_reconstruction":"PASS","one_bit_attack_changes_content":"PASS",
            "exact_or_mask_probability_half":"PASS",
            "black_count_mask_probability_half":"PASS"}
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset",type=Path,required=True,help="Directory with actual image files")
    ap.add_argument("--root",type=Path,help="Experiments root; defaults to script parent parent")
    ap.add_argument("--output",type=Path)
    ap.add_argument("--c09",type=Path)
    ap.add_argument("--strict-c09",action="store_true")
    ap.add_argument("--max-side",type=int,default=128)
    ap.add_argument("--trials-per-image",type=int,default=128)
    ap.add_argument("--seed",type=int,default=20261115)
    ap.add_argument("--include-mat",action="store_true",help="Process MATLAB .mat arrays (scipy/numpy required)")
    ap.add_argument("--mat-key",help="Explicit MATLAB array key if files contain multiple arrays")
    ap.add_argument("--limit",type=int,help="Pilot only: process first N discovered files")
    ap.add_argument("--require-count",type=int,help="Fail if number of successfully decoded files differs")
    args=ap.parse_args()
    if not args.dataset.is_dir():ap.error("Dataset directory does not exist")
    if args.max_side<1 or args.trials_per_image<1:ap.error("max-side and trials-per-image must be positive")
    if args.limit is not None and args.limit<1:ap.error("limit must be positive")
    try:from PIL import Image
    except ImportError:ap.error("Pillow is required: python -m pip install Pillow")
    root=args.root or Path(__file__).resolve().parent.parent
    out=args.output or root/"Results"/"EOW_C10"
    report=out/"reports"
    upstream=audit_upstream(args.c09 or root/"Results"/"EOW_C09")
    if args.strict_c09 and upstream["status"]!="LOADED":
        ap.error("C09 verdict missing; pass --c09 ZIP or folder")
    checks=tests()
    allfiles=discover(args.dataset,args.include_mat)
    selected=allfiles[:args.limit] if args.limit else allfiles
    if not selected:ap.error("No eligible files discovered. Check --dataset and --include-mat.")
    results=[]; failures=[]; duplicates=Counter()
    rng=random.Random(args.seed)
    tracemalloc.start()
    started=time.perf_counter()
    for idx,path in enumerate(selected,1):
        rel=path.relative_to(args.dataset).as_posix()
        t0=time.perf_counter()
        try:
            # Hash raw bytes, not reconstructed or transformed image.
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            duplicates[digest]+=1
            secret,w,h,original_size=load_binary(path,args.max_side,args.mat_key)
            if not secret:raise ValueError("EMPTY_IMAGE")
            a,b=make_shares(secret,rng)
            correct=(reconstruct(a,b)==secret)
            if not correct:raise AssertionError("RECONSTRUCTION_MISMATCH")
            trials=min(args.trials_per_image,len(secret))
            # Independent random positions, repeated positions allowed for small images.
            accepted={"exact_or":0,"black_count":0}
            for _ in range(trials):
                pixel=rng.randrange(len(secret))
                modified,changed_bit=attack(a,b,pixel)
                mask=(rng.getrandbits(1),rng.getrandbits(1))
                for observer in accepted:
                    accepted[observer]+=int(verify_single_pixel(b,modified,changed_bit,mask,observer))
            elapsed=time.perf_counter()-t0
            results.append({"file":rel,"sha256":digest,"source_width":original_size[0],
                "source_height":original_size[1],"processed_width":w,"processed_height":h,
                "pixels":len(secret),"black_fraction":sum(secret)/len(secret),
                "reconstruction_correct":correct,"attack_trials":trials,
                "exact_or_accepted":accepted["exact_or"],
                "black_count_accepted":accepted["black_count"],
                "exact_or_attack_rate":accepted["exact_or"]/trials,
                "black_count_attack_rate":accepted["black_count"]/trials,
                "elapsed_seconds":round(elapsed,6)})
        except Exception as e:
            failures.append({"file":rel,"error_type":type(e).__name__,"message":str(e)[:250]})
        if idx%50==0:print(f"Processed {idx}/{len(selected)}; decoded={len(results)}; failed={len(failures)}",flush=True)
    duration=time.perf_counter()-started
    _,peak=tracemalloc.get_traced_memory()
    tracemalloc.stop()
    cols=["file","sha256","source_width","source_height","processed_width",
          "processed_height","pixels","black_fraction","reconstruction_correct",
          "attack_trials","exact_or_accepted","black_count_accepted",
          "exact_or_attack_rate","black_count_attack_rate","elapsed_seconds"]
    write_csv(report/"image_level_results.csv",results,cols)
    write_csv(report/"failed_inputs.csv",failures,["file","error_type","message"])
    write_json(report/"c09_source_audit.json",upstream)
    write_json(report/"self_tests.json",{"passed":len(checks),"total":len(checks),"checks":checks})
    n=sum(r["attack_trials"] for r in results)
    rates={}
    for observer in ("exact_or","black_count"):
        k=sum(r[f"{observer}_accepted"] for r in results)
        lo,hi=wilson(k,n)
        rates[observer]={"accepted":k,"trials":n,"empirical_acceptance":k/n if n else None,
                         "wilson_95pct_interval":[lo,hi],
                         "structural_exact_single_flip_probability":0.5}
    success=len(results)
    duplicate_extra=sum(x-1 for x in duplicates.values() if x>1)
    counts_ok=args.require_count is None or success==args.require_count
    summary={"discovered_eligible_files":len(allfiles),
             "selected_files":len(selected),"decoded_files":success,
             "failed_files":len(failures),"duplicate_extra_by_sha256":duplicate_extra,
             "total_processed_pixels":sum(r["pixels"] for r in results),
             "total_attack_trials":n,"all_reconstructions_correct":all(r["reconstruction_correct"] for r in results),
             "attack_rates":rates,"elapsed_seconds":round(duration,4),
             "peak_tracemalloc_bytes":peak,"c09_source_status":upstream["status"],
             "pilot_run":args.limit is not None,"required_count":args.require_count,
             "required_count_satisfied":counts_ok,
             "research_verdict":"NO_SECURITY_QUALIFIED_CONSTRUCTION"}
    write_json(report/"summary.json",summary)
    write_json(out/"configuration"/"run.json",{
        "experiment":"EOW_C10","timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "dataset":str(args.dataset.resolve()),"max_side":args.max_side,
        "trials_per_image":args.trials_per_image,"seed":args.seed,
        "include_mat":args.include_mat,"mat_key":args.mat_key,
        "limit":args.limit,"require_count":args.require_count,
        "python":sys.version.split()[0],"pillow":Image.__version__})
    write_json(report/"model_assumptions.json",{
        "binarization":"grayscale intensity >=128 => black; otherwise white",
        "resizing":"Pillow thumbnail with bilinear resampling; longest dimension <= max-side",
        "secret_sampling":"actual decoded images, NOT synthetic replacements",
        "share_encoding":"randomized 2-subpixel (2,2) classical OR VSS, independently sampled per pixel",
        "attack":"one changed B subpixel, guaranteed to change reconstructed pixel; random pixel per trial",
        "challenge":"two independent uniform mask bits at attacked pixel; ideal exact OR and black-count",
        "confidence_intervals":"Wilson descriptive interval for pooled Bernoulli trials; does not correct for shared images",
        "structural_limit":"one-subpixel forgery succeeds with exact probability 1/2 under this uniform-mask game",
        "privacy":"NOT inferred from finite dataset; C07 remains the source of privacy-game conclusions",
        "enrollment":"C08 evidence is upstream; no cryptographic operations here",
        "optical":"computational surrogates only; no physical measurements or human participants",
        "file_handling":"decode errors reported, no fabricated replacements; SHA-256 duplicates counted",
        "mat":"MAT files skipped unless --include-mat; ambiguous arrays rejected unless --mat-key",
        "references":["https://doi.org/10.1007/BFb0053419",
                      "https://doi.org/10.6028/NIST.FIPS.204"]})
    gates=[
        {"gate":"execution","status":"PASS" if success and counts_ok else "FAIL","evidence":f"{success} decoded"},
        {"gate":"reconstruction","status":"PASS_TESTED_ONLY" if success and summary["all_reconstructions_correct"] else "FAIL","evidence":f"{success} images"},
        {"gate":"content_integrity","status":"FAIL_MODEL","evidence":"one-subpixel content-changing forgery succeeds with probability 0.5"},
        {"gate":"privacy","status":"NOT_TESTED","evidence":"dataset statistics are not information-theoretic privacy games"},
        {"gate":"human_optical_verification","status":"NOT_ESTABLISHED","evidence":"no human participants"},
        {"gate":"physical_robustness","status":"NOT_TESTED","evidence":"no print/registration/illumination tests"},
        {"gate":"post_quantum_enrollment","status":"UPSTREAM_ONLY","evidence":"C08 separate experiment"},
    ]
    write_csv(report/"feasibility_gates.csv",gates,["gate","status","evidence"])
    verdict={"execution":"PASS" if success and counts_ok else "FAIL",
             "benchmark_type":"FULL_DATASET_BASELINE" if args.limit is None else "PILOT_BASELINE",
             "research_verdict":"NO_SECURITY_QUALIFIED_CONSTRUCTION",
             "human_optical_integrity":"NOT_ESTABLISHED",
             "cryptographic_enrollment":"NOT_RETESTED",
             "universal_impossibility_theorem":"NOT_CLAIMED"}
    write_json(report/"verdict.json",verdict)
    lines=["# EOW_C10 — Full-Dataset OR-VSS Baseline Benchmark","",
           f"- Decoded {success} / {len(selected)} selected files ({len(failures)} failures).",
           f"- Source-file SHA-256 duplicate extras: {duplicate_extra}.",
           f"- Reconstructed correctly: {sum(r['reconstruction_correct'] for r in results)}.",
           f"- Total attack trials: {n}.",
           f"- Elapsed wall-clock time: {duration:.3f} seconds.",
           f"- Peak Python tracemalloc allocation: {peak} bytes (not full process RSS).","",
           "## Attack baseline",""]
    for obs,metric in rates.items():
        lines.append(f"- {obs}: {metric['accepted']}/{metric['trials']} accepted; "
                     f"empirical={metric['empirical_acceptance']}; "
                     f"Wilson 95% interval={metric['wilson_95pct_interval']}.")
    lines+=["","The exact structural acceptance probability for the selected one-bit attack is 1/2 under the specified independent uniform mask. The empirical rate is a sampling diagnostic, not a proof of image-size-dependent security.","",
            "## Limitations","",
            "This is a resized binary-image baseline. It does not test physical transparency fabrication, registration, human perception, issuer verification, or general adversarial optimality. Input errors and duplicates are disclosed. The C07 privacy and C08 enrollment results are separate.",
            "","## References","",
            "- [Naor and Shamir — Visual Cryptography](https://doi.org/10.1007/BFb0053419)",
            "- [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)"]
    (report/"scientific_report.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps(summary,indent=2))
    if not success or not counts_ok:return 2
    return 0
if __name__=="__main__":
    raise SystemExit(main())
