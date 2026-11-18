#!/usr/bin/env python3
"""EOW_C13 — printable (2,2) OR-VSS prototype and physical capture audit.

PURPOSE: Physical feasibility of optical reconstruction, NOT security.
Generate PNG/PDF share pairs with calibration fiducials, plus an ideal-overlay
reference and a blank evaluation manifest. After actually printing on transparent
media and physically stacking the shares, photograph the overlay. To evaluate a
capture, fill capture_path and corners_px in captures.json, then run --mode evaluate.
Corners are [top-left, top-right, bottom-right, bottom-left] of the OUTER BLACK
registration square in the captured photo, in captured-image pixel coordinates.
Use OpenCV for homography; physical captures are NEVER fabricated.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,math,random,sys,time
from datetime import datetime,timezone
from pathlib import Path
from PIL import Image,ImageOps,ImageDraw
import numpy as np

try:
    from reportlab.pdfgen import canvas as pdf_canvas
    from reportlab.lib.units import mm
except ImportError:
    pdf_canvas=None
    mm=72/25.4

VERSION="1.1.0"
def save_json(p,v):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(v,indent=2,sort_keys=True,default=str)+"\n",encoding="utf-8")
def save_csv(p,rows,cols):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=cols,extrasaction="ignore");w.writeheader();w.writerows(rows)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def secret_image(path,side):
    with Image.open(path) as f: im=ImageOps.exif_transpose(f).convert("L")
    original=im.size
    im.thumbnail((side,side),Image.Resampling.BILINEAR)
    return np.asarray(im,dtype=np.uint8)<128,original
def encode(secret,rng):
    h,w=secret.shape
    choose=rng.integers(0,2,size=(h,w),dtype=np.uint8)
    a=np.zeros((h,w,2),dtype=np.uint8);b=np.zeros_like(a)
    yy,xx=np.indices((h,w))
    a[yy,xx,choose]=1
    b[yy,xx,choose^secret.astype(np.uint8)]=1
    return a.reshape(h,w*2).astype(bool),b.reshape(h,w*2).astype(bool)
def reconstruct(a,b):
    h,w=a.shape
    return np.logical_or(a,b).reshape(h,w//2,2).all(axis=2)
def check():
    rng=np.random.default_rng(7)
    for v in (False,True):
        s=np.full((7,9),v)
        a,b=encode(s,rng)
        assert np.array_equal(reconstruct(a,b),s)
        assert np.array_equal(a|b,np.logical_or(a,b))
        assert np.all(a.reshape(7,9,2).sum(axis=2)==1)
        assert np.all(b.reshape(7,9,2).sum(axis=2)==1)
    return {"reconstruction":"PASS","logical_overlay":"PASS","one_opaque_subpixel_per_share_pixel":"PASS"}
def fiducial_image(bits,cell_px,margin_cells=6,subpixel_mm=1.4):
    """PNG is an optical-layout preview, not calibrated print geometry."""
    h,w=bits.shape
    margin=margin_cells*cell_px
    im=Image.new("RGB",(w*cell_px+2*margin,h*cell_px+2*margin),"white")
    d=ImageDraw.Draw(im)
    for y in range(h):
        for x in range(w):
            if bits[y,x]:
                x0=margin+x*cell_px;y0=margin+y*cell_px
                d.rectangle((x0,y0,x0+cell_px-1,y0+cell_px-1),fill="black")
    # Four CROSS fiducials, identical to the PDF design in subpixel units.
    # Centers are 3 subpixels outside each payload corner on both axes.
    outer=(margin-3*cell_px,margin-3*cell_px,
           margin+w*cell_px+3*cell_px,margin+h*cell_px+3*cell_px)
    x0,y0,x1,y1=outer
    arm=round(3*cell_px/subpixel_mm)  # physical 3 mm arms
    th=max(1,round(.3*cell_px/subpixel_mm))
    for x in (x0,x1):
        for y in (y0,y1):
            d.line([(x-arm,y),(x+arm,y)],fill="black",width=th)
            d.line([(x,y-arm),(x,y+arm)],fill="black",width=th)
    return im,{"registration_offset_subpixels":3,"payload_box_px":[margin,margin,margin+w*cell_px,margin+h*cell_px],
               "registration_corners_px":[[x0,y0],[x1,y0],[x1,y1],[x0,y1]],
               "canvas_size_px":list(im.size)}
def make_pdf(path,bits,subpixel_mm,paper="A4",margin_mm=15):
    if pdf_canvas is None:raise RuntimeError("reportlab required for PDF output: pip install reportlab")
    paper_size={"A4":(210,297),"Letter":(215.9,279.4)}[paper]
    h,w=bits.shape
    # Exact same marker offset as PNG: three subpixels from payload.
    pad=3*subpixel_mm
    if w*subpixel_mm+2*(margin_mm+pad+3)>paper_size[0] or h*subpixel_mm+2*(margin_mm+pad+3)>paper_size[1]:
        raise ValueError("PAYLOAD_EXCEEDS_PAPER: reduce --max-side or --subpixel-mm")
    c=pdf_canvas.Canvas(str(path),pagesize=(paper_size[0]*mm,paper_size[1]*mm),pageCompression=1)
    c.setTitle("EOW_C13 print at 100 percent; disable fit-to-page")
    x0=(paper_size[0]-w*subpixel_mm)/2
    y0=(paper_size[1]-h*subpixel_mm)/2
    c.setFillColorRGB(0,0,0)
    for y in range(h):
        for x in range(w):
            if bits[y,x]:
                c.rect((x0+x*subpixel_mm)*mm,
                       (y0+(h-1-y)*subpixel_mm)*mm,
                       subpixel_mm*mm,subpixel_mm*mm,fill=1,stroke=0)
    # Four registration crosses with known geometry.
    corners=[(x0-pad,y0-pad),(x0+w*subpixel_mm+pad,y0-pad),
             (x0+w*subpixel_mm+pad,y0+h*subpixel_mm+pad),
             (x0-pad,y0+h*subpixel_mm+pad)]
    c.setLineWidth(.3*mm)
    for x,y in corners:
        c.line((x-3)*mm,y*mm,(x+3)*mm,y*mm)
        c.line(x*mm,(y-3)*mm,x*mm,(y+3)*mm)
    # Scale bar 10 mm, below payload, no text touching overlay.
    bx=x0;by=y0-12
    c.line(bx*mm,by*mm,(bx+10)*mm,by*mm)
    for x in (bx,bx+10):c.line(x*mm,(by-1)*mm,x*mm,(by+1)*mm)
    c.setFont("Helvetica",8)
    c.drawString(bx*mm,(by-3)*mm,"10 mm")
    c.showPage();c.save()
    return {"paper":paper,"subpixel_mm":subpixel_mm,"registration_offset_subpixels":3,"payload_box_mm":[x0,y0,w*subpixel_mm,h*subpixel_mm],
            "registration_corners_mm_bottom_left_origin":[list(t) for t in corners],
            "print_instruction":"100% actual size; no fit/shrink; verify 10 mm bar"}
def manifest_record(stem,source,paths,layout,physical):
    return {"sample_id":stem,"source":str(source),"source_sha256":sha(source),
            "share_a_png":str(paths["a_png"]),"share_b_png":str(paths["b_png"]),
            "ideal_overlay_png":str(paths["ideal_png"]),
            "share_a_pdf":str(paths["a_pdf"]),"share_b_pdf":str(paths["b_pdf"]),
            "payload_shape_subpixels":[int(x) for x in paths["shape"]],
            "png_layout":layout,"pdf_layout":physical,
            "capture_path":None,
            "corners_px":None,
            "print_media":None,"printer_model":None,"print_scale_percent":None,
            "overlay_method":None,"lighting":None,"camera_model":None,
            "capture_timestamp":None,
            "notes":"Fill capture_path and corners_px after REAL physical capture. Never use ideal_overlay_png as capture."}
def generate(args):
    if not args.dataset or not args.dataset.is_dir():raise ValueError("--dataset must be an existing image directory")
    out=args.output
    files=sorted((p for p in args.dataset.rglob("*") if p.is_file() and p.suffix.lower() in
                  {".jpg",".jpeg",".png",".bmp",".tif",".tiff",".webp"}),
                 key=lambda p:p.relative_to(args.dataset).as_posix().lower())
    if args.limit:files=files[:args.limit]
    if not files:raise ValueError("No source images found")
    rng=np.random.default_rng(args.seed)
    records=[];fail=[];timings=[]
    for idx,path in enumerate(files,1):
        t=time.perf_counter()
        rel=path.relative_to(args.dataset).as_posix()
        stem=f"{idx:04d}_{hashlib.sha256(rel.encode()).hexdigest()[:10]}"
        folder=out/"samples"/stem
        folder.mkdir(parents=True,exist_ok=True)
        try:
            s,original=secret_image(path,args.max_side)
            a,b=encode(s,rng)
            if not np.array_equal(reconstruct(a,b),s):raise AssertionError("Reconstruction failed")
            a_png=folder/"share_A_preview.png";b_png=folder/"share_B_preview.png"
            ideal_png=folder/"ideal_overlay_preview.png"
            a_pdf=folder/"share_A_PRINT_100pct.pdf";b_pdf=folder/"share_B_PRINT_100pct.pdf"
            ai,layout=fiducial_image(a,args.cell_px,subpixel_mm=args.subpixel_mm)
            bi,_=fiducial_image(b,args.cell_px,subpixel_mm=args.subpixel_mm)
            oi,_=fiducial_image(a|b,args.cell_px,subpixel_mm=args.subpixel_mm)
            ai.save(a_png);bi.save(b_png);oi.save(ideal_png)
            physical=make_pdf(a_pdf,a,args.subpixel_mm,args.paper)
            make_pdf(b_pdf,b,args.subpixel_mm,args.paper)
            # PDF uses bottom-left origin; convert to top-left and compare
            # normalized offsets against PNG fiducial centers.
            pbox=physical["payload_box_mm"]
            pdf_corners=physical["registration_corners_mm_bottom_left_origin"]
            png_corners=layout["registration_corners_px"]
            pngbox=layout["payload_box_px"]
            pdf_tl=[pdf_corners[3][0],pdf_corners[3][1]]
            expected_dx=(pngbox[0]-png_corners[0][0])/args.cell_px
            measured_dx=(pbox[0]-pdf_tl[0])/args.subpixel_mm
            if not math.isclose(expected_dx,measured_dx,abs_tol=1e-8):
                raise AssertionError("PDF_PNG_FIDUCIAL_GEOMETRY_MISMATCH")
            pdf_width=(pdf_corners[2][0]-pdf_corners[3][0])/args.subpixel_mm
            png_width=(png_corners[1][0]-png_corners[0][0])/args.cell_px
            if not math.isclose(pdf_width,png_width,abs_tol=1e-8):
                raise AssertionError("PDF_PNG_FIDUCIAL_WIDTH_MISMATCH")
            paths={"a_png":a_png,"b_png":b_png,"ideal_png":ideal_png,
                   "a_pdf":a_pdf,"b_pdf":b_pdf,"shape":a.shape}
            rec=manifest_record(stem,path,paths,layout,physical)
            rec["source_size_px"]=list(original)
            rec["binary_secret_size_px"]=[int(s.shape[1]),int(s.shape[0])]
            records.append(rec)
            timings.append(time.perf_counter()-t)
        except Exception as e:
            fail.append({"file":rel,"error_type":type(e).__name__,"message":str(e)[:300]})
        if idx%25==0:print(f"Generated {idx}/{len(files)}; successful={len(records)}",flush=True)
    save_json(out/"captures.json",{"schema":"EOW_C13_CAPTURE_V1","records":records})
    save_csv(out/"reports"/"failed_inputs.csv",fail,["file","error_type","message"])
    summary={"mode":"generate","selected_source_images":len(files),"generated_print_pairs":len(records),
             "failed_source_images":len(fail),"average_generation_seconds":sum(timings)/len(timings) if timings else None,
             "real_physical_captures":0,"physical_feasibility":"NOT_YET_TESTED",
             "research_verdict":"NO_SECURITY_QUALIFIED_CONSTRUCTION"}
    save_json(out/"reports"/"summary.json",summary)
    return summary,0 if records and not fail else 2
def evaluate(args):
    try:import cv2
    except ImportError as e:raise RuntimeError("Physical capture evaluation requires opencv-python: pip install opencv-python") from e
    manifest=args.manifest or args.output/"captures.json"
    data=json.loads(manifest.read_text(encoding="utf-8"))
    rows=[];fail=[];skipped=[]
    for rec in data["records"]:
        path=rec.get("capture_path")
        corners=rec.get("corners_px")
        if not path or not corners:
            skipped.append(rec["sample_id"]);continue
        try:
            capture=Path(path)
            if not capture.is_absolute():capture=manifest.parent/capture
            if not capture.exists():raise FileNotFoundError(str(capture))
            if capture.resolve()==Path(rec["ideal_overlay_png"]).resolve():
                raise ValueError("IDEAL_OVERLAY_IS_NOT_A_PHYSICAL_CAPTURE")
            pts=np.asarray(corners,dtype=np.float32)
            if pts.shape!=(4,2) or not np.isfinite(pts).all():raise ValueError("Invalid corners_px: need four [x,y] points")
            # Corners describe outer registration square of PNG preview.
            ideal=Image.open(rec["ideal_overlay_png"]).convert("L")
            expected=np.asarray(ideal,dtype=np.uint8)<128
            h,w=expected.shape
            layout=rec["png_layout"]
            target=np.asarray(layout["registration_corners_px"],dtype=np.float32)
            # Exact 4-corner perspective rectification; corners MUST be manually measured.
            H=cv2.getPerspectiveTransform(pts,target)
            raw=cv2.imread(str(capture),cv2.IMREAD_COLOR)
            if raw is None:raise ValueError("CAPTURE_NOT_DECODABLE")
            gray=cv2.cvtColor(raw,cv2.COLOR_BGR2GRAY)
            rect=cv2.warpPerspective(gray,H,(w,h),flags=cv2.INTER_LINEAR,
                                     borderMode=cv2.BORDER_CONSTANT,borderValue=255)
            box=layout["payload_box_px"]
            x0,y0,x1,y1=map(int,box)
            expected_payload=expected[y0:y1,x0:x1]
            observed=rect[y0:y1,x0:x1]
            # Threshold sensitivity is explicitly reported, not optimized on reference.
            results={}
            for threshold in (96,128,160):
                binary=observed<threshold
                errors=int(np.count_nonzero(binary!=expected_payload))
                results[f"error_rate_t{threshold}"]=errors/expected_payload.size
            # Black/white region contrast is a measured image-statistic proxy.
            black=observed[expected_payload]
            white=observed[~expected_payload]
            contrast=(float(np.mean(white))-float(np.mean(black))) if black.size and white.size else None
            rows.append({"sample_id":rec["sample_id"],"capture":str(capture),
                "capture_sha256":sha(capture),"payload_pixels":int(expected_payload.size),
                "error_rate_t96":results["error_rate_t96"],
                "error_rate_t128":results["error_rate_t128"],
                "error_rate_t160":results["error_rate_t160"],
                "mean_white_minus_black_intensity":contrast,
                "capture_width":raw.shape[1],"capture_height":raw.shape[0],
                "corners_manually_supplied":1,
                "measurement_type":"REAL_CAPTURE_IF_MANIFEST_TRUTHFUL"})
            preview=args.output/"rectified"/f"{rec['sample_id']}_rectified.png"
            preview.parent.mkdir(parents=True,exist_ok=True)
            Image.fromarray(rect).save(preview)
        except Exception as e:
            fail.append({"sample_id":rec.get("sample_id"),"error_type":type(e).__name__,"message":str(e)[:300]})
    cols=["sample_id","capture","capture_sha256","payload_pixels","error_rate_t96",
          "error_rate_t128","error_rate_t160","mean_white_minus_black_intensity",
          "capture_width","capture_height","corners_manually_supplied","measurement_type"]
    save_csv(args.output/"reports"/"capture_measurements.csv",rows,cols)
    save_csv(args.output/"reports"/"capture_failures.csv",fail,["sample_id","error_type","message"])
    summary={"mode":"evaluate","manifest_records":len(data["records"]),
             "captures_with_metadata":len(data["records"])-len(skipped),
             "evaluated_captures":len(rows),"skipped_missing_capture_metadata":len(skipped),
             "failed_capture_evaluations":len(fail),
             "mean_payload_error_rate_t128":sum(r["error_rate_t128"] for r in rows)/len(rows) if rows else None,
             "physical_feasibility":"MEASURED_IMAGE_QUALITY_ONLY" if rows else "NOT_YET_TESTED",
             "human_verification":"NOT_TESTED",
             "research_verdict":"NO_SECURITY_QUALIFIED_CONSTRUCTION"}
    save_json(args.output/"reports"/"capture_summary.json",summary)
    return summary,0 if rows and not fail else 2
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("generate","evaluate"),default="generate")
    ap.add_argument("--dataset",type=Path,help="Image directory; required for generate")
    ap.add_argument("--output",type=Path,default=Path("../Results/EOW_C13"))
    ap.add_argument("--manifest",type=Path,help="Capture manifest; default OUTPUT/captures.json")
    ap.add_argument("--max-side",type=int,default=32,help="Secret image longest side (default 32 for A4 printability)")
    ap.add_argument("--subpixel-mm",type=float,default=1.4)
    ap.add_argument("--cell-px",type=int,default=12)
    ap.add_argument("--paper",choices=("A4","Letter"),default="A4")
    ap.add_argument("--limit",type=int,default=10,help="Print pilot samples; 0 means all")
    ap.add_argument("--seed",type=int,default=20261115)
    args=ap.parse_args()
    if args.max_side<1 or args.subpixel_mm<=0 or args.cell_px<2 or args.limit<0:
        ap.error("Invalid dimensions or limit")
    if args.mode=="generate" and pdf_canvas is None:
        ap.error("ReportLab required: python -m pip install reportlab")
    checks=check()
    args.output.mkdir(parents=True,exist_ok=True)
    save_json(args.output/"reports"/"self_tests.json",{"passed":len(checks),"total":len(checks),"checks":checks})
    save_json(args.output/"configuration"/"run.json",{
        "experiment":"EOW_C13","version":VERSION,"mode":args.mode,
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "dataset":str(args.dataset) if args.dataset else None,
        "output":str(args.output),"max_side":args.max_side,
        "subpixel_mm":args.subpixel_mm,"cell_px":args.cell_px,
        "paper":args.paper,"limit":args.limit,"seed":args.seed,
        "python":sys.version.split()[0],"pillow":Image.__version__,
        "numpy":np.__version__})
    summary,code=generate(args) if args.mode=="generate" else evaluate(args)
    save_json(args.output/"reports"/"verdict.json",{
        "research_verdict":"NO_SECURITY_QUALIFIED_CONSTRUCTION",
        "physical_feasibility":summary["physical_feasibility"],
        "human_optical_integrity":"NOT_ESTABLISHED",
        "issuer_authenticity":"NOT_RETESTED",
        "note":"Printed outputs are experimental share media, not secure credentials."})
    (args.output/"reports"/"scientific_report.md").write_text(
        "# EOW_C13 — Physical Optical Reconstruction Feasibility\n\n"
        "Purpose: measure whether printed share pairs can be physically overlaid and reconstructed.\n\n"
        "This is NOT a security demonstration or a human authentication experiment.\n\n"
        f"Mode: {args.mode}\n\n"
        f"Summary:\n```json\n{json.dumps(summary,indent=2)}\n```\n\n"
        "Print A/B PDF pages on transparent media at **100% actual size**, no fit-to-page. "
        "Check the 10 mm calibration bar. Align the four registration crosses, "
        "photograph the physical overlay with even lighting, then fill captures.json "
        "with actual capture_path and corners_px [TL,TR,BR,BL] of the OUTER registration square "
        "visible in the preview. Evaluation rectifies the image using those points. "
        "Manual registration introduces operator uncertainty.\n\n"
        "Thresholds 96/128/160 are sensitivity checks, not calibrated psychophysical thresholds. "
        "The pixel-error comparison requires an electronic reference and is not unaided human verification.\n\n"
        "No actual capture is counted without user-supplied image and registration metadata. "
        "No attack-resistance, privacy, or post-quantum verification claim is made.\n\n"
        "References: Naor and Shamir, Visual Cryptography, https://doi.org/10.1007/BFb0053419 ; "
        "NIST FIPS 204, https://doi.org/10.6028/NIST.FIPS.204\n",encoding="utf-8")
    print(json.dumps(summary,indent=2))
    return code
if __name__=="__main__":
    raise SystemExit(main())
