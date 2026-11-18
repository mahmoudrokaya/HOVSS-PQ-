#!/usr/bin/env python3
"""Read-only exploration of an existing HOVSS-PQ Experiments tree.

Only writes to Results/F8_00_Exploration (or --output). Does not import or run
existing project scripts. Standard library only; Python >=3.9.
"""
from __future__ import annotations
import argparse, collections, csv, datetime as dt, hashlib, json, os, re, sys, traceback
from pathlib import Path

DEFAULT_ROOT = r'D:\48\481\New Papers\Nature_Idea\Experiments'
IMAGE_EXT = {'.jpg','.jpeg','.png','.bmp','.tif','.tiff','.webp','.gif'}
CODE_EXT = {'.py','.ipynb','.m','.r','.jl','.cpp','.c','.h','.ps1','.bat','.sh'}
DATA_EXT = {'.csv','.json','.jsonl','.npy','.npz','.mat','.parquet','.xlsx','.xls','.txt','.xml'}
DOC_EXT = {'.pdf','.doc','.docx','.ppt','.pptx','.md','.rtf'}
ARCHIVE_EXT = {'.zip','.7z','.rar','.tar','.gz'}
SECRET_NAME_RE = re.compile(r'(^|[._-])(secret|private|password|passwd|token|credential|api[_-]?key|\.env)([._-]|$)',re.I)
F_RE = re.compile(r'(?<![A-Za-z0-9])F([1-8])(?:[_\-.]|\b)', re.I)


def category(path: Path) -> str:
    e=path.suffix.lower()
    if e in IMAGE_EXT: return 'image'
    if e in CODE_EXT: return 'code'
    if e in DATA_EXT: return 'data'
    if e in DOC_EXT: return 'document'
    if e in ARCHIVE_EXT: return 'archive'
    return 'other'


def hash_file(path: Path, chunk=1024*1024):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(chunk),b''): h.update(b)
    return h.hexdigest()


def iso(ts): return dt.datetime.fromtimestamp(ts,dt.timezone.utc).isoformat()


def safe_relative(p, root):
    return p.relative_to(root).as_posix()


def scan(root, out, args):
    rows=[]; errors=[]; dir_rows=[]; visited=0
    output_resolved=out.resolve(strict=False)
    root_resolved=root.resolve(strict=True)
    if output_resolved==root_resolved:
        raise ValueError('Output cannot be the root directory')
    for current,dirs,files in os.walk(root, topdown=True, followlinks=False):
        base=Path(current)
        kept=[]
        for d in sorted(dirs,key=str.lower):
            p=base/d
            if p.is_symlink():
                errors.append({'path':safe_relative(p,root),'issue':'symlink_directory_skipped'})
            elif p.resolve(strict=False)==output_resolved or output_resolved in p.resolve(strict=False).parents and p.resolve(strict=False)==output_resolved:
                continue
            else: kept.append(d)
        dirs[:]=kept
        depth=len(base.relative_to(root).parts)
        if args.max_depth is not None and depth>=args.max_depth: dirs[:]=[]
        dir_rows.append({'path':'.' if base==root else safe_relative(base,root),'depth':depth,'files_direct':len(files),'dirs_direct':len(dirs)})
        for filename in sorted(files,key=str.lower):
            p=base/filename
            rel=safe_relative(p,root)
            if p.is_symlink():
                errors.append({'path':rel,'issue':'symlink_file_skipped'});continue
            try:
                st=p.stat()
                record={'path':rel,'directory':'.' if base==root else safe_relative(base,root),
                        'filename':filename,'extension':p.suffix.lower(),'category':category(p),
                        'size_bytes':st.st_size,'modified_utc':iso(st.st_mtime),
                        'sha256':'','hash_status':'not_requested',
                        'sensitive_name_flag':bool(SECRET_NAME_RE.search(filename))}
                if args.hash_mode=='all' or (args.hash_mode=='small' and st.st_size<=args.hash_max_mb*1024*1024):
                    try: record['sha256']=hash_file(p);record['hash_status']='computed'
                    except (OSError,PermissionError) as exc:
                        record['hash_status']='error';errors.append({'path':rel,'issue':f'hash_error:{type(exc).__name__}'})
                rows.append(record)
            except (OSError,PermissionError) as exc:
                errors.append({'path':rel,'issue':f'stat_error:{type(exc).__name__}'})
        visited+=1
        if args.progress_every and visited%args.progress_every==0:
            print(f'Scanned {visited} directories; indexed {len(rows)} files',flush=True)
    return rows,dir_rows,errors


def write_csv(path, rows, columns):
    with path.open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=columns,extrasaction='ignore');w.writeheader();w.writerows(rows)


def grouped_summary(rows, key):
    counts=collections.Counter(); sizes=collections.Counter()
    for r in rows: counts[r[key]]+=1;sizes[r[key]]+=r['size_bytes']
    return [{'name':k,'files':counts[k],'size_bytes':sizes[k]} for k in sorted(counts,key=lambda x:(-sizes[x],str(x)))]


def main():
    ap=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('--root',default=DEFAULT_ROOT,help='Experiments directory')
    ap.add_argument('--output',help='Report directory (default: ROOT/Results/F8_00_Exploration)')
    ap.add_argument('--hash-mode',choices=['none','small','all'],default='small',help='SHA256 mode; all may be slow')
    ap.add_argument('--hash-max-mb',type=float,default=32,help='Max file size hashed in small mode')
    ap.add_argument('--max-depth',type=int,default=None,help='Optional maximum directory depth')
    ap.add_argument('--progress-every',type=int,default=100,help='Progress per N scanned directories; 0 disables')
    ap.add_argument('--top',type=int,default=30,help='Number of largest files to display')
    args=ap.parse_args()
    root=Path(args.root).expanduser()
    if not root.is_dir():
        print(f'ERROR: root directory does not exist or is inaccessible: {root}',file=sys.stderr);return 2
    out=Path(args.output).expanduser() if args.output else root/'Results'/'F8_00_Exploration'
    try:
        # Write only inside root by default; reject output equal to or ancestor of root.
        resolved_root=root.resolve(strict=True)
        resolved_out=out.resolve(strict=False)
        if resolved_out==resolved_root or resolved_out in resolved_root.parents:
            print('ERROR: output cannot be root or an ancestor of root',file=sys.stderr);return 2
        out.mkdir(parents=True,exist_ok=True)
        rows,dirs,errors=scan(root,out,args)
        total=sum(r['size_bytes'] for r in rows)
        by_category=grouped_summary(rows,'category')
        by_extension=grouped_summary(rows,'extension')
        top_dirs=collections.Counter()
        for r in rows:
            parts=Path(r['path']).parts
            top_dirs[parts[0] if len(parts)>1 else '(root)']+=r['size_bytes']
        by_stage={}
        for n in range(1,9):
            matched=[r for r in rows if re.search(r'(?<![A-Za-z0-9])F'+str(n)+r'(?:[_\-.]|\b)',r['path'],re.I)]
            by_stage['F'+str(n)]={'file_count':len(matched),'code_count':sum(r['category']=='code' for r in matched),'total_bytes':sum(r['size_bytes'] for r in matched),'examples':[r['path'] for r in matched[:12]]}
        duplicates=[]
        groups=collections.defaultdict(list)
        for r in rows:
            if r['sha256']: groups[(r['size_bytes'],r['sha256'])].append(r['path'])
        for (size,digest),paths in groups.items():
            if len(paths)>1: duplicates.append({'size_bytes':size,'sha256':digest,'paths':paths})
        duplicates.sort(key=lambda d:(-len(d['paths']),-d['size_bytes']))
        dataset_counts={
          'BSDS500_image_candidates':sum(r['category']=='image' and ('bsds500' in r['path'].lower() or '/bsr/' in '/'+r['path'].lower()) for r in rows),
          'USC_SIPI_image_candidates':sum(r['category']=='image' and ('misc/' in r['path'].lower() or 'sipi' in r['path'].lower()) for r in rows),
          'synthetic_name_candidates':sum(r['category']=='image' and 'synthetic' in r['path'].lower() for r in rows),
        }
        summary={'generated_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'root':str(root.resolve()),
                 'output':str(out.resolve()),'scan_options':{'hash_mode':args.hash_mode,'hash_max_mb':args.hash_max_mb,'max_depth':args.max_depth},
                 'file_count':len(rows),'directory_count':len(dirs),'total_bytes':total,'total_gib':round(total/1024**3,4),
                 'category_summary':by_category,'extension_summary':by_extension,'top_level_bytes':dict(top_dirs.most_common()),
                 'f1_f8_inventory':by_stage,'dataset_image_name_candidates':dataset_counts,
                 'duplicate_hash_groups':len(duplicates),'duplicate_files_beyond_first':sum(len(d['paths'])-1 for d in duplicates),
                 'flagged_sensitive_filenames':sum(r['sensitive_name_flag'] for r in rows),'scan_errors':len(errors),
                 'limitations':['Dataset counts are path-based candidates, not verified benchmark counts.',
                                'Duplicate groups are complete only for files actually hashed.',
                                'Files inside archives are not inspected.',
                                'Code is inventoried but never executed or imported.',
                                'Symlinks are not traversed.']}
        write_csv(out/'files_inventory.csv',rows,['path','directory','filename','extension','category','size_bytes','modified_utc','sha256','hash_status','sensitive_name_flag'])
        write_csv(out/'directories_inventory.csv',dirs,['path','depth','files_direct','dirs_direct'])
        write_csv(out/'largest_files.csv',sorted(rows,key=lambda r:-r['size_bytes'])[:max(0,args.top)],['path','size_bytes','category','modified_utc'])
        write_csv(out/'extension_summary.csv',by_extension,['name','files','size_bytes'])
        with (out/'summary.json').open('w',encoding='utf-8') as f:json.dump(summary,f,indent=2,ensure_ascii=False)
        with (out/'duplicates.json').open('w',encoding='utf-8') as f:json.dump(duplicates,f,indent=2,ensure_ascii=False)
        with (out/'scan_errors.json').open('w',encoding='utf-8') as f:json.dump(errors,f,indent=2,ensure_ascii=False)
        lines=['# HOVSS-PQ Experiments Directory Exploration','',f'Root: `{summary["root"]}`',f'Generated (UTC): {summary["generated_utc"]}','',
               f'- Files: **{len(rows):,}**',f'- Directories: **{len(dirs):,}**',f'- Size: **{summary["total_gib"]:,.3f} GiB**',
               f'- SHA-256 duplicate groups: **{len(duplicates)}**',f'- Scan errors: **{len(errors)}**','','## Categories','',
               '| Category | Files | Bytes |','|---|---:|---:|']
        lines += [f'| {d["name"]} | {d["files"]:,} | {d["size_bytes"]:,} |' for d in by_category]
        lines += ['','## F1–F8 path-based inventory','','| Stage | Files | Code files |','|---|---:|---:|']
        lines += [f'| {k} | {v["file_count"]} | {v["code_count"]} |' for k,v in by_stage.items()]
        lines += ['','## Largest files','']+[f'- `{r["path"]}` ({r["size_bytes"]:,} bytes)' for r in sorted(rows,key=lambda r:-r['size_bytes'])[:max(0,args.top)]]
        lines += ['','## Important limitations','']+[f'- {x}' for x in summary['limitations']]
        (out/'README_Exploration.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
        print(json.dumps({'output':str(out),'files':len(rows),'directories':len(dirs),'total_gib':summary['total_gib'],'duplicate_groups':len(duplicates),'errors':len(errors),'f1_f8':{k:v['file_count'] for k,v in by_stage.items()}},indent=2))
        return 0 if not errors else 1
    except Exception as exc:
        print(f'ERROR: {exc}',file=sys.stderr);traceback.print_exc();return 2

if __name__=='__main__':sys.exit(main())
