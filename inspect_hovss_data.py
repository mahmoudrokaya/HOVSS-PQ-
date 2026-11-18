    p.add_argument('--all-files', action='store_true', help='Inspect all file types, not only data and archives')
    args = p.parse_args()

    root = args.root.expanduser().resolve()
    if not root.is_dir():
        p.error(f'Repository directory not found: {root}')
    output = (args.output or root / 'metadata' / 'inspection').expanduser().resolve()
    if output == root:
        p.error('Output directory must not equal repository root')
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = (args.manifest or root / 'metadata' / 'manifest.csv').expanduser().resolve()

    records = []
    errors = []
    hash_groups = defaultdict(list)
    for base, dirs, names in os.walk(root, followlinks=False):
        current = Path(base)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (current / d).is_symlink() and not (current / d).resolve().is_relative_to(output))
        for name in sorted(names):
            path = current / name
            if path.is_symlink() or path.resolve().is_relative_to(output):
                continue
            rel = path.relative_to(root).as_posix()
            ext = path.suffix.lower()
            if not args.all_files and ext not in DATA_EXTS | {'.zip'}:
                continue
            try:
                size = path.stat().st_size
                record = {
                    'path': rel, 'extension': ext, 'category': rel.split('/')[0],
                    'size_bytes': size, 'over_25_mib': size > MAX_BYTES,
                    'sha256': sha256(path) if args.hash else None,
                }
                if record['sha256']:
                    hash_groups[record['sha256']].append(rel)
                if ext == '.zip':
                    record.update(inspect_zip(path, args.inspect_archives))
                elif ext in DATA_EXTS and size <= MAX_BYTES:
                    record.update(inspect_file(path, ext))
                records.append(record)
            except (OSError, PermissionError) as exc:
                errors.append({'path': rel, 'error': f'{type(exc).__name__}: {exc}'})

    manifest = load_manifest(manifest_path)
    manifest_checks = []
    for row in manifest:
        dest = row.get('destination', '').replace('\\', '/')
        if not dest:
            continue
        candidate = (root / dest).resolve()
        if not candidate.is_relative_to(root):
            manifest_checks.append({'destination': dest, 'status': 'unsafe_path'})
            continue
        if not candidate.is_file():
            manifest_checks.append({'destination': dest, 'status': 'missing'})
            continue
        try:
            expected_size = int(row.get('size_bytes', ''))
            if candidate.stat().st_size != expected_size:
                status = 'size_mismatch'
            elif args.hash and row.get('sha256') and sha256(candidate).lower() != row['sha256'].lower():
                status = 'sha256_mismatch'
            else:
                status = 'present_verified' if args.hash and row.get('sha256') else 'present_size_checked'
        except (ValueError, OSError) as exc:
            status = f'check_error: {exc}'
        manifest_checks.append({'destination': dest, 'status': status})

    duplicates = [paths for paths in hash_groups.values() if len(paths) > 1]
    summary = {
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'root': str(root),
        'files_inspected': len(records),
        'size_mib': round(sum(r['size_bytes'] for r in records) / 1048576, 3),
        'by_extension': dict(sorted(Counter(r['extension'] or '(none)' for r in records).items())),
        'by_top_level_folder': dict(sorted(Counter(r['category'] for r in records).items())),
        'files_over_25_mib': [r['path'] for r in records if r['over_25_mib']],
        'duplicate_sha256_groups': duplicates if args.hash else 'not_checked',
        'manifest_entries': len(manifest_checks),
        'manifest_status': dict(Counter(r['status'] for r in manifest_checks)),
        'scan_errors': errors,
        'notes': [
            'Read-only scan: no source files or ZIP archives were modified or extracted.',
            'ZIP content is inventoried using directory metadata, not decompressed or validated.',
            'A matching file and hash does not establish experiment reproducibility.',
            'Potential personal or sensitive data must be reviewed manually before release.',
        ],
    }
    (output / 'inspection.json').write_text(json.dumps(records, indent=2, ensure_ascii=False, default=str), encoding='utf-8')
    (output / 'summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    with (output / 'manifest_audit.csv').open('w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=['destination', 'status'])
        w.writeheader()
        w.writerows(manifest_checks)
    with (output / 'inventory.csv').open('w', newline='', encoding='utf-8-sig') as f:
        fields = ['path', 'category', 'extension', 'size_bytes', 'over_25_mib', 'sha256']
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(records)
    print(json.dumps({k: v for k, v in summary.items() if k not in {'duplicate_sha256_groups', 'scan_errors', 'files_over_25_mib'}}, indent=2))
    print(f'Reports: {output}')
    return 0 if not errors else 1


if __name__ == '__main__':
    sys.exit(main())
