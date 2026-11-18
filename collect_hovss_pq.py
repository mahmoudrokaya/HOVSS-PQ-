
from pathlib import Path
from collections import Counter
import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import zipfile

ROOT = Path(r"D:\48\481\New Papers\Nature_Idea\Experiments")
DEST = ROOT / "HOVSS-PQ"
MAX_SIZE = 25 * 1024 * 1024

CODE = {".py", ".ipynb", ".m", ".r", ".sh", ".ps1", ".bat",
        ".cpp", ".c", ".h", ".java", ".sql"}
DATA = {".csv", ".tsv", ".json", ".jsonl", ".npy", ".npz",
        ".mat", ".parquet", ".jpg", ".jpeg", ".png", ".tif",
        ".tiff", ".bmp"}
RESULTS = {".pdf", ".md", ".txt", ".xlsx", ".docx", ".pptx",
           ".svg", ".html", ".log"}
CONFIG = {".yaml", ".yml", ".toml", ".ini", ".xml"}
ALLOWED = CODE | DATA | RESULTS | CONFIG | {".zip"}

SKIP_DIRS = {
    "hovss-pq", ".git", "__pycache__", ".venv", "venv",
    "node_modules", ".pytest_cache", ".ipynb_checkpoints",
    "literature_expanded", "literature_math"
}

RELEVANCE = re.compile(
    r"hovss|visual.?crypt|visual.?secret|secret.?shar|"
    r"post.?quantum|optical|integrity|authentication|"
    r"human.?verif|ml.?dsa|reconstruction|"
    r"experiment|results?|benchmark|evaluation|"
    r"observation|overlay|registration|"
    r"(?<![a-z0-9])(?:c0?[1-9]|c1[0-9]|f[1-9]|eow)(?![a-z0-9])",
    re.I
)

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def category(path):
    ext = path.suffix.lower()
    if ext == ".zip":
        return "archives"
    if ext in CODE:
        return "code"
    if ext in DATA:
        return "data"
    if ext in CONFIG:
        return "configs"
    return "results"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--include-uncertain", action="store_true")
    args = parser.parse_args()

    files = []
    decisions = []

    for base, dirs, names in os.walk(ROOT):
        base = Path(base)

        dirs[:] = sorted(
            d for d in dirs
            if d.lower() not in SKIP_DIRS
            and (base / d).resolve() != DEST.resolve()
        )

        for name in sorted(names):
            path = base / name

            if path.is_symlink() or name.startswith("~$"):
                continue

            rel = path.relative_to(ROOT)

            try:
                size = path.stat().st_size
            except OSError:
                continue

            if path.suffix.lower() not in ALLOWED:
                decisions.append((str(rel), "excluded", "extension"))
                continue

            if size > MAX_SIZE:
                decisions.append((str(rel), "excluded", "over_25_MiB"))
                continue

            if not args.include_uncertain and not RELEVANCE.search(str(rel)):
                decisions.append((str(rel), "excluded", "uncertain_relevance"))
                continue

            files.append((path, rel, size))

    archives = [x for x in files if x[0].suffix.lower() == ".zip"]
    regular = [x for x in files if x[0].suffix.lower() != ".zip"]

    # ZIP preference uses verified content identity,
    # not filename similarity alone.
    archive_index = {}
    valid_archives = []

    for archive, rel, size in archives:
        try:
            with zipfile.ZipFile(archive) as z:
                if z.testzip() is not None:
                    raise zipfile.BadZipFile("Corrupt member")

                for info in z.infolist():
                    if info.is_dir() or info.file_size > MAX_SIZE:
                        continue

                    member = Path(info.filename.replace("\\", "/"))
                    if member.is_absolute() or ".." in member.parts:
                        continue

                    key = (member.name.lower(), info.file_size)
                    archive_index.setdefault(key, []).append(
                        (archive, info.filename)
                    )

            valid_archives.append((archive, rel, size))

        except (OSError, zipfile.BadZipFile, RuntimeError):
            decisions.append((str(rel), "excluded", "invalid_zip"))

    selected = list(valid_archives)

    for path, rel, size in regular:
        key = (path.name.lower(), size)
        covered_by = None

        for archive, member in archive_index.get(key, []):
            try:
                h = hashlib.sha256()

                with zipfile.ZipFile(archive) as z:
                    with z.open(member) as f:
                        for block in iter(
                            lambda: f.read(1024 * 1024), b""
                        ):
                            h.update(block)

                if h.hexdigest() == digest(path):
                    covered_by = archive
                    break
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue

        if covered_by:
            decisions.append((
                str(rel), "excluded",
                "identical_content_in_zip: " +
                str(covered_by.relative_to(ROOT))
            ))
        else:
            selected.append((path, rel, size))

    # Preview reports are written outside the repository.
    report_dir = (
        DEST / "metadata" if args.execute
        else ROOT.parent / "HOVSS_PQ_Collection_Preview"
    )
    report_dir.mkdir(parents=True, exist_ok=True)

    manifest = []

    for path, rel, size in sorted(selected, key=lambda x: str(x[1])):
        target_rel = Path(category(path)) / rel

        record = {
            "source": str(rel),
            "destination": str(target_rel),
            "size_bytes": size,
            "sha256": digest(path),
            "category": category(path)
        }
        manifest.append(record)

        if args.execute:
            target = DEST / target_rel
            target.parent.mkdir(parents=True, exist_ok=True)

            if target.exists() and digest(target) != record["sha256"]:
                raise RuntimeError(
                    f"Conflicting destination file: {target}"
                )

            if not target.exists():
                shutil.copy2(path, target)

            if digest(target) != record["sha256"]:
                raise RuntimeError(f"Checksum mismatch: {target}")

    with open(report_dir / "manifest.csv", "w",
              newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "source", "destination", "size_bytes",
            "sha256", "category"
        ])
        writer.writeheader()
        writer.writerows(manifest)

    with open(report_dir / "excluded_files.csv", "w",
              newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["source", "decision", "reason"])
        writer.writerows(decisions)

    summary = {
        "mode": "COPY" if args.execute else "PREVIEW",
        "selected_files": len(manifest),
        "selected_size_MB": round(
            sum(x["size_bytes"] for x in manifest) / 1048576, 2
        ),
        "categories": dict(Counter(
            x["category"] for x in manifest
        )),
        "excluded_files": len(decisions)
    }

    (report_dir / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8"
    )

    if args.execute:
        (DEST / "README.md").write_text(
            "# HOVSS-PQ\n\n"
            "Code, datasets, and experimental results supporting "
            "the HOVSS-PQ research paper.\n\n"
            "See `metadata/manifest.csv` for file provenance "
            "and SHA-256 checksums.\n\n"
            "The archive requires author review before publication.\n",
            encoding="utf-8"
        )

    print(json.dumps(summary, indent=2))
    print("Reports:", report_dir)

if __name__ == "__main__":
    main()
