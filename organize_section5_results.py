
#!/usr/bin/env python3
"""
HOVSS-PQ — Section 5 Results Organizer

Organizes experimental artifacts for GitHub/Zenodo release.

Features:
- Read-only preview by default
- Optional copying with --execute
- 25 MiB maximum file size
- ZIP preference for identical archived files
- SHA-256 verification
- C01-C16 and F1-F8 experiment identification
- Tables 2-6 and Figures 6-8 identification
- CSV and JSON audit reports

Requires Python 3.10+.
Uses Python standard library only.

IMPORTANT:
File-to-manuscript mapping is filename-based.
Manually validate all mappings before publication.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import zipfile

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


MAX_SIZE = 25 * 1024 * 1024

SUPPORTED = {
    ".csv", ".tsv", ".json", ".jsonl",
    ".txt", ".md", ".pdf", ".xlsx",
    ".png", ".jpg", ".jpeg", ".svg",
    ".tif", ".tiff", ".npy", ".npz",
    ".mat", ".zip"
}

EXPERIMENT_RE = re.compile(
    r"(?<![a-z0-9])"
    r"(C(?:0?[1-9]|1[0-6])|F(?:0?[1-8]))"
    r"(?![a-z0-9])",
    re.IGNORECASE
)

TABLE_RE = re.compile(
    r"(?:table|tab|tbl)[ _-]*([2-6])",
    re.IGNORECASE
)

FIGURE_RE = re.compile(
    r"(?:figure|fig)[ _-]*([6-8])",
    re.IGNORECASE
)


def sha256(path):
    """Calculate SHA-256 checksum."""
    digest = hashlib.sha256()

    with open(path, "rb") as stream:
        for chunk in iter(
            lambda: stream.read(1024 * 1024), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def classify(relative_path):
    """
    Classify using filename/path patterns.

    This is not a verified mapping to the manuscript.
    """
    text = relative_path.as_posix()

    match = TABLE_RE.search(text)
    if match:
        return "tables", f"Table_{match.group(1)}"

    match = FIGURE_RE.search(text)
    if match:
        return "figures", f"Figure_{match.group(1)}"

    match = EXPERIMENT_RE.search(text)
    if match:
        code = match.group(1).upper()
        return "experiments", (
            f"{code[0]}{int(code[1:]):02d}"
        )

    return "unmapped", "Needs_Review"


def inspect_zip(path):
    """Check archive readability and member safety."""
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                name = member.filename.replace("\\", "/")

                if (
                    name.startswith("/")
                    or ".." in name.split("/")
                    or re.match(r"^[A-Za-z]:", name)
                ):
                    return False

            return archive.testzip() is None

    except (OSError, RuntimeError, zipfile.BadZipFile):
        return False


def zip_member_hashes(path, max_size):
    """Identify ZIP members by filename, size and SHA-256."""
    members = set()

    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size > max_size:
                continue

            digest = hashlib.sha256()

            with archive.open(info) as stream:
                for chunk in iter(
                    lambda: stream.read(1024 * 1024), b""
                ):
                    digest.update(chunk)

            members.add((
                Path(info.filename).name.lower(),
                info.file_size,
                digest.hexdigest()
            ))

    return members


def write_csv(path, records, columns):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(
        path, "w", newline="", encoding="utf-8-sig"
    ) as stream:
        writer = csv.DictWriter(
            stream, fieldnames=columns
        )
        writer.writeheader()
        writer.writerows(records)


def main():

    parser = argparse.ArgumentParser(
        description="Organize HOVSS-PQ Section 5 results"
    )

    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="HOVSS-PQ repository root"
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Copy files (default is preview only)"
    )

    parser.add_argument(
        "--max-mib",
        type=float,
        default=25,
        help="Maximum individual file size in MiB"
    )

    args = parser.parse_args()

    root = args.root.resolve()
    output = root / "results" / "section5_organized"
    reports = root / "metadata" / "section5_organization"

    if not root.is_dir():
        parser.error(f"Repository not found: {root}")

    if args.max_mib <= 0:
        parser.error("--max-mib must be positive")

    max_size = int(args.max_mib * 1024 * 1024)

    reports.mkdir(parents=True, exist_ok=True)

    candidates = []
    skipped = []

    # Scan repository, excluding generated output,
    # reports and Git metadata.
    for path in root.rglob("*"):

        if not path.is_file() or path.is_symlink():
            continue

        if (
            output in path.parents
            or reports in path.parents
            or ".git" in path.relative_to(root).parts
        ):
            continue

        relative = path.relative_to(root)

        if path.suffix.lower() not in SUPPORTED:
            continue

        if path.stat().st_size > max_size:
            skipped.append({
                "source": str(relative),
                "reason": "over_size_limit"
            })
            continue

        candidates.append(path)

    # ZIP files are processed before individual files.
    candidates.sort(
        key=lambda p: (
            p.suffix.lower() != ".zip",
            str(p).lower()
        )
    )

    plan = []
    seen_hashes = {}
    archived_members = set()

    for path in candidates:

        relative = path.relative_to(root)
        size = path.stat().st_size
        checksum = sha256(path)

        if checksum in seen_hashes:
            skipped.append({
                "source": str(relative),
                "reason": (
                    "duplicate_of:" + seen_hashes[checksum]
                )
            })
            continue

        if path.suffix.lower() == ".zip":

            if not inspect_zip(path):
                skipped.append({
                    "source": str(relative),
                    "reason": "invalid_or_unsafe_zip"
                })
                continue

            archived_members.update(
                zip_member_hashes(path, max_size)
            )

        else:
            identity = (
                path.name.lower(),
                size,
                checksum
            )

            if identity in archived_members:
                skipped.append({
                    "source": str(relative),
                    "reason": "identical_content_in_zip"
                })
                continue

        category, group = classify(relative)

        # Preserve relative paths to prevent collisions.
        destination = (
            Path(category) / group / relative
        )

        record = {
            "source": relative.as_posix(),
            "destination": destination.as_posix(),
            "category": category,
            "group": group,
            "size_bytes": size,
            "sha256": checksum,
            "status": (
                "copied" if args.execute else "planned"
            )
        }

        plan.append(record)
        seen_hashes[checksum] = relative.as_posix()

        if args.execute:

            target = output / destination
            target.parent.mkdir(
                parents=True, exist_ok=True
            )

            if target.exists():
                if sha256(target) != checksum:
                    raise RuntimeError(
                        "Destination conflict: "
                        + str(target)
                    )
            else:
                shutil.copy2(path, target)

            if sha256(target) != checksum:
                raise RuntimeError(
                    "Checksum mismatch: " + str(target)
                )

    write_csv(
        reports / "organization_plan.csv",
        plan,
        [
            "source", "destination",
            "category", "group",
            "size_bytes", "sha256", "status"
        ]
    )

    write_csv(
        reports / "skipped_files.csv",
        skipped,
        ["source", "reason"]
    )

    summary = {
        "generated_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "mode": (
            "COPY" if args.execute else "PREVIEW"
        ),
        "repository": str(root),
        "selected_files": len(plan),
        "skipped_files": len(skipped),
        "selected_size_mib": round(
            sum(r["size_bytes"] for r in plan)
            / 1048576, 3
        ),
        "categories": dict(Counter(
            r["category"] for r in plan
        )),
        "groups": dict(Counter(
            r["group"] for r in plan
        )),
        "warning": (
            "Mappings are heuristic and require "
            "manual manuscript verification."
        )
    }

    (reports / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8"
    )

    print(json.dumps(summary, indent=2))
    print(f"\nReports saved to: {reports}")


if __name__ == "__main__":
    main()
