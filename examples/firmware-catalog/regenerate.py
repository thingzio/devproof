#!/usr/bin/env python3
# Copyright 2026 Thingz LLC
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the firmware catalogs from public NVIDIA release notes.

Everything this writes comes from two public documentation pages, listed in
SOURCES below. Nothing here is an NVIDIA publication, and nothing is derived
from restricted material.

The parsing is deliberately mechanical: fetch the page, walk its headings and
tables in document order, emit one file per row. An earlier attempt read these
pages through a summarizing model and produced version strings that are not on
them -- an NVOS version for a tray whose page lists no NVOS version, and
filename stems reported as versions. A catalog is only worth publishing if
re-deriving it is a mechanical step somebody else can repeat, so this is that
step.

It is NOT run in CI. Tests use the committed output, because a test suite that
reached docs.nvidia.com would fail for reasons that have nothing to do with
this repository.

Usage:  python3 regenerate.py [--check]

    --check  re-derive and diff against what is committed, without writing
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

SOURCES = [
    {
        "slug": "gb200-nvl72",
        "system": "NVIDIA DGX GB200 NVL72",
        "release": "1.3.10",
        "url": "https://docs.nvidia.com/dgx/dgxgb200nvl72-release-notes/package-contents.html",
    },
    {
        "slug": "gb300-nvl72",
        "system": "NVIDIA DGX GB300 NVL72",
        "release": "1.0.10",
        "url": "https://docs.nvidia.com/dgx/dgxgb300nvl72-release-notes/package-contents.html",
    },
]

# Both pages embed a GitHub repository card for NVIDIA/gdrcopy whose rows read
# "Stars | 1006" and "Language | C++". Those are page furniture, not firmware,
# and a catalog that listed a star count as a component version would be
# wrong in a way that is easy to miss and hard to explain.
SKIP_SECTIONS = {"NVIDIA/gdrcopy"}

ROOT = pathlib.Path(__file__).resolve().parent
CATALOG = ROOT / "catalog"


def strip_tags(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


def slug(value: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return out or "unnamed"


def fetch(url: str) -> str:
    # curl rather than urllib: this repository's environment pins a CA bundle
    # that urllib does not read, and a TLS failure here should look like a TLS
    # failure rather than a mysterious empty page.
    result = subprocess.run(
        ["curl", "-sS", "--fail", "--max-time", "30", url],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        sys.exit(f"fetching {url} failed: {result.stderr.strip()}")
    return result.stdout


def sections(page: str):
    """Yield ("table", heading, rows) and ("lines", heading, pairs) in order.

    Tables are not the whole page. Each section also carries a line-block
    holding the values that identify the package itself -- the bundle's own
    Version and its Bundle file -- and reading tables alone silently dropped
    them. The catalog then listed a tray's sub-components while omitting the
    NVOS version and the primary BMC and HMC bundle filenames, which is most
    of what "which packages belong together" means.
    """
    heading = "root"
    pattern = (r"(<h[1-6][^>]*>.*?</h[1-6]>"
               r"|<table.*?</table>"
               r'|<div class="line-block">.*?</div>\s*</div>)')
    for part in re.findall(pattern, page, re.S):
        if part.startswith("<h"):
            heading = strip_tags(part).rstrip("#").strip()
        elif part.startswith("<table"):
            rows = []
            for row in re.findall(r"<tr.*?</tr>", part, re.S):
                cells = [strip_tags(c) for c in re.findall(r"<t[hd].*?</t[hd]>", row, re.S)]
                if cells:
                    rows.append(cells)
            if rows:
                yield "table", heading, rows
        else:
            pairs = []
            for line in re.findall(r'<div class="line">(.*?)</div>', part, re.S):
                label = re.search(r"<strong>(.*?)</strong>", line, re.S)
                if not label:
                    continue
                value = strip_tags(re.sub(r"<strong>.*?</strong>\s*:?", "", line, count=1, flags=re.S))
                if value:
                    pairs.append((strip_tags(label.group(1)), value))
            if pairs:
                yield "lines", heading, pairs


def entries(page: str):
    """Yield one record per real component row."""
    for kind, heading, payload in sections(page):
        if heading in SKIP_SECTIONS:
            continue

        if kind == "lines":
            # The package's own identity: its Version, and the file it ships
            # as. Named for the label the page uses rather than invented here.
            for label, value in payload:
                field = "filename" if "file" in label.lower() else "version"
                yield {
                    "section": heading,
                    "name": f"{heading} {label}",
                    "field": field,
                    "value": value,
                    # "Bundle file" already says bundle; "Version" does not.
                    "key": slug(label if label.lower().startswith("bundle")
                                else f"bundle {label}"),
                }
            continue

        rows = payload
        header, body = rows[0], rows[1:]
        # A three-column table carries a vendor that spans its rows; the
        # GB300 power shelf lists two PSU vendors this way, and flattening it
        # to component+version alone would merge two different parts.
        vendored = len(header) == 3
        vendor = ""
        seen: dict[str, int] = {}
        for cells in body:
            if vendored:
                if cells[0]:
                    vendor = cells[0]
                name, value = cells[1], cells[2]
            else:
                name, value = cells[0], cells[1]
            if not name or not value:
                continue

            field = "filename" if header[-1].lower() == "filename" else "version"
            label = f"{vendor} {name}".strip() if vendor else name
            key = slug(label)
            seen[key] = seen.get(key, 0) + 1
            if seen[key] > 1:
                # CX8 lists two CoRIMs under one heading. Distinct paths, so
                # composition never has to guess which one owns the name.
                key = f"{key}-{seen[key]}"

            yield {
                "section": heading,
                "name": label,
                "field": field,
                "value": value,
                "key": key,
            }


def yaml_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_catalog(source: dict, page: str, into: pathlib.Path, retrieved: str) -> int:
    count = 0
    for entry in entries(page):
        directory = into / slug(entry["section"])
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{entry['key']}.yaml"
        path.write_text(
            "# Generated by regenerate.py from public NVIDIA documentation.\n"
            "# Do not hand-edit: re-run the script instead.\n"
            f"component: {yaml_quote(entry['name'])}\n"
            f"subsystem: {yaml_quote(entry['section'])}\n"
            f"{entry['field']}: {yaml_quote(entry['value'])}\n",
            encoding="utf-8",
        )
        count += 1

    # Provenance lives once per catalog rather than in every component.
    #
    # Not tidiness: the system name and release number differ between any two
    # catalogs, so repeating them in each file would make every component
    # differ from its counterpart and a diff would report eighty-odd changes
    # where three firmware versions moved. What is invariant across a catalog
    # belongs to the catalog.
    # No retrieval date here, deliberately.
    #
    # SOURCE.yaml is part of the bundle, so anything in it reaches the subject
    # digest. A date meant the same version data regenerated tomorrow produced
    # a different digest -- in a demo whose entire subject is that identical
    # content has one name. The snapshot date belongs in the README, which
    # nobody signs.
    (into / "SOURCE.yaml").write_text(
        "# Generated by regenerate.py. Provenance for every component beside it.\n"
        f"system: {yaml_quote(source['system'])}\n"
        f"release: {yaml_quote(source['release'])}\n"
        f"url: {yaml_quote(source['url'])}\n",
        encoding="utf-8",
    )
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="re-derive and compare against the committed catalog")
    args = parser.parse_args()

    retrieved = _dt.date.today().isoformat()  # reported, not written
    target = pathlib.Path(tempfile.mkdtemp()) if args.check else CATALOG

    if not args.check and CATALOG.exists():
        shutil.rmtree(CATALOG)

    total = 0
    for source in SOURCES:
        page = fetch(source["url"])
        into = target / f"{source['slug']}-{source['release']}"
        written = write_catalog(source, page, into, retrieved)
        print(f"{source['slug']}: {written} components")
        total += written

    if args.check:
        # A straight comparison: the catalog is a pure function of the pages,
        # so anything that differs is the pages having changed. The earlier
        # version needed an ignore rule for the retrieval date and got its
        # indentation wrong, so --check would have reported drift every day
        # while quietly never comparing that line.
        diff = subprocess.run(
            ["diff", "-r", str(CATALOG), str(target)],
            capture_output=True, text=True, check=False,
        )
        if diff.returncode != 0:
            print(diff.stdout)
            sys.exit("the published pages no longer match the committed catalog")
        print("committed catalog matches the published pages")
    print(f"total: {total} components")


if __name__ == "__main__":
    main()
