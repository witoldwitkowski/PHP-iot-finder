#!/usr/bin/env python3
"""Regenerate data/oui.tsv from the IEEE registry.

Usage:
    scripts/update-oui.py                         # uses /usr/share/ieee-data (apt install ieee-data)
    scripts/update-oui.py oui.csv mam.csv         # or explicit IEEE CSV files
                                                  # (https://standards-oui.ieee.org/oui/oui.csv, .../oui28/mam.csv)
"""
import csv
import sys
from pathlib import Path

SUFFIXES = (", Inc.", ", Inc", " Inc.", " Inc", " Co., Ltd.", " Co.,Ltd.", " Co.,Ltd", " Co., Ltd", " CO.,LTD.",
            " Corporation", " Corp.", " Limited", " Ltd.", " GmbH", " LLC", " S.A.", " B.V.")


def rows(path, key_len):
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        r = csv.reader(fh)
        next(r)
        for row in r:
            if len(row) < 3:
                continue
            key, name = row[1].strip().upper(), " ".join(row[2].split()).replace("\t", " ")
            for s in SUFFIXES:
                if name.endswith(s):
                    name = name[: -len(s)].rstrip(",. ")
            if len(key) == key_len and name:
                yield key, name


def main():
    args = sys.argv[1:]
    if args:
        oui, mam = args[0], (args[1] if len(args) > 1 else None)
    else:
        base = Path("/usr/share/ieee-data")
        oui, mam = base / "oui.csv", base / "mam.csv"
    out = dict(rows(oui, 6))
    if mam and Path(mam).exists():
        out.update(rows(mam, 7))
    dest = Path(__file__).resolve().parent.parent / "data" / "oui.tsv"
    dest.write_text("".join(f"{k}\t{v}\n" for k, v in sorted(out.items())))
    print(f"wrote {len(out)} entries to {dest}")


if __name__ == "__main__":
    main()
