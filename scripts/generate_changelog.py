#!/usr/bin/env python3
"""generate_changelog.py - 直前のfeedとの差分からCHANGELOG.mdの今日のエントリを生成

使い方 (Actions/local):
  python3 scripts/generate_changelog.py --old <(git show HEAD:feeds/iocs.csv) --new feeds/iocs.csv
  または --prev-file で古いCSVを指定。
設計:
  - エントリは日付見出し1個/日 (再実行で上書き = 無意味なdiffを出さない)
  - 履歴は最新MAX_ENTRIES件 (デフォルト90) にtruncate
"""
import argparse
import csv
import io
import sys
csv.field_size_limit(10 * 1024 * 1024)
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

MAX_ENTRIES = 90
HEADER = """# Changelog

Generated automatically from feed rebuilds. Newest first.
"""


def load_csv(text):
    return list(csv.DictReader(io.StringIO(text)))


def diff_summary(old_rows, new_rows):
    def key(r):
        return (r["type"], r["indicator"])
    old = {key(r): r for r in old_rows}
    new = {key(r): r for r in new_rows}
    added = Counter()
    removed = Counter()
    expired = 0
    unexpired = 0
    for k, r in new.items():
        if k not in old:
            added[r["type"]] += 1
        elif r["status"] == "expired" and old[k]["status"] != "expired":
            expired += 1
    for k, r in old.items():
        if k not in new:
            removed[r["type"]] += 1
        elif r["status"] != "expired" and new.get(k, {}).get("status", "") == "expired":
            pass  # 上で数えた
        elif r["status"] == "expired" and new.get(k, {}).get("status") != "expired":
            unexpired += 1
    return added, removed, expired, unexpired


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prev-file", default=None, help="古いfeeds/iocs.csv (無ければ初回扱い)")
    ap.add_argument("--new-file", default="feeds/iocs.csv")
    ap.add_argument("--out", default="CHANGELOG.md")
    ap.add_argument("--date", default=None)
    a = ap.parse_args()

    new_rows = load_csv(Path(a.new_file).read_text(encoding="utf-8"))
    old_rows = load_csv(Path(a.prev_file).read_text(encoding="utf-8")) if a.prev_file and Path(a.prev_file).exists() else []
    day = a.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    added, removed, expired, unexpired = diff_summary(old_rows, new_rows)
    if not any(added.values()) and not any(removed.values()) and expired == 0 and unexpired == 0:
        print("CHANGELOG: 差分なし — エントリ追加せず")
        return

    parts = []
    for t, label in (("ip", "IPv4/v6"), ("url", "URLs"), ("sha256", "SHA256")):
        if added.get(t):
            parts.append(f"+{added[t]} {label}")
        if removed.get(t):
            parts.append(f"-{removed[t]} {label}")
    if expired:
        parts.append(f"-{expired} expired")
    if unexpired:
        parts.append(f"+{unexpired} reactivated")
    entry = f"## {day}\n\n{', '.join(parts)}\n"

    # 既存CHANGELOGから当日エントリを置換、日付順に並べ替え、MAX_ENTRIESで切る
    entries = {}
    outp = Path(a.out)
    if outp.exists():
        cur = outp.read_text(encoding="utf-8")
        chunks = cur.split("\n## ")
        for ch in chunks[1:]:
            d = ch.split("\n", 1)[0].strip()
            entries[d] = "## " + ch.rstrip("\n")
    entries[day] = entry.rstrip("\n")
    ordered = [entries[d] for d in sorted(entries, reverse=True)[:MAX_ENTRIES]]
    outp.write_text(HEADER + "\n" + "\n\n".join(ordered) + "\n", encoding="utf-8")
    print(f"CHANGELOG: {day} — {', '.join(parts)}")


if __name__ == "__main__":
    main()
