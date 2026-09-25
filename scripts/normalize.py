#!/usr/bin/env python3
"""normalize.py - 観測intake (observations) / 旧形式CSV を正規化レコードへ変換

正規化レコード (dict, 内部処理用):
  indicator, type(ip/url/sha256), first_seen, last_seen (YYYY-MM-DD), hits,
  categories (list), sources (list), size

入力:
  - observations/YYYY/MM/DD.jsonl (集約観測。本流)
      {"kind":"ip","ip":..,"event_type":..,"day":..,"hits":..}
      {"kind":"url","url":..,"day":..,"hits":..}
      {"kind":"hash","sha256":..,"size":..,"day":..,"hits":..}
  - 旧CSV (type,value,category,...) は convert_legacy.py による観測変換後は
    本流では使わない (互換ユーティリティとして parse_legacy_csv のみ残す)
"""
import csv
import json
import re
import sys
csv.field_size_limit(10 * 1024 * 1024)
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from classify import EMPTY_SHA256, classify_artifact

DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _new_rec(indicator, type_, first, last, hits, cats, sources, size=None):
    return {
        "indicator": indicator, "type": type_,
        "first_seen": first, "last_seen": last,
        "hits": max(1, int(hits or 1)),
        "categories": sorted(set(cats)),
        "sources": sorted(set(sources)),
        "size": size,
        "event_type": None,  # classify段で決定
    }


def parse_observations(path) -> list:
    """observations 1ファイル → レコード列 (dayは文字列日付のまま)。"""
    out = []
    for ln, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError as ex:
            raise ValueError(f"{path}:{ln} JSONパース失敗 {ex}") from ex
        day = e.get("day", "")
        if not DAY_RE.match(day):
            raise ValueError(f"{path}:{ln} day形式不正: {day!r}")
        kind = e.get("kind")
        hits = e.get("hits", 1)
        if kind == "ip":
            out.append(_new_rec(e["ip"], "ip", day, day, hits, [e["event_type"]], ["ssh" if e["event_type"].startswith("ssh") else "http"], None))
        elif kind == "url":
            out.append(_new_rec(e["url"], "url", day, day, hits, ["payload-url"], ["ssh"], None))
        elif kind == "hash":
            sha = str(e["sha256"]).lower()
            if sha == EMPTY_SHA256:
                continue
            out.append(_new_rec(sha, "sha256", day, day, hits, [classify_artifact(sha)], ["ssh"], e.get("size")))
        else:
            raise ValueError(f"{path}:{ln} kind不正: {kind!r}")
    return out


def parse_legacy_csv(path) -> list:
    """旧 iocs.csv (ルート互換形式) を正規化レコード列へ (変換ユーティリティ)。"""
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            typ = (row.get("type") or "").strip()
            val = (row.get("value") or "").strip()
            if not typ or not val:
                continue
            cats = [c for c in re.split(r"[/;]", row.get("category") or "") if c]
            sources = [s for s in (row.get("source") or "").split("+") if s]
            first = (row.get("first_seen") or "")[:10]  # 日付粒度へ切詰め
            last = (row.get("last_seen") or first)[:10]
            if typ == "sha256":
                val = val.lower()
                if val == EMPTY_SHA256:
                    continue
                cats = [classify_artifact((row.get("detail") or "") or val)]
            size = None
            sm = (row.get("detail") or "")
            m = re.search(r"size=(\d+)", sm)
            if m:
                size = int(m.group(1))
            out.append(_new_rec(val, typ, first, last, row.get("hits") or 1, cats, sources, size))
    return out


def aggregate(records: list) -> list:
    """indicator単位に集計 (first/last/hits/categories/sourcesをマージ)。"""
    agg = {}
    for r in records:
        k = (r["type"], r["indicator"])
        d = agg.get(k)
        if d is None:
            agg[k] = dict(r)
            continue
        d["first_seen"] = min(d["first_seen"], r["first_seen"])
        d["last_seen"] = max(d["last_seen"], r["last_seen"])
        d["hits"] += r["hits"]
        d["categories"] = sorted(set(d["categories"]) | set(r["categories"]))
        d["sources"] = sorted(set(d["sources"]) | set(r["sources"]))
        if r["size"] is not None:
            d["size"] = r["size"] if d["size"] is None else min(d["size"], r["size"])
    from classify import primary_event_type
    out = []
    for (typ, val), d in agg.items():
        if typ == "sha256" and d.get("size") == 0:
            continue
        d["event_type"] = primary_event_type(d["categories"])
        out.append(d)
    out.sort(key=lambda x: (-x["hits"], x["indicator"]))
    return out


def load(observations_dir: str | None = None, legacy_csv: str | None = None) -> list:
    records = []
    if observations_dir:
        for p in sorted(Path(observations_dir).rglob("*.jsonl")):
            records += parse_observations(p)
    if legacy_csv:
        records += parse_legacy_csv(legacy_csv)
    return aggregate(records)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="観測を正規化・集計してJSONへ吐く")
    ap.add_argument("--observations-dir", default="observations")
    ap.add_argument("--legacy-csv", default=None)
    ap.add_argument("-o", "--out", default="-")
    a = ap.parse_args()
    recs = load(a.observations_dir, a.legacy_csv)
    body = json.dumps(recs, ensure_ascii=False, indent=1)
    if a.out == "-":
        print(body)
    else:
        Path(a.out).write_text(body, encoding="utf-8")
        print(f"OK {len(recs)} indicators -> {a.out}", file=sys.stderr)
