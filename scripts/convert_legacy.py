#!/usr/bin/env python3
"""convert_legacy.py - 旧形式データ → observations 集約観測への変換ユーティリティ

対象:
  1) v2.1までの raw/YYYY/MM/DD.jsonl (イベント単位) → 集約観測
  2) v1の iocs.csv (type,value,category,...) → 集約観測 (day=last_seen日)

使い方:
  python3 scripts/convert_legacy.py --from-raw raw --from-legacy-csv old-iocs.csv --out observations
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import normalize  # noqa: E402


def write_observations(records, out_root):
    byday = defaultdict(list)
    for r in records:
        day = r["last_seen"][:10]
        if r["type"] == "ip":
            byday[day].append({"kind": "ip", "ip": r["indicator"],
                               "event_type": r["event_type"], "day": day, "hits": r["hits"]})
        elif r["type"] == "url":
            byday[day].append({"kind": "url", "url": r["indicator"], "day": day, "hits": r["hits"]})
        elif r["type"] == "sha256":
            rec = {"kind": "hash", "sha256": r["indicator"], "day": day, "hits": r["hits"]}
            if r.get("size") is not None:
                rec["size"] = r["size"]
            byday[day].append(rec)
    n = 0
    for day, recs in sorted(byday.items()):
        y, m, d = day.split("-")
        # 同一 (kind, key, event_type) をマージ
        merged = {}
        for r in recs:
            k = (r["kind"], r.get("ip") or r.get("url") or r.get("sha256"), r.get("event_type", ""))
            if k in merged:
                merged[k]["hits"] += r["hits"]
            else:
                merged[k] = r
        out = sorted(merged.values(),
                     key=lambda r: (r["kind"], r.get("ip") or r.get("url") or r.get("sha256") or ""))
        p = Path(out_root) / y / m / (d + ".jsonl")
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            for r in out:
                f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
                n += 1
    print(f"OK {n} observation records -> {out_root}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-raw", default=None, help="旧 raw/ ルート (イベント単位jsonl)")
    ap.add_argument("--from-legacy-csv", default=None, help="v1形式 iocs.csv")
    ap.add_argument("--out", default="observations")
    a = ap.parse_args()
    if not a.from_raw and not a.from_legacy_csv:
        ap.error("--from-raw か --from-legacy-csv を指定")
    records = []
    if a.from_raw:
        # 旧イベント形式はnormalizeのlegacy経路で集約してから観測化
        for p in sorted(Path(a.from_raw).rglob("*.jsonl")):
            records += _parse_old_events(p)
    if a.from_legacy_csv:
        records += normalize.parse_legacy_csv(a.from_legacy_csv)
    recs = normalize.aggregate(records)
    write_observations(recs, a.out)


def _parse_old_events(path):
    """v2.1までのイベント単位jsonl → normalize互換レコード (最小解釈)。"""
    IP_EVENT_MAP = {
        "connect": "ssh-probe", "login.failed": "ssh-bruteforce",
        "login.success": "ssh-post-auth", "command.input": "ssh-post-auth",
        "url.observed": "ssh-post-auth", "file.download": "ssh-malware-drop",
        "request": "http-scan", "decoy.fetch": "decoy-harvester",
    }
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        e = json.loads(line)
        day = e.get("timestamp", "")[:10]
        ip = e.get("src_ip", "")
        ev = e.get("event", "")
        svc = e.get("service", "ssh")
        if ip and ev in IP_EVENT_MAP:
            etype = IP_EVENT_MAP[ev]
            out.append({"indicator": ip, "type": "ip", "first_seen": day, "last_seen": day,
                        "hits": 1, "categories": [etype], "sources": [svc], "size": None,
                        "event_type": None})
        url = e.get("url") or ""
        if url and ev in ("url.observed", "file.download"):
            out.append({"indicator": url, "type": "url", "first_seen": day, "last_seen": day,
                        "hits": 1, "categories": ["payload-url"], "sources": [svc], "size": None,
                        "event_type": None})
        sha = (e.get("sha256") or "").lower()
        if sha and len(sha) == 64:
            out.append({"indicator": sha, "type": "sha256", "first_seen": day, "last_seen": day,
                        "hits": 1, "categories": ["unknown-artifact"], "sources": [svc],
                        "size": e.get("size"), "event_type": None})
    return out


if __name__ == "__main__":
    main()
