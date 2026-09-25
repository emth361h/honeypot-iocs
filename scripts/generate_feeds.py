#!/usr/bin/env python3
"""generate_feeds.py - パイプライン統括: normalize → classify → enrichment適用 → feed生成

公開最小化設計 (v2.2):
  - 入力: observations/YYYY/MM/DD.jsonl (集約観測のみ。生テレメトリはGitHubに置かない)
  - deterministic: as_of = データ内max last_seen (--as-ofで上書き可)。再実行で無意味なdiffを出さない
  - enrichmentはenrich-cache.json (git管理外) から適用。cacheが無ければenrichment列は空で生成
  - research-scanner設定は basis (official/verified/heuristic) を持ち、
    official/verified のみ event_type強制とblocklist除外に使う (heuristicは安全側に無視)

出力:
  feeds/iocs.csv            公開メインfeed (最小構成)
  feeds/iocs-enriched.csv   メイン + asn/as_name/country/malware_family
  feeds/{ips,urls,hashes,blocklist-high,research-scanners}.txt
  iocs.csv (ルート, 旧互換: detailはevent_typeのみ)
  internal/iocs-internal.csv (git管理外。enrich.py用の全列)
  metadata.json, README AUTO-STATS
"""
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

csv.field_size_limit(10 * 1024 * 1024)

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import classify  # noqa: E402
import normalize  # noqa: E402
import generate_readme  # noqa: E402

PUBLIC_COLS = ["indicator", "type", "event_type", "severity", "confidence", "status",
               "first_seen", "last_seen", "hits"]
ENRICHED_EXTRA = ["asn", "as_name", "country", "malware_family"]
INTERNAL_EXTRA = ["size", "external_sources", "external_malicious",
                  "external_confidence", "last_enriched"]
INTERNAL_COLS = PUBLIC_COLS + ENRICHED_EXTRA + INTERNAL_EXTRA
LEGACY_COLS = ["type", "value", "category", "source", "first_seen", "last_seen", "hits", "detail"]


def load_research_config():
    """config/research-scanners.json → [(prefix, org, basis)]。信頼できるのはofficial/verifiedのみ。"""
    p = ROOT / "config" / "research-scanners.json"
    entries = []
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            for e in data.get("entries", []):
                pref = str(e.get("prefix", "")).rstrip("*")
                if pref:
                    entries.append((pref, e.get("org", ""), e.get("basis", "heuristic")))
        except json.JSONDecodeError:
            print("WARN research-scanners.json 破損", file=sys.stderr)
    return entries


def research_match(indicator: str, entries):
    """official/verified のprefixに一致した場合のみ (org, basis) を返す。"""
    for pref, org, basis in entries:
        if basis in ("official", "verified") and (indicator == pref or indicator.startswith(pref)):
            return org, basis
    return None


def load_enrich_cache(path):
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def apply_enrichment(row, cache):
    ti = cache.get("__ti__", {}).get(row["indicator"], {})
    ip_info = cache.get(row["indicator"], {}) if row["type"] == "ip" else {}
    row["asn"] = ip_info.get("asn", "")
    row["as_name"] = ip_info.get("as_name", "")
    row["country"] = ip_info.get("country", "")
    row["malware_family"] = ti.get("signature", "")
    row["external_sources"] = ";".join(ti.get("sources", []))
    row["external_malicious"] = ti.get("malicious", "")
    row["external_confidence"] = ti.get("confidence", "")
    row["last_enriched"] = ti.get("checked", "") or ip_info.get("checked", "")
    return row


def build(recs, now, research_entries):
    rows = []
    for r in recs:
        et = r["event_type"]
        if r["type"] == "ip":
            m = research_match(r["indicator"], research_entries)
            if m:
                et = "research-scanner"
        row = {
            "indicator": r["indicator"], "type": r["type"],
            "event_type": et,
            "severity": classify.severity_of(et),
            "confidence": classify.confidence_of(et),
            "status": classify.status_of(r["last_seen"], et, now),
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "hits": r["hits"],
            "size": "" if r.get("size") is None else r["size"],
            "_categories": r["categories"],
        }
        rows.append(row)
    rows.sort(key=lambda x: (-int(x["hits"]), x["indicator"]))
    return rows


def write_csv(path, rows, cols):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_all(rows, updated, cache):
    feeds = ROOT / "feeds"
    feeds.mkdir(exist_ok=True)
    (ROOT / "internal").mkdir(exist_ok=True)

    for r in rows:
        apply_enrichment(r, cache)

    write_csv(feeds / "iocs.csv", rows, PUBLIC_COLS)
    write_csv(feeds / "iocs-enriched.csv", rows, PUBLIC_COLS + ENRICHED_EXTRA)
    write_csv(ROOT / "internal" / "iocs-internal.csv", rows, INTERNAL_COLS)

    ips = [r["indicator"] for r in rows if r["type"] == "ip"]
    urls = [r["indicator"] for r in rows if r["type"] == "url"]
    hashes = [r["indicator"] for r in rows if r["type"] == "sha256"]
    (feeds / "ips.txt").write_text("\n".join(ips) + "\n", encoding="utf-8")
    (feeds / "urls.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
    (feeds / "hashes.txt").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    bl = sorted(set(r["indicator"] for r in rows
                    if r["type"] != "sha256" and classify.in_blocklist(
                        r["event_type"], r["hits"], r["_categories"])))
    rs = sorted(set(r["indicator"] for r in rows if r["event_type"] == "research-scanner"))
    (feeds / "blocklist-high.txt").write_text("\n".join(bl) + "\n", encoding="utf-8")
    (feeds / "research-scanners.txt").write_text("\n".join(rs) + "\n", encoding="utf-8")

    # ルート旧互換 (detail = event_type のみ。内部ID/セッション情報は出さない)
    with open(ROOT / "iocs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(LEGACY_COLS)
        for r in rows:
            src = {"ip": "ssh", "url": "ssh-command", "sha256": "cowrie/evidence"}.get(r["type"], "")
            w.writerow([r["type"], r["indicator"], r["event_type"], src,
                        r["first_seen"], r["last_seen"], r["hits"], r["event_type"]])

    st = {"active": 0, "stale": 0, "expired": 0}
    for r in rows:
        st[r["status"]] += 1
    meta = {
        "updated": updated,
        "indicators": len(rows),
        "ipv4": sum(1 for r in rows if r["type"] == "ip" and "." in r["indicator"]),
        "ipv6": sum(1 for r in rows if r["type"] == "ip" and ":" in r["indicator"]),
        "url": sum(1 for r in rows if r["type"] == "url"),
        "sha256": sum(1 for r in rows if r["type"] == "sha256"),
        "active": st["active"], "stale": st["stale"], "expired": st["expired"],
        "by_event_type": {},
        "schema": "v2",
    }
    for r in rows:
        meta["by_event_type"][r["event_type"]] = meta["by_event_type"].get(r["event_type"], 0) + 1
    (ROOT / "metadata.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--observations-dir", default=str(ROOT / "observations"))
    ap.add_argument("--legacy-csv", default=None, help="旧形式CSV (変換ユーティリティ用)")
    ap.add_argument("--enrich-cache", default=str(ROOT / "enrich-cache.json"))
    ap.add_argument("--as-of", default=None, help="status計算の基準日 YYYY-MM-DD (default: データ内max last_seen)")
    a = ap.parse_args()

    recs = normalize.load(a.observations_dir, a.legacy_csv)
    if not recs:
        print("入力レコード0件 (observationsが空)", file=sys.stderr)
        sys.exit(1)

    if a.as_of:
        as_of = datetime.fromisoformat(a.as_of + "T23:59:59+00:00")
    else:
        as_of = max(datetime.fromisoformat(r["last_seen"]) for r in recs).replace(tzinfo=timezone.utc)

    research_entries = load_research_config()
    rows = build(recs, as_of, research_entries)
    cache = load_enrich_cache(a.enrich_cache)
    meta = write_all(rows, as_of.strftime("%Y-%m-%dT%H:%M:%SZ"), cache)
    generate_readme.update_stats(meta)
    print(f"OK {meta['indicators']} indicators "
          f"(ip {meta['ipv4'] + meta['ipv6']} / url {meta['url']} / sha256 {meta['sha256']}) "
          f"active {meta['active']} / stale {meta['stale']} / expired {meta['expired']} "
          f"as_of={meta['updated']}")


if __name__ == "__main__":
    main()
