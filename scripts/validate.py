#!/usr/bin/env python3
"""validate.py - 生成されたfeedの自動検証。エラー時はnon-zeroで終了。

チェック: IP形式 / URL形式 / SHA256 64桁 / 空ファイルsha除外 / duplicate /
first_seen<=last_seen / hits正整数 / timestamp形式 / 必須フィールド / 不正event_type /
size非負 / blocklist構成 (research-scanner混入禁止) / metadata集計整合
"""
import csv
import ipaddress
import json
import re
import sys
from datetime import datetime
from pathlib import Path

csv.field_size_limit(10 * 1024 * 1024)  # 巨大URL/detail対策

sys.path.insert(0, str(Path(__file__).parent))
from classify import EMPTY_SHA256, VALID_EVENT_TYPES

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_COLS = ["indicator", "type", "event_type", "severity", "confidence", "status",
               "first_seen", "last_seen", "hits"]
REQUIRED_COLS = PUBLIC_COLS
FORBIDDEN_FEED_COLS = {"event_id", "detail", "session", "session_id", "password", "username"}
ENRICHED_COLS = PUBLIC_COLS + ["asn", "as_name", "country", "malware_family"]


def _err(errs, rowno, msg):
    errs.append(f"行{rowno}: {msg}")


def validate_iocs_csv(path, strict_public=True) -> list:
    errs = []
    seen = {}
    with open(path, newline="", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        cols = rdr.fieldnames or []
        for req in REQUIRED_COLS:
            if req not in cols:
                errs.append(f"ヘッダ欠落: {req} (実際: {cols})")
        if strict_public:
            bad = FORBIDDEN_FEED_COLS & set(cols)
            if bad:
                errs.append(f"公開feedに禁止カラム: {sorted(bad)}")
        for i, row in enumerate(rdr, 2):
            ind = (row.get("indicator") or "").strip()
            typ = (row.get("type") or "").strip()
            for req in REQUIRED_COLS:
                if not (row.get(req) or "").strip():
                    _err(errs, i, f"必須フィールド欠落 {req}")
            if not ind:
                continue
            key = (typ, ind)
            if key in seen:
                _err(errs, i, f"duplicate ({typ}) {ind} (行{seen[key]}と重複)")
            seen[key] = i
            # timestamp (日付粒度)
            for col in ("first_seen", "last_seen"):
                v = (row.get(col) or "").strip()
                if v and not TS_RE.match(v):
                    _err(errs, i, f"{col} 日付形式不正: {v}")
            try:
                f_, l_ = (row.get("first_seen") or ""), (row.get("last_seen") or "")
                if f_ and l_ and f_ > l_:
                    _err(errs, i, "first_seen > last_seen")
            except ValueError:
                pass
            # hits
            try:
                h = int(row.get("hits") or "0")
                if h < 1:
                    _err(errs, i, f"hitsは正整数であること: {h}")
            except ValueError:
                _err(errs, i, f"hits非整数: {row.get('hits')}")
            # type別
            if typ == "ip":
                try:
                    ipaddress.ip_address(ind)
                except ValueError:
                    _err(errs, i, f"IP形式不正: {ind}")
            elif typ == "url":
                if not re.match(r"^https?://[A-Za-z0-9._\-]+", ind):
                    _err(errs, i, f"URL形式不正: {ind}")
            elif typ == "sha256":
                if not SHA_RE.match(ind):
                    _err(errs, i, f"SHA256は64桁hex小文字であること: {ind[:20]}...")
                if ind == EMPTY_SHA256:
                    _err(errs, i, "空ファイルSHA256が混入している")
            else:
                _err(errs, i, f"不明なtype: {typ}")
            # event_type / severity / confidence / status
            et = (row.get("event_type") or "").strip()
            if et and et not in VALID_EVENT_TYPES:
                _err(errs, i, f"不正なevent_type: {et}")
            try:
                c = int(row.get("confidence") or "-1")
                if not 0 <= c <= 100:
                    _err(errs, i, f"confidence範囲外: {c}")
            except ValueError:
                _err(errs, i, "confidence非整数")
            if (row.get("status") or "").strip() not in ("active", "stale", "expired"):
                _err(errs, i, f"status不正: {row.get('status')}")
            # 外部enrichmentフィールドの整合 (optional)
            try:
                ec = (row.get("external_confidence") or "").strip()
                if ec and not 0 <= int(ec) <= 100:
                    _err(errs, i, f"external_confidence範囲外: {ec}")
                em = (row.get("external_malicious") or "").strip()
                if em and int(em) < 0:
                    _err(errs, i, f"external_malicious負値: {em}")
            except ValueError:
                _err(errs, i, "external_*フィールド非整数")
            # size
            sz = (row.get("size") or "").strip()
            if sz:
                try:
                    if int(sz) < 0:
                        _err(errs, i, f"size負値: {sz}")
                except ValueError:
                    _err(errs, i, f"size非整数: {sz}")
    return errs


def validate_feeds_dir(feeds: Path) -> list:
    errs = []
    # 純粋リスト形式
    for fn, pat, desc in (("ips.txt", r"^\d+\.\d+\.\d+\.\d+$|^[0-9a-f:]+$", "IP"),
                          ("hashes.txt", r"^[0-9a-f]{64}$", "SHA256")):
        p = feeds / fn
        if not p.exists():
            continue
        for i, ln in enumerate(p.read_text().splitlines(), 1):
            v = ln.strip()
            if v and not re.match(pat, v):
                errs.append(f"{fn}:{i} {desc}形式不正: {v[:40]}")
    bl = (feeds / "blocklist-high.txt").read_text().splitlines() if (feeds / "blocklist-high.txt").exists() else []
    rs = set((feeds / "research-scanners.txt").read_text().splitlines()) if (feeds / "research-scanners.txt").exists() else set()
    for i, ln in enumerate(bl, 1):
        if ln.strip() and ln.strip() in rs:
            errs.append(f"blocklist-high.txt:{i} research-scannerが混入: {ln}")
        if ln.strip() == EMPTY_SHA256:
            errs.append(f"blocklist-high.txt:{i} 空ファイルsha混入")
    return errs


def validate_metadata(feeds: Path) -> list:
    errs = []
    mp = feeds.parent / "metadata.json"
    ip = feeds / "iocs.csv"
    if not mp.exists() or not ip.exists():
        return [f"metadata.json または feeds/iocs.csv が無い"]
    meta = json.loads(mp.read_text(encoding="utf-8"))
    rows = list(csv.DictReader(open(ip, newline="", encoding="utf-8")))
    by = {}
    for r in rows:
        by[r["type"]] = by.get(r["type"], 0) + 1
        st = r.get("status")
        meta[st] = meta.get(st, 0)  # 存在確認用
    expect = {
        "indicators": len(rows),
        "ipv4": sum(1 for r in rows if r["type"] == "ip" and "." in r["indicator"]),
        "url": by.get("url", 0),
        "sha256": by.get("sha256", 0),
    }
    for k, v in expect.items():
        if meta.get(k) != v:
            errs.append(f"metadata.{k}={meta.get(k)} 実データ={v} 不整合")
    st_cnt = {"active": 0, "stale": 0, "expired": 0}
    for r in rows:
        if r.get("status") in st_cnt:
            st_cnt[r["status"]] += 1
    for k, v in st_cnt.items():
        if meta.get(k) != v:
            errs.append(f"metadata.{k}={meta.get(k)} 実データ={v} 不整合")
    if not meta.get("updated"):
        errs.append("metadata.updated 欠落")
    return errs


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    root = Path(__file__).parent.parent
    feeds = root / "feeds"
    errs = []
    tgt = feeds / "iocs.csv"
    if tgt.exists():
        errs += validate_iocs_csv(tgt)
    else:
        errs.append("feeds/iocs.csv が存在しない (generate_feeds.py を先に実行)")
    enr = feeds / "iocs-enriched.csv"
    if enr.exists():
        errs += validate_iocs_csv(enr)
        cols = (csv.DictReader(open(enr, newline="", encoding="utf-8")).fieldnames or [])
        if cols and cols != ENRICHED_COLS:
            errs.append(f"iocs-enriched.csv カラム構成不正: {cols}")
    errs += validate_feeds_dir(feeds)
    errs += validate_metadata(feeds)
    if errs:
        print(f"NG validation失敗 ({len(errs)}件):")
        for e in errs[:40]:
            print(f"  - {e}")
        sys.exit(1)
    print("OK validation合格 (feeds/iocs.csv + 派生feed + metadata)")


if __name__ == "__main__":
    main()
