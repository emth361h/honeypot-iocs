#!/usr/bin/env python3
"""honeypot_export.py - 汎用exporter: Cowrie JSON + HTTP captures → 集約観測 (observations)

公開repoに出せる「集約済み観測」だけを生成する。生テレメトリ (session ID / 秒精度
timestamp / コマンド本文 / login成否のイベント列) は一切出力しない構造。

出力 (observations/YYYY/MM/DD.jsonl, 1行 = 1集約):
  {"kind":"ip",   "ip":"1.2.3.4", "event_type":"ssh-bruteforce", "day":"...", "hits":N}
  {"kind":"url",  "url":"http://...", "day":"...", "hits":N}
  {"kind":"hash", "sha256":"...", "size":N, "day":"...", "hits":N}
  ※ url/hash は攻撃者インフラ側の指標。src_ipとの対応付けはローカルrawにのみ残る。

環境依存の値は環境変数 / 外部configからのみ読む (公開コードに実値を埋めない):
  HONEYPOT_SELF_IPS      カンマ区切り。自ホストIP (出力から完全除外+テキスト内マスク)
  HONEYPOT_EXCLUDE_NETS  カンマ区切り。除外network (未設定ならloopback/RFC1918のみ)
  HONEYPOT_DECOY_CONFIG  decoy判定keywordのjson (未設定ならdecoy判定なし=全てrequest)
    例: /etc/honeypot-iocs/decoy-patterns.json  {"keywords": [".env", ...]}

使い方:
  python3 scripts/honeypot_export.py --cowrie $COWRIE_LOG --captures $CAPTURES_LOG \
      --out observations [--date 2026-09-24]
"""
import argparse
import glob
import gzip
import ipaddress
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

URL_RE = __import__("re").compile(r"https?://[A-Za-z0-9._\-/:?=&%#~]+")

# --- 設定 (危険なデフォルト値は持たない) --------------------------------------
SELF_IPS = [x.strip() for x in os.environ.get("HONEYPOT_SELF_IPS", "").split(",") if x.strip()]
EXCLUDE_NETS = [ipaddress.ip_network(n) for n in os.environ.get(
    "HONEYPOT_EXCLUDE_NETS",
    "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fe80::/10").split(",") if n]

DECOY_KEYWORDS = []
_cfg = os.environ.get("HONEYPOT_DECOY_CONFIG", "")
if _cfg and os.path.exists(_cfg):
    try:
        DECOY_KEYWORDS = [str(k).lower() for k in json.load(open(_cfg, encoding="utf-8")).get("keywords", [])]
    except (OSError, json.JSONDecodeError):
        print("WARN: decoy configの読み込みに失敗 - decoy判定なしで続行", file=sys.stderr)
if not SELF_IPS:
    print("WARN: HONEYPOT_SELF_IPS未設定 (自IPのマスクなしで動作)", file=sys.stderr)


def sanitize_text(s: str) -> str:
    for ip in SELF_IPS:
        s = s.replace(ip, "[self]")
    return s


def ip_excluded(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if ip in SELF_IPS:
        return True
    return any(a in n for n in EXCLUDE_NETS)


def norm_day(ts: str) -> str:
    return str(ts).strip()[:10]


# --- Cowrie -------------------------------------------------------------------
COWRIE_ETYPE = {
    "cowrie.session.connect": "ssh-probe",
    "cowrie.login.failed": "ssh-bruteforce",
    "cowrie.login.success": "ssh-post-auth",
    "cowrie.command.input": "ssh-post-auth",
}

def scan_cowrie(paths, day, ip_hits, urls, hashes):
    for f in paths:
        opener = gzip.open if f.endswith(".gz") else open
        try:
            fh = opener(f, "rt", errors="ignore")
        except OSError:
            continue
        with fh:
            for line in fh:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if norm_day(e.get("timestamp", "")) != day:
                    continue
                ip = e.get("src_ip") or ""
                if ip_excluded(ip):
                    continue
                ev = e.get("eventid", "")
                # username/password/コマンド本文は絶対に集約対象にしない
                if ev in COWRIE_ETYPE:
                    ip_hits[(ip, COWRIE_ETYPE[ev])] += 1
                    if ev == "cowrie.command.input":
                        cmd = sanitize_text(str(e.get("input", "")))
                        for u in sorted(set(URL_RE.findall(cmd))):
                            urls[sanitize_text(u)] += 1
                elif ev in ("cowrie.file_download", "cowrie.file_upload"):
                    sha = str(e.get("shasum") or "").lower()
                    if len(sha) == 64 and sha != EMPTY_SHA:
                        hashes[(sha, int(e.get("fileSize") or 0))] += 1


# --- HTTP honeypot (captures.jsonl) -------------------------------------------
def scan_captures(paths, day, ip_hits):
    for f in paths:
        try:
            fh = gzip.open(f, "rt", errors="ignore") if f.endswith(".gz") else open(f, errors="ignore")
        except OSError:
            continue
        with fh:
            for line in fh:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if norm_day(e.get("ts", "")) != day:
                    continue
                ip = e.get("ip") or ""
                if ip_excluded(ip):
                    continue
                path = str(e.get("path", "")).lower()
                etype = "decoy-harvester" if any(k in path for k in DECOY_KEYWORDS) else "http-scan"
                ip_hits[(ip, etype)] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cowrie", default=None, help="cowrie.json path (env COWRIE_LOGも可)")
    ap.add_argument("--captures", default=None, help="captures.jsonl path (env CAPTURES_LOGも可)")
    ap.add_argument("--out", default="observations", help="出力ルート")
    ap.add_argument("--date", default=None, help="対象日 YYYY-MM-DD (default: 今日UTC)")
    a = ap.parse_args()
    cowrie = a.cowrie or os.environ.get("COWRIE_LOG")
    captures = a.captures or os.environ.get("CAPTURES_LOG")
    if not cowrie and not captures:
        ap.error("--cowrie/--captures (または COWRIE_LOG/CAPTURES_LOG) が必要")
    day = a.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    ip_hits, urls, hashes = defaultdict(int), defaultdict(int), defaultdict(int)
    if cowrie:
        files = [cowrie] + sorted(glob.glob(cowrie + ".[0-9]*") + glob.glob(cowrie + "*.gz"))
        scan_cowrie([f for f in files if os.path.exists(f)], day, ip_hits, urls, hashes)
    if captures:
        files = [captures] + sorted(glob.glob(captures + ".*"))
        scan_captures([f for f in files if os.path.exists(f)], day, ip_hits)

    records = []
    for (ip, etype), n in ip_hits.items():
        records.append({"kind": "ip", "ip": ip, "event_type": etype, "day": day, "hits": n})
    for u, n in urls.items():
        records.append({"kind": "url", "url": u, "day": day, "hits": n})
    for (sha, size), n in hashes.items():
        records.append({"kind": "hash", "sha256": sha, "size": size, "day": day, "hits": n})
    records.sort(key=lambda r: (r["kind"], r.get("ip") or r.get("url") or r.get("sha256") or ""))

    y, m, d = day.split("-")
    outp = Path(a.out) / y / m / (d + ".jsonl")
    outp.parent.mkdir(parents=True, exist_ok=True)
    with open(outp, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"OK {day}: {len(records)} aggregated observations -> {outp}")


if __name__ == "__main__":
    main()
