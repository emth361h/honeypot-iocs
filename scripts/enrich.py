#!/usr/bin/env python3
"""enrich.py - ASN/Geo/TI enrichment (Actions側で実行。honeypotには置かない)

方針:
  - ASN/AS name/country: Team Cymru whois (port 43, 無料・キー不要) を一括バルク問い合わせ
  - cache: enrich-cache.json (git管理外。Actions cache/artifactで持ち回す。IP→{asn,as_name,country,checked})
  - TTL: ASN情報 14日。失敗時は古いcache値を保持して処理続行 (fail-open)
  - TI (任意): URLhaus / MalwareBazaar (キー不要) + VirusTotal / GreyNoise / AbuseIPDB (env key)
  - API keyが無い/失敗した場合もworkflow全体は失敗させない
  - 外部判定は独立フィールドへ (confidence を上書きしない):
      external_sources, external_malicious, external_confidence, last_enriched
使い方:
  python3 scripts/enrich.py --feeds internal/iocs-internal.csv --cache enrich-cache.json [--force] [--max N]
  ※ 結果はcacheにのみ書き出す。feed列への適用は generate_feeds が行う。
"""
import argparse
import csv
import sys
csv.field_size_limit(10 * 1024 * 1024)  # 巨大URL/detail対策
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

CACHE_TTL_DAYS = 14
TI_TTL_DAYS = 7
HTTP_TIMEOUT = 12
RETRIES = 2

# ---------------- Team Cymru bulk whois --------------------------------------
def cymru_bulk(ips: list, fetch=None) -> dict:
    """whois.cymru.com:43 へバルク問い合わせ。{ip: {asn,as_name,country}} を返す。"""
    if fetch is not None:  # test hook
        try:
            return fetch(ips)
        except Exception as e:  # mock含め障害は全てfail-open
            print(f"  WARN cymru失敗 ({e}) — cache保持で続行", file=sys.stderr)
            return {}
    q = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    last_err = None
    for attempt in range(RETRIES + 1):
        try:
            s = socket.create_connection(("whois.cymru.com", 43), timeout=20)
            s.sendall(q.encode())
            time.sleep(1.0)  # cymruは即SHUT_WRすると空応答になる (2026-09-24実証)
            s.settimeout(30)
            buf = b""
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            except socket.timeout:
                pass  # 読み出しタイムアウトはバナー分完成済みの可能性
            s.close()
            out = {}
            lines = buf.decode(errors="replace").splitlines()
            # 1行目は "Bulk mode; ..." バナー。データ行: asn|ip|prefix|cc|registry|allocated|as_name
            for line in lines[1:]:
                f = [x.strip() for x in line.split("|")]
                if len(f) >= 7:
                    asn, ip, country, as_name = f[0], f[1], f[3], f[6]
                    out[ip] = {"asn": "" if asn in ("NA", "") else asn.split()[0],
                               "as_name": as_name if asn != "NA" else "",
                               "country": country if len(country) == 2 else ""}
            return out
        except (OSError, socket.timeout) as e:
            last_err = e
            time.sleep(2 * (attempt + 1))
    print(f"  WARN cymru失敗 ({last_err}) — cache保持で続行", file=sys.stderr)
    return {}

# ---------------- 任意TI (env key必須、失敗はskip) -----------------------------
def _http_json(url, data=None, headers=None, fetch=None):
    if fetch is not None:
        return fetch(url, data, headers)
    req = urllib.request.Request(url, data=(urllib.parse.urlencode(data).encode() if data else None),
                                 headers=headers or {})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return json.loads(r.read().decode(errors="replace"))

def ti_check_urlhaus(url: str) -> bool | None:
    """URLhaus照会。True=malicious, False=clean, None=不明/失敗"""
    try:
        key = os.environ.get("URLHAUS_AUTH_KEY")
        h = {"Auth-Key": key} if key else {}
        j = _http_json("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers=h)
        return j.get("query_status") == "found"
    except Exception:
        return None

def ti_check_malwarebazaar(sha256: str) -> str | None:
    """MalwareBazaar照会 → signature (malware family) or None"""
    try:
        j = _http_json("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": sha256})
        data = (j.get("data") or [{}])[0]
        sig = data.get("signature")
        return sig if j.get("query_status") == "ok" and sig else None
    except Exception:
        return None

def ti_check_abuseipdb(ip: str) -> bool | None:
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return None
    try:
        j = _http_json(f"https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ip={ip}",
                       headers={"Key": key, "Accept": "application/json"})
        d = j.get("data", {})
        return d.get("abuseConfidenceScore", 0) >= 25
    except Exception:
        return None

def ti_check_virustotal(indicator: str, type_: str) -> bool | None:
    key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return None
    try:
        base = "https://www.virustotal.com/api/v3/"
        path = {"ip": f"ip_addresses/{indicator}", "url": f"urls/{indicator}",
                "sha256": f"files/{indicator}"}[type_]
        j = _http_json(base + path, headers={"x-apikey": key})
        stats = ((j.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        return stats.get("malicious", 0) > 0
    except Exception:
        return None

def ti_check_greynoise(ip: str) -> bool | None:
    key = os.environ.get("GREYNOISE_API_KEY")
    if not key:
        return None
    try:
        j = _http_json(f"https://api.greynoise.io/v3/community/{ip}",
                       headers={"key": key})
        return j.get("classification") == "malicious"
    except Exception:
        return None

TI_CHECKERS = {  # (type) -> func; env key必須のものは内部で判定
    "ip": [("abuseipdb", ti_check_abuseipdb), ("virustotal", lambda v: ti_check_virustotal(v, "ip")),
           ("greynoise", ti_check_greynoise)],
    "url": [("urlhaus", ti_check_urlhaus), ("virustotal", lambda v: ti_check_virustotal(v, "url"))],
    "sha256": [("malwarebazaar", ti_check_malwarebazaar)],
}

def run_ti(indicator: str, type_: str, ti_cache: dict, fetch=None) -> dict:
    """1指標分のTI照会+cache更新。{sources, malicious, family} を返す。"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    c = ti_cache.get(indicator)
    if c and now < c.get("expires", ""):
        return c
    sources, malicious, fam = [], 0, None
    for name, fn in TI_CHECKERS.get(type_, []):
        r = fn(indicator)
        if r is None:
            continue
        sources.append(name)
        if r is True:
            malicious += 1
        if name == "malwarebazaar" and isinstance(r, str):
            fam = r
        time.sleep(0.3)  # rate配慮
    out = {"sources": sources, "malicious": malicious, "family": fam,
           "expires": (datetime.now(timezone.utc) + timedelta(days=TI_TTL_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "checked": now}
    if sources:
        ti_cache[indicator] = out
    return out

# ---------------- main --------------------------------------------------------
def apply_asn(rows, cache, got, now_iso):
    """rows/cache へASN結果を適用。失敗IPは既存cache値を保持 (fail-open)。戻り値: 無ASN数"""
    asn_fail = 0
    for r in rows:
        if r["type"] != "ip":
            continue
        ip = r["indicator"]
        c = cache.get(ip, {})
        if ip in got:
            c.update(got[ip]); c["checked"] = now_iso
            cache[ip] = c
        r["asn"], r["as_name"], r["country"] = c.get("asn", ""), c.get("as_name", ""), c.get("country", "")
        if not c.get("asn"):
            asn_fail += 1
    return asn_fail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds", default="internal/iocs-internal.csv")
    ap.add_argument("--cache", default="enrich-cache.json")
    ap.add_argument("--force", action="store_true", help="cache TTL無視で再照会")
    ap.add_argument("--max", type=int, default=400, help="TI照会する指標の上限 (rate保護)")
    ap.add_argument("--no-ti", action="store_true")
    a = ap.parse_args()

    rows = list(csv.DictReader(open(a.feeds, newline="", encoding="utf-8")))
    cache = {}
    if Path(a.cache).exists():
        try:
            cache = json.loads(Path(a.cache).read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("WARN cache破損 — 作り直し", file=sys.stderr)
    nowd = datetime.now(timezone.utc)
    fresh_horizon = (nowd - timedelta(days=CACHE_TTL_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 1) ASN/Geo
    need = sorted(set(r["indicator"] for r in rows
                      if r["type"] == "ip" and (a.force or not (cache.get(r["indicator"], {}).get("checked", "") >= fresh_horizon))))
    print(f"ASN照会: {len(need)} IP")
    got = cymru_bulk(need) if need else {}
    asn_fail = apply_asn(rows, cache, got, nowd.strftime("%Y-%m-%dT%H:%M:%SZ"))
    if got == {} and need:
        print(f"WARN ASN全滅 — 既存値/空欄で続行 ({asn_fail} IP無ASN)", file=sys.stderr)

    # 2) TI (任意)
    ti_cache = cache.get("__ti__", {})
    if not a.no_ti:
        ti_rows = [r for r in rows if r["event_type"] not in ("research-scanner",)]
        # 優先度: malware-drop/post-auth/sha256/url → それ以外
        prio = {"sha256": 0, "url": 1, "ip": 2}
        ti_rows.sort(key=lambda r: (prio.get(r["type"], 3), -int(r["hits"] or 1)))
        done = 0
        for r in ti_rows:
            if done >= a.max:
                break
            res = run_ti(r["indicator"], r["type"], ti_cache)
            if res.get("sources"):
                done += 1
                r["external_sources"] = ",".join(res["sources"])
                r["external_malicious"] = str(res["malicious"])
                r["external_confidence"] = str(round(100 * res["malicious"] / len(res["sources"])))
            if res.get("family") and not r.get("malware_family"):
                r["malware_family"] = res["family"]
                r["family_confidence"] = "80"
            r["last_enriched"] = nowd.strftime("%Y-%m-%dT%H:%M:%SZ")
    cache["__ti__"] = ti_cache

    # 3) cache書き戻しのみ (feed列は generate_feeds がcacheから適用する。二重管理しない)
    cache["__ti__"] = ti_cache
    Path(a.cache).write_text(json.dumps(cache, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")
    asn_ok = sum(1 for ip, c in cache.items() if ip != "__ti__" and c.get("asn"))
    print(f"OK enrich: ASN {asn_ok} IP in cache, TI {len(ti_cache)} entries")

if __name__ == "__main__":
    main()
