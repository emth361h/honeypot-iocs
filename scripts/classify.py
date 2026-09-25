#!/usr/bin/env python3
"""classify.py - IOC分類・重要度・信頼度・TTLの一元管理 (設定はこのファイルのみ)

event_typeごとの定義:
  severity    : 行為の危険度 (low/medium/high/critical)
  confidence  : 悪性IOCである確からしさ (0-100)
  ttl_days    : last_seenからこの日数を過ぎたら expired。active/staleの境界は ttl の 1/2
"""
from datetime import datetime, timedelta, timezone

# ---- 唯一の設定源 -----------------------------------------------------------
EVENT_TYPES = {
    # IPイベント (昇順 = 深刻度昇順で並べること。primary選択はこの順で行う)
    "ssh-probe":          {"severity": "low",      "confidence": 20,  "ttl_days": 7},
    "http-scan":          {"severity": "low",      "confidence": 30,  "ttl_days": 14},
    "decoy-harvester":    {"severity": "medium",   "confidence": 55,  "ttl_days": 30},
    "research-scanner":   {"severity": "info",     "confidence": 90,  "ttl_days": 90},   # 悪性ではない=別フィードへ
    "ssh-bruteforce":     {"severity": "medium",   "confidence": 60,  "ttl_days": 30},
    "ssh-post-auth":      {"severity": "high",     "confidence": 90,  "ttl_days": 90},
    "ssh-malware-drop":   {"severity": "critical", "confidence": 100, "ttl_days": 180},
    # URL / artifact
    "payload-url":        {"severity": "high",     "confidence": 80,  "ttl_days": 90},
    # artifact分類 (sha256)
    "malware-binary":     {"severity": "critical", "confidence": 90,  "ttl_days": 365},
    "dropper-script":     {"severity": "critical", "confidence": 85,  "ttl_days": 365},
    "persistence-artifact": {"severity": "high",   "confidence": 75,  "ttl_days": 365},
    "authorized-key":     {"severity": "high",     "confidence": 85,  "ttl_days": 365},
    "shell-profile":      {"severity": "medium",   "confidence": 50,  "ttl_days": 365},
    "forensic-artifact":  {"severity": "info",     "confidence": 30,  "ttl_days": 365},
    "unknown-artifact":   {"severity": "medium",   "confidence": 30,  "ttl_days": 365},
}
VALID_EVENT_TYPES = set(EVENT_TYPES)
IP_EVENT_TYPES = {"ssh-probe", "http-scan", "decoy-harvester", "research-scanner",
                  "ssh-bruteforce", "ssh-post-auth", "ssh-malware-drop"}
ARTIFACT_EVENT_TYPES = {"malware-binary", "dropper-script", "persistence-artifact",
                        "authorized-key", "shell-profile", "forensic-artifact", "unknown-artifact"}

# primary event_type選択の優先順位 (indexが小さいほど優先)
# research-scannerは測定機関判定を最優先にする (絶対にblocklistへ入れないため)
_PRIORITY = [
    "research-scanner",
    "ssh-malware-drop", "ssh-post-auth", "ssh-bruteforce", "decoy-harvester",
    "http-scan", "ssh-probe",
]

# ---- artifact分類ヒューリスティック -----------------------------------------
_ARTIFACT_RULES = [
    # (event_type, path/nameキーワード (小文字部分一致))
    ("dropper-script",       (".sh", "clean.sh", ".py", ".pl", "deploy", "install", "setup")),
    ("authorized-key",       ("authorized_keys", "id_rsa", "id_ed25519", ".pub", "ssh_key")),
    ("persistence-artifact", ("crontab", "cron.", "systemd", ".service", ".bashrc", ".profile",
                              "rc.local", "ld.so.preload", "pam.", ".update-logs", "persist")),
    ("shell-profile",        (".bash_profile", "zshrc", "profile.", "bashrc")),
    ("malware-binary",       ("redtail", ".16", "network", "xmrig", "brute", "masscan",
                              "billgates", "pan-chans", "kal64", "rt-", "kdevtmpfsi", "kinsing")),
]

def classify_artifact(name_hint: str) -> str:
    """パス/ファイル名ヒントからartifact種別を推定。確実でなければ unknown-artifact。"""
    n = (name_hint or "").lower()
    for etype, keys in _ARTIFACT_RULES:
        if any(k in n for k in keys):
            return etype
    return "unknown-artifact"

def primary_event_type(categories) -> str:
    """複数カテゴリから最重要の1つを選ぶ。"""
    cats = set(categories or [])
    for t in _PRIORITY:
        if t in cats:
            return t
    if cats:
        return sorted(cats)[0]
    return "unknown-artifact"

def severity_of(event_type: str) -> str:
    return EVENT_TYPES.get(event_type, {}).get("severity", "medium")

def confidence_of(event_type: str) -> int:
    return EVENT_TYPES.get(event_type, {}).get("confidence", 30)

def ttl_days_of(event_type: str) -> int:
    return EVENT_TYPES.get(event_type, {}).get("ttl_days", 30)

# ---- status計算 -------------------------------------------------------------
def status_of(last_seen: str, event_type: str, now: datetime | None = None) -> str:
    """last_seen + TTL から active / stale / expired を計算する。"""
    if now is None:
        now = datetime.now(timezone.utc)
    if isinstance(last_seen, str):
        last = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
    else:
        last = last_seen
    ttl = timedelta(days=ttl_days_of(event_type))
    age = now - last
    if age <= ttl / 2:
        return "active"
    if age <= ttl:
        return "stale"
    return "expired"

# blocklist-high 収録判定 (研究スキャナは絶対に入れない)
BLOCKLIST_EVENT_TYPES = {"ssh-malware-drop", "payload-url"}
BLOCKLIST_POSTAUTH_MIN_HITS = 3   # ssh-post-authはhits>=3で収録

def in_blocklist(event_type: str, hits: int, categories=None) -> bool:
    if event_type == "research-scanner" or "research-scanner" in (categories or set()):
        return False
    if event_type in BLOCKLIST_EVENT_TYPES:
        return True
    if event_type == "ssh-post-auth" and hits >= BLOCKLIST_POSTAUTH_MIN_HITS:
        return True
    return False

# 空ファイルSHA256 (絶対に登録しない)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
