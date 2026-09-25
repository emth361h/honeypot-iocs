#!/usr/bin/env python3
"""validate_raw.py - observations JSONLのschema検証 (CI gate)

観測intake (observations/YYYY/MM/DD.jsonl) が公開可能な形状か検証する。
生テレメトリ (session/event_id/秒精度timestamp) や秘密情報が混入したら落とす。

ルール:
  - 行はJSON。kindは ip|url|hash のみ
  - 禁止キー: session, event_id, timestamp, src_ip, password, username, message, input, command
  - day は YYYY-MM-DD でファイルパス (YYYY/MM/DD) と一致
  - ip: global unicast (private/loopbackは混入禁止。self IPはそもそも除外済みのはず)
  - url: http(s) scheme。サイズ上限
  - hash: sha256 64hex・size>=0。空ファイルshaは禁止
  - 同一 (kind,キー) の重複行は禁止 (集約済みであること)
exit 1 = 検証失敗 (CI落ち)
"""
import ipaddress
import json
import re
import sys
from pathlib import Path

EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
FORBIDDEN_KEYS = {"session", "event_id", "timestamp", "src_ip", "password", "username",
                  "message", "input", "command", "token", "secret"}
ALLOWED_KEYS = {"kind", "ip", "url", "sha256", "size", "event_type", "day", "hits"}
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
EVENT_TYPES = {"ssh-probe", "ssh-bruteforce", "ssh-post-auth", "ssh-malware-drop",
               "http-scan", "decoy-harvester", "research-scanner", "unknown-artifact"}


def validate_file(path: Path) -> int:
    errors = 0
    m = re.search(r"(\d{4})[/\\](\d{2})[/\\](\d{2})\.jsonl$", str(path))
    expect_day = f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else None
    seen = set()
    n = 0
    for i, line in enumerate(open(path, encoding="utf-8"), 1):
        n += 1
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"ERR {path.name}:{i} JSONでない: {e}")
            errors += 1
            continue
        bad = FORBIDDEN_KEYS & set(rec)
        if bad:
            print(f"ERR {path.name}:{i} 禁止キー混入: {sorted(bad)}")
            errors += 1
        extra = set(rec) - ALLOWED_KEYS
        if extra:
            print(f"ERR {path.name}:{i} 未定義キー: {sorted(extra)}")
            errors += 1
        day = rec.get("day", "")
        if not DAY_RE.match(day) or (expect_day and day != expect_day):
            print(f"ERR {path.name}:{i} day不正: {day!r}")
            errors += 1
        kind = rec.get("kind")
        key = None
        if kind == "ip":
            key = rec.get("ip")
            try:
                addr = ipaddress.ip_address(key)
                if not addr.is_global:
                    print(f"ERR {path.name}:{i} non-global IP: {key}")
                    errors += 1
            except (ValueError, TypeError):
                print(f"ERR {path.name}:{i} IP形式不正: {key!r}")
                errors += 1
            if rec.get("event_type") not in EVENT_TYPES:
                print(f"ERR {path.name}:{i} event_type不正: {rec.get('event_type')!r}")
                errors += 1
        elif kind == "url":
            key = rec.get("url")
            if not isinstance(key, str) or not key.startswith(("http://", "https://")) or len(key) > 2048:
                print(f"ERR {path.name}:{i} url不正: {str(key)[:60]!r}")
                errors += 1
        elif kind == "hash":
            key = rec.get("sha256")
            if not isinstance(key, str) or not SHA_RE.match(key) or key == EMPTY_SHA:
                print(f"ERR {path.name}:{i} sha256不正: {str(key)[:20]!r}")
                errors += 1
            size = rec.get("size")
            if size is not None and (not isinstance(size, int) or size < 0):
                print(f"ERR {path.name}:{i} size不正: {size!r}")
                errors += 1
        else:
            print(f"ERR {path.name}:{i} kind不正: {kind!r}")
            errors += 1
        hits = rec.get("hits")
        if not isinstance(hits, int) or hits < 1:
            print(f"ERR {path.name}:{i} hits不正: {hits!r}")
            errors += 1
        if key is not None:
            if (kind, key, rec.get("event_type", "")) in seen:
                print(f"ERR {path.name}:{i} 重複record: {str(key)[:40]}")
                errors += 1
            seen.add((kind, key, rec.get("event_type", "")))
    print(f"  {path}: {n} records" + ("" if errors == 0 else f" ({errors} errors)"))
    return errors


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "observations")
    files = sorted(root.rglob("*.jsonl")) if root.exists() else []
    if not files:
        print(f"OK (no observation files under {root})")
        return
    total = sum(validate_file(f) for f in files)
    n = sum(1 for f in files for _ in open(f, encoding="utf-8"))
    if total:
        print(f"NG observation validation: {total} errors, {len(files)} files")
        sys.exit(1)
    print(f"OK observation validation: {n} records, {len(files)} files")


if __name__ == "__main__":
    main()
