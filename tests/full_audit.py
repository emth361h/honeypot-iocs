#!/usr/bin/env python3
"""full-audit.py - repo全面捜査: 構成・整合性・冪等性・セキュリティ"""
import csv, json, subprocess, sys, hashlib
csv.field_size_limit(10 * 1024 * 1024)
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
issues, oks = [], []

def ok(msg): oks.append(msg)
def issue(msg): issues.append(msg)

# 1. ファイル構成
expected = ["README.md", "metadata.json", "iocs.csv", "LICENSE",
            "feeds/iocs.csv", "feeds/iocs-enriched.csv", "feeds/ips.txt", "feeds/urls.txt", "feeds/hashes.txt",
            "feeds/blocklist-high.txt", "feeds/research-scanners.txt",
            "scripts/normalize.py", "scripts/classify.py", "scripts/validate.py",
            "scripts/generate_feeds.py", "scripts/generate_readme.py",
            "scripts/honeypot_export.py", "scripts/validate_raw.py", "scripts/publish.sh",
            "scripts/enrich.py", "scripts/generate_changelog.py",
            "config/research-scanners.json", "docs/SETUP.md",
            "tests/test_pipeline.py", "tests/test_enrich.py", "tests/test_determinism.py",
            ".github/workflows/process.yml", ".github/workflows/scheduled-enrichment.yml",
            ".env.example", "scripts/convert_legacy.py"]
for e in expected:
    if (ROOT / e).exists():
        ok(f"存在: {e}")
    else:
        issue(f"欠落: {e}")

# 2. 機密物の不在スキャン
danger_src = [b"PRIVATE KEY-----"]
for p in ROOT.rglob("*"):
    if p.name == "full_audit.py" or not p.is_file() or ".git" in str(p):
        continue
    if p.suffix in (".py", ".md", ".json", ".yml", ".sh", ".txt", ".csv"):
        try:
            if any(d in p.read_bytes() for d in danger_src):
                issue(f"⚠️ 秘密鍵らしき内容: {p}")
        except Exception: pass
ok("秘密鍵スキャン: 検出なし" if not any("秘密鍵らしき" in i for i in issues) else "秘密鍵検出")

# 3. feed整合性: 主feedと派生の一致
rows = list(csv.DictReader(open(ROOT/"feeds/iocs.csv", newline="", encoding="utf-8")))
ips_f = [l.strip() for l in open(ROOT/"feeds/ips.txt", encoding="utf-8") if l.strip()]
hashes_f = [l.strip() for l in open(ROOT/"feeds/hashes.txt", encoding="utf-8") if l.strip()]
ips_r = [r["indicator"] for r in rows if r["type"]=="ip"]
hashes_r = [r["indicator"] for r in rows if r["type"]=="sha256"]
ok(f"ips一致 ({len(ips_r)})") if sorted(ips_f)==sorted(ips_r) else issue("ips.txt不一致")
ok(f"hashes一致 ({len(hashes_r)})") if sorted(hashes_f)==sorted(hashes_r) else issue("hashes.txt不一致")

# 空sha/size0/research混入
EMPTY="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
for r in rows:
    if r["indicator"]==EMPTY: issue("空sha混入")
    sz = r.get("size","")
    if sz and sz.lstrip("-").isdigit() and int(sz)<0: issue("size negative")
bl = set(l.strip() for l in open(ROOT/"feeds/blocklist-high.txt", encoding="utf-8") if l.strip())
rs = set(l.strip() for l in open(ROOT/"feeds/research-scanners.txt", encoding="utf-8") if l.strip())
issue("research混入blocklist") if bl & rs else ok(f"blocklist {len(bl)}件, research除外OK")
for r in rows:
    if r["event_type"]=="research-scanner" and r["indicator"] in bl: issue("research分類なのにblocklist入り")

# 4. metadata整合
meta = json.loads((ROOT/"metadata.json").read_text(encoding="utf-8"))
st = Counter(r["status"] for r in rows)
for k in ("active","stale","expired"):
    if meta[k]!=st.get(k,0): issue(f"metadata.{k}不一致")
if meta["indicators"]!=len(rows): issue("metadata.indicators不一致")
ok(f"metadata整合 ({meta['indicators']}ind, active {meta['active']}/stale {meta['stale']}/exp {meta['expired']})")

# 5. ルート互換CSV整合
legacy = list(csv.DictReader(open(ROOT/"iocs.csv", newline="", encoding="utf-8")))
ok(f"root互換CSV {len(legacy)}行 (schema: {list(legacy[0].keys())[:4]}...)") if len(legacy)==len(rows) else issue(f"root CSV行数不一致 {len(legacy)} vs {len(rows)}")

# 6. README AUTO-STATSとmetadataの一致
rd = (ROOT/"README.md").read_text(encoding="utf-8")
if f"**{meta['indicators']}**" in rd: ok("README統計=metadata")
else: issue("README統計不一致")
if "AUTO-STATS:START" in rd: ok("AUTO-STATSマーカー存在")

# 7. raw所在地とevent総数
raws = sorted((ROOT/"raw").rglob("*.jsonl"))
n = sum(1 for f in raws for _ in open(f, encoding="utf-8"))
ok(f"raw {len(raws)}ファイル {n}events")

# 8. CHANGELOG
cl = ROOT/"CHANGELOG.md"
ok("CHANGELOG存在") if cl.exists() else issue("CHANGELOG無し (generate_changelog未実行)")

print(f"=== 捜査結果: OK {len(oks)} / 要注意 {len(issues)} ===")
for i in issues: print("⚠️ ", i)
print("(全OK)" if not issues else "")
