#!/usr/bin/env python3
"""generate_readme.py - README.mdの AUTO-STATS:START/END マーカー範囲のみ自動更新"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent

BLOCK = """<!-- AUTO-STATS:START -->
Updated: {updated}

- Indicators: **{indicators}** (IPv4 {ipv4}, IPv6 {ipv6}, URL {url}, SHA256 {sha256})
- Status: {active} active / {stale} stale / {expired} expired
- High-confidence blocklist (`feeds/blocklist-high.txt`): {blocklist} entries
- Research scanners (separate list, do **not** block): {research}

<details><summary>By event type</summary>

| event_type | count | severity | confidence | TTL(days) |
|---|---|---|---|---|
{event_table}
</details>
<!-- AUTO-STATS:END -->"""


def update_stats(meta: dict, blocklist_count: int | None = None, research_count: int | None = None):
    sys.path.insert(0, str(ROOT / "scripts"))
    import classify
    readme = ROOT / "README.md"
    if not readme.exists():
        readme.parent.mkdir(parents=True, exist_ok=True)
        readme.write_text("# Honeypot IOC Feed\n\n## Current stats\n\n<!-- AUTO-STATS:START -->\n<!-- AUTO-STATS:END -->\n", encoding="utf-8")
    text = readme.read_text(encoding="utf-8")
    if blocklist_count is None:
        bl = ROOT / "feeds" / "blocklist-high.txt"
        blocklist_count = len([l for l in bl.read_text().splitlines() if l.strip()]) if bl.exists() else 0
    if research_count is None:
        rs = ROOT / "feeds" / "research-scanners.txt"
        research_count = len([l for l in rs.read_text().splitlines() if l.strip()]) if rs.exists() else 0
    tbl = "\n".join(
        f"| {et} | {n} | {classify.severity_of(et)} | {classify.confidence_of(et)} | {classify.ttl_days_of(et)} |"
        for et, n in sorted(meta.get("by_event_type", {}).items(), key=lambda x: -x[1]))
    block = BLOCK.format(
        updated=meta["updated"], indicators=meta["indicators"],
        ipv4=meta.get("ipv4", 0), ipv6=meta.get("ipv6", 0),
        url=meta.get("url", 0), sha256=meta.get("sha256", 0),
        active=meta.get("active", 0), stale=meta.get("stale", 0), expired=meta.get("expired", 0),
        blocklist=blocklist_count, research=research_count, event_table=tbl)
    new = re.sub(r"<!-- AUTO-STATS:START -->.*?<!-- AUTO-STATS:END -->",
                 lambda _: block, text, flags=re.S)
    if "<!-- AUTO-STATS:START -->" not in text:
        new = text.rstrip() + "\n\n## Current stats\n\n" + block + "\n"
    readme.write_text(new, encoding="utf-8")
    print(f"README.md stats updated ({meta['updated']})", file=sys.stderr)


if __name__ == "__main__":
    import json
    meta = json.loads((ROOT / "metadata.json").read_text(encoding="utf-8"))
    update_stats(meta)
