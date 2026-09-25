# Honeypot IOC Feed

Indicators of compromise observed on a self-hosted, internet-facing honeypot
(SSH + HTTP surfaces). Aggregated, sanitized, and published as machine-readable feeds.

> This repository publishes **aggregated IOCs only**. Session-level telemetry,
> exact timestamps, honeypot internals, and decoy/detection logic are **not**
> part of the public data or code.

## Current stats

<!-- AUTO-STATS:START -->
Updated: 2026-09-25T00:00:00Z

- Indicators: **964** (IPv4 938, IPv6 0, URL 20, SHA256 6)
- Status: 647 active / 0 stale / 317 expired
- High-confidence blocklist (`feeds/blocklist-high.txt`): 222 entries
- Research scanners (separate list, do **not** block): 1

<details><summary>By event type</summary>

| event_type | count | severity | confidence | TTL(days) |
|---|---|---|---|---|
| ssh-probe | 502 | low | 20 | 7 |
| ssh-post-auth | 202 | high | 90 | 90 |
| http-scan | 146 | low | 30 | 14 |
| ssh-bruteforce | 74 | medium | 60 | 30 |
| payload-url | 20 | high | 80 | 90 |
| ssh-malware-drop | 7 | critical | 100 | 180 |
| decoy-harvester | 6 | medium | 55 | 30 |
| unknown-artifact | 6 | medium | 30 | 365 |
| research-scanner | 1 | info | 90 | 90 |
</details>
<!-- AUTO-STATS:END -->

## Feeds

| file | content |
|---|---|
| `feeds/iocs.csv` | main feed, minimal schema (see below) |
| `feeds/iocs-enriched.csv` | main feed + ASN / AS name / country / malware family |
| `feeds/ips.txt` | plain IP list |
| `feeds/urls.txt` | payload URLs seen in attacker commands |
| `feeds/hashes.txt` | SHA256 of dropped files |
| `feeds/blocklist-high.txt` | high-confidence subset recommended for blocking |
| `feeds/research-scanners.txt` | known measurement/research scanners (do **not** block) |
| `iocs.csv` (root) | legacy-compatible export of the main feed |
| `metadata.json` | counts, snapshot timestamp, per-type breakdown |

### Main feed schema (`feeds/iocs.csv`)

```text
indicator, type, event_type, severity, confidence, status,
first_seen, last_seen, hits
```

- `type`: `ip` | `url` | `sha256`
- `event_type`: behavioral classification (see table above)
- `severity` / `confidence` / TTL policy: defined in `scripts/classify.py`
- `status`: `active` / `stale` / `expired` (TTL-based, per event_type)
- dates are **day-granularity**; no session IDs, no event IDs, no raw commands

## Intake (what we publish and why it is safe)

The collector (`scripts/honeypot_export.py`) reads honeypot logs locally and
pushes only **pre-aggregated daily observations** (`observations/YYYY/MM/DD.jsonl`):
per (IP, event_type, day) counters, distinct payload URLs, and file hashes.
Environment-specific values (self IP, exclusion networks, decoy detection
patterns) live in a private config on the honeypot host and are never committed.

## Update flow

```text
honeypot (daily, systemd timer)
  raw logs → sanitize → aggregate → push observations/
GitHub Actions (on observations push)
  validate → normalize → classify → enrich (ASN via Team Cymru;
  TI lookups optional via Secrets) → generate feeds → tests → commit
```

Enrichment caches are kept in GitHub Actions cache, not in git.

## License / usage

See `LICENSE`. Feeds are provided for defensive and research purposes, as-is.
Research scanner ranges are excluded from blocklist output only when backed by
official or verified sources (`config/research-scanners.json`, `basis` field).
