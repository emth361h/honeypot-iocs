# Honeypot IOC Feed

Indicators of compromise harvested from a personal internet-facing honeypot (HTTP + SSH, running since 2026-09-08). Updated daily automatically.

## Files

| File | Format | Description |
|---|---|---|
| `iocs.csv` | CSV | Consolidated indicator feed (latest snapshot) |
| `history/` | CSV | Daily snapshots (YYYY-MM-DD.csv) |

## Schema

```
type,value,category,source,first_seen,last_seen,hits,detail
```

- **type**: `ip` / `url` / `sha256`
- **category**:
  - `ssh-bruteforce` — credential attacks against SSH
  - `ssh-post-auth` — executed commands after successful login (high-confidence malicious)
  - `ssh-malware-drop` — uploaded/downloaded binaries (highest confidence)
  - `ssh-probe` — connection-only scanning
  - `http-scan` — web vulnerability scanning
  - `decoy-harvester` — collected planted decoy credentials/config files
  - `payload-url` (urls) — malware distribution URLs observed in commands
  - `malware-sample` (sha256) — captured binary hashes
  - `research-scanner` — known internet measurement orgs (Censys, ONYPHE, Bitsight, ...). Listed for transparency; **blocking these is not necessarily recommended**.

## Notes & Disclaimer

- IPs may belong to shared hosting, proxies, or compromised machines — treat as "observed attacking", not as attribution.
- User-generated / university network ranges and the honeypot's own address are excluded.
- Data: [CC0](https://creativecommons.org/publicdomain/zero/1.0/). Code in this repo: MIT.
- Provided as-is for defensive research. No warranty.

## Stats

<!-- STATS-START -->
(updated automatically on push)
<!-- STATS-END -->
