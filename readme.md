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
  - `ssh-bruteforce`  Ecredential attacks against SSH
  - `ssh-post-auth`  Eexecuted commands after successful login (high-confidence malicious)
  - `ssh-malware-drop`  Euploaded/downloaded binaries (highest confidence)
  - `ssh-probe`  Econnection-only scanning
  - `http-scan`  Eweb vulnerability scanning
  - `decoy-harvester`  Ecollected planted decoy credentials/config files
  - `payload-url` (urls)  Emalware distribution URLs observed in commands
  - `malware-sample` (sha256)  Ecaptured binary hashes
  - `research-scanner`  Eknown internet measurement orgs (Censys, ONYPHE, Bitsight, ...). Listed for transparency; **blocking these is not necessarily recommended**.

## Notes & Disclaimer

- IPs may belong to shared hosting, proxies, or compromised machines  Etreat as "observed attacking", not as attribution.
- User-generated / university network ranges and the honeypot's own address are excluded.
- Data: [CC0](https://creativecommons.org/publicdomain/zero/1.0/). Code in this repo: MIT.
- Provided as-is for defensive research. No warranty.

## Stats

<!-- STATS-START -->
2026-09-12 11:01 ? 311 indicators (303 IPs)
<!-- STATS-END -->



