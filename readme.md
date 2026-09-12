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
  - `ssh-bruteforce` 窶・credential attacks against SSH
  - `ssh-post-auth` 窶・executed commands after successful login (high-confidence malicious)
  - `ssh-malware-drop` 窶・uploaded/downloaded binaries (highest confidence)
  - `ssh-probe` 窶・connection-only scanning
  - `http-scan` 窶・web vulnerability scanning
  - `decoy-harvester` 窶・collected planted decoy credentials/config files
  - `payload-url` (urls) 窶・malware distribution URLs observed in commands
  - `malware-sample` (sha256) 窶・captured binary hashes
  - `research-scanner` 窶・known internet measurement orgs (Censys, ONYPHE, Bitsight, ...). Listed for transparency; **blocking these is not necessarily recommended**.

## Notes & Disclaimer

- IPs may belong to shared hosting, proxies, or compromised machines 窶・treat as "observed attacking", not as attribution.
- User-generated / university network ranges and the honeypot's own address are excluded.
- Data: [CC0](https://creativecommons.org/publicdomain/zero/1.0/). Code in this repo: MIT.
- Provided as-is for defensive research. No warranty.

## Stats

<!-- STATS-START -->
- Last updated: 2026-09-12 UTC
- Unique IPs: 409 | Payload URLs: 8 | Malware hashes: 10
- Categories (IP may overlap): ssh-probe 271 / http-scan 131 / ssh-bruteforce 90 / ssh-post-auth 32 / decoy-harvester 18 / research-scanner 5 / ssh-malware-drop 4
- Notable: DIICOT-family toolkit (spreader+deployer+miner+key implants), BillGates-family DDoS bot (kal64), handshakebins.sh multi-binary loader
<!-- STATS-END -->



