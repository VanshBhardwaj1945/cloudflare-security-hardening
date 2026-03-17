# Threat Observations

> Real traffic observations from Cloudflare Security Analytics on `vanshbhardwaj.com`
> Observation period: March 16, 2026 (last 24 hours)

## Traffic Summary

| Metric | Value |
|---|---|
| Total requests | 12 |
| Served by Cloudflare | 7 |
| Served by origin | 5 |
| Unique source IPs | 3 |
| Top country | United States |

## Notable Findings

### AWS Bot — `3.18.186.238`
- Hit the site root (`/`) twice at 6:54 AM and 6:55 AM
- No CSS, JS, or images loaded — not a real browser
- `whois` confirmed: Amazon EC2, Amazon Technologies Inc., Seattle WA
- Behaviour consistent with automated crawler/reconnaissance

### Unexpected POST Requests
- 4 out of 12 total requests used POST method
- Site is fully static — no endpoint should accept public POST requests
- Indicates automated probing

## Rules Triggered
- None — no security rules configured at time of observation

## Rules Created Based on These Findings
| Observation | Rule | File |
|---|---|---|
| POST requests on static site | Block non-GET methods | `terraform/waf.tf` |
| AWS bot crawling site | Challenge cloud provider IPs | `terraform/waf.tf` |