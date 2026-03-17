# Threat Observations

> This document records real traffic observations from Cloudflare Security Analytics on `vanshbhardwaj.com`.  
> Updated as new patterns are identified.

---

## Observation Period

**Start date:** _fill in when you start_  
**Zone:** `vanshbhardwaj.com`  
**Target endpoint of interest:** `resume.vanshbhardwaj.com/api/visitorcount`

---

## Traffic Summary

| Metric | Value |
|---|---|
| Total requests observed | _TBD_ |
| Requests flagged as threats | _TBD_ |
| Bot traffic % | _TBD_ |
| Top source country (suspicious) | _TBD_ |
| Top threat type | _TBD_ |

---

## Threat Types Observed

_Fill in after reviewing the Security Events dashboard. Examples:_

| Threat Type | Volume | Description |
|---|---|---|
| SQLi attempt | _TBD_ | SQL injection strings in query parameters |
| XSS attempt | _TBD_ | Script tags in request headers or body |
| Bad bot | _TBD_ | Known malicious user agents |
| Credential stuffing | _TBD_ | High volume login-style requests |

---

## API Endpoint Observations (`/api/visitorcount`)

_Document anything unusual hitting the Azure Function endpoint specifically._

- Request volume: _TBD_
- Unusual HTTP methods observed: _TBD_
- Geographic anomalies: _TBD_
- Burst traffic patterns: _TBD_

---

## Rules Created Based on Observations

_After Phase 2 — link each rule back to what triggered it here._

| Observation | Rule Created | File |
|---|---|---|
| _TBD_ | _TBD_ | `terraform/waf.tf` |

---

## Notes

_Any other observations worth documenting for the portfolio or interview._
