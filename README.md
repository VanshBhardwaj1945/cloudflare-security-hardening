# Cloudflare Security Hardening

> **Target:** [resume.vanshbhardwaj.com](https://resume.vanshbhardwaj.com) — a live Azure-hosted resume site  
> **Objective:** Harden a real production web application using Cloudflare's security platform  
> **Built on top of:** [azure-resume](https://github.com/VanshBhardwaj1945/cloud-resume-challenge-azure)

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Phase 1 — Threat Observation (Security Analytics)](#phase-1--threat-observation-security-analytics)
4. [Phase 2 — WAF and Firewall Rules](#phase-2--waf-and-firewall-rules)
5. [Phase 3 — Zero Trust Access](#phase-3--zero-trust-access)
6. [Phase 4 — Cloudflare Workers (Rate Limiting)](#phase-4--cloudflare-workers-rate-limiting)
7. [Infrastructure as Code](#infrastructure-as-code)
8. [Key Findings and Takeaways](#key-findings-and-takeaways)

---

## Project Overview

This project extends my [Azure Cloud Resume Challenge](https://github.com/VanshBhardwaj1945/cloud-resume-challenge-azure) by layering Cloudflare's security platform on top of a live production site. Rather than simulating attacks in a sandbox, everything here is implemented against real traffic on a real domain.

The goal is to demonstrate a security-first approach to web application hardening using Cloudflare's tooling — the same tools used to protect millions of Internet properties globally.

**What was already in place:**
- Cloudflare DNS with DNSSEC enabled
- Azure Front Door for CDN and HTTPS termination
- Azure Functions API (visitor counter) — a real attack surface

**What this project adds:**

| Phase | What | Why |
|---|---|---|
| 1 | Security Analytics | Observe real traffic and identify threats before building defenses |
| 2 | WAF + Firewall Rules | Block OWASP Top 10 attacks, bad bots, and API abuse |
| 3 | Zero Trust Access | Identity-gate a protected resource using Cloudflare Access |
| 4 | Cloudflare Workers | Rate limit the Azure Function API at the edge |

---

## Architecture

```
Internet
    │
    ▼
Cloudflare Edge (330+ cities)
    ├── DNS + DNSSEC          ← already in place
    ├── DDoS Protection       ← automatic on all plans
    ├── WAF / Firewall Rules  ← Phase 2
    ├── Cloudflare Access     ← Phase 3
    └── Cloudflare Workers    ← Phase 4
    │
    ▼
Azure Front Door (CDN + HTTPS)
    │
    ├── Azure Storage (Static Website — frontend)
    └── Azure Functions (Visitor Counter API — backend)
        │
        └── Azure Cosmos DB
```

Every request to `resume.vanshbhardwaj.com` passes through Cloudflare before it ever reaches Azure. This gives us a programmable security layer at the edge — close to the attacker, far from the origin.

---

## Phase 1 — Threat Observation (Security Analytics)

### Objective
Before building any defenses, observe what is actually hitting the site. Real traffic, real bots, real attack patterns.

### What I looked at
- Cloudflare Security Events dashboard
- Top threat types by request volume
- Geographic distribution of suspicious traffic
- Bot traffic vs human traffic breakdown
- Requests hitting the `/api/` endpoint (Azure Function)

### Findings

> 📸 *Screenshot: Security Events dashboard — `docs/screenshots/01-security-events.png`*

> 📸 *Screenshot: Top threats by type — `docs/screenshots/02-threat-types.png`*

> 📸 *Screenshot: Bot traffic analysis — `docs/screenshots/03-bot-traffic.png`*

**Documented observations:** [`docs/threat-observations.md`](docs/threat-observations.md)

---

## Phase 2 — WAF and Firewall Rules

### Objective
Block the threats identified in Phase 1 using Cloudflare's WAF and custom firewall rules. All rules are written as code in Terraform.

### Rules Implemented

| Rule | Action | Targets |
|---|---|---|
| Block SQLi / XSS | Block | OWASP Top 10 attack signatures on all requests |
| Block bad bots | Block | Known malicious user agents and bot signatures |
| Rate limit API | Block | More than 10 requests per minute to `/api/*` |
| Block non-GET to API | Block | PUT, DELETE, PATCH on the visitor counter endpoint |
| Challenge suspicious ASNs | JS Challenge | High-risk ASNs with no legitimate traffic history |

### Cloudflare Managed Ruleset
Enabled the Cloudflare OWASP Core Ruleset — a managed set of rules maintained by Cloudflare that covers the OWASP Top 10 attack categories including:
- **SQL Injection (SQLi)** — attacker inserts SQL code into form fields to manipulate the database
- **Cross-Site Scripting (XSS)** — attacker injects malicious scripts into pages viewed by other users
- **Cross-Site Request Forgery (CSRF)** — attacker tricks a user's browser into making unauthorised requests

### Source
**Terraform:** [`terraform/waf.tf`](terraform/waf.tf)

> 📸 *Screenshot: WAF rules in Cloudflare dashboard — `docs/screenshots/04-waf-rules.png`*

> 📸 *Screenshot: Blocked requests in Security Events — `docs/screenshots/05-blocked-requests.png`*

---

## Phase 3 — Zero Trust Access

### Objective
Demonstrate Zero Trust principles by putting an identity gate in front of a protected resource. No implicit trust — every request must prove identity before access is granted.

### What Zero Trust Means
Traditional security assumes that anyone inside the network perimeter is trusted. Zero Trust assumes the opposite — **trust nobody by default, verify every request regardless of where it comes from.**

Cloudflare Access implements this by sitting in front of any application and requiring authentication before the request ever reaches the origin.

### What I Protected
Added a Cloudflare Access policy to a protected admin path (`/admin`) on the site. Any request to that path must authenticate via email OTP before proceeding. Unauthenticated requests are blocked at the Cloudflare edge — the origin server never sees them.

### Source
**Terraform:** [`terraform/access.tf`](terraform/access.tf)

> 📸 *Screenshot: Access policy configuration — `docs/screenshots/06-access-policy.png`*

> 📸 *Screenshot: Authentication prompt on protected path — `docs/screenshots/07-access-login.png`*

---

## Phase 4 — Cloudflare Workers (Rate Limiting)

### Objective
Deploy a Cloudflare Worker to rate limit the Azure Function API at the edge — stopping abuse before it reaches the origin.

### Why This Matters
The visitor counter API (`/api/visitorcount`) is a public HTTP endpoint. Without rate limiting, anyone can call it thousands of times per second, inflating the counter, exhausting Cosmos DB request units, and running up costs. By handling rate limiting at the Cloudflare edge in a Worker, we stop abuse at the closest point to the attacker.

### How It Works

```
Request to /api/visitorcount
        │
        ▼
Cloudflare Worker intercepts request
        │
        ├── Check request count for this IP in last 60 seconds
        │
        ├── Under limit? → Forward to Azure Function origin
        │
        └── Over limit? → Return 429 Too Many Requests immediately
                          (Azure Function never receives the request)
```

### Source
**Worker code:** [`workers/rate-limiter.js`](workers/rate-limiter.js)  
**Terraform:** [`terraform/workers.tf`](terraform/workers.tf)

> 📸 *Screenshot: Worker deployed in Cloudflare dashboard — `docs/screenshots/08-worker-deployed.png`*

> 📸 *Screenshot: 429 response when rate limit exceeded — `docs/screenshots/09-rate-limit-response.png`*

---

## Infrastructure as Code

All Cloudflare security configuration is managed as Terraform code — no manual portal changes. This ensures every rule, policy, and worker binding is version-controlled, auditable, and reproducible.

```
terraform/
├── waf.tf         # WAF rulesets and custom firewall rules
├── access.tf      # Zero Trust Access policies
├── workers.tf     # Worker scripts and route bindings
└── variables.tf   # Input variables (zone ID, account ID)
```

**Provider:** `cloudflare/cloudflare ~> 5`  
**State:** local (terraform.tfstate — gitignored)  
**Secrets:** passed via environment variables, never committed

---

## Key Findings and Takeaways

> *This section will be filled in after completing all four phases with real observations from the security analytics dashboard.*

**What I observed in traffic:**
- _TBD after Phase 1_

**Most impactful rule:**
- _TBD after Phase 2_

**What I learned about Zero Trust in practice:**
- _TBD after Phase 3_

**Why edge-based rate limiting is superior to origin-based:**
- Stops malicious traffic before it consumes any origin resources
- Adds no latency for legitimate users
- Scales automatically with Cloudflare's network

---

## References

- [Cloudflare WAF Documentation](https://developers.cloudflare.com/waf/)
- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [Cloudflare Access Documentation](https://developers.cloudflare.com/cloudflare-one/policies/access/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Cloudflare 2025 DDoS Threat Report](https://blog.cloudflare.com/ddos-threat-report-for-2025-q4/)
