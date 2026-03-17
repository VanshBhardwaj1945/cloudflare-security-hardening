# Cloudflare Security Hardening

> **Target:** [resume.vanshbhardwaj.com](https://resume.vanshbhardwaj.com) — a live Azure-hosted resume site  
> **Objective:** Harden a real production web application using Cloudflare's security platform  
> **Built on top of:** [azure-resume](https://github.com/VanshBhardwaj1945/azure-resume)

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Phase 1 — Threat Observation (Security Analytics)](#phase-1--threat-observation-security-analytics)
4. [Phase 2 — WAF and Firewall Rules](#phase-2--waf-and-firewall-rules)
5. [Phase 3 — Zero Trust Access](#phase-3--zero-trust-access)
6. [Phase 4 — Cloudflare Workers](#phase-4--cloudflare-workers)
7. [Infrastructure as Code](#infrastructure-as-code)
8. [Key Findings and Takeaways](#key-findings-and-takeaways)

---

## Project Overview

This project extends my [Azure Cloud Resume Challenge](https://github.com/VanshBhardwaj1945/azure-resume) by layering Cloudflare's security platform on top of a live production site. Rather than simulating attacks in a sandbox, everything here is implemented against real traffic on a real domain.

The goal is to demonstrate a security-first approach to web application hardening using Cloudflare's tooling — the same tools used to protect millions of Internet properties globally.

**What was already in place:**
- Cloudflare DNS with DNSSEC enabled
- Azure Front Door for CDN and HTTPS termination
- Azure Functions API (visitor counter) — a real attack surface

**What this project adds:**

| Phase | What | Status |
|---|---|---|
| 1 | Security Analytics — observe real traffic | ✅ Complete |
| 2 | WAF + Firewall Rules — block attacks | ✅ Complete |
| 3 | Zero Trust Access — identity gate on protected resource | ✅ Complete |
| 4 | Cloudflare Workers — edge compute | 🔜 In progress |

---

## Architecture

```
Internet
    │
    ▼
Cloudflare Edge (330+ cities)
    ├── DNS + DNSSEC              ← already in place
    ├── DDoS Protection           ← automatic on all plans
    ├── WAF / Firewall Rules      ← Phase 2 ✅
    ├── Cloudflare Access         ← Phase 3 ✅
    └── Cloudflare Workers        ← Phase 4 🔜
    │
    ▼
Azure Front Door (CDN + HTTPS)
    │
    ├── Azure Storage (Static Website — frontend)
    │   └── /admin                ← protected by Cloudflare Access
    └── Azure Functions (Visitor Counter API — backend)
        │
        └── Azure Cosmos DB
```

Every request to `resume.vanshbhardwaj.com` passes through Cloudflare before it ever reaches Azure. This gives a programmable security layer at the edge — close to the attacker, far from the origin.

---

## Phase 1 — Threat Observation (Security Analytics)

### Objective
Before building any defenses, observe what is actually hitting the site. Real traffic, real bots, real attack patterns. The goal was to understand the threat landscape before writing a single rule — the same way a real security engineer would approach hardening a production system.

### What I Looked At
- Cloudflare Security Analytics dashboard — request volume, served vs mitigated traffic
- HTTP method breakdown — identifying unexpected POST requests on a static site
- Source IP analysis — identifying non-human traffic
- Cache status distribution — understanding how traffic flows through Cloudflare's edge

### Findings

**Traffic summary (last 24 hours):**

| Metric | Value |
|---|---|
| Total requests | 12 |
| Served by Cloudflare edge | 7 |
| Served by origin (Azure) | 5 |
| Unique source IPs | 3 |
| Countries | United States only |

**Notable observation — Unknown AWS bot (`3.18.186.238`):**

An IP outside my own devices made two automated requests to the site root (`/`) at 6:54 AM and 6:55 AM while no human activity was expected. A `whois` lookup confirmed the IP belongs to **Amazon EC2 (Amazon Technologies Inc., Seattle WA)** — meaning an automated process running on AWS was crawling the site.

The requests loaded only the root path with no subsequent asset requests (no CSS, JS, or images), which is characteristic of an automated crawler doing reconnaissance rather than a real browser visit.

```bash
$ whois 3.18.186.238
OrgName: Amazon Technologies Inc.
OrgId:   AT-88-Z
Address: 410 Terry Ave N., Seattle WA 98109
# Confirmed: Amazon EC2 infrastructure
```

**Unexpected POST requests:**

4 out of 12 requests used the POST method. This site is a static resume — there are no forms or endpoints that should accept POST requests from the public. This is a classic signal of automated probing.

**No security rules were firing** — expected, as none had been configured yet. This confirmed the need for WAF rules.

> 📸 `docs/screenshots/01-security-analytics.png` — Security Analytics dashboard

> 📸 `docs/screenshots/02-traffic-breakdown.png` — Top source IPs and HTTP methods

**Documented observations:** [`docs/threat-observations.md`](docs/threat-observations.md)

### What This Informed
Two categories of rules to build in Phase 2:

1. **Observation-based** — block unexpected HTTP methods on a static site, challenge known cloud provider IPs doing automated crawls
2. **Best practice** — block known attack tool User-Agents, block SQLi and XSS patterns, rate limit the API endpoint

---

## Phase 2 — WAF and Firewall Rules

### Objective
Translate the observations from Phase 1 into active defenses using Cloudflare's WAF and custom firewall rules. All rules follow the principle of **default deny** — block anything that has no legitimate reason to exist on this site.

All rules are version-controlled as Terraform code in [`terraform/waf.tf`](terraform/waf.tf) and were imported into Terraform state after being built and verified in the Cloudflare dashboard.

> 📸 `docs/screenshots/08-rate-limit.png` — Full active rules list (4 custom + 1 rate limiting, all Active)

### Rules Implemented

| Order | Rule Name | Type | Action |
|---|---|---|---|
| 1 | Block non-GET methods on static site | Custom rule | Block |
| 2 | Block empty User-Agent | Custom rule | Block |
| 3 | Block known attack scanner User-Agents | Custom rule | Block |
| 4 | Block SQLi and XSS attempts | Custom rule | Block |
| 5 | Rate limit visitor counter API | Rate limiting | Block |

---

### Rule 1 — Block Non-GET Methods

**Expression:**
```
(http.request.method ne "GET")
```

**Why:** This is a static resume website. The only legitimate HTTP method is GET — fetching pages and assets. POST, PUT, DELETE, PATCH, and other methods have no valid use here. The 4 POST requests observed in Phase 1 analytics confirmed this. Blocking all non-GET requests eliminates an entire class of attacks including form injection and API abuse attempts against the static site.

> 📸 `docs/screenshots/03-block-non-Get.png`

---

### Rule 2 — Block Empty User-Agent

**Expression:**
```
(http.user_agent eq "")
```

**Why:** Every legitimate browser sends a User-Agent header identifying itself. Automated bots and vulnerability scanners frequently omit this header entirely because they are not trying to impersonate a real browser. Blocking empty User-Agents eliminates a large volume of low-effort automated traffic before it consumes any origin resources.

> 📸 `docs/screenshots/04-block-empty-User-Agent.png`

---

### Rule 3 — Block Known Attack Scanner User-Agents

**Expression:**
```
(http.user_agent contains "sqlmap") or 
(http.user_agent contains "nikto") or 
(http.user_agent contains "nmap")
```

**Why each tool is blocked:**

| Tool | What It Does |
|---|---|
| `sqlmap` | Automated SQL injection tool — systematically tries hundreds of injection techniques against every input |
| `nikto` | Web vulnerability scanner — probes for thousands of known misconfigurations and CVEs |
| `nmap` | Network scanner — maps open ports and services for reconnaissance |

Legitimate users never send these strings as their User-Agent. Blocking by name is a zero-false-positive rule.

> 📸 `docs/screenshots/05-block-attack-scanners.png`

---

### Rule 4 — Block SQLi and XSS Attempts

**Expression:**
```
(http.request.uri.query contains "SELECT" and http.request.uri.query contains "FROM") or
(http.request.uri.query contains "UNION" and http.request.uri.query contains "SELECT") or
(http.request.uri.query contains "DROP TABLE") or
(http.request.uri.query contains "INSERT INTO") or
(http.request.uri.query contains "OR 1=1") or
(http.request.uri.query contains "<script") or
(http.request.uri.query contains "javascript:") or
(http.request.uri.query contains "onerror=") or
(http.request.uri.query contains "../") or
(http.request.uri.query contains "etc/passwd")
```

**Why each pattern is blocked:**

| Pattern | Attack Type | What It Does |
|---|---|---|
| `SELECT...FROM` | SQL Injection | Core SQL read query — extracts database contents |
| `UNION SELECT` | SQL Injection | Joins malicious query to legitimate one to steal data from other tables |
| `DROP TABLE` | SQL Injection | Permanently deletes database tables |
| `INSERT INTO` | SQL Injection | Writes data directly into the database |
| `OR 1=1` | SQL Injection | Makes WHERE conditions always true — returns all records |
| `<script` | XSS | Injects JavaScript that executes in other users' browsers |
| `javascript:` | XSS | Executes JS via href attributes |
| `onerror=` | XSS | Executes JS via HTML event handlers |
| `../` | Path Traversal | Navigates outside web root to access system files |
| `etc/passwd` | Path Traversal | Targets Linux user account file — classic recon target |

These patterns cover the most critical categories of the **OWASP Top 10** — the industry standard list of the most dangerous web application vulnerabilities. Cloudflare's managed OWASP ruleset handles this automatically on paid plans. On the free tier these custom rules replicate that core protection manually.

> 📸 `docs/screenshots/06-block-SQLi-XSS.png`

---

### Rule 5 — Rate Limit the Visitor Counter API

**Configuration:**
- **Match:** URI Path contains `/api/`
- **Characteristics:** IP address
- **Limit:** 4 requests per 10 seconds per IP
- **Duration:** Block for 10 seconds
- **Action:** Block

**Why:** The visitor counter Azure Function is a public HTTP endpoint with no built-in rate limiting. Without this rule, a script could call it thousands of times per second — inflating the counter, exhausting Cosmos DB request units, and potentially taking the function down. Rate limiting at the Cloudflare edge stops abuse before it ever reaches Azure. A real human visitor calls this endpoint once per page load, so 4 requests per 10 seconds is generous for legitimate use and stops all automated abuse.

> 📸 `docs/screenshots/07-rate-limit.png`

---

## Phase 3 — Zero Trust Access

### Objective
Demonstrate Zero Trust principles by putting an identity gate in front of a protected resource. No implicit trust — every request must prove identity before access is granted.

### What Zero Trust Means
Traditional security assumes anyone inside the network perimeter is trusted. Zero Trust flips this — **trust nobody by default, verify every request regardless of where it comes from.**

Cloudflare Access implements this by sitting in front of any resource and requiring authentication before the request ever reaches the origin. Unauthenticated requests are redirected to a Cloudflare-hosted login page — the origin server never sees them.

### What I Protected

Created a protected admin page at `resume.vanshbhardwaj.com/admin` hosted on the same Azure Storage static website as the rest of the site. Without Cloudflare Access, this page is publicly accessible. With Access, every visitor must verify their email via a one-time PIN before the page loads.

**Protected resource:** [`frontend/admin/index.html`](https://github.com/VanshBhardwaj1945/azure-resume/blob/main/frontend/admin/index.html)

### How It Works

```
User visits resume.vanshbhardwaj.com/admin
        │
        ▼
Cloudflare Access intercepts request
        │
        ├── Has valid session token? → Allow through to origin
        │
        └── No token? → Redirect to Cloudflare login page
                        │
                        ▼
                User enters email address
                        │
                        ▼
                Cloudflare sends one-time PIN to that email
                        │
                        ▼
                User enters PIN → Session token issued
                        │
                        ▼
                Access granted → Origin serves the page
```

### Configuration

| Setting | Value |
|---|---|
| Application name | Resume Admin Panel |
| Domain | `resume.vanshbhardwaj.com/admin` |
| Session duration | 24 hours |
| Login method | One-time PIN (email) |
| Policy | Allow everyone who completes email verification |

The policy is set to **Allow all** — anyone who can verify any email address gets in. This is appropriate for a lab/demo environment where the goal is to demonstrate the authentication flow rather than restrict specific users.

**Source:** [`terraform/access.tf`](terraform/access.tf)

> 📸 `docs/screenshots/09-access-login-prompt.png` — Cloudflare Access login page at `/admin`

> 📸 `docs/screenshots/10-access-granted.png` — Admin page after successful authentication

### Why This Matters

The origin server (Azure Storage) has no authentication capability of its own — any file uploaded to the `$web` container is publicly accessible by default. Cloudflare Access adds an identity layer in front of it without touching the origin at all. This is the core value of Zero Trust — security enforced at the network edge, independent of the application itself.

---

## Phase 4 — Cloudflare Workers

> 🔜 Coming soon

### Objective
Deploy a Cloudflare Worker to run custom security logic at the edge — extending beyond what WAF rules alone can do.

**Source:** [`workers/rate-limiter.js`](workers/rate-limiter.js)

---

## Infrastructure as Code

All Cloudflare security configuration is managed as Terraform code — no manual portal changes as the source of truth. Every rule and policy is version-controlled, auditable, and reproducible.

```
terraform/
├── waf.tf         # WAF rulesets and custom firewall rules ✅
├── access.tf      # Zero Trust Access application and policy ✅
├── workers.tf     # Worker scripts and route bindings 🔜
└── variables.tf   # Input variables (zone ID, account ID)
```

**Provider:** `cloudflare/cloudflare ~> 5`  
**Secrets:** passed via `CLOUDFLARE_API_TOKEN` environment variable, never committed  
**State:** local — `terraform.tfstate` gitignored

---

## Key Findings and Takeaways

**What I observed in real traffic:**
- An AWS EC2 bot (`3.18.186.238`) crawled the site at 6:54–6:55 AM — confirmed via `whois` as Amazon infrastructure doing automated reconnaissance
- 4 POST requests hit a fully static site that should only receive GETs — clear signal of automated probing
- Zero security rules were firing before this project — the site was completely undefended at the application layer

**Most impactful rule:**
Rate limiting the API endpoint — the Azure Function was a completely open endpoint. A single script could have called it thousands of times, inflating the counter and exhausting Cosmos DB resources.

**Key lesson — observe before you defend:**
The analytics phase revealed real attack patterns that directly informed the rules built in Phase 2. Building rules blind would have missed site-specific threats.

**Zero Trust in practice:**
Azure Storage has no native authentication — any file in the `$web` container is public by default. Cloudflare Access adds an identity gate without modifying the origin at all. This demonstrates that Zero Trust security can be layered on top of any resource regardless of whether that resource supports authentication natively.

**Why edge-based protection matters:**
Every rule and policy stops threats at the point closest to the attacker — before they consume any Azure infrastructure, before they touch the origin, before they cost anything.

---

## References

- [Cloudflare WAF Documentation](https://developers.cloudflare.com/waf/)
- [Cloudflare Access Documentation](https://developers.cloudflare.com/cloudflare-one/policies/access/)
- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Cloudflare 2025 DDoS Threat Report](https://blog.cloudflare.com/ddos-threat-report-for-2025-q4/)