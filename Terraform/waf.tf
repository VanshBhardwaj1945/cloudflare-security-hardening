terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5"
    }
  }
}

provider "cloudflare" {}

# ---------------------------------------------------------------
# Custom Firewall Rules
# Security → Security Rules → Custom rules in Cloudflare dashboard
# ---------------------------------------------------------------

resource "cloudflare_ruleset" "waf_custom_rules" {
  zone_id     = var.cloudflare_zone_id
  name        = "Custom WAF Rules"
  description = "Custom security rules for resume.vanshbhardwaj.com"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    # Rule 1 — Block non-GET methods
    {
      action      = "block"
      description = "Block non-GET methods on static site"
      enabled     = true
      expression  = "(http.request.method ne \"GET\")"
    },

    # Rule 2 — Block empty User-Agent
    {
      action      = "block"
      description = "Block empty User-Agent"
      enabled     = true
      expression  = "(http.user_agent eq \"\")"
    },

    # Rule 3 — Block known attack tool scanners
    {
      action      = "block"
      description = "Block known attack scanner User-Agents"
      enabled     = true
      expression  = "(http.user_agent contains \"sqlmap\") or (http.user_agent contains \"nikto\") or (http.user_agent contains \"nmap\")"
    },

    # Rule 4 — Block SQLi and XSS attempts
    # SQL Injection: SELECT/FROM, UNION SELECT, DROP TABLE, INSERT INTO, OR 1=1
    # XSS: <script, javascript:, onerror=
    # Path Traversal: ../, etc/passwd
    {
      action      = "block"
      description = "Block SQLi and XSS attempts"
      enabled     = true
      expression  = "(http.request.uri.query contains \"SELECT\" and http.request.uri.query contains \"FROM\") or (http.request.uri.query contains \"UNION\" and http.request.uri.query contains \"SELECT\") or (http.request.uri.query contains \"DROP TABLE\") or (http.request.uri.query contains \"INSERT INTO\") or (http.request.uri.query contains \"OR 1=1\") or (http.request.uri.query contains \"<script\") or (http.request.uri.query contains \"javascript:\") or (http.request.uri.query contains \"onerror=\") or (http.request.uri.query contains \"../\") or (http.request.uri.query contains \"etc/passwd\")"
    }
  ]
}

# Rate Limiting Rule
# Security → Security Rules → Rate limiting rules in dashboard
resource "cloudflare_ruleset" "rate_limiting" {
  zone_id     = var.cloudflare_zone_id
  name        = "Rate Limiting Rules"
  description = "Rate limiting for the Azure Function API endpoint"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    # Rule 5 — Rate limit visitor counter API
    # 10 requests per minute per IP on /api/*
    {
      action      = "block"
      description = "Rate limit visitor counter API — 10 req/min per IP"
      enabled     = true
      expression  = "(http.request.uri.path contains \"/api/\")"

      ratelimit = {
        characteristics     = ["cf.colo.id", "ip.src"]
        period              = 10
        requests_per_period = 4
        mitigation_timeout  = 10
      }
    }
  ]
}
