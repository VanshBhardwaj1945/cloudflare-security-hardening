# WAF and Firewall Rules
# Manages Cloudflare WAF rulesets and custom firewall rules for vanshbhardwaj.com

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5"
    }
  }
}

# ---------------------------------------------------------------
# OWASP Managed Ruleset
# Cloudflare-maintained rules covering the OWASP Top 10
# ---------------------------------------------------------------

# TODO: Add cloudflare_ruleset resource for OWASP managed rules
# Will be added after Phase 1 analytics review

# ---------------------------------------------------------------
# Custom Firewall Rules
# ---------------------------------------------------------------

# TODO: Add custom rules based on Phase 1 threat observations:
# - Block bad bots
# - Rate limit /api/* endpoint
# - Block non-GET requests to visitor counter
# - Challenge high-risk ASNs
