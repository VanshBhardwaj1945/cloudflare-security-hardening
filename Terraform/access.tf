resource "cloudflare_zero_trust_access_application" "admin_panel" {
  account_id       = var.cloudflare_account_id
  name             = "Resume Admin Panel"
  domain           = "resume.vanshbhardwaj.com/admin"
  session_duration = "24h"
  type             = "self_hosted"
}

resource "cloudflare_zero_trust_access_policy" "allow_all" {
  account_id = var.cloudflare_account_id
  name       = "Allow all"
  decision   = "allow"

  include = [{
    everyone = {}
  }]
}