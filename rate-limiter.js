/**
 * Cloudflare Worker — Rate Limiter
 * Target: /api/visitorcount (Azure Function visitor counter)
 *
 * Limits each IP to 10 requests per 60 seconds.
 * Requests over the limit receive a 429 response.
 * The Azure Function origin never sees rate-limited requests.
 */

// TODO: Implement after Phase 3
// Logic:
// 1. Extract client IP from request
// 2. Check request count in KV store for this IP
// 3. If under limit — forward request to origin
// 4. If over limit — return 429 Too Many Requests

export default {
  async fetch(request, env, ctx) {
    // Implementation coming in Phase 4
    return fetch(request);
  },
};
