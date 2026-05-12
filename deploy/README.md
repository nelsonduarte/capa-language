# Deployment

This folder holds infrastructure configuration that lives outside
the application but is reproducible from source.

## `cloudflare-dns.zone`

BIND-format zone file for the `capa-language.com` domain. Hosted on
Cloudflare; points the apex and `www` subdomain to GitHub Pages.

### How to import (first-time setup)

1. Sign in at <https://dash.cloudflare.com>.
2. Pick the `capa-language.com` zone.
3. **DNS** → **Records** → **Import and Export** → **Import**.
4. Upload `cloudflare-dns.zone`.
5. Confirm the preview.

### One-time manual step after import

For every imported record, set **Proxy status** to **DNS only**
(gray cloud). The Let's Encrypt certificate GitHub Pages issues on
first setup requires the DNS to resolve directly to GitHub. With
the Cloudflare proxy on (orange cloud), the certificate cannot be
issued.

Once HTTPS is active and stable, the proxy may be turned on for
caching / DDoS / WAF, **but only with the Cloudflare SSL/TLS mode
set to "Full" (or "Full (strict)")**. "Flexible" SSL with the
proxy on causes a redirect loop because GitHub Pages enforces
HTTPS server-side.

### Verification

```bash
dig capa-language.com +short
#  185.199.108.153
#  185.199.109.153
#  185.199.110.153
#  185.199.111.153

dig www.capa-language.com +short
#  nelsonduarte.github.io.
#  (then the same four IPs)
```

### Updating

If GitHub Pages rotates the published IPs (rare, but it happens),
edit the four `A` records and the four `AAAA` records here, then
re-import on Cloudflare to overwrite the zone.

Current source of truth for the IPs:
<https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site>.
