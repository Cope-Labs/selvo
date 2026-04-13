# Self-hosting selvo

This directory contains the same compose stack that runs `selvo.dev` in
production. ELv2 license: free to deploy for your own organization, free
to modify, free to redistribute. Not free to offer as a managed service to
third parties — for that contact <licensing@cope-labs.dev>.

## Five-minute install

You need a Linux host with Docker + Docker Compose, a domain name pointed
at it, and ports 80/443 open.

```bash
git clone https://github.com/Cope-Labs/selvo.git
cd selvo/deploy/selfhost

# 1. Configure secrets
cp .env.example .env
$EDITOR .env  # at minimum: set SELVO_API_SECRET

# 2. Configure domain
cp Caddyfile.example Caddyfile
$EDITOR Caddyfile  # replace selvo.example.com with your domain

# 3. Bring it up
docker compose up -d

# 4. Watch first-boot warm the bulk caches (~30s — DST, KEV, EPSS, Nuclei)
docker compose logs -f selvo
```

Open `https://your-domain/` — sign up an org, generate an API key in the
dashboard, scan a server with the `install.sh` one-liner shown on the
scan page.

## Updating

```bash
cd selvo/deploy/selfhost
docker compose pull && docker compose up -d
```

The `selvo` image is rebuilt on every push to main of the public repo.

## What runs where

- `selvo` container (~250 MB) — FastAPI server + dashboard + scan
  workers. Listens on `127.0.0.1:8765`. Persistent state lives in the
  `data/` directory (sqlite for orgs/keys/snapshots + an OSV/EPSS/KEV
  cache that warms once per day).
- `caddy` container (~25 MB) — TLS termination + automatic Let's Encrypt
  via HTTP-01 challenge. State in `caddy_data/`.

## Sizing

- Hetzner shared-cpu (4 vCPU / 4 GB) handles a 2,700-package real Ubuntu
  desktop scan in ~15 s with cold caches, ~3 s warm.
- For >100 daily scans across multiple orgs, bump `cpus`/`memory` in
  `docker-compose.yml` and consider mounting `data/` on faster storage.

## Backup

Everything stateful is in `./data/` and `./caddy_data/`. A simple
nightly:

```bash
tar czf "selvo-backup-$(date -u +%F).tar.gz" data caddy_data .env Caddyfile
```

## What this stack doesn't include

- **No automatic backups** — your problem to wire up.
- **No HA / failover** — single node. Run two only if you put a load
  balancer in front and accept that snapshots/data live per-node.
- **No external auth provider (SSO/SAML)** — dashboard auth is org_id +
  email match against the local sqlite. Fine for single-team use.
- **No prebuilt Stripe billing** — works if you set the env vars and
  configure prices in your Stripe dashboard, but most self-hosters don't
  need this.

## Going behind Cloudflare

If you front this with Cloudflare in proxied mode:

1. **Set SSL/TLS encryption mode to "Full (strict)"** in the CF dashboard.
   "Flexible" sends API keys over plaintext between Cloudflare and your
   origin — a real security incident.
2. Caddy's automatic Let's Encrypt cert satisfies CF's strict-mode
   validation. No origin certificate setup needed for the first ~90 days.
3. After 90 days CF proxying may interfere with Let's Encrypt's
   HTTP-01/TLS-ALPN-01 renewal challenges. Either install a Cloudflare
   Origin Certificate (15-year, free) or switch Caddy to DNS-01 challenge
   with a Cloudflare API token.

## Reporting bugs

[Open a GitHub issue](https://github.com/Cope-Labs/selvo/issues). For security
disclosure please see [SECURITY.md](../../SECURITY.md).
