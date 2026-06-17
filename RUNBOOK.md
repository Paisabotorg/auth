# Paisabot Auth — Operations Runbook

Central auth gating all Paisabot WordPress sites. Service on the VPS, gate as a
WordPress mu-plugin on each site.

## Topology

| Piece | Where |
|-------|-------|
| Auth service | VPS `187.127.172.162`, `/opt/paisabot/auth`, PM2 app `paisabot-auth`, port 3100 |
| Public URL | `https://auth.paisabot.com` (nginx → 127.0.0.1:3100) |
| Auth DB | Postgres `paisabot_auth` @ 127.0.0.1:5433 (`users`, `oauth_identities`, `sessions`) |
| Variant data | Read-only on `paisabot_cms.public.generated_posts` (`CMS_DATABASE_URL`) |
| Redis | 127.0.0.1:6379 (rate limits + alert dedupe) |
| RS256 keys | `/opt/paisabot/auth/keys/{private,public}.pem`, kid `pb-auth-v1` |
| Gate plugin | `wp-content/mu-plugins/pb-auth-gate/` on all 11 sites + loader `pb-auth-gate.php` |

## Health checks

```bash
curl -s https://auth.paisabot.com/health
curl -s https://auth.paisabot.com/.well-known/jwks.json | jq '.keys[0].kid'
curl -s -o /dev/null -w '%{http_code}\n' https://auth.paisabot.com/api/v1/story/<uuid>/variants
# Security headers present:
curl -sI https://auth.paisabot.com/health | grep -i strict-transport
```

## Deploy the auth service

```bash
cd /Users/amar/paisabot/auth
# syntax check first
for f in $(git ls-files 'src/**.js'); do node --check "$f"; done
rsync -avz -e "ssh -i ~/.ssh/hostinger_paisabot" src/ \
  root@187.127.172.162:/opt/paisabot/auth/src/
ssh -i ~/.ssh/hostinger_paisabot root@187.127.172.162 \
  "pm2 restart paisabot-auth --update-env && sleep 3 && curl -s localhost:3100/health"
```
If startup fails: `pm2 logs paisabot-auth --lines 30 --nostream`.

## Deploy the gate mu-plugin (FTP)

Use `wordpress-plugin/deploy-muplugin.py` (auto-tries FTPS, falls back to FTP —
the `ta/mr/gu/kn/bn/or` accounts require TLS). Deploy QA first, verify, then prod.
A WordPress critical error (HTTP 500) after deploy almost always means a PHP
syntax slip — re-check the edited file and redeploy just that file.

**Rollback:** delete `wp-content/mu-plugins/pb-auth-gate/` and the loader
`wp-content/mu-plugins/pb-auth-gate.php` via FTP → site reverts to fully open
instantly, no theme change needed.

## Site topology gotchas (learned the hard way)

- **Docroots live under `domains/<host>/public_html/`.** Subdomain FTP users
  (`u928714162.hi.paisabot.com`) land directly in their docroot. The MAIN
  account (`u928714162`) lands in a home dir where `cwd public_html` **fails** —
  the real apex docroot is `domains/paisabot.com/public_html`. `deploy-muplugin.py`
  now encodes this via the `base` key; don't revert it.
- **Gate CSS/JS are inlined** into the page HTML (not enqueued as files) because
  Hostinger HCDN (`server: hcdn`) and Cloudflare cache static assets and ignore
  `?ver=` busting. Inlining rides the (uncached, no-store) HTML so deploys take
  effect immediately. Don't switch back to `wp_enqueue_*` with file URLs.
- **CDN per host differs:** apex `paisabot.com` → Cloudflare; `qa`/`hi` → hcdn;
  `ml`/`tel` → LiteSpeed direct. Check `curl -sI` `server:`/`cf-cache-status:`
  before blaming code for "stale" behaviour.
- **ta/mr/gu/kn/bn/or are SUBDOMAINS, not addon sites.** They were originally
  addon websites but a broken Hostinger addon-vhost mapping served the "Parked
  Domain" page for every URL (proven: same HCDN edge, `Host: ta` → parked,
  `Host: hi` → WordPress — purely a Host→vhost fault, not DNS/CDN/files). Fix:
  delete the addon sites in hPanel, recreate as subdomains of `paisabot.com` via
  `createWebsiteSubdomainV1`. Docroots are now
  `domains/paisabot.com/public_html/<sub>` and they deploy via the MAIN FTP user
  (`u928714162`) — see `deploy-muplugin.py`. After recreating, Hostinger AutoSSL
  issues each origin cert asynchronously; until then Cloudflare (SSL mode "full")
  returns **HTTP 525**. A WP reinstall does NOT rebuild a vhost — only
  delete+recreate does.

## Onboarding a NEW language site

1. Add the lang→subdomain mapping in **three** places (keep them identical):
   - `src/config.js` `LANG_SUBDOMAIN`
   - `wordpress-plugin/pb-auth-gate/pb-auth-gate.php` `PB_LANG_SUBDOMAIN`
   - `wordpress-plugin/deploy-muplugin.py` `SITES`
2. Add the new origin to `ALLOWED_ORIGINS` in `src/config.js`, redeploy service.
3. Deploy the mu-plugin + loader to the new site (FTP).
4. In Hostinger hPanel: enable **Force HTTPS** for the site.
5. Verify: open a post in incognito → 3rd read shows the gate; `pb_session`
   cookie is honoured across `*.paisabot.com`.
6. Remember the **te→tel trap**: lang code `te` maps to subdomain `tel`.

## Staged rollout (gate)

The gate is metered (`PB_GATE_FREE_READS=2`) and client-side, so it's already
low-risk. To ramp deliberately:

| Stage | Action |
|-------|--------|
| 1 | QA only — verify gate, login, interstitial, account panel |
| 2 | One prod language (e.g. `hi`) for 24–48h, watch logs + reuse alerts |
| 3 | Remaining prod languages |
| To soften | raise `PB_GATE_FREE_READS` (e.g. 4) in `pb-auth-gate.php`, redeploy |
| To harden | set `PB_GATE_MODE=immediate` (gate on first read) |
| Kill switch | remove the mu-plugin dir (see Rollback) |

## Security alerts (Telegram)

Refresh-token-reuse fires `sendAlert()` (dedup 10 min/user). Enable by setting on
the VPS `/opt/paisabot/auth/.env`:
```
PB_ALERT_TELEGRAM_TOKEN=<bot token>      # or reuse TELEGRAM_BOT_TOKEN
PB_ALERT_TELEGRAM_CHAT_ID=<chat id>
```
Discover chat id: message the bot, then
`curl -s https://api.telegram.org/bot<token>/getUpdates`. Restart with
`pm2 restart paisabot-auth --update-env`. Unset → alerts no-op (service unaffected).

## Account self-service (DPDP)

`[pb_account]` shortcode renders profile + active sessions (revoke / sign-out-all)
+ account deletion. Place it on an `/account` page on each site.
- `DELETE /me` requires `{"confirm":"DELETE"}`; cascades to sessions +
  oauth_identities; clears cookies. This is the DPDP right-to-erasure path.

## Common incidents

| Symptom | Likely cause / fix |
|---------|--------------------|
| Gate not appearing | Loader `pb-auth-gate.php` missing in `mu-plugins/` root (WP ignores subdir-only plugins) |
| Gate appears for logged-in users | WP page cache served stale; gate.js re-checks `pb_session` client-side — confirm cookie present on `.paisabot.com` |
| 500 on posts after deploy | PHP syntax error in mu-plugin — fix + redeploy that file |
| `column ... does not exist` in logs | a migration didn't run on the right DB (auth vs cms) |
| Google login fails | redirect URI `https://auth.paisabot.com/callback/google` missing in Google Console |
| Variant API hangs/500 | `CMS_DATABASE_URL` unset or `paisabot_auth` lacks SELECT on `generated_posts` |
