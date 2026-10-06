# Self-hosted branding and Google OAuth

Studio display names and the public Auth hostname are **different**:

| Concept | Config | Effect |
|--|--|--|
| Studio organization | `branding.organization_name` → `STUDIO_DEFAULT_ORGANIZATION` → Studio `DEFAULT_ORGANIZATION_NAME` | Label in Studio UI only |
| Studio project | `branding.project_name` → `STUDIO_DEFAULT_PROJECT` → Studio `DEFAULT_PROJECT_NAME` | Label in Studio UI only |
| Public Supabase/API host | `domain` / `public_url` → `SUPABASE_PUBLIC_URL` | What browsers and apps call |
| Auth API external URL | derived → `API_EXTERNAL_URL` = `${public_url}/auth/v1` | OAuth callbacks, JWT issuer |
| App site | `site_url` → `SITE_URL` | Default Auth redirect after login |

Changing Studio project name does **not** change the Google "continue to …" hostname. That hostname comes from the Auth callback URL.

After create, change Studio labels (and the fleet display name) with `sbfleet configure` — do not hand-edit `.env` for ordinary presentation settings. Apply Studio Env with `stop` then `start` when the stack is running.

## Example: separate app and auth hostnames

Application: `https://example.com`
Self-hosted Supabase/Auth: `https://auth.example.com`

```bash
sbfleet create myapp \
  --name "My App" \
  --domain auth.example.com \
  --organization-name Acme \
  --studio-project Orders \
  --site-url https://example.com \
  --redirect-url 'https://example.com/**' \
  --google-oauth \
  --yes
```

Generated (non-secret) values:

```text
STUDIO_DEFAULT_ORGANIZATION=Acme
STUDIO_DEFAULT_PROJECT=Orders
SUPABASE_PUBLIC_URL=https://auth.example.com
API_EXTERNAL_URL=https://auth.example.com/auth/v1
SITE_URL=https://example.com
ADDITIONAL_REDIRECT_URLS=https://example.com/**
GOOGLE_ENABLED=true
```

Google **Authorized redirect URI** (register manually in Google Cloud Console):

```text
https://auth.example.com/auth/v1/callback
```

Show the same summary anytime:

```bash
sbfleet connection myapp --oauth-setup
```

Set `GOOGLE_CLIENT_ID` and `GOOGLE_SECRET` privately in `deployment/.env` (mode `0600`). Never commit them. SBfleet never prints those values from `connection` or `doctor`.

## DNS / TLS / nginx

- Point `auth.example.com` at the SBfleet host.
- `sbfleet nginx generate myapp` emits a reverse proxy to the project gateway (loopback). TLS certificates and host nginx install remain operator steps (`nginx install` prints instructions only).
- Self-hosted avoids the managed-platform custom-domain add-on; you own DNS and certificates.
- Studio remains behind the same gateway Basic auth; do not confuse Studio display branding with public OAuth hostname.

## Doctor

`sbfleet doctor myapp` checks HTTPS public URL, exact `/auth/v1` on `API_EXTERNAL_URL`, `SITE_URL` presence, hostname alignment, and Google enablement consistency — without revealing secrets.
