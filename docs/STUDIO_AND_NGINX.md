# Original Studio and additive nginx

## Studio

`studio P` returns the project's Studio URL: with a configured domain it uses `https://<domain>/project/default`; otherwise (or with `--local`) `http://127.0.0.1:<gateway>/project/default`. It uses the upstream gateway and Studio — sbfleet does not build a Studio UI.

Flags:

- `--local` — force loopback URL even when domain metadata exists
- `--url-only` — print the URL and skip the browser opener

Behavior (shipped):

- Print the URL when Studio is ready (and Basic Auth guidance without the password)
- On **stopped** projects: print that the project is stopped; with `--url-only`, also print the local/canonical URL and exit unhealthy (7) without opening a browser; without `--url-only`, offer interactive start when a TTY is available
- Browser open uses Python `webbrowser.open(url)` (platform-dependent; typically `xdg-open` on Linux when a desktop session exists). There is **no** SSH detection, DISPLAY/WAYLAND gate, or port-forward automation. If the opener returns false or raises, print a warning; the URL remains printed for manual use
- Studio open does not claim Studio is healthy by itself; `status` / probes are authoritative
- Do not put credentials in the URL

Domain is optional and stored at create; local-only works without DNS. Public URL is `https://<domain>` and API_EXTERNAL_URL adds `/auth/v1` exactly once. Setting metadata does **not** provision DNS/TLS. Project URL/host changes after create remain an operator `.env`+metadata maintenance procedure, not a domain platform. Studio organization/project display names are changed with `sbfleet configure` (not slug rename); they are display-only — see [SELF_HOSTED_OAUTH.md](SELF_HOSTED_OAUTH.md) and [CLI_REFERENCE.md](CLI_REFERENCE.md).

## nginx generate

`nginx generate P [--json]` writes `projects/<slug>/generated/nginx.conf`.

Shipped scope:

- Domain metadata optional; without domain the file is an annotated **uninstalled template**
- With domain, certificate paths in the file remain commented stubs — `ready_to_install` stays **false** until an operator supplies host certificates outside sbfleet
- Refuses overwrite when the existing file differs (no `--force` / `--yes` / `--certificate` / `--certificate-key` / `--output` flags)
- Unique upstream name `sbfleet_<project12>` → `127.0.0.1:GATEWAY`
- Thin reverse-proxy template (catch-all to gateway). It does **not** claim production-proven Realtime websocket timeouts, Storage buffering, or certificate automation

Not implemented (do not treat as shipped): `--output`, `--certificate`, `--certificate-key`, `--force`, automated TLS, DNS, host install/reload.

## nginx validate

`nginx validate P` runs `nginx -t` against a **private prefix** that includes a **modified** copy of the generated site with SSL `listen` lines commented out when certificates are absent. Success means that modified syntax-check text parsed under the private prefix — **not** that the install-ready TLS artifact or host `/etc/nginx` config is valid. No reload; no write to `/etc/nginx`. Missing `nginx` binary → prerequisite failure.

There is no `--file` flag; validation always uses `projects/<slug>/generated/nginx.conf`.

## nginx install (INSTRUCTIONS_ONLY)

`nginx install P` prints reviewable operator steps and the generated path. Exit 0 means instructions were printed — never INSTALLED. No sudo, no filesystem mutation. Operator copies to `/etc/nginx/sites-available/…`, enables the site, runs host `nginx -t`, and reloads only on success. Installing nginx packages, obtaining TLS certificates, and DNS are external prerequisites.

Create stores optional domain metadata; it does **not** auto-generate nginx config. Run `sbfleet nginx generate P` explicitly.
