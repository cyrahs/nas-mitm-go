# nas-mitm-go

The intercepting proxy that runs as a sidecar beside RSSHub and Suwayomi in
the home cluster (charys117/nas-gitops). It replaces mitmproxy and its Python
addons: same behaviour, about a tenth of the memory (mitmproxy alone was
~75 MiB per Pod before any addon ran).

It decrypts only the hosts a handler claims, on port 443, with a CA minted
inside the Pod; every other connection is tunnelled untouched.

| Handler | Pod | Hosts | What it does |
| --- | --- | --- | --- |
| `suwayomi` | suwayomi | `manga2025.com`, `manga2026.com` | Replays each chapter read through a rotating residential exit (Decodo): free titles anonymously, paid titles with the token and paced under the account's 10-per-minute limit. A throttle (HTTP 200, code 210) is retried and never handed back. |
| `flaresolverr` | rsshub | `javlibrary.com` | Gets Cloudflare clearance from FlareSolverr once, then serves later requests directly with that cookie and user agent through the same exit. |
| `bilibili` | rsshub | `bilibili.com` | Replaces the Cookie header with the logged-in session fav holds, polled every 5 minutes. |

The package comments in `internal/<handler>` carry the measurements behind
each design.

## Usage

```sh
nas-mitm gen-ca --dir /certs        # init container: writes ca.crt (0644) and ca.key (0600)
nas-mitm run --certs /certs --listen 127.0.0.1:8080 --intercept-ports 443,80 --handlers flaresolverr,bilibili
nas-mitm run --certs /certs --socks5 0.0.0.0:1080 --handlers suwayomi
nas-mitm probe 127.0.0.1:1080       # readiness check (the image has no shell)
nas-mitm fetch --proxy http://exit:80 -H 'User-Agent: x' https://site/   # one GET with the handlers' HTTP client
```

`--socks5` is for clients that only speak SOCKS5 (Suwayomi's JVM proxy
setting). Each SOCKS5 CONNECT is handed to the HTTP proxy, so both entrances
share the same interception rules.

Intercepted TLS connections offer only HTTP/1.1. `--intercept-ports` (default
`443`) lists the CONNECT ports of a claimed host that are intercepted; add
`80` to also rewrite plain HTTP that arrives inside a CONNECT, as sing-box's
HTTP outbound sends it.

### Environment

| Variable | Handler | Default |
| --- | --- | --- |
| `DECODO` | suwayomi | `http://gate.decodo.com:10000` |
| `UPSTREAM_HOST` | suwayomi | `api.manga2026.com` |
| `CLIENT_DEADLINE`, `CLIENT_MARGIN`, `UPSTREAM_TIMEOUT` (s) | suwayomi | 30, 3, 4 |
| `RETRIES` | suwayomi | 4 |
| `PAID_CAPACITY`, `PAID_WINDOW`, `PAID_FREE_SLOTS`, `PAID_RAMP_MIN`, `PAID_RAMP_MAX` | suwayomi | 10, 63, 4, 2, 12 |
| `LOG_EXIT_IP`, `EXIT_ECHO` | suwayomi | off, `https://api.ipify.org` |
| `SOLVED_HOSTS` | flaresolverr | `javlibrary.com` |
| `FLARESOLVERR_URL` | flaresolverr | `http://flaresolverr.proxy.svc.cluster.local/v1` |
| `SOLVER_EXIT_PROXY` | flaresolverr | direct |
| `FAV_CREDENTIAL_URL`, `FAV_CREDENTIAL_TOKEN` | bilibili | required |
| `BILI_EXIT_PROXY` | bilibili | direct |

## Image

`ghcr.io/cyrahs/nas-mitm-go:latest` (and `:sha-<commit>`), linux/amd64 and
linux/arm64, built and pushed by CI on every push to `main` after the tests
pass. Pull requests build without pushing. Flux in nas-gitops follows
`latest` by digest.

## Tests

```sh
go test -race ./...
```

The proxy tests run real HTTP CONNECT and SOCKS5 clients against a local
TLS origin; the handler tests use fakes for every upstream. Nothing touches
a real account or site.
