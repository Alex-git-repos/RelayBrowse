# Relay Browse

A small web proxy: a Node.js backend that fetches pages on your behalf and rewrites them, and a browser-style frontend with an address bar, back, forward and reload.

## Run it

```bash
npm install
npm start
# open http://127.0.0.1:3000
```

Requires Node 18.17 or newer.

## Settings

Set these as environment variables.

| Variable | Default | What it does |
|---|---|---|
| `PORT` | `3000` | Port to listen on |
| `HOST` | `127.0.0.1` | Interface to bind. Use `0.0.0.0` to accept outside connections |
| `AUTH_TOKEN` | built-in token | Secret token. Visiting `/<token>` sets an `auth` cookie that unlocks the site; everyone else sees a default page |
| `RATE_LIMIT` | `600` | Requests per IP per minute. A single page can use dozens |
| `TRUST_PROXY` | off | Set to `1` behind a reverse proxy to read the client IP from `X-Forwarded-For` |
| `ALLOW_PRIVATE` | off | Set to `1` to allow private-network targets. Testing only |

## How it works

- `GET /proxy?url=<address>` fetches the page. HTML and CSS are rewritten so links, images, stylesheets, scripts, forms and `<meta refresh>` keep going through the proxy.
- Redirects are sent back through the proxy so every hop is checked again.
- `public/inject.js` is added to every page. It reroutes `fetch`, `XMLHttpRequest`, `history.pushState`, `window.open` and dynamically created elements.
- The frontend shows pages in an iframe and keeps the address bar in sync through `postMessage`.

## Security built in

- **Private network blocking.** The proxy refuses loopback, private, link-local (including cloud metadata at 169.254.169.254) and multicast addresses, for both IP literals and hostnames. The check runs at connection time, which also stops DNS rebinding.
- Only `http` and `https`, and only ports 80, 443, 8080 and 8443.
- Size limits (25 MB per response, 8 MB for pages it rewrites, 1 MB for form posts) and a 25 second timeout.
- Cookies are not forwarded in either direction. The proxy sends no cookies upstream and drops `Set-Cookie`.
- Cookie-token access (`/<token>` sets the `auth` cookie) and per-IP rate limiting.

## Before you put this on the internet

1. **Set `AUTH_TOKEN`.** An open proxy gets found and abused within hours.
2. **Use HTTPS** with a reverse proxy such as Caddy or nginx, and set `TRUST_PROXY=1`.
3. **Serve proxied pages from their own origin.** Right now the interface and every proxied site share one origin, so a proxied page's scripts could read the interface's local storage or spoof the address bar. For anything beyond personal use, put `/proxy` on a separate subdomain.
4. You are responsible for how it is used. Follow the laws where you operate and the terms of the sites you visit.

## Limitations

- JavaScript-heavy apps (Google sign-in, YouTube, most web apps) often break. Static and server-rendered sites work best.
- Script files are not rewritten, so URLs hard-coded inside JavaScript can bypass the proxy and fail.
- Assigning `location.href` from page scripts can't be intercepted.
- No cookie jar, so sign-in sessions don't persist. WebSockets and range requests (video seeking) are not supported.
