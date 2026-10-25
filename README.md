# Relay Browse

Split into two deployable parts:

- `backend/`  Node API/proxy, deployed at https://relaybrowse.onrender.com
- `frontend/` plain static site (HTML/CSS/JS, no build step), host anywhere

## Backend

    cd backend && npm install && AUTH_TOKEN=yoursecret FRONTEND_ORIGIN=https://your-frontend npm start

| Variable          | Purpose |
|-------------------|---------|
| `AUTH_TOKEN`      | Your access key. If unset, a random one is printed at startup. |
| `FRONTEND_ORIGIN` | Where the frontend is hosted (CORS, `frame-ancestors`, and the only origin pages may talk to). Set this in production. |
| `TRUST_PROXY=1`   | Needed on Render so rate limiting sees real client IPs. |
| `PORT`, `HOST`    | Default `3000` / `0.0.0.0`. Render sets PORT itself. |
| `RATE_LIMIT`      | Requests per IP per minute (default 600). |
| `ALLOW_PRIVATE=1` | Testing only: lets the server reach internal networks. Any other value (including `on`) is ignored. |

Endpoints: `POST /api/auth`, `GET /api/session`, `GET|POST /proxy`, `GET /inject.js`, `GET /health`.
Every response carries `X-Robots-Tag: noindex, nofollow`.

### Internal network protection

The server refuses to fetch anything on a private network, however the address is written:

- loopback, private, link-local (cloud metadata `169.254.169.254`), CGNAT and reserved IPv4 ranges
- IPv6 loopback, unique-local, link-local, multicast, and IPv4 hidden inside IPv6 (`::ffff:7f00:1`, NAT64, 6to4)
- odd spellings (`2130706433`, `0x7f.1`, trailing dots), `localhost`, `*.local`, `*.internal`, `*.svc`, and single-word hostnames
- ports other than 80, 443, 8080, 8443
- the server's own hostname (no loops back into the login endpoint)
- hostnames that *resolve* to a private address, checked again at connection time (so DNS tricks don't work)
- every redirect hop, since redirects are sent back through the same checks

Public sites are unaffected, including IPv6-only networks that reach them through NAT64.

## Frontend

The backend URL is in `frontend/config.js`. Serve the `frontend/` folder from any static host
(Render Static Site, Netlify, GitHub Pages, ...).

There are two pages, kept apart on purpose:

- `index.html` is the browser itself. Without a saved sign-in it redirects to the sign-in page (a plain "Not available" page is only a fallback if the redirect fails).
- `m-8c1f3e/` is the sign-in page. It says nothing about what the site is, loads nothing from third parties,
  and is marked `noindex`, so search engines never index it.

**Rename `m-8c1f3e/` to something of your own before deploying, and set `window.APP_GATE` in `frontend/config.js`
to the new folder name (with a trailing slash).** Open `https://your-frontend/<your-folder>/`, enter the access key once, and it is remembered on that
device. Visiting the root without a saved sign-in, or after one expires, redirects there automatically (an optional `?go=` is carried through).
You can also sign in with a link: `https://your-frontend/<your-folder>/#key=SECRET`.

> **If this repository is public, the folder name is public too**, and so is anything in `RelayBrowse.env` from
> older commits. Keep the repo private (or deploy from a private copy) if you want the sign-in address to stay unknown.

## Local testing

    cd backend && AUTH_TOKEN=test FRONTEND_ORIGIN=http://localhost:8080 npm start
    cd frontend && python3 -m http.server 8080
    # set window.APP_API = 'http://localhost:3000' in frontend/config.js
    # sign in at http://localhost:8080/m-8c1f3e/

## Secrets

`RelayBrowse.env` used to be committed, with a real `AUTH_TOKEN` in it. It has been removed and `*.env` is now
git-ignored; `RelayBrowse.env.example` shows the shape. **Anything that was ever committed is still in git history,
so change `AUTH_TOKEN` on your host.** (Changing it also invalidates every saved sign-in, which is the point.)

## What changed from the single-server version

- The backend no longer serves the UI; the old `public/index.html` and `app.js` are in `frontend/`.
- Cookie auth became `POST /api/auth` (access key -> frame token), because cookies don't
  work between two different domains. The `/<token>` cookie route is gone.
- Unused dependencies (`acorn`, `ws`) were dropped.
