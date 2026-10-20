# Relay Browse

Split into two deployable parts:

- `backend/`  Node API/proxy, deployed at https://relaybrowse.onrender.com
- `frontend/` plain static site (HTML/CSS/JS, no build step), host anywhere

## Backend

    cd backend && npm install && AUTH_TOKEN=yoursecret FRONTEND_ORIGIN=https://your-frontend npm start

| Variable          | Purpose |
|-------------------|---------|
| `AUTH_TOKEN`      | Your access key. If unset, a random one is printed at startup. |
| `FRONTEND_ORIGIN` | Where the frontend is hosted (CORS + `frame-ancestors`). Set this in production. |
| `TRUST_PROXY=1`   | Needed on Render so rate limiting sees real client IPs. |
| `PORT`, `HOST`    | Default `3000` / `0.0.0.0`. Render sets PORT itself. |
| `RATE_LIMIT`      | Requests per IP per minute (default 600). |

Endpoints: `POST /api/auth`, `GET|POST /proxy`, `GET /inject.js`, `GET /health`.

## Frontend

The backend URL is in `frontend/config.js`. Serve the `frontend/` folder from any static host
(Render Static Site, Netlify, GitHub Pages, ...). Open it, enter the access key once; it is
remembered in that browser. You can also sign in with a link: `https://your-frontend/#key=SECRET`.

## Local testing

    cd backend && AUTH_TOKEN=test FRONTEND_ORIGIN=http://localhost:8080 npm start
    cd frontend && python3 -m http.server 8080
    # set window.RELAY_BACKEND = 'http://localhost:3000' in frontend/config.js

## What changed from the single-server version

- The backend no longer serves the UI; the old `public/index.html` and `app.js` are in `frontend/`.
- Cookie auth became `POST /api/auth` (access key -> frame token), because cookies don't
  work between two different domains. The `/<token>` cookie route is gone.
- The hard-coded default `AUTH_TOKEN` was removed from the source. Since it was in the zip, treat it as leaked.
- Unused dependencies (`acorn`, `ws`) were dropped.
