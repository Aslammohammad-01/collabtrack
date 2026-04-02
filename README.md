# CollabTrack

Brand collaboration payment tracker — private, secure, mobile-ready.

## Repo structure

```
collabtrack/
├── frontend/          ← Cloudflare Pages (connect this folder)
│   ├── index.html
│   ├── _headers
│   └── _redirects
├── worker/            ← Cloudflare Worker (paste code in dashboard)
│   ├── worker.js
│   └── wrangler.toml
└── .github/
    └── workflows/
        └── deploy-worker.yml
```

---

## Deploy Guide (GitHub + Cloudflare Dashboard)

### PART A — Worker (API + Database)

#### 1. Create KV Namespace
1. Cloudflare Dashboard → **Workers & Pages** → **KV**
2. Click **Create a namespace** → name it `collabtrack-kv` → **Add**

#### 2. Create & Deploy the Worker
1. **Workers & Pages** → **Create application** → **Create Worker**
2. Name it `collabtrack-worker` → **Deploy**
3. Click **Edit code** → select all → delete → paste contents of `worker/worker.js`
4. Click **Save and Deploy**
5. **Copy the Worker URL** shown (e.g. `collabtrack-worker.yourname.workers.dev`)

#### 3. Bind KV to Worker
1. Your Worker → **Settings** → **KV Namespace Bindings** → **Add binding**
2. Variable name: `COLLABTRACK_KV` | Namespace: `collabtrack-kv`
3. **Save**

#### 4. Add Secrets
1. Worker → **Settings** → **Environment Variables** → **Add variable** (×2, both Encrypted):

| Name | Value |
|------|-------|
| `AUTH_PASSWORD` | your chosen login password |
| `JWT_SECRET` | random 48-char string ([generate here](https://generate.plus/en/alphanumeric?length=48)) |

2. **Save and Deploy**

---

### PART B — Frontend (Cloudflare Pages via GitHub)

#### 5. Update Worker URL in frontend
Open `frontend/index.html`, find:
```js
return 'PASTE_YOUR_WORKER_URL_HERE';
```
Replace with your Worker URL:
```js
return 'https://collabtrack-worker.yourname.workers.dev';
```
Commit and push to GitHub.

#### 6. Connect GitHub to Cloudflare Pages
1. **Workers & Pages** → **Create application** → **Pages** → **Connect to Git**
2. Select your GitHub repo → **Begin setup**
3. Fill in build settings:

| Setting | Value |
|---------|-------|
| Project name | `collabtrack` |
| Production branch | `main` |
| Build command | *(leave empty)* |
| Build output directory | `frontend` |

4. Click **Save and Deploy**
5. Your app is live at `https://collabtrack.pages.dev`

---

## After setup

- **Update frontend** → push to GitHub → Pages auto-deploys in ~30 seconds
- **Update worker** → paste new code in Worker dashboard → Save and Deploy
- **Add custom domain** → Pages → Custom domains → Add domain

---

## Security

- Password verified server-side only — never in frontend code
- JWT tokens: 30-day expiry, stored in `sessionStorage` (clears on tab close)
- POC details & commercial amounts hidden behind 👁 button
- All data encrypted at rest in Cloudflare KV
- HTTPS enforced by Cloudflare — no plain HTTP
- Security headers applied via `_headers` file
