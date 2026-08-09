# Anmol Digital Library — Firestore backend (Cloud Run)

This is the new backend that replaces Firebase Realtime Database. All four
portal HTML files (and the Dashboard) now talk to this service instead of
talking to Firebase directly.

## 1. One-time setup
```bash
gcloud config set project YOUR_PROJECT_ID

# Enable the services this backend needs
gcloud services enable run.googleapis.com firestore.googleapis.com

# Create the Firestore database, if you haven't already (Native mode)
gcloud firestore databases create --location=asia-south1
```

## 2. Deploy
From inside this `backend/` folder:
```bash
gcloud run deploy anmol-library-api \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated \
  --set-env-vars ALLOWED_ORIGINS=https://YOUR_PROJECT_ID.appspot.com
```
`gcloud run deploy --source .` builds the Dockerfile automatically — no
separate `docker build`/`docker push` step needed.

This prints a URL like:
```
https://anmol-library-api-xxxxxxxxxx-uc.a.run.app
```
That's your new `API_BASE`. Cloud Run's own service account already has
Firestore access in the same project by default — no separate API key or
credentials file needed, unlike the old Firebase client key.

## 3. Point the frontend at it
In each of `index.html`, `admin.html`, `agent.html`, `hrms.html`,
`student.html` there's a line like:
```js
const API_BASE = window.SHDL_API_BASE || 'https://YOUR-CLOUD-RUN-URL.a.run.app/api';
```
Two ways to set the real URL:
- **Simplest:** find-and-replace that placeholder with your real Cloud Run
  URL + `/api` in all five files, then redeploy the frontend package.
- **Cleaner (one place to change):** add this one line to `static/index.html`
  (and the other four) right before everything else runs:
  ```html
  <script>window.SHDL_API_BASE = "https://anmol-library-api-xxxxxxxxxx-uc.a.run.app/api";</script>
  ```

## 4. Sanity check
```bash
curl https://anmol-library-api-xxxxxxxxxx-uc.a.run.app/api/health
# {"status": "ok", "time": 1234567890123}
```
The small green/red dot each portal already shows (bottom corner) polls
this same `/api/health` endpoint every 10 seconds — if it's red after
deploying, the frontend's `API_BASE` doesn't match the real Cloud Run URL
yet, or CORS isn't allowing your App Engine origin (see `ALLOWED_ORIGINS`
above).

## Verifying the shim itself
`docs/firestore-shim.js` is the exact file inlined into the four portal
pages (and loaded separately by `index.html`). `docs/test-shim.js` is a
small standalone test suite that exercises it against an in-memory mock of
this backend's API — useful if you ever modify the shim and want to check
you haven't broken `.set()`/`.update()`/`.transaction()`/query behavior:
```bash
node docs/test-shim.js
```

## What changed vs. Firebase
- **No more Firebase SDK, no more client-side database key.** Firestore
  access happens only inside this backend, using Cloud Run's own service
  identity — nothing about the database is reachable directly from a
  browser anymore.
- **All ~165 `FBDB.ref(...)` call sites across the four portal files were
  left completely untouched.** A drop-in shim (`static/firestore-shim.js`,
  also inlined directly into admin/agent/hrms/student for consistency with
  how those files are built) reimplements the small part of the old
  `firebase.database()` API they use, backed by this REST API instead.
- **Money-moving logic already lived server-side before this migration**
  (createStudentPaymentTransaction / hrmsVerifyTransaction /
  hrmsRejectTransaction all call `API.post('/payments/...')`) — that part
  doesn't change here. It still needs those `/payments/...` routes
  implemented (they aren't part of this generic backend yet — see
  "Still to build" below).
- **Real-time listeners (`.on('value')`) are now polling** every 6 seconds
  instead of an instant push. For attendance/wallet dashboards this is
  unlikely to be noticeable; if you want faster updates for a specific
  screen, lower the interval inside `firestore-shim.js`.
- **Three call sites use real atomic transactions** (agent wallet
  increments, and HRMS's two-step "soft lock" that stops two admins from
  approving the same registration at once). Those go through a dedicated
  compare-and-set endpoint backed by a real Firestore transaction — this
  is the one part of the migration where correctness under concurrent
  requests actually matters, and it's handled server-side, not with a
  blind client-side read-then-write.

## Login verification — now real, not a stub
`/api/auth/login` verifies credentials against the actual stored records —
it no longer issues a token for any random username/password:
- `admin` → checked against `shdl/admins`
- `agent` / `staff` → checked against `shdl/agent_logins`
- `hrms_employee` → checked against `shdl/employees` (empId + registered
  mobile — HRMS's own employee login, separate from agent_logins "Staff")
- `student` → checked against `shdl/students` (studentId + registered
  mobile)

Passwords are hashed (werkzeug scrypt) with **lazy migration**: an
existing plaintext password (from before this change) still logs in
correctly, and is transparently re-hashed and saved back on that first
successful login — no manual data migration needed.

**Lockout:** 5 failed attempts for the same (role, username) locks that
account out for 15 minutes (429 response), tracked in a Firestore
`login_attempts` collection so it survives across Cloud Run instances.

**Tokens expire** after 12 hours and are checked on every protected route.

**Role-protected routes:** Full Reset (`DELETE /api/node/<namespace>`,
admin only) and the two payment routes (`verify`/`reject`, restricted to
`admin` or `hrms_employee` — **never** `agent`/`staff`, so an agent can
never approve their own pending payment).

**The frontend login flow was changed to match:** admin.html, agent.html,
and hrms.html's dashboards now only open *after* the backend confirms the
login — previously this was a "non-blocking bridge" that let the
dashboard open on local data match alone, with the backend token fetched
only in the background. student.html's login was intentionally left as
non-blocking — it has no separate secret (just studentId + mobile) and no
route currently depends on its token; only fix if you want defense in
depth there too.

Logout now also clears the stored token (`AUTH_TOKEN = null` +
`localStorage.removeItem('shdl_auth_token')`) in all three files —
previously a token could outlive its own logout.

Tested in `docs/test_auth.py` (15 checks: wrong password, plaintext →
hash migration, lockout + expiry, lockout window recovery, all four
roles, role-restricted routes, expired-token rejection).
```bash
python3 docs/test_auth.py
```

## Dashboard navigation (index.html)
The Dashboard shows the four portal links directly — no login step of its
own. Clicking a portal navigates (a real page load, not a same-page
toggle) to that portal's separate `_login.html` page; a correct login
there navigates again to that portal's separate `_dashboard.html` page;
logout navigates back to `/`. Each `_dashboard.html` has its own boot-time
auth guard that redirects to its `_login.html` if there's no valid
session — there is no code path that shows dashboard content without a
real login on the matching login page first.

## Website Content Manager (nav buttons, login options, footer, stats,
## ticker, homepage content, app list) — secured GCS writes
The Admin Panel can edit the public Dashboard's content live, without a
redeploy, via `/api/site-content/upload-json` and `/api/site-content/upload-file`
(both admin-only, both path/folder-allowlisted — see `main.py`). The
Dashboard (`index.html`) reads this content directly from GCS's public
read URL, which is safe and normal (same as loading any public CDN
asset) — only the **write** side needed to move behind auth.

**One-time setup this feature needs:** the Cloud Run service account
needs write access to the bucket:
```bash
# Create the bucket if it doesn't exist yet
gcloud storage buckets create gs://digital-library-21663-uploads \
  --location=asia-south1 --uniform-bucket-level-access

# Make objects in it publicly READABLE (safe — this is just content
# the Dashboard displays, e.g. nav-buttons.json, homepage images)
gcloud storage buckets add-iam-policy-binding gs://digital-library-21663-uploads \
  --member=allUsers --role=roles/storage.objectViewer

# Grant ONLY this backend's own service account WRITE access —
# NOT allUsers. This is the fix for the original insecure design.
gcloud storage buckets add-iam-policy-binding gs://digital-library-21663-uploads \
  --member=serviceAccount:YOUR-CLOUD-RUN-SERVICE-ACCOUNT@YOUR_PROJECT_ID.iam.gserviceaccount.com \
  --role=roles/storage.objectAdmin
```
Find your Cloud Run service's service account with:
```bash
gcloud run services describe anmol-library-api --region asia-south1 --format='value(spec.template.spec.serviceAccountName)'
```
If that's blank, it's using the default Compute Engine service account
(`PROJECT_NUMBER-compute@developer.gserviceaccount.com`) — grant that one
instead.

If your bucket name is ever different from `digital-library-21663-uploads`,
set it via an env var on the Cloud Run service instead of editing code:
```bash
gcloud run services update anmol-library-api --region asia-south1 \
  --set-env-vars GCS_BUCKET=your-actual-bucket-name
```
(update the matching `GCS_BUCKET` constant in `admin_dashboard.html` and
`index.html` too, since those still read directly from the public URL).

## Payments — real, atomic, tested
`/api/payments/student-transaction`, `/api/payments/transactions/<id>/verify`,
and `/api/payments/transactions/<id>/reject` are real, atomic Firestore
transactions (see `main.py`) — not stubs. Each one touches every document
it needs to (transactions / agent_wallets / admin_wallet / commission_ledger)
inside a single `@firestore.transactional` function, so a verify and a
reject racing the same transaction can't both succeed, and double-verifying
an already-approved transaction is rejected with a 409 instead of
double-crediting the wallet.

Commission rate defaults to 10% and is read from `shdl/commission_rate` (a
plain number) via the existing generic node store — change it anytime with:
```bash
curl -X POST $API_BASE/node/shdl/commission_rate -H 'Content-Type: application/json' -d '{"value": 12}'
```

Tested with `docs/test_payments.py` (17 checks: creation, verify math,
commission-ledger entries, double-verify rejection, reject rollback,
input validation, and a custom commission rate) against an in-memory fake
of the Firestore client — no real GCP project needed to run it:
```bash
python3 docs/test_payments.py
```

## Still to build
- **Firestore Security Rules equivalent.** Firestore rules can't help here
  since nothing calls Firestore directly from the browser anymore — but
  add IAM/service-account scoping and rate limiting on the Cloud Run
  service itself if this becomes public-facing at scale.
- **Password reset / "forgot password" flow.** Not part of this change —
  currently the only way to reset a stuck account is direct Firestore
  edit or an admin re-setting it through the existing UI.

## Known scaling limitation
`transactions` and `comments` are stored as one Firestore document each
(same "whole node" model as everything else), for consistency and to keep
this migration tractable. If either grows into the thousands of records,
that single document could approach Firestore's 1 MiB per-document limit.
When that becomes a real concern, migrate just those two keys to true
Firestore subcollections (one document per record) — everything else can
stay exactly as it is.
