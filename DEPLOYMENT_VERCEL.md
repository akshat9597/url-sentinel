# Deploy ByteForce: Vercel frontend + Render backend

ByteForce is a full-stack application. Deploy the React frontend on Vercel and the persistent FastAPI/PostgreSQL backend on Render. This preserves authentication, database records, model loading, and access-log ingestion.

## Why the backend is separate

Vercel can execute FastAPI, but ByteForce also uses large Python ML dependencies, PostgreSQL migrations, background ingestion, file-based model versions, and optional Zeek subprocesses. Vercel Functions have serverless filesystem/runtime constraints and a 4.5 MB request/response body limit. A persistent container host is more reliable for this application.

## Step 1: push the deployment files

From the repository:

```bash
cd "/Users/cyph3rrr/Documents/PROJECT 2908/url-sentinel"
git add frontend/vercel.json render.yaml backend/database.py backend/migrations/env.py backend/scripts/start.sh DEPLOYMENT_VERCEL.md
git commit -m "Add Vercel and Render deployment configuration"
git push origin main
```

## Step 2: deploy the backend on Render first

1. Sign in at <https://dashboard.render.com/> using the GitHub account that can access `akshat9597/url-sentinel`.
2. Choose **New → Blueprint**.
3. Select the `url-sentinel` repository.
4. Render reads `render.yaml` and proposes:
   - Web service: `byteforce-api-akshat9597`
   - PostgreSQL database: `byteforce-db`
5. Enter the prompted environment variables:

| Variable | Value |
|---|---|
| `BYTEFORCE_ADMIN_EMAIL` | Your administrator email, for example `admin@byteforce.local` |
| `BYTEFORCE_ADMIN_PASSWORD` | A new strong password used only for ByteForce |
| `BYTEFORCE_ALLOWED_ORIGINS` | `https://byteforce-sih-2025.vercel.app` initially |
| `BYTEFORCE_DEFAULT_HOST` | The domain you own/monitor, or `authorized-site.local` for judging |

6. Create/apply the Blueprint and wait for the API health check to pass.
7. Open `https://byteforce-api-akshat9597.onrender.com/api/health`.

If Render assigns a different service URL, change the API destination in `frontend/vercel.json`, commit, and push before deploying Vercel.

### If creating the Render service manually

Use these exact settings. The **Root Directory** is important: without it, Render uses the repository root as the Docker build context and `COPY requirements.txt` fails because the file is inside `backend/`.

| Setting | Value |
|---|---|
| Environment | Docker |
| Root Directory | blank / repository root |
| Dockerfile Path | `backend/Dockerfile` |
| Docker Build Context Directory | `.` |
| Health Check Path | `/api/health` |

The Dockerfile is intentionally written for the repository-root context: it copies `backend/requirements.txt` and the `backend/` source tree into the image. These settings match the Render build log and avoid the error `"/requirements.txt": not found`.

Add these variables under **Render → Service → Environment** before the first
production deploy:

| Variable | Required value |
|---|---|
| `BYTEFORCE_ENV` | `production` |
| `BYTEFORCE_OBSERVATION_MODE` | `true` |
| `BYTEFORCE_AUTH_ENABLED` | `false` for the public hackathon demo; use `true` only when you want administrator sign-in |
| `BYTEFORCE_SECRET_KEY` | Required only when `BYTEFORCE_AUTH_ENABLED=true`; use Render's **Generate** option, or a private random value of at least 32 characters |
| `BYTEFORCE_ADMIN_EMAIL` | Required only when `BYTEFORCE_AUTH_ENABLED=true` |
| `BYTEFORCE_ADMIN_PASSWORD` | Required only when `BYTEFORCE_AUTH_ENABLED=true` |
| `BYTEFORCE_AUTO_SEED` | `false` |
| `BYTEFORCE_BOOTSTRAP_MODEL` | `false` |
| `BYTEFORCE_ALLOWED_ORIGINS` | Your exact Vercel origin, such as `https://byteforce-sih-2025.vercel.app` |
| `BYTEFORCE_TRUSTED_HOSTS` | `*.onrender.com,*.vercel.app,localhost,127.0.0.1` |

Generate a value locally if Render's **Generate** button is unavailable:

```bash
openssl rand -hex 32
```

Paste the output only into Render's `BYTEFORCE_SECRET_KEY` value. Do not commit
it, put it in Vercel, reuse the administrator password, or use a public file
checksum as the secret. After saving the variables, choose **Manual Deploy →
Deploy latest commit** (or restart the service).

If startup reports `BYTEFORCE_SECRET_KEY must contain at least 32 characters`,
authentication is enabled and the variable is missing, shorter than 32
characters, or was added to the wrong Render service/environment. For a public
hackathon demo, set `BYTEFORCE_AUTH_ENABLED=false`, save, rebuild, and deploy.

The free Render PostgreSQL offering is suitable for a short demonstration but currently expires after its free period. Use a paid PostgreSQL plan or another managed PostgreSQL service for a lasting deployment.

## Step 3: deploy the frontend on Vercel

On Vercel's **New Project** screen use:

| Setting | Value |
|---|---|
| Repository | `akshat9597/url-sentinel` |
| Project Name | `byteforce-sih-2025` |
| Framework Preset | `Vite` |
| Root Directory | `frontend` |
| Build Command | `npm run build` (default) |
| Output Directory | `dist` (default) |
| Install Command | `npm install` (default) |

The frontend needs no secret environment variables. The repository's `frontend/vercel.json` rewrites `/api/*` to the Render API, so `VITE_API_URL` can remain unset. If you prefer direct API calls, set `VITE_API_URL` to the Render API URL, for example `https://byteforce-api-akshat9597.onrender.com`; never put database passwords or `BYTEFORCE_SECRET_KEY` into a `VITE_*` variable because Vite variables are public browser code.

Remove backend variables accidentally detected by Vercel. Only variables beginning with `VITE_` are exposed to the browser.

Click **Deploy** only after the Render health URL works.

## Step 4: verify and correct the final origin

1. Open the assigned Vercel URL.
2. If it differs from `https://byteforce-sih-2025.vercel.app`, open the Render service settings.
3. Set `BYTEFORCE_ALLOWED_ORIGINS` to the exact assigned Vercel origin, without a trailing slash.
4. Redeploy/restart the Render service.
5. Open `<your-vercel-url>/operations` and confirm the page loads without a sign-in form.

For a custom frontend domain, set `BYTEFORCE_ALLOWED_ORIGINS` to that exact `https://` origin. If using direct API calls instead of the Vercel rewrite, also set `VITE_API_URL` in Vercel and redeploy the frontend. Render's `BYTEFORCE_TRUSTED_HOSTS` must include the Render hostname and any custom API hostname.

## Step 5: load data

For a judging dashboard:

1. Open **Settings**.
2. Click **Load Demo Dataset**.

For authorized real telemetry:

1. Open **Operations**.
2. Upload an Nginx/Apache `.log` file or JSON Lines file.
3. Refresh Ingestion Jobs.
4. Open Threat Explorer.

## Verification checklist

- `/api/health` shows `database: postgresql`.
- Vercel `/operations` opens after a direct refresh.
- Dashboard, Settings, PCAP Analyzer, and Operations work without sign-in in public demo mode.
- Load Demo Dataset populates charts.
- `backend/data/demo_access.log` produces five processed records and three threats.
- CSV and JSON downloads work.
- PCAP page clearly reports Zeek availability.

## Deployment limitations

- The provided Render Docker image does not install Zeek; PCAP uses the safe fallback unless you build a Zeek-enabled image.
- The synthetic bootstrap model is recreated on a fresh ephemeral backend deployment. For durable organization-trained model versions, attach persistent storage or use object storage/model registry infrastructure.
- Free services may sleep and have cold starts.
- Use paid PostgreSQL/backups for any lasting or important telemetry.
- Do not upload third-party traffic without authorization.
