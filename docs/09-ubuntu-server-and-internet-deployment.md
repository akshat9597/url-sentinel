# ByteForce Ubuntu Server and Internet Deployment Runbook

## Purpose

This runbook explains how to publish ByteForce for internet access from an Ubuntu server. It covers domain setup, firewall rules, Docker deployment, PostgreSQL, Nginx, HTTPS, environment variables, verification, updates, backups, and safe operating practices.

ByteForce is an observation-only defensive analysis platform. Only ingest traffic and URLs from systems you own or are explicitly authorized to monitor. Do not use a public deployment to scan, crawl, exploit, or block third-party websites.

## Recommended architecture

For a self-managed Ubuntu VPS, use one public domain and keep the application services private:

```text
Internet
   |
   | HTTPS 443
   v
Nginx reverse proxy on Ubuntu
   |
   +--> Frontend container on 127.0.0.1:5173
   +--> Backend container on 127.0.0.1:8000
             |
             +--> PostgreSQL container on the private Docker network
```

Users open:

```text
https://byteforce.example.com
```

The browser calls `/api/*` through the same public origin. This avoids exposing the database, backend port, or frontend port to the internet.

## Server requirements

Recommended minimum for a demonstration:

- Ubuntu Server 22.04 LTS or 24.04 LTS.
- 2 CPU cores.
- 4 GB RAM.
- 30 GB SSD.
- A domain name whose DNS you control.
- A public IPv4 address.
- Docker Engine and the Docker Compose plugin.

For larger datasets, model training, PCAP processing, or multiple users, use more memory and persistent storage. The included free Render plan is simpler for a demo; an Ubuntu VPS gives more control but makes patching, backups, TLS, and monitoring your responsibility.

## 1. Point the domain to the server

Create an `A` record at your DNS provider:

```text
Type: A
Name: byteforce
Value: YOUR_SERVER_PUBLIC_IP
TTL: 300
```

Wait for DNS propagation and verify from your computer:

```bash
dig +short byteforce.example.com
```

The result should be your server IP. Do not request a certificate until DNS resolves correctly.

## 2. Connect and update Ubuntu

```bash
ssh YOUR_USER@YOUR_SERVER_PUBLIC_IP
sudo apt update
sudo apt full-upgrade -y
sudo apt install -y ca-certificates curl git nginx certbot python3-certbot-nginx ufw
```

Create a non-root deployment user if needed:

```bash
sudo adduser byteforce
sudo usermod -aG sudo byteforce
sudo usermod -aG docker byteforce
```

Reconnect as that user before continuing:

```bash
ssh byteforce@YOUR_SERVER_PUBLIC_IP
```

## 3. Configure the firewall

Allow SSH before enabling the firewall so you do not lock yourself out. If your SSH port is not 22, replace it below.

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
sudo ufw status verbose
```

Do not open ports `5432`, `8000`, or `5173` publicly. Restrict SSH to a known office/VPN IP when practical:

```bash
sudo ufw delete allow OpenSSH
sudo ufw allow from YOUR_ADMIN_IP to any port 22 proto tcp
```

## 4. Install Docker

Use Docker's official installation instructions for the current Ubuntu release. A common package-based installation is:

```bash
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in so the group change takes effect, then verify:

```bash
docker --version
docker compose version
```

## 5. Download the project

```bash
cd ~
git clone https://github.com/akshat9597/url-sentinel.git
cd url-sentinel
```

For a repeatable deployment, deploy a tagged release or reviewed commit rather than an unreviewed branch:

```bash
git checkout main
git pull --ff-only origin main
```

## 6. Create production environment settings

```bash
cp .env.example .env
nano .env
```

Use real values and never commit this file:

```text
POSTGRES_DB=byteforce
POSTGRES_USER=byteforce
POSTGRES_PASSWORD=GENERATE_A_LONG_UNIQUE_DATABASE_PASSWORD
DATABASE_URL=
BYTEFORCE_ENV=production
BYTEFORCE_OBSERVATION_MODE=true
BYTEFORCE_AUTH_ENABLED=true
BYTEFORCE_SECRET_KEY=GENERATE_AT_LEAST_32_RANDOM_CHARACTERS
BYTEFORCE_ADMIN_EMAIL=admin@byteforce.example.com
BYTEFORCE_ADMIN_PASSWORD=GENERATE_A_LONG_UNIQUE_ADMIN_PASSWORD
BYTEFORCE_AUTO_SEED=false
BYTEFORCE_BOOTSTRAP_MODEL=false
BYTEFORCE_ALLOWED_ORIGINS=https://byteforce.example.com
BYTEFORCE_TRUSTED_HOSTS=byteforce.example.com,localhost,127.0.0.1
BYTEFORCE_RETENTION_DAYS=90
BYTEFORCE_MAX_UPLOAD_BYTES=26214400
BYTEFORCE_RATE_LIMIT_PER_MINUTE=120
BYTEFORCE_LOG_WATCH_PATH=
BYTEFORCE_LOG_FORMAT=auto
BYTEFORCE_DEFAULT_HOST=authorized-site.example.com
BYTEFORCE_DEFAULT_DST_IP=127.0.0.1
```

Generate secrets without placing them in shell history:

```bash
openssl rand -hex 32
openssl rand -base64 32
```

`DATABASE_URL` may remain empty for the included Docker Compose deployment because Compose supplies the PostgreSQL connection through its service environment. For an external managed database, set it to the provider's private connection string.

## 7. Bind application ports privately

For a public Ubuntu deployment, do not publish container ports on every network interface. Update the backend and frontend port mappings in `docker-compose.yml` to:

```yaml
ports:
  - "127.0.0.1:8000:8000"
```

for the backend, and:

```yaml
ports:
  - "127.0.0.1:5173:80"
```

for the frontend.

Do not add a public PostgreSQL port mapping. The database should remain reachable only by the backend over the Docker network.

## 8. Start ByteForce

```bash
docker compose up -d --build
```

Check the services:

```bash
docker compose ps
docker compose logs --tail=100 backend
```

Test locally on the server before adding HTTPS:

```bash
curl http://127.0.0.1:8000/api/health
curl -I http://127.0.0.1:5173
```

The backend startup script runs the Alembic migration. In production, automatic demo seeding and model bootstrapping are disabled; load reviewed data or explicitly prepare a model through the documented workflow.

## 9. Configure Nginx

Create a site configuration:

```bash
sudo nano /etc/nginx/sites-available/byteforce
```

Use this HTTP configuration initially:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name byteforce.example.com;

    client_max_body_size 25m;

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://127.0.0.1:5173;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Replace `byteforce.example.com` with your real domain:

```bash
sudo ln -s /etc/nginx/sites-available/byteforce /etc/nginx/sites-enabled/byteforce
sudo nginx -t
sudo systemctl reload nginx
```

Test:

```bash
curl -I http://byteforce.example.com
curl http://byteforce.example.com/api/health
```

## 10. Enable HTTPS

Request a Let's Encrypt certificate after DNS and HTTP routing work:

```bash
sudo certbot --nginx -d byteforce.example.com
```

Choose the redirect option when prompted. Verify renewal:

```bash
sudo certbot renew --dry-run
```

Update `.env` if necessary and restart the backend:

```text
BYTEFORCE_ALLOWED_ORIGINS=https://byteforce.example.com
BYTEFORCE_TRUSTED_HOSTS=byteforce.example.com,localhost,127.0.0.1
```

```bash
docker compose up -d backend
```

The production authentication cookie requires HTTPS. Do not use `BYTEFORCE_HTTPS_REDIRECT=true` unless the application receives the correct forwarded HTTPS scheme through the reverse proxy and you have tested it; Nginx should perform the public HTTP-to-HTTPS redirect.

## 11. Verify the public deployment

```bash
curl -fsS https://byteforce.example.com/api/health
```

Check the response for:

```json
{
  "status": "online",
  "database": "postgresql",
  "mode": "OBSERVATION",
  "auth_enabled": true
}
```

Then verify in a browser:

1. Open `https://byteforce.example.com`.
2. Open Operations and sign in with the configured administrator account.
3. Load demo data only if this is a demonstration environment.
4. Analyze an artificial URL string.
5. Open Threat Explorer and confirm API requests do not return CORS or 401 errors.
6. Export a filtered CSV and JSON result.
7. Confirm the browser address bar remains on your ByteForce domain and no submitted test URL is visited.

## 12. Updates and rollback

Before updating, record the current image and database backup status:

```bash
docker compose ps
cd ~/url-sentinel
git status --short
git log -1 --oneline
```

Pull and rebuild:

```bash
git pull --ff-only origin main
docker compose up -d --build
```

Watch startup:

```bash
docker compose logs -f backend
```

If a reviewed deployment must be rolled back:

```bash
git checkout KNOWN_GOOD_COMMIT

docker compose up -d --build
```

Do not delete Docker volumes during a normal update. `docker compose down -v` deletes the PostgreSQL data volume and should be treated as a destructive operation.

## 13. Backups and retention

The application retention setting is not a backup. Schedule PostgreSQL backups outside the application host and test restoring them. A simple logical backup is:

```bash
mkdir -p ~/byteforce-backups
docker compose exec -T postgres pg_dump -U byteforce -d byteforce | gzip > ~/byteforce-backups/byteforce-$(date +%F).sql.gz
```

Protect backups because they may contain sensitive URLs, IP addresses, and evidence. Use encrypted off-server storage, restricted permissions, a retention policy, and periodic restore tests.

## 14. Monitoring and logs

Useful checks:

```bash
docker compose ps
docker compose logs --since=15m backend
sudo systemctl status nginx
sudo ufw status
curl -fsS https://byteforce.example.com/api/health
```

Monitor disk usage, memory, PostgreSQL health, certificate renewal, failed logins, ingestion errors, and unexpected upload volume. Add external uptime monitoring for the public health endpoint without sending sensitive data in query strings.

## Common deployment problems

### Render or Docker says `requirements.txt` is not found

For the repository-root Docker context, the Dockerfile must contain:

```dockerfile
COPY backend/requirements.txt ./requirements.txt
COPY backend/ .
```

Render should use `backend/Dockerfile` with the repository root as context. The current repository is configured this way.

### Browser shows a CORS error

Set `BYTEFORCE_ALLOWED_ORIGINS` to the exact public frontend origin, including `https://` and excluding a trailing slash. Restart the backend after changing it.

### Browser receives 401

Authentication is enabled. Open Operations and sign in. Confirm that the browser is using HTTPS and that cookies are not blocked.

### Nginx returns 502

Check that containers are running and ports are listening locally:

```bash
docker compose ps
curl http://127.0.0.1:8000/api/health
curl -I http://127.0.0.1:5173
sudo nginx -t
```

### PCAP processing is unavailable

The standard image does not install Zeek. Use access logs or datasets, or build a reviewed Zeek-enabled image. Encrypted HTTPS PCAPs generally do not expose complete URLs or request bodies.

### Database connection fails

Check the PostgreSQL service, credentials, and `DATABASE_URL`:

```bash
docker compose logs --tail=100 postgres
docker compose logs --tail=100 backend
```

Do not expose PostgreSQL to the internet while troubleshooting.

## Alternative: Vercel and Render

For the simplest internet deployment:

```text
Vercel       -> frontend static site
Render       -> FastAPI web service
Render       -> managed PostgreSQL
```

Use [DEPLOYMENT_VERCEL.md](../DEPLOYMENT_VERCEL.md) for that setup. The Vercel frontend can use the repository rewrite in `frontend/vercel.json`, or set `VITE_API_URL` to the Render API URL. Render must receive the exact Vercel origin in `BYTEFORCE_ALLOWED_ORIGINS`.

## Final security checklist

- [ ] Domain DNS points to the correct server.
- [ ] Only ports 80 and 443 are publicly reachable.
- [ ] SSH is restricted and protected with keys where possible.
- [ ] Database, backend, and frontend ports are not publicly exposed.
- [ ] Production authentication is enabled.
- [ ] `BYTEFORCE_SECRET_KEY`, admin password, and database password are unique and private.
- [ ] HTTPS works and certificate renewal has been tested.
- [ ] CORS and trusted hosts contain only required origins and hosts.
- [ ] Backups are encrypted, off-server, and restorable.
- [ ] Demo data is not presented as real-world detection accuracy.
- [ ] Only authorized telemetry is uploaded.
- [ ] The browser extension is not claimed as currently available.
