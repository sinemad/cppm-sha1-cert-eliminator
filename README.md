# SHA-1 Certificate Eliminator for Aruba ClearPass

Finds and removes SHA-1 signed certificates from the Aruba ClearPass certificate trust list. Runs as either a **web UI** (default) or a **CLI tool**, both packaged as a Docker container.

SHA-1 is cryptographically broken and rejected by modern browsers and OS trust stores. This tool automates the cleanup process via the ClearPass REST API.

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed
- A ClearPass API token or OAuth2 client credentials (see [Authentication](#authentication))

### 1. Clone the repository

```bash
git clone https://github.com/your-org/cppm-sha1-cert-eliminator.git
cd cppm-sha1-cert-eliminator
```

### 2. Configure credentials

Copy the example environment file and fill in your ClearPass details:

```bash
cp .env.example .env
```

Open `.env` in your editor and set the required values:

```env
# Full URL to the ClearPass API — must include /api
CLEARPASS_SERVER=https://clearpass.example.com/api

# Authentication — use an API token OR client credentials (not both)
CLEARPASS_API_TOKEN=your-token-here

# CLEARPASS_CLIENT_ID=your-client-id
# CLEARPASS_CLIENT_SECRET=your-client-secret

# Set to false only if your ClearPass uses a self-signed certificate
CLEARPASS_VERIFY_SSL=true
```

See [Authentication](#authentication) for how to obtain credentials.

### 3. Build the Docker image

```bash
docker compose build
```

This installs all Python dependencies into the image. Only needed once (or after pulling updates).

### 4. Run the web UI

```bash
docker compose up
```

Docker Compose reads your `.env` file automatically. Once the container starts, open [http://localhost:8080](http://localhost:8080) in your browser. If credentials were set in `.env`, the app connects to ClearPass automatically on startup.

To run in the background:

```bash
docker compose up -d
docker compose logs -f   # tail logs
docker compose down      # stop and remove the container
```

### 5. Or run the CLI

The CLI runs as a one-shot container and exits when done. Your `.env` credentials are passed through automatically.

```bash
# Dry run — list SHA-1 certs without deleting anything
docker compose run --rm sha1-cert-eliminator python sha1_cert_eliminator.py --dry-run

# Interactive — lists found certs, prompts you to select which to delete
docker compose run --rm sha1-cert-eliminator python sha1_cert_eliminator.py

# Delete all SHA-1 certs without prompting
docker compose run --rm sha1-cert-eliminator python sha1_cert_eliminator.py --auto-remove

# Output results as JSON (useful for scripting or auditing)
docker compose run --rm sha1-cert-eliminator python sha1_cert_eliminator.py --json
```

You can also pass credentials directly as flags instead of using `.env`:

```bash
docker compose run --rm sha1-cert-eliminator python sha1_cert_eliminator.py \
  --server https://clearpass.example.com/api \
  --api-token your-token-here \
  --dry-run
```

---

## Authentication

Two methods are supported. Choose one based on what your ClearPass deployment provides.

| Method | Environment Variables | CLI Flags |
|---|---|---|
| API Token | `CLEARPASS_API_TOKEN` | `--api-token` |
| OAuth2 Client Credentials | `CLEARPASS_CLIENT_ID` + `CLEARPASS_CLIENT_SECRET` | `--client-id` + `--client-secret` |

The server URL must include the `/api` path suffix, e.g. `https://clearpass.example.com/api`.

---

### Option A — API Token

An API token is the simpler option and is recommended for one-off or admin use.

1. Log in to the ClearPass Policy Manager web UI as an administrator.
2. From the Dashboard, navigate to **ClearPass Guest**.
3. In the ClearPass Guest Administration UI, go to **Administration → API Services → API Clients**.
4. Click **Create API Client**.
5. Set **Operator Profile** to a profile with at minimum read access to the certificate trust list (e.g. the built-in `Super Administrator` or a custom profile with `Platform → Certificates` read/write permissions).
6. Under **Grant Type**, select **Client Credentials** and click **Create API Client**.
7. On the next screen, copy the **Access Token** that is displayed. This value is your `CLEARPASS_API_TOKEN`. It does not expire by default but can be revoked from the same page.

> **Note:** The Access Token shown on the creation screen is only displayed once. Copy it before navigating away.

---

### Option B — OAuth2 Client Credentials

Client credentials are preferred for automated or long-running use because they allow ClearPass to issue fresh tokens without manual intervention.

1. Log in to the ClearPass Policy Manager web UI as an administrator.
2. From the Dashboard, navigate to **ClearPass Guest**.
3. In the ClearPass Guest Administration UI, go to **Administration → API Services → API Clients**.
4. Click **Create API Client**.
5. Give the client a descriptive name (e.g. `sha1-cert-eliminator`).
6. Set **Operator Profile** to a profile with `Platform → Certificates` read/write permissions.
7. Under **Grant Type**, select **Client Credentials**.
8. Click **Create API Client**.
9. Copy the **Client ID** and **Client Secret** displayed on the confirmation screen. These are your `CLEARPASS_CLIENT_ID` and `CLEARPASS_CLIENT_SECRET`.

> **Note:** The Client Secret is only shown once at creation time. If lost, you must create a new API client.

---

### Required Permissions

Whichever method you use, the associated operator profile needs:

| Permission | Level Required |
|---|---|
| Platform → Certificates | Read (to scan) + Write (to delete) |

If you only intend to audit (dry-run or `--json`), read-only access is sufficient.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CLEARPASS_SERVER` | — | ClearPass server URL (required) |
| `CLEARPASS_API_TOKEN` | — | API token for authentication |
| `CLEARPASS_CLIENT_ID` | — | OAuth2 client ID |
| `CLEARPASS_CLIENT_SECRET` | — | OAuth2 client secret |
| `CLEARPASS_VERIFY_SSL` | `true` | Set to `false` to skip SSL verification |

---

## Web UI

The web UI starts automatically with `docker compose up` and is accessible at `http://localhost:8080`.

**Workflow:**

1. **Connect** — Enter your ClearPass server URL and credentials. The app validates the connection immediately and pre-populates fields from environment variables if set.
2. **Scan** — Click "Scan for SHA-1 Certificates" to fetch the full trust list and identify SHA-1 signed entries.
3. **Review** — Certificates are shown in a table with subject, issuer, expiry, usage, and how they were detected. Click any row to see full certificate details.
4. **Delete** — Select one or more certificates and click "Delete Selected". A confirmation modal lists what will be removed before any action is taken.

If full credentials are present in environment variables at startup, the app auto-connects without requiring the connection form.

---

## CLI Reference

```
python sha1_cert_eliminator.py [OPTIONS]
```

| Flag | Description |
|---|---|
| `--server URL` | ClearPass server URL |
| `--api-token TOKEN` | API token |
| `--client-id ID` | OAuth2 client ID |
| `--client-secret SECRET` | OAuth2 client secret |
| `--no-verify-ssl` | Disable SSL certificate verification |
| `--dry-run` | List SHA-1 certs but do not delete |
| `--auto-remove` | Delete all SHA-1 certs without prompting |
| `--json` | Print SHA-1 cert list as JSON (implies `--dry-run`) |

CLI flags take precedence over environment variables.

**Interactive mode** (no `--dry-run` or `--auto-remove`): lists found certs and prompts for selection. Enter comma-separated numbers (e.g. `1,3`), `all`, or `none`/`q` to exit.

---

## How Detection Works

Each trust list entry is checked in two passes:

1. **Metadata fields** — If the entry's `signature_algorithm`, `hash_algorithm`, or similar fields contain `sha1`, `sha-1`, `sha1withrsaencryption`, etc., it is flagged immediately.
2. **Certificate parsing** — If metadata fields are absent or inconclusive, the tool fetches the full certificate (PEM or DER) and parses it with the Python `cryptography` library to inspect the actual signature hash algorithm.

This two-pass approach handles ClearPass deployments that return incomplete metadata in the list endpoint.

---

## Running Without Docker

```bash
pip install -r requirements.txt

# Web UI
uvicorn app.main:app --host 0.0.0.0 --port 8080

# CLI
python sha1_cert_eliminator.py --server https://cppm.example.com/api --api-token TOKEN --dry-run
```

Python 3.12+ is recommended.

---

## Project Structure

```
.
├── sha1_cert_eliminator.py   # CLI entry point
├── app/
│   ├── clearpass.py          # Shared ClearPass API logic and SHA-1 detection
│   ├── main.py               # FastAPI web application
│   └── static/
│       ├── index.html        # Web UI
│       └── app.js            # Web UI JavaScript
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```
