# SHA-1 Certificate Eliminator for Aruba ClearPass

Finds and removes SHA-1 signed certificates from the Aruba ClearPass certificate trust list. Runs as either a **web UI** (default) or a **CLI tool**, both packaged as a Docker container.

SHA-1 is cryptographically broken and rejected by modern browsers and OS trust stores. This tool automates the cleanup process via the ClearPass REST API.

---

## Quick Start

### 1. Configure credentials

Copy `.env.example` to `.env` and fill in your ClearPass details:

```bash
cp .env.example .env
```

```env
CLEARPASS_SERVER=https://clearpass.example.com/api
CLEARPASS_API_TOKEN=your-token-here
CLEARPASS_VERIFY_SSL=true
```

See [Authentication](#authentication) for `client_id`/`client_secret` as an alternative to an API token.

### 2. Run the web UI

```bash
docker compose up
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

### 3. Or run the CLI

```bash
# Dry run — list SHA-1 certs without deleting
docker compose run --rm sha1-cert-eliminator python sha1_cert_eliminator.py --dry-run

# Interactive selection
docker compose run --rm sha1-cert-eliminator python sha1_cert_eliminator.py

# Delete all SHA-1 certs without prompting
docker compose run --rm sha1-cert-eliminator python sha1_cert_eliminator.py --auto-remove

# Output results as JSON
docker compose run --rm sha1-cert-eliminator python sha1_cert_eliminator.py --json
```

---

## Authentication

Two methods are supported. Use whichever your ClearPass instance provides.

| Method | Environment Variables | CLI Flags |
|---|---|---|
| API Token | `CLEARPASS_API_TOKEN` | `--api-token` |
| OAuth2 Client Credentials | `CLEARPASS_CLIENT_ID` + `CLEARPASS_CLIENT_SECRET` | `--client-id` + `--client-secret` |

The server URL must include the `/api` path suffix, e.g. `https://clearpass.example.com/api`.

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
