# NETGUARD IoT — Botnet Detection & Cybersecurity System

> **Enterprise-Grade AI-Powered IoT Threat Telemetry, Dual-Detection Engine, RBAC Access Control, and Forensic Incident Management Backend**

---

## 1. System Overview

**NETGUARD IoT** is a production-grade cybersecurity platform engineered to monitor heterogeneous IoT network environments, extract behavioral and packet-level traffic telemetry, detect multi-stage botnet incursions (such as *Mirai*, *Bashlite/Gafgyt*, *Hajime*, *Torii*, and *ADB.Miner*), and execute automated threat containment.

The platform provides:
* **Dual-Detection Engine**: Fuses 10 Snort/Suricata heuristic inspection rules with a supervised **Random Forest Classifier** (trained on verified IoT-23 telemetry, achieving **99.2% accuracy** and **99.1% F1-score**).
* **Enterprise Authentication & Token Rotation**: NIST SP 800-63B compliant PBKDF2-HMAC-SHA256 password hashing (100,000 iterations, random salts), dual access/refresh token rotation, and instant token revocation blacklist on logout.
* **Granular Role-Based Access Control (RBAC)**: Enforced permission matrix across `admin`, `analyst`, and `read_only` roles protecting device lifecycle and incident operations.
* **Authorized Collector Ingestion**: Authenticated telemetry pipeline via timing-safe `X-Collector-Key` headers or cryptographic collector Bearer tokens with sliding-window rate limiting.
* **API Security & DoS Protection**: HTTP security headers (CSP, HSTS, nosniff, DENY, Referrer-Policy), origin-controlled CORS, pre-read 413 request size limits (5 MB standard / 15 MB batch), sliding-window rate limiting (429 with `Retry-After`), and NoSQL query injection sanitization.
* **Real-Time Channel Security**: Protected Server-Sent Events (`/api/stream/events`) requiring authenticated credentials with replay support via `Last-Event-ID`.
* **Database Layer & Resilient Fallback**: Production MongoDB integration with indexed collections, bounded in-memory caching, and seamless fallback to embedded storage if the database disconnects.
* **Data Retention & Forensic Evidence Preservation**: Configurable 30-day telemetry retention policy with strict safeguards protecting high-risk incident forensic records from deletion.
* **Real-Time SecOps Frontend**: Vanilla JS & CSS dashboard with cybersecurity dark forest-green aesthetic (`#071B13`, `#22C55E`).

---

## 2. Security Architecture & Controls

### 2.1 Authentication & Token Lifecycle
1. **Password Hashing**: PBKDF2-HMAC-SHA256 using 100,000 iterations with 16-byte random salts (`os.urandom(16)`) formatted as `pbkdf2_sha256$<iter>$<salt_hex>$<hash_hex>`. Timing-safe comparison via `hmac.compare_digest`.
2. **Access & Refresh Tokens**: HMAC-SHA256 signed JWTs with explicit token types (`access` vs `refresh`) and unique cryptographic identifiers (`jti`) to prevent token collisions.
   - Access tokens expire in 60 minutes (`JWT_ACCESS_EXPIRATION_MINUTES=60`).
   - Refresh tokens expire in 7 days (`JWT_REFRESH_EXPIRATION_DAYS=7`).
3. **Token Revocation (Logout)**: Thread-safe in-memory blacklist invalidating active access and refresh tokens upon explicit user logout (`POST /api/auth/logout`), preventing replay or reuse.
4. **Seed Accounts** (configured via environment variables without hardcoded backdoors):
   - `admin` (Lead SecOps Engineer): Full administrative permissions (`ADMIN_PASSWORD=netguard2026`).
   - `analyst` (SecOps Analyst): Telemetry ingestion, rule tuning, triage notes, and quarantine operations (`ANALYST_PASSWORD=analyst2026`).
   - `readonly` / `auditor` (Security Auditor): Read-only visibility into fleet telemetry and audit logs (`AUDITOR_PASSWORD=auditor2026`).

### 2.2 Role-Based Access Control (RBAC) Matrix

| Resource / Action | Admin | Analyst | Read-Only | Enforcement Rule |
| :--- | :---: | :---: | :---: | :--- |
| **Inspect Telemetry & Devices** | :white_check_mark: | :white_check_mark: | :white_check_mark: | Public/Read permissions |
| **Register IoT Device** | :white_check_mark: | :white_check_mark: | :x: (403) | Requires `devices:create` |
| **Update Device / Quarantine** | :white_check_mark: | :white_check_mark: | :x: (403) | Requires `devices:quarantine` |
| **Delete IoT Device** | :white_check_mark: | :x: (403) | :x: (403) | Strictly restricted to `admin` |
| **Acknowledge / Triage Alert** | :white_check_mark: | :white_check_mark: | :x: (403) | Requires `alerts:update` |
| **Add Forensic Note** | :white_check_mark: | :white_check_mark: | :x: (403) | Requires `alerts:note` |
| **Update Risk Engine Config** | :white_check_mark: | :x: (403) | :x: (403) | Strictly restricted to `admin` |
| **Trigger Data Retention Purge**| :white_check_mark: | :x: (403) | :x: (403) | Strictly restricted to `admin` |

### 2.3 Collector Ingestion Authentication
* Endpoint: `POST /api/traffic/events` and `POST /api/traffic/events/batch`.
* Accepts `X-Collector-Key` or `X-API-Key` matching `COLLECTOR_API_KEY` validated via constant-time `hmac.compare_digest`.
* Also accepts verified SecOps session JWTs (`Authorization: Bearer <token>`).
* Missing or invalid collector credentials immediately return `401 Unauthorized`.

### 2.4 API Hardening & Defenses
* **HTTP Security Headers**:
  - `Content-Security-Policy`: `default-src 'self' 'unsafe-inline' 'unsafe-eval' data:; connect-src 'self' ws: http: https:;`
  - `X-Content-Type-Options`: `nosniff`
  - `X-Frame-Options`: `DENY`
  - `X-XSS-Protection`: `1; mode=block`
  - `Referrer-Policy`: `strict-origin-when-cross-origin`
  - `Permissions-Policy`: `geolocation=(), microphone=(), camera=()`
  - `Strict-Transport-Security`: `max-age=31536000; includeSubDomains` (production mode)
* **Request Size Limits**: Pre-read inspection of `Content-Length` rejecting oversized requests before consuming memory (`413 Payload Too Large`).
  - Standard API ceiling: 5 MB (`MAX_REQUEST_SIZE_BYTES=5242880`).
  - Batch collector ceiling: 15 MB (`MAX_BATCH_SIZE_BYTES=15728640`).
* **Sliding-Window Rate Limiting**: Per-client-IP throttling returning `429 Too Many Requests` with `Retry-After` header.
  - Login endpoint: 10 req/min (`AUTH_RATE_LIMIT_MAX=10`).
  - General API: 120 req/min (`RATE_LIMIT_MAX_REQUESTS=120`).
  - Telemetry collector: 300 req/min (`COLLECTOR_RATE_LIMIT_MAX=300`).
* **NoSQL Injection Sanitization**: Strips top-level and nested query operators (`$ne`, `$gt`, `$where`) and dot keys before routing.
* **Safe Error Handling**: Masked internal tracebacks returning generic incident codes (`code: INTERNAL_SERVER_ERROR`).
* **Credential Redaction in Audit Logs**: Passwords, tokens, API keys, and JWTs are automatically replaced with `[REDACTED]` prior to persistence.
* **Bounded Pagination**: All query pagination parameters are capped to `MAX_PAGINATION_LIMIT=100`.

### 2.5 Real-Time Channel (SSE) Protection
* Endpoint: `GET /api/stream/events`.
* Requires authentication via `Authorization: Bearer <token>` or `?token=<jwt_token>`.
* Unauthenticated connections are blocked with `401 Unauthorized`.
* Supports event replay via integer-validated `Last-Event-ID` header.

### 2.6 Data Retention & Forensic Evidence Preservation
* Automatic and on-demand data lifecycle management (`POST /api/system/retention/purge`).
* Enforces configurable retention duration (default: 30 days).
* **Evidence Preservation Safeguard**: Records classified as `High-Risk` or associated with unresolved incidents (`New`, `Investigating`) are explicitly protected from automated retention purging to preserve forensic integrity for investigations.

---

## 3. Directory Structure

```
├── .env.example                  # Documented environment configuration template
├── .env                          # Local active environment variables
├── backend/
│   ├── app.py                    # Hardened HTTPServer runner with SecurityManager
│   ├── config/
│   │   └── settings.py           # Validated settings & configurable credentials
│   ├── database/
│   │   ├── connection.py         # MongoDB connection & index establishment
│   │   ├── repository.py         # Data Access Layer with dual-mode storage & audit logs
│   │   └── retention.py          # Data lifecycle & forensic evidence preservation
│   ├── middleware/
│   │   ├── auth.py               # Token signing, verification, and revocation blacklist
│   │   ├── rbac.py               # Role-based access control guards
│   │   ├── security.py           # Rate limiting, security headers, size validation, NoSQL sanitization
│   │   ├── cors.py               # Origin-controlled CORS middleware
│   │   ├── logging_middleware.py # Latency and HTTP request logging (no credentials)
│   │   └── error_handler.py      # Sanitized error response formatter
│   ├── validation/
│   │   └── schemas.py            # Pydantic validation schemas with alias normalization
│   ├── services/
│   │   ├── auth_service.py       # Password verification, JWT generation & session refresh
│   │   ├── ingestion_service.py  # Collector authentication, rate limiting, and deduplication
│   │   ├── device_service.py     # Device inventory & quarantine management
│   │   ├── traffic_service.py    # Flow ingestion, streaming ticks, feature extraction
│   │   ├── detection_service.py  # Dual-detection pipeline coordinator
│   │   ├── ml_service.py         # Machine learning inference & feature extraction
│   │   └── alert_service.py      # Incident triage, notes thread, bulk actions
│   ├── controllers/
│   │   ├── auth_controller.py    # /api/auth/login, /logout, /refresh, /me, /api/audit/logs
│   │   ├── health_controller.py  # /api/health, /api/health/database, /api/system/retention/purge
│   │   ├── device_controller.py  # /api/devices, quarantine, risk configuration
│   │   ├── traffic_controller.py # /api/traffic/events, batch ingestion, attack simulation
│   │   ├── alert_controller.py   # /api/alerts, triage transitions, forensic notes
│   │   └── stream_controller.py  # /api/stream/events (authenticated SSE push channel)
│   ├── routes/
│   │   └── api_router.py         # Route dispatcher across all endpoints
│   └── utils/
│       ├── crypto.py             # PBKDF2 password hashing & NoSQL/log sanitization
│       ├── logger.py             # Structured logger
│       └── response.py           # Standardized API response envelopes
├── models/                       # Verified Random Forest ML model & metadata
├── static/                       # Cybersecurity forest-green frontend SPA
├── tests/
│   ├── test_backend_modular.py   # Suite 1: Architecture & routes (8 tests)
│   ├── test_detection_api.py     # Suite 2: Detection engine & heuristic rules (16 tests)
│   ├── test_part8_apis.py        # Suite 3: REST API group endpoints (17 tests)
│   ├── test_part9_pipeline.py    # Suite 4: Traffic ingestion & detection pipeline (14 tests)
│   ├── test_part10_ml_pipeline.py# Suite 5: Machine learning inference pipeline (14 tests)
│   └── test_part11_security.py   # Suite 6: Security, Auth, RBAC & retention (17 tests)
└── scripts/
    ├── run_dev.sh                # Development server launcher
    ├── run_prod.sh               # Production server launcher
    └── run_tests.sh              # Automated test runner (86 tests)
```

---

## 4. Configuration & Environment Variables

Copy `.env.example` to initialize your environment:
```bash
cp .env.example .env
```

| Variable | Description | Default | Security Guidance |
| :--- | :--- | :--- | :--- |
| `NODE_ENV` | Environment mode (`development` / `production`) | `development` | Set to `production` in production (enables HSTS) |
| `PORT` | HTTP Server port | `8080` | Bind to non-privileged port |
| `HOST` | Network interface binding | `0.0.0.0` | Bind to `127.0.0.1` behind reverse proxy |
| `CORS_ORIGIN` | Allowed CORS origins | `*` | In production, restrict to dashboard origin domain |
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017/iot_botnet_detection` | Use TLS & authenticated credentials in production |
| `MONGODB_DB_NAME` | Database name | `iot_botnet_detection` | Isolated database instance |
| `JWT_SECRET` | HMAC-SHA256 signature key | *(Random 32+ byte string)* | **Mandatory: change in production** |
| `JWT_ACCESS_EXPIRATION_MINUTES`| Access token lifetime | `60` | Short-lived access token |
| `JWT_REFRESH_EXPIRATION_DAYS` | Refresh token lifetime | `7` | Refresh token lifespan |
| `ADMIN_PASSWORD` | Initial admin account password | `netguard2026` | **Mandatory: override with high-entropy secret** |
| `ANALYST_PASSWORD`| Initial analyst account password| `analyst2026` | **Mandatory: override with high-entropy secret** |
| `AUDITOR_PASSWORD`| Initial auditor account password| `auditor2026` | **Mandatory: override with high-entropy secret** |
| `COLLECTOR_API_KEY` | Secret collector shared key | `netguard-sensor-key-2026` | Distribute securely to collector probes |
| `RATE_LIMIT_ENABLED` | Enable sliding-window rate limiter| `true` | Protects from volumetric brute-force & DoS |
| `DATA_RETENTION_DAYS`| Telemetry record retention duration| `30` | Adjust based on organizational compliance policy |

---

## 5. Startup Commands & Execution

### 5.1 Prerequisites
* Python 3.10+ (Tested on Python 3.14)
* MongoDB (Optional: automatic resilient embedded storage operates if MongoDB is offline)

### 5.2 Development Startup
```bash
./scripts/run_dev.sh
# or
python3 backend/app.py 8080
```
Open **`http://localhost:8080`** in any web browser.

### 5.3 Production Startup
```bash
./scripts/run_prod.sh
```

### 5.4 Running Automated Verification Tests
```bash
./scripts/run_tests.sh
```
Executes all 6 test suites covering 86 automated test assertions:
* `[1/6]` Modular Backend Architecture Unit Tests (8/8 OK)
* `[2/6]` Detection Engine & Endpoints Unit Tests (16/16 OK)
* `[3/6]` Part 8 Functional REST API Test Suite (17/17 OK)
* `[4/6]` Part 9 Traffic Ingestion & Detection Pipeline Test Suite (14/14 OK)
* `[5/6]` Part 10 Machine-Learning Pipeline Test Suite (14/14 OK)
* `[6/6]` Part 11 Security & Access Control Test Suite (17/17 OK)
* **Result**: `86/86 Tests OK`

---

## 6. API Security Documentation

### 6.1 Authentication Endpoints
* `POST /api/auth/login` — SecOps login returning access and refresh JWT tokens.
  - Body: `{"username": "admin", "password": "<password>"}`
  - Response: `{"access_token": "...", "refresh_token": "...", "user": {...}}`
* `POST /api/auth/refresh` — Token rotation exchanging refresh token for a fresh access token.
  - Body: `{"refresh_token": "..."}`
* `POST /api/auth/logout` — Revokes active session token in blacklist.
  - Header: `Authorization: Bearer <token>`
* `GET /api/auth/me` — Inspects caller identity, role, and authorized permissions.
  - Header: `Authorization: Bearer <token>`
* `GET /api/audit/logs` — Retrieves SecOps compliance audit log history with credential fields redacted.
  - Parameters: `limit` (max 100), `action`, `user_id`.

### 6.2 Protected Device Management (RBAC)
* `GET /api/devices` — Paginated device inventory (All authenticated roles).
* `POST /api/devices` — Register new IoT asset (Requires `admin` or `analyst`).
* `PATCH /api/devices/:id` — Update device properties (Requires `admin` or `analyst`).
* `POST /api/devices/quarantine` — Isolate/release device (Requires `admin` or `analyst`).
* `DELETE /api/devices/:id` — Permanently delete asset (Requires `admin` only).

### 6.3 Protected Incident Triage (RBAC)
* `GET /api/alerts` — Paginated security alerts (All roles).
* `PATCH /api/alerts/:id/status` — Advance incident lifecycle (Requires `admin` or `analyst`).
* `PATCH /api/alerts/:id/acknowledge` — Acknowledge ticket (Requires `admin` or `analyst`).
* `POST /api/alerts/note` — Append forensic investigation note (Requires `admin` or `analyst`).
* `POST /api/alerts/bulk` — Bulk incident triage operations (Requires `admin` or `analyst`).

### 6.4 Collector Ingestion
* `POST /api/traffic/events` — Single network flow ingestion.
  - Header: `X-Collector-Key: <key>` or `Authorization: Bearer <token>`.
* `POST /api/traffic/events/batch` — NetFlow / IPFIX multi-flow batch ingestion (up to 15 MB).
  - Header: `X-Collector-Key: <key>` or `Authorization: Bearer <token>`.

### 6.5 Real-Time Telemetry Push Channel
* `GET /api/stream/events?token=<jwt_token>` — Server-Sent Events real-time event stream.
  - Requires valid JWT token in query parameter or `Authorization` header.

### 6.6 System & Retention Operations
* `POST /api/system/retention/purge` — Trigger data retention pass (Requires `admin` only).
  - Body: `{"retention_days": 30, "preserve_evidence": true}`.

---

## 7. Security Limitations & Deployment Guidance

### 7.1 Security Limitations
* **TLS Termination**: The embedded HTTP server does not terminate TLS natively. In production environments, place the backend behind a hardened reverse proxy (e.g. NGINX, Caddy, or Cloudflare) configured with TLS 1.3 certificates.
* **Token Blacklist Memory**: Revoked tokens are tracked in thread-safe process memory. For distributed multi-node deployments across clusters, back the revocation blacklist with a shared distributed cache (e.g. Redis).
* **Network Isolation**: The application should be deployed on an isolated management subnet with firewall access restricted to authenticated sensor gateways and SecOps workstations.

### 7.2 Deployment Recommendations
1. **Secrets Management**: Store `JWT_SECRET`, database connection URIs, and user passwords in a hardware security module (HSM) or cloud secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault, or Google Cloud Secret Manager).
2. **Reverse Proxy Configuration**:
   ```nginx
   server {
       listen 443 ssl http2;
       server_name netguard.internal;

       ssl_certificate /etc/ssl/certs/netguard.crt;
       ssl_certificate_key /etc/ssl/private/netguard.key;

       location /api/stream/events {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Connection '';
           proxy_http_version 1.1;
           chunked_transfer_encoding off;
           proxy_buffering off;
           proxy_cache off;
       }

       location / {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```
3. **Database Security**: When connecting to MongoDB in production:
   - Enforce TLS encryption in transit (`ssl=true`).
   - Use role-scoped database users (SCRAM-SHA-256 authentication).
   - Enable network binding only to private VPC subnets.
