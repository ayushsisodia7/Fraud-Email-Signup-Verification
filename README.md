# Fraud Email Signup Verification

A robust microservice designed to detect and prevent fraudulent email signups in real-time. It analyzes email addresses using multiple risk signals (syntax validation, domain reputation, MX verification, entropy, velocity, IP intelligence, domain age, patterns) and returns an actionable decision.

## 🚀 Features

*   **Real-time Risk Analysis**: Instant scoring of email signups.
*   **Risk Scoring & Classification**: Provides a score (0-100) and actionable levels (LOW, MEDIUM, HIGH) with recommended actions (ALLOW, CHALLENGE, BLOCK).
*   **Explainability**: Returns a `reasons` array showing which signals contributed to the score.
*   **Comprehensive Checks**:
    *   **Syntax Validation**: Ensures email adheres to standard formats.
    *   **Disposable Domain Detection**: Checks against a known list of disposable/temporary email providers (backed by Redis).
    *   **MX Record Verification**: Validates that the domain has valid Mail Exchange records and can receive email.
    *   **Entropy Analysis**: Detects randomly generated email addresses (e.g., `a8f93kd@...`) using Shannon entropy.
    *   **Velocity Limiting**: Tracks signup attempts by IP and Domain to prevent automated abuse and spam attacks.
    *   **Alias Detection**: Identifies email aliases (e.g., `user+test@gmail.com`).
    *   **VPN/Proxy Detection**: Identifies users connecting through VPNs, proxies, or datacenter IPs.
    *   **Domain Age Verification**: Flags newly registered domains (<30 days) using WHOIS lookup.
    *   **Pattern Detection**: Detects sequential patterns, number suffixes, and similar emails using Levenshtein distance.
    *   **Email Deliverability (SMTP)**: Optionally verifies if mailbox actually exists via SMTP protocol.
    *   **Webhook Notifications**: Real-time alerts for high-risk signups.
    *   **Admin Dashboard**: Beautiful web UI for monitoring fraud statistics and IP activity.
*   **Background Enrichment (Queue + Worker)**: Use `POST /api/v1/analyze/fast` for low-latency decisions and enrich results asynchronously via a Redis-backed worker.
*   **Signal Normalization**: Returns a normalized version of the email for consistent storage (handling aliases and case insensitivity).
*   **High Performance**: Built with FastAPI and Redis for low-latency responses.
*   **Observability**:
    *   **Request IDs**: Accepts `X-Request-ID` and returns it in responses.
    *   **Prometheus Metrics**: Exposes `/metrics` with request + signal + cache + enrichment metrics.
*   **Admin Security**: Admin endpoints require `X-Admin-API-Key` when configured (and can fail-closed in non-dev).

## 🛠️ Tech Stack

*   **Language**: Python 3.11+
*   **Framework**: FastAPI
*   **Database**: Redis (for caching, blacklists, rate limiting, and background jobs)
*   **Containerization**: Docker & Docker Compose
*   **Testing**: Pytest

## ⚡ Getting Started

### Prerequisites

*   Docker and Docker Compose installed on your machine.

### Installation & Running

1.  **Clone the repository**
    ```bash
    git clone https://github.com/ayushsisodia7/Fraud-Email-Signup-Verification.git
    cd Fraud-Email-Signup-Verification
    ```

2.  **Start the service**
    Use Docker Compose to build and start the API, Redis, and the background worker.
    ```bash
    docker-compose up --build
    ```

    The API will be available at `http://localhost:8000`.
    - **API Documentation**: `http://localhost:8000/docs`
    - **Admin Dashboard**: `http://localhost:8000/dashboard`
    - **Prometheus Metrics**: `http://localhost:8000/metrics`

## 📖 API Documentation

### Analyze Email Risk

**Endpoint**: `POST /api/v1/analyze`

Analyzes an email address and returns a risk profile.

**Request Body**

```json
{
  "email": "test.user+spam@disposable.com",
  "ip_address": "192.168.1.5",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)..."
}
```

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `email` | `string` | Yes | The email address to analyze. |
| `ip_address` | `string` | Yes | The IP address of the user attempting signup. Used for velocity checks. |
| `user_agent` | `string` | Yes | The browser User-Agent string. |


**Response**

```json
{
  "email": "test.user+spam@disposable.com",
  "normalized_email": "test.user@disposable.com",
  "reasons": [
    {
      "code": "DISPOSABLE_DOMAIN",
      "points": 90,
      "message": "Domain disposable.com is a known disposable email provider",
      "meta": { "domain": "disposable.com" }
    }
  ],
  "risk_summary": {
    "score": 90,
    "level": "HIGH",
    "action": "BLOCK"
  },
  "signals": {
    "is_disposable": true,
    "mx_found": true,
    "velocity_breach": false,
    "entropy_score": 3.45,
    "is_alias": true,
    "is_vpn": false,
    "is_proxy": false,
    "is_datacenter": false,
    "ip_country": "United States",
    "domain_age_days": 5,
    "is_new_domain": true,
    "pattern_detected": "NUMBER_SUFFIX",
    "is_sequential": false,
    "has_number_suffix": false,
    "is_similar_to_recent": false
  }
}
```

### Fast Analyze + Background Enrichment

Use this endpoint when you want a **very fast response** and are OK enriching slow signals asynchronously.

- **Endpoint**: `POST /api/v1/analyze/fast`
- **Response** includes:
  - `enrichment.status`: `DISABLED` or `PENDING` (later becomes `COMPLETE` in the stored result)
  - `enrichment.job_id`: non-null when background enrichment is enabled

Poll results:

- **Endpoint**: `GET /api/v1/results/{job_id}`

### Request IDs

- Send: `X-Request-ID: <your-id>`
- API returns: `X-Request-ID` response header on every request

### Prometheus Metrics

- **Endpoint**: `GET /metrics`
- Includes:
  - Request counters/latency
  - Per-signal latency (MX / WHOIS / IP intel)
  - Decision counts
  - Cache hit/miss/error counts
  - Enrichment job lifecycle counters

### 📚 Response Field Reference

Detailed explanation of all response parameters to help developers integrate the API logic.

#### Root Objects

| Field | Type | Description |
| :--- | :--- | :--- |
| `email` | `string` | The original email address provided in the request. |
| `normalized_email` | `string` | The canonical version of the email. It is lowercased, and any alias (part after `+`) is removed (e.g., `user+tag@gmail.com` -> `user@gmail.com`). Use this for checking duplicate accounts. |
| `risk_summary` | `object` | Contains the aggregated risk assessment. |
| `signals` | `object` | Detailed flags for each check performed. |
| `reasons` | `array` | Explainability: list of `{code, points, message, meta?}` contributions. |

#### `risk_summary` Object

This object dictates the final decision the client should take.

| Field | Type | Possible Values | Description |
| :--- | :--- | :--- | :--- |
| `score` | `integer` | `0` to `100` | The calculated risk score. Higher means riskier. <br>• **0-30**: Safe <br>• **31-70**: Suspicious <br>• **71-100**: Fraudulent |
| `level` | `string` | `"LOW"`, `"MEDIUM"`, `"HIGH"` | A human-readable classification of the score. |
| `action` | `string` | `"ALLOW"`, `"CHALLENGE"`, `"BLOCK"` | The recommended action for the client application. <br>• **ALLOW**: Proceed with signup. <br>• **CHALLENGE**: Trigger additional verification (Phone OTP, Captcha). <br>• **BLOCK**: Reject the signup request immediately. |

#### `signals` Object

Granular details on *why* a certain score was assigned.

| Field | Type | Possible Values | Description |
| :--- | :--- | :--- | :--- |
| `is_disposable` | `boolean` | `true`, `false` | **True** if the domain belongs to a known temporary/disposable email provider (e.g., mailinator.com). This is a strong fraud signal. |
| `mx_found` | `boolean` | `true`, `false` | **True** if the domain has valid DNS MX records. **False** implies the domain cannot receive email (likely invalid or fake). |
| `velocity_breach`| `boolean` | `true`, `false` | **True** if the request IP or Domain has exceeded the allowed signup rate (e.g., >10 signups per hour). |
| `entropy_score` | `float` | `0.0` - `8.0`+ | A measure of randomness in the local part of the email. <br>• **< 3.5**: Normal (e.g., `john.doe`) <br>• **> 4.5**: High/Random (e.g., `a82j19s`) |
| `is_alias` | `boolean` | `true`, `false` | **True** if the email uses a `+` alias. While often legitimate, multiple aliases pointing to the same inbox can indicate account farming. |
| `is_vpn` | `boolean` | `true`, `false` | **True** if the IP address appears to be a VPN service. |
| `is_proxy` | `boolean` | `true`, `false` | **True** if the IP address appears to be a proxy server. |
| `is_datacenter` | `boolean` | `true`, `false` | **True** if the IP originates from a datacenter/cloud provider rather than a residential ISP. |
| `ip_country` | `string` | Country name or `null` | Geographic country of the IP address. |
| `domain_age_days` | `integer` | Number or `null` | Age of the email domain in days since registration. |
| `is_new_domain` | `boolean` | `true`, `false` | **True** if the domain was registered less than 30 days ago. |
| `pattern_detected` | `string` | `"SEQUENTIAL"`, `"NUMBER_SUFFIX"`, `"SIMILAR_TO_RECENT"`, `null` | Type of suspicious pattern detected in the email. |
| `is_sequential` | `boolean` | `true`, `false` | **True** if email follows sequential pattern (e.g., `user1@domain.com`, `user2@domain.com`). |
| `has_number_suffix` | `boolean` | `true`, `false` | **True** if email has 2+ numbers at the end (e.g., `john123@domain.com`). |
| `is_similar_to_recent` | `boolean` | `true`, `false` | **True** if email is very similar (85%+ match) to a recently submitted email. |
| `smtp_deliverable` | `boolean` | `true`, `false`, `null` | **True** if SMTP verification confirms the mailbox exists. `null` if disabled. |
| `smtp_valid` | `boolean` | `true`, `false`, `null` | **True** if SMTP handshake succeeded. |
| `catch_all_domain` | `boolean` | `true`, `false`, `null` | **True** if the domain accepts all email addresses (catch-all). |

## ⚙️ Configuration

You can configure the service using environment variables. Create a `.env` file in the project root:

```env
# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379

# Environment
# dev: allows insecure conveniences (like leaving admin key empty)
# prod/staging: fail-closed when secrets are missing
ENVIRONMENT=dev

# Admin API Key (recommended)
ADMIN_API_KEY=secret

# Webhook URLs (comma-separated)
WEBHOOK_URLS=https://your-webhook-url.com/alerts,https://backup-webhook.com/notify

# Webhook TLS verification (keep true in prod; can set false in dev if your container lacks a trusted CA chain)
WEBHOOK_VERIFY_SSL=true

# SMTP Email Verification (Warning: Can be slow and unreliable)
ENABLE_SMTP_VERIFICATION=false

# Background enrichment (fast path + worker)
ENABLE_BACKGROUND_ENRICHMENT=true

# IP intelligence provider behavior
IP_INTEL_VERIFY_SSL=true
IP_INTEL_FALLBACK_PROVIDERS=ipwhois,ipapi_http

# Scoring knobs (optional)
RISK_LOW_MAX=30
RISK_MEDIUM_MAX=70
SCORE_DISPOSABLE_DOMAIN=90
SCORE_NO_MX=100
ENTROPY_THRESHOLD=4.5
SCORE_HIGH_ENTROPY=30
VELOCITY_IP_LIMIT_PER_HOUR=10
SCORE_VELOCITY_BREACH=40
SCORE_VPN_OR_PROXY=50
SCORE_DATACENTER_IP=30
NEW_DOMAIN_AGE_DAYS=30
SCORE_NEW_DOMAIN=60
SCORE_PATTERN_SEQUENTIAL=40
SCORE_PATTERN_NUMBER_SUFFIX=25
SCORE_PATTERN_SIMILAR_TO_RECENT=35
SCORE_SMTP_UNDELIVERABLE=70
SCORE_SMTP_CATCH_ALL=20
```

### Webhooks

Configure webhook URLs to receive real-time notifications when high-risk signups are detected:

**Webhook Payload Format:**
```json
{
  "event": "high_risk_signup",
  "timestamp": "2025-12-26T15:30:00Z",
  "data": {
    "email": "suspicious@example.com",
    "normalized_email": "suspicious@example.com",
    "ip_address": "8.8.8.8",
    "user_agent": "Mozilla/5.0...",
    "risk_summary": {
      "score": 85,
      "level": "HIGH",
      "action": "BLOCK"
    },
    "signals": { /* all fraud signals */ },
    "reasons": [ /* explainability contributions */ ]
  }
}
```

## 📊 Admin Dashboard

Access the admin dashboard at `http://localhost:8000/dashboard` to:

*   View real-time fraud statistics
*   Monitor most active IP addresses
*   Track recent email signups
*   Identify velocity abuse patterns

The dashboard auto-refreshes every 30 seconds.

**Dashboard Features:**
- 📈 Live statistics (unique IPs, domains, recent signups)
- 🌐 IP activity monitoring with risk levels
- 📧 Recent email tracking
-  Auto-refresh capabilities


## 🧪 Running Tests

To run the test suite, you can execute pytest inside the running container or locally.

**Using Docker:**
```bash
docker-compose exec api pytest
```

**Locally:**
1.  Install dependencies: `pip install -r requirements.txt`
2.  Ensure Redis is running locally.
3.  Run: `pytest`

## 📂 Project Structure

```
.
├── app
│   ├── api                 # API route handlers
│   ├── core                # specific configuration (config, logging)
│   ├── data                # Static data (disposable domains list)
│   ├── services            # Business logic (Risk Engine, Validators)
│   └── main.py             # Application entry point
├── tests                   # Unit and integration tests
├── Dockerfile              # Docker image definition
├── docker-compose.yaml     # Service orchestration
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

## 🛡️ License

This project is licensed under the MIT License.
