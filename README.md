# Fraud Email Signup Verification

A robust, production-ready microservice designed to detect and prevent fraudulent email signups in real-time. This service analyzes email addresses using multiple risk signals including syntax validation, domain reputation, MX record verification, entropy analysis, and velocity checks.

## 🚀 Features

*   **Real-time Risk Analysis**: Instant scoring of email signups.
*   **Risk Scoring & Classification**: Provides a score (0-100) and actionable levels (LOW, MEDIUM, HIGH) with recommended actions (ALLOW, CHALLENGE, BLOCK).
*   **Comprehensive Checks**:
    *   **Syntax Validation**: Ensures email adheres to standard formats.
    *   **Disposable Domain Detection**: Checks against a known list of disposable/temporary email providers (backed by Redis).
    *   **MX Record Verification**: Validates that the domain has valid Mail Exchange records and can receive email.
    *   **Entropy Analysis**: Detects randomly generated email addresses (e.g., `a8f93kd@...`) using Shannon entropy.
    *   **Velocity Limiting**: Tracks signup attempts by IP and Domain to prevent automated abuse and spam attacks.
    *   **Alias Detection**: Identifies email aliases (e.g., `user+test@gmail.com`).
*   **Signal Normalization**: Returns a normalized version of the email for consistent storage (handling aliases and case insensitivity).
*   **High Performance**: Built with FastAPI and Redis for low-latency responses.

## 🛠️ Tech Stack

*   **Language**: Python 3.11+
*   **Framework**: FastAPI
*   **Database**: Redis (for caching, blacklists, and rate limiting)
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
    Use Docker Compose to build and start the API and Redis services.
    ```bash
    docker-compose up --build
    ```

    The API will be available at `http://localhost:8000`.

## 📖 API Documentation

### Analyze Email Risk

**Endpoint**: `POST /api/v1/analyze`

Analyzes an email address and returns a risk profile.

**Request Body**:

```json
{
  "email": "test.user+spam@disposable.com",
  "ip_address": "192.168.1.5",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)..."
}
```

**Response**:

```json
{
  "email": "test.user+spam@disposable.com",
  "normalized_email": "test.user@disposable.com",
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
    "is_alias": true
  }
}
```

**Risk Levels**:

| Score | Level | Action | Description |
| :--- | :--- | :--- | :--- |
| 0 - 30 | **LOW** | ALLOW | legitimate user, standard signup. |
| 31 - 70 | **MEDIUM** | CHALLENGE | Suspicious signals detected (e.g., high entropy, unknown domain). Recommend CAPTCHA or email verification. |
| 71+ | **HIGH** | BLOCK | Strong evidence of fraud (e.g., disposable domain, invalid MX, velocity breach). |

## 🧪 Running Tests

To run the test suite, you can execute pytest inside the running container or locally.

**Using Docker:**
```bash
docker-compose exec app pytest
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
