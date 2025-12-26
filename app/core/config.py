from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Fraud Email Signup Verification"
    API_V1_STR: str = "/api/v1"

    # Runtime environment
    # - dev: allows some insecure conveniences (e.g., optional admin auth)
    # - staging/prod: fail-closed on missing secrets
    ENVIRONMENT: str = "dev"
    
    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    
    # Risk Thresholds
    # Score-to-action thresholds (inclusive bounds; final score is capped at 100)
    RISK_LOW_MAX: int = 30
    RISK_MEDIUM_MAX: int = 70

    # Configurable scoring weights / thresholds
    SCORE_DISPOSABLE_DOMAIN: int = 90
    SCORE_NO_MX: int = 100

    ENTROPY_THRESHOLD: float = 4.5
    SCORE_HIGH_ENTROPY: int = 30

    VELOCITY_IP_LIMIT_PER_HOUR: int = 10
    SCORE_VELOCITY_BREACH: int = 40

    SCORE_VPN_OR_PROXY: int = 50
    SCORE_DATACENTER_IP: int = 30

    NEW_DOMAIN_AGE_DAYS: int = 30
    SCORE_NEW_DOMAIN: int = 60

    SCORE_PATTERN_SEQUENTIAL: int = 40
    SCORE_PATTERN_NUMBER_SUFFIX: int = 25
    SCORE_PATTERN_SIMILAR_TO_RECENT: int = 35

    SCORE_SMTP_UNDELIVERABLE: int = 70
    SCORE_SMTP_CATCH_ALL: int = 20
    
    # External Data Sources
    DISPOSABLE_EMAILS_URL: str = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
    
    # Webhooks (comma-separated URLs)
    WEBHOOK_URLS: str = ""

    # Admin auth (optional but strongly recommended)
    # If empty, admin endpoints will be left unprotected (dev-only).
    ADMIN_API_KEY: str = ""

    # Background enrichment (queue-based full analysis)
    ENABLE_BACKGROUND_ENRICHMENT: bool = False
    ENRICHMENT_QUEUE_KEY: str = "queue:enrichment"
    ENRICHMENT_RESULT_PREFIX: str = "enrichment:result:"
    ENRICHMENT_RESULT_TTL_SECONDS: int = 60 * 60  # 1 hour
    
    # SMTP Verification
    ENABLE_SMTP_VERIFICATION: bool = False  # Disabled by default (can be slow/unreliable)

    # Caching (seconds)
    # - WHOIS is slow but fairly static, so cache longer.
    # - IP intelligence changes, but not minute-to-minute, so 1 day is a good default.
    WHOIS_CACHE_TTL_SECONDS: int = 60 * 60 * 24 * 7  # 7 days
    WHOIS_NEGATIVE_CACHE_TTL_SECONDS: int = 60 * 60  # 1 hour
    IP_INTEL_CACHE_TTL_SECONDS: int = 60 * 60 * 24  # 1 day
    IP_INTEL_NEGATIVE_CACHE_TTL_SECONDS: int = 60 * 10  # 10 minutes

    # IP intelligence HTTP behavior
    IP_INTEL_VERIFY_SSL: bool = True
    # Comma-separated fallback providers. Options: ipwhois, ipapi_http
    # - ipwhois uses https://ipwho.is/{ip}
    # - ipapi_http uses http://ip-api.com/json/{ip} (HTTP, no TLS)
    IP_INTEL_FALLBACK_PROVIDERS: str = "ipwhois,ipapi_http"
    
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
