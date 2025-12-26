from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Fraud Email Signup Verification"
    API_V1_STR: str = "/api/v1"
    
    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    
    # Risk Thresholds
    RISK_SCORE_THRESHOLD: int = 70  # Above this is HIGH risk
    
    # External Data Sources
    DISPOSABLE_EMAILS_URL: str = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
    
    # Webhooks (comma-separated URLs)
    WEBHOOK_URLS: str = ""
    
    # SMTP Verification
    ENABLE_SMTP_VERIFICATION: bool = False  # Disabled by default (can be slow/unreliable)
    
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
