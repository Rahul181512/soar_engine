import os
class Settings:
    """
    Central configuration class for the SOAR Engine.
    Reads values from environment variables with sensible defaults.
    """
    # Logging Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv("LOG_FILE", "soar_engine.log")

    # Threat Intelligence APIs (for future use)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

    # Application Configuration
    APP_NAME: str = os.getenv("APP_NAME", "SOAR Incident Containment Engine")
    APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")

    # ✅ Server Configuration
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8000))
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"

    # Risk Engine Thresholds
    LOW_RISK_THRESHOLD: int = int(os.getenv("LOW_RISK_THRESHOLD", 30))
    MEDIUM_RISK_THRESHOLD: int = int(os.getenv("MEDIUM_RISK_THRESHOLD", 60))
    HIGH_RISK_THRESHOLD: int = int(os.getenv("HIGH_RISK_THRESHOLD", 80))

# Global settings instance
settings = Settings()