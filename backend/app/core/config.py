"""
ARKA Core Configuration Settings.
Uses Pydantic v2 BaseSettings for type-safe environment configuration.
"""


from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Environment
    ARKA_ENV: str = Field(default="development")
    DEBUG: bool = Field(default=True)
    LOG_LEVEL: str = Field(default="INFO")

    # API Configuration
    PROJECT_NAME: str = "ARKA — Advanced Real-time Kinetic Analytics"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = Field(
        default="arka-dev-secret-key-change-this-in-production-to-a-secure-random-32-byte-string"
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    ALGORITHM: str = "HS256"

    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # PostgreSQL Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "arka_user"
    POSTGRES_PASSWORD: str = "arka_password_change_me"
    POSTGRES_DB: str = "arka_db"
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://arka_user:arka_password_change_me@localhost:5432/arka_db"
    )

    # Apache Kafka Event Bus
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_TOPIC_EVENTS_RAW: str = "arka.events.raw"
    KAFKA_TOPIC_EVENTS_NORMALIZED: str = "arka.events.normalized"
    KAFKA_TOPIC_ALERTS: str = "arka.alerts"
    KAFKA_TOPIC_AUDIT: str = "arka.audit"
    KAFKA_TOPIC_DLQ: str = "arka.events.dlq"
    KAFKA_CONSUMER_GROUP: str = "arka-processor-group"

    # OpenSearch Storage
    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200
    OPENSEARCH_SCHEME: str = "http"
    OPENSEARCH_USER: str = "admin"
    OPENSEARCH_PASSWORD: str = "admin"
    OPENSEARCH_INDEX_PREFIX: str = "arka-events"

    # Redis Cache
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_DB: int = 0

    # Keycloak / OAuth2 OIDC
    KEYCLOAK_SERVER_URL: str = "http://localhost:8080"
    KEYCLOAK_REALM: str = "arka"
    KEYCLOAK_CLIENT_ID: str = "arka-backend"
    KEYCLOAK_CLIENT_SECRET: str = "change-me"


settings = Settings()
