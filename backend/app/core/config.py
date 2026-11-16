from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", protected_namespaces=())

    app_name: str = "PhishGuard"
    database_url: str = "postgresql+psycopg://phishguard:phishguard@localhost:5432/phishguard"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = "dev-only-secret"
    jwt_access_minutes: int = 30
    jwt_refresh_days: int = 7
    credential_key: str = ""

    admin_username: str = "admin"
    admin_password: str = ""

    model_dir: str = "/models"
    raw_mail_dir: str = "/data/rawmail"

    sync_interval_seconds: int = 60
    raw_retention_days: int = 30
    observe_mode_default: bool = True

    enable_docs: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
