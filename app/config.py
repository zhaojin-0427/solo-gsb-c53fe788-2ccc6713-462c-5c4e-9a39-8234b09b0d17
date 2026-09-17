from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = (
        "postgresql+psycopg2://artifactlog:artifactlog@localhost:5432/artifactlog"
    )
    # Optional fixed active signing key. When empty, a key is generated on first
    # boot and persisted in the database (see app/crypto.py).
    signing_key_id: str = ""
    signing_private_key: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
