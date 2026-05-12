from pydantic_settings import BaseSettings, SettingsConfigDict

from typing import List

class Settings(BaseSettings):
    # App
    APP_NAME: str = "SSL Certificate Checker API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int

    # CORS
    CORS_ORIGINS: List[str] = ["*"]

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()

CACHE_TTL_HOURS = 24