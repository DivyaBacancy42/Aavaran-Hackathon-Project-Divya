from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "SHODH"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True
    SECRET_KEY: str = "change-this-to-a-random-string"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/shodh"

    # Optional API Keys
    SHODAN_API_KEY: Optional[str] = None
    SECURITYTRAILS_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    HIBP_API_KEY: Optional[str] = None
    HUNTER_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
