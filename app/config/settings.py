"""
Settings module — loads configuration from environment variables.

How it works:
- pydantic-settings reads from .env file automatically
- All secrets come from environment variables, never hardcoded
- Settings is a singleton: import and use `get_settings()` everywhere

To configure: copy .env.example to .env and fill in your values.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


# Project root = two levels up from this file (app/config/settings.py → project root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables / .env file.

    Each field maps to an environment variable with the same name (case-insensitive).
    For example, `gemini_api_key` reads from GEMINI_API_KEY in .env.
    """

    # Tell pydantic-settings to read from .env file in the project root
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # Ignore unknown env vars without crashing
    )

    # --- Gemini AI ---
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.5-flash"

    # --- Telegram ---
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    alert_max_age_hours: int = 400

    # --- De.Fi REKT API ---
    defi_rekt_api_key: str = ""

    # --- Database ---
    database_path: str = "data/radar.db"

    # --- Scheduler ---
    rss_collection_interval_minutes: int = 15
    daily_digest_time: str = "10:00"
    scheduler_timezone: str = "UTC"

    # --- Web Dashboard ---
    web_host: str = "127.0.0.1"
    web_port: int = 8000

    # --- Logging ---
    log_level: str = "INFO"
    log_file: str = "logs/radar.log"

    # === Computed properties ===

    @property
    def database_full_path(self) -> Path:
        """Absolute path to the SQLite database file."""
        db_path = Path(self.database_path)
        if db_path.is_absolute():
            return db_path
        return PROJECT_ROOT / db_path

    @property
    def log_full_path(self) -> Path:
        """Absolute path to the log file."""
        log_path = Path(self.log_file)
        if log_path.is_absolute():
            return log_path
        return PROJECT_ROOT / log_path

    @property
    def has_gemini(self) -> bool:
        """Check if Gemini API key is configured."""
        return bool(self.gemini_api_key and self.gemini_api_key != "your-gemini-api-key-here")

    @property
    def has_telegram(self) -> bool:
        """Check if Telegram bot is configured."""
        return bool(
            self.telegram_bot_token
            and self.telegram_bot_token != "your-telegram-bot-token-here"
            and self.telegram_chat_id
            and self.telegram_chat_id != "your-chat-id-here"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Get the application settings (singleton).

    The first call loads from .env; subsequent calls return the cached instance.
    This means changes to .env require a restart.
    """
    return Settings()
