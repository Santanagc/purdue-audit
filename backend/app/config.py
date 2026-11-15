"""Configuração centralizada via variáveis de ambiente (Pydantic Settings)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR: Path = Path(__file__).resolve().parent.parent
SAMPLE_PCAP_PATH: Path = BACKEND_DIR / "tests" / "sample_ot_capture.pcap"


class Settings(BaseSettings):
    """Variáveis de ambiente do backend Purdue Audit."""

    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["development", "production"] = "development"
    cors_origins: str = "http://localhost:3000"

    llm_provider: Literal["auto", "anthropic", "openai", "mock"] = "auto"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-opus-5-5"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = Field(default=60.0, gt=0)

    max_upload_mb: int = Field(default=10, gt=0)

    # Proteções de borda
    rate_limit_audit_per_minute: int = Field(default=10, gt=0)
    trust_proxy_headers: bool = False
    trusted_proxy_hops: int = Field(default=1, ge=0, le=5)

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def resolved_llm_provider(self) -> Literal["anthropic", "openai", "mock"]:
        """Resolve o provedor efetivo: chaves vazias caem no Modo Mock Inteligente."""
        if self.llm_provider == "anthropic":
            return "anthropic" if self.anthropic_api_key else "mock"
        if self.llm_provider == "openai":
            return "openai" if self.openai_api_key else "mock"
        if self.llm_provider == "mock":
            return "mock"
        if self.anthropic_api_key:
            return "anthropic"
        if self.openai_api_key:
            return "openai"
        return "mock"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
