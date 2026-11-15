"""Fixtures compartilhadas: Modo Mock (sem custo de API) e PCAP sintético."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

os.environ.update(
    {
        "ENV": "development",
        "LLM_PROVIDER": "mock",
        "ANTHROPIC_API_KEY": "",
        "OPENAI_API_KEY": "",
        "RATE_LIMIT_AUDIT_PER_MINUTE": "1000",
        "TRUST_PROXY_HEADERS": "false",
    }
)

from app.config import SAMPLE_PCAP_PATH, get_settings  # noqa: E402
from app.models.schemas import NetworkAuditSummary  # noqa: E402
from app.services.pcap_analyzer import analyze_pcap  # noqa: E402
from app.utils.generate_sample_pcap import generate_sample_pcap  # noqa: E402

get_settings.cache_clear()


@pytest.fixture(scope="session")
def sample_pcap() -> Iterator[Path]:
    yield generate_sample_pcap(SAMPLE_PCAP_PATH)


@pytest.fixture(scope="session")
def summary(sample_pcap: Path) -> NetworkAuditSummary:
    return analyze_pcap(sample_pcap)
