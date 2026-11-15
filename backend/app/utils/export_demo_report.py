"""Exporta o laudo da captura de demonstração para o frontend (`frontend/public/demo-report.json`).

O snapshot é produzido pelo próprio endpoint `/api/v1/audit/demo` (Motor Especialista Local), garantindo que a
demo do site seja idêntica à análise ao vivo mesmo quando o backend gratuito estiver hibernando.

Uso: `cd backend && python -m app.utils.export_demo_report [caminho_de_saída]`
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from app.config import BACKEND_DIR

DEFAULT_OUTPUT: Path = BACKEND_DIR.parent / "frontend" / "public" / "demo-report.json"


def export_demo_report(output: Path = DEFAULT_OUTPUT) -> Path:
    os.environ["LLM_PROVIDER"] = "mock"
    from app.config import get_settings

    get_settings.cache_clear()
    from fastapi.testclient import TestClient

    from app.main import app

    response = TestClient(app).post("/api/v1/audit/demo")
    response.raise_for_status()
    payload = response.json()
    if payload.get("ai_provider") != "mock":
        raise RuntimeError("O snapshot deve ser gerado pelo motor local determinístico.")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return output


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT
    path = export_demo_report(target)
    print(f"Laudo de demonstração exportado: {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
