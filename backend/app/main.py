"""API FastAPI do OT-Shield AI (stateless: nenhum PCAP é retido após a análise)."""

from __future__ import annotations

import logging
import os
import tempfile
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from app.config import SAMPLE_PCAP_PATH, get_settings
from app.models.schemas import AuditResponse, ErrorResponse, HealthResponse, NetworkAuditSummary
from app.security import API_CSP, HSTS, SECURITY_HEADERS, SlidingWindowRateLimiter, client_ip
from app.services.ai_auditor import AuditResult, generate_audit_report
from app.services.pcap_analyzer import PcapAnalysisError, analyze_pcap

APP_VERSION = "1.0.0"
ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".pcap", ".pcapng", ".cap"})
PCAP_MAGIC_NUMBERS: tuple[bytes, ...] = (
    b"\xd4\xc3\xb2\xa1",  # pcap little-endian (µs)
    b"\xa1\xb2\xc3\xd4",  # pcap big-endian (µs)
    b"\x4d\x3c\xb2\xa1",  # pcap little-endian (ns)
    b"\xa1\xb2\x3c\x4d",  # pcap big-endian (ns)
    b"\x0a\x0d\x0d\x0a",  # pcapng Section Header Block
)
UPLOAD_CHUNK_BYTES = 1024 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("otshield.api")

settings = get_settings()
audit_limiter = SlidingWindowRateLimiter(settings.rate_limit_audit_per_minute)

app = FastAPI(
    title="OT-Shield AI",
    version=APP_VERSION,
    description=(
        "Auditoria passiva de tráfego industrial (Modbus TCP, OPC UA, Modelo Purdue) com laudo ISA/IEC 62443-3-3. "
        "Arquitetura stateless: arquivos PCAP são apagados imediatamente após a extração de metadados."
    ),
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
)


@app.middleware("http")
async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    if not request.url.path.startswith("/docs"):
        response.headers.setdefault("Content-Security-Policy", API_CSP)
    if settings.is_production:
        response.headers.setdefault("Strict-Transport-Security", HSTS)
    return response


def audit_rate_limit(request: Request) -> None:
    key = client_ip(request, settings.trust_proxy_headers, settings.trusted_proxy_hops)
    if not audit_limiter.allow(f"audit:{key}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Muitas requisições. Aguarde um minuto.")


def _build_response(
    summary: NetworkAuditSummary,
    result: AuditResult,
    source: Literal["upload", "demo"],
    file_name: str,
    started: float,
) -> AuditResponse:
    return AuditResponse(
        audit_id=str(uuid.uuid4()),
        generated_at=datetime.now(timezone.utc),
        source=source,
        file_name=file_name,
        ai_provider=result.provider,
        processing_time_ms=int((time.perf_counter() - started) * 1000),
        llm_payload_bytes=result.llm_payload_bytes,
        report=result.report,
        network_summary=summary,
    )


def _secure_remove(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except OSError:
        logger.exception("Falha ao remover arquivo temporário de captura.")


@app.get("/api/v1/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=APP_VERSION,
        ai_provider=settings.resolved_llm_provider,
        sample_pcap_available=SAMPLE_PCAP_PATH.is_file(),
        max_upload_mb=settings.max_upload_mb,
    )


@app.post(
    "/api/v1/audit/upload",
    response_model=AuditResponse,
    responses={
        400: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    tags=["audit"],
    dependencies=[Depends(audit_rate_limit)],
)
async def audit_upload(file: UploadFile = File(..., description="Captura .pcap ou .pcapng")) -> AuditResponse:
    original_name = Path(file.filename or "captura.pcap").name[:200]
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Formato inválido: envie um arquivo .pcap ou .pcapng.")

    max_mb = settings.max_upload_mb
    max_bytes = max_mb * 1024 * 1024
    fd, temp_path = tempfile.mkstemp(prefix="otshield_", suffix=extension)
    started = time.perf_counter()
    written = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            while chunk := await file.read(UPLOAD_CHUNK_BYTES):
                written += len(chunk)
                if written > max_bytes:
                    raise HTTPException(
                        status.HTTP_413_CONTENT_TOO_LARGE, f"Arquivo excede o limite de {max_mb} MB."
                    )
                handle.write(chunk)
        if written == 0:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Arquivo vazio.")
        with open(temp_path, "rb") as handle:
            if handle.read(4) not in PCAP_MAGIC_NUMBERS:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "O arquivo não possui assinatura PCAP/PCAPNG válida.")
        summary = await run_in_threadpool(analyze_pcap, temp_path)
    except PcapAnalysisError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    finally:
        await file.close()
        _secure_remove(temp_path)

    result = await run_in_threadpool(generate_audit_report, summary)
    return _build_response(summary, result, "upload", original_name, started)


@app.post(
    "/api/v1/audit/demo",
    response_model=AuditResponse,
    responses={429: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    tags=["audit"],
    dependencies=[Depends(audit_rate_limit)],
)
async def audit_demo() -> AuditResponse:
    if not SAMPLE_PCAP_PATH.is_file():
        from app.utils.generate_sample_pcap import generate_sample_pcap

        try:
            await run_in_threadpool(generate_sample_pcap, SAMPLE_PCAP_PATH)
        except OSError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Captura de demonstração indisponível.") from exc
    started = time.perf_counter()
    summary = await run_in_threadpool(analyze_pcap, SAMPLE_PCAP_PATH)
    result = await run_in_threadpool(generate_audit_report, summary)
    return _build_response(summary, result, "demo", SAMPLE_PCAP_PATH.name, started)
