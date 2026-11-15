"""Proteções de borda: rate limiting em memória e cabeçalhos HTTP de segurança."""

from __future__ import annotations

import threading
import time
from collections import deque

from fastapi import Request

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    "Cache-Control": "no-store",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
HSTS = "max-age=63072000; includeSubDomains"


class SlidingWindowRateLimiter:
    """Limite de requisições por chave em janela deslizante (por instância do container)."""

    def __init__(self, limit: int, window_seconds: float = 60.0, max_keys: int = 50_000) -> None:
        self._limit = limit
        self._window = window_seconds
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        moment = now if now is not None else time.monotonic()
        with self._lock:
            if len(self._hits) >= self._max_keys and key not in self._hits:
                cutoff = moment - self._window
                for stale in [k for k, q in self._hits.items() if not q or q[-1] < cutoff]:
                    del self._hits[stale]
                if len(self._hits) >= self._max_keys:
                    return False
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= moment - self._window:
                bucket.popleft()
            if len(bucket) >= self._limit:
                return False
            bucket.append(moment)
            return True


def client_ip(request: Request, trust_proxy: bool, trusted_hops: int = 1) -> str:
    """IP real do cliente.

    Atrás de proxies confiáveis (Render, Cloud Run), cada proxy ACRESCENTA o IP de quem o contatou ao final do
    X-Forwarded-For. Entradas à esquerda são fornecidas pelo cliente e podem ser forjadas; por isso o IP confiável
    é o `trusted_hops`-ésimo a partir da DIREITA (1 = último salto, adicionado pela borda da plataforma).
    """
    if trust_proxy and trusted_hops > 0:
        hosts = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        if len(hosts) >= trusted_hops:
            return hosts[-trusted_hops][:64]
    return request.client.host if request.client else "unknown"
