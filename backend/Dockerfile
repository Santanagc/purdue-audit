# syntax=docker/dockerfile:1.7
# OT-Shield AI — backend FastAPI (Google Cloud Run / Render.com)

FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN grep -v -E '^(pytest|httpx)' requirements.txt > requirements.prod.txt \
 && pip install --prefix=/install -r requirements.prod.txt

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENV=production \
    PORT=8080
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=builder /install /usr/local
COPY app ./app
COPY tests/sample_ot_capture.pcap ./tests/sample_ot_capture.pcap
RUN mkdir -p /app/data && chown -R 10001:10001 /app/data
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8080') + '/api/v1/health', timeout=4)"]
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --no-proxy-headers --no-server-header --timeout-keep-alive 30"]
