# syntax=docker/dockerfile:1.7
# Multi-stage, non-root, read-only-friendly image for aicos-api / aicos-worker.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY packages packages
COPY services services
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install ".[postgres,redis,knowledge,observability]"

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="aicompany-os" org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/aicompany-os/aicompany-os"
RUN apt-get update && apt-get install -y --no-install-recommends tini git && rm -rf /var/lib/apt/lists/* && \
    groupadd -g 65532 aicos && useradd -u 65532 -g aicos -s /usr/sbin/nologin -M aicos
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root agents agents
COPY --chown=root:root security/policies security/policies
COPY --chown=root:root security/trusted-keys security/trusted-keys
COPY --chown=root:root models models
COPY --chown=root:root services/worker services/worker
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 AICOS_ENV=production
USER 65532:65532
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=3).status==200 else 1)"
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "aicos_api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*", "--no-server-header"]
