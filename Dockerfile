# =============================================================================
# marmot-nids — Multi-stage production Dockerfile
# =============================================================================
# Stage 1: Builder — installs dependencies into a virtual environment
# Stage 2: Runtime — copies only the venv and source code
#
# Security notes:
#   - Non-root user (marmot, UID 1000) runs the application
#   - CAP_NET_RAW is granted at container runtime via docker-compose, not
#     baked into the image
#   - No development tools, compilers, or package managers in the runtime
#     image — reduces attack surface
#   - .dockerignore excludes .env, .git, __pycache__, and node_modules
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS builder

WORKDIR /build

# Install build dependencies (needed for some pip packages)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy dependency specification first for better layer caching
COPY pyproject.toml ./

# Install Python dependencies into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install production dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        fastapi[standard] \
        uvicorn[standard] \
        scapy \
        pydantic \
        python-decouple \
        httpx \
        websockets

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS runtime

# Install runtime-only dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 tini && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1000 marmot && \
    useradd --uid 1000 --gid marmot --shell /bin/bash --create-home marmot

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy application source
WORKDIR /app
COPY core/ ./core/
COPY signatures/ ./signatures/
COPY dashboard/ ./dashboard/
COPY scripts/ ./scripts/

# Set ownership
RUN chown -R marmot:marmot /app

USER marmot

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8000/api/health'); exit(0 if r.status_code == 200 else 1)"

# Use tini as init system for proper signal handling
ENTRYPOINT ["tini", "--"]

# Default command — production Uvicorn with single worker
CMD ["uvicorn", "core.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

EXPOSE 8000
