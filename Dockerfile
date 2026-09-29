# Multi-stage build for albert_server
# Build stage
FROM python:3.13-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.13-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libssl3 \
    libffi8 \
    usbmuxd \
    libimobiledevice-utils \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 app && chown -R app:app /app
USER app

# Secure-by-default: bind localhost only; override with -e ALBERT_HOST=0.0.0.0 for LAN
ENV ALBERT_HOST=127.0.0.1

# Create required directories
RUN mkdir -p certs logs static

EXPOSE 18090 18443

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=10s \
    CMD curl -f http://127.0.0.1:18090/health || exit 1

CMD ["gunicorn", "-c", "gunicorn_conf.py", "albert_server:app"]