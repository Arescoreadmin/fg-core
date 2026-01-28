# Admin Gateway Dockerfile
# Multi-stage build for minimal image size

FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY admin_gateway/requirements.txt ./admin_gateway/
COPY contracts/ ./contracts/

# Install dependencies
RUN pip install --no-cache-dir --prefix=/install -r admin_gateway/requirements.txt

# Production stage
FROM python:3.12-slim

WORKDIR /app

# Create non-root user
RUN addgroup --system app && adduser --system --ingroup app app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=app:app admin_gateway/ ./admin_gateway/
COPY contracts/ ./contracts/

# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"

EXPOSE 8080

USER app

CMD ["python", "-m", "uvicorn", "admin_gateway.main:app", "--host", "0.0.0.0", "--port", "8080"]
