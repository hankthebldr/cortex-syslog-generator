# Cortex Syslog Generator - Production Docker Image
# Multi-stage build for optimized production deployment

# Stage 1: Build environment
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements-prod.txt pyproject.toml ./
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements-prod.txt

# Stage 2: Production runtime
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    PORT=5001

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r cortex \
    && useradd -r -g cortex -d /app -s /bin/bash cortex

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=cortex:cortex . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/tmp && \
    chown -R cortex:cortex /app

# Switch to non-root user
USER cortex

# Expose port
EXPOSE ${PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Default command
CMD ["python", "app.py"]

# Labels for metadata
LABEL maintainer="Palo Alto Networks <cortex-support@paloaltonetworks.com>" \
      description="Enterprise Security Log Generator for Cortex XSIAM" \
      version="2.1.0" \
      vendor="Palo Alto Networks" \
      name="cortex-syslog-generator"