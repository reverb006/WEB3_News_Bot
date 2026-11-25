# ============================================================
# Web3 Security Radar — Docker Container
# Autonomous 24/7 Security Intelligence Daemon
# ============================================================

FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies (curl for healthchecks if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application codebase
COPY app/ app/

# Create persistent state directories
RUN mkdir -p data logs reports pocs

# Create non-root user for security
RUN useradd -m -u 1000 radaruser && \
    chown -R radaruser:radaruser /app

USER radaruser

EXPOSE 8000

# Default command: launch the autonomous 24/7 daemon
CMD ["python", "-m", "app.main", "daemon"]
