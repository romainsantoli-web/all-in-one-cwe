FROM python:3.12-slim

LABEL maintainer="e2e-crypto-audit"
LABEL description="E2E Encryption Security Audit Toolkit — 6 modules"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wabt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .

ENTRYPOINT ["python", "cli.py"]
CMD ["--list-modules"]
