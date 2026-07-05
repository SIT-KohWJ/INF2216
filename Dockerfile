# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# libmagic1 is needed by python-magic for magic-byte MIME checks (B3, B7)
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmagic1 \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Defence in depth: never run the app as root.
# instance/ must exist appuser-owned in the image: compose.prod.yaml mounts a
# named volume there, and docker seeds a fresh volume with the image dir's
# ownership — without this, the mount point is root-owned and the app cannot
# write its audit signing key.
RUN useradd --create-home --uid 10001 appuser \
 && mkdir -p /app/instance \
 && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# nginx terminates TLS and proxies to gunicorn on :5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "wsgi:app"]
