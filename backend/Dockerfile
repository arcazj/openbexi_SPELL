FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY backend/requirements.hashes.lock /tmp/requirements.hashes.lock
RUN python -m pip install --require-hashes -r /tmp/requirements.hashes.lock

COPY backend /app/backend
COPY procedures /app/procedures
COPY scripts/issue_dev_token.py scripts/qualify_v03.py \
    scripts/qualify_browser_stream_server.py scripts/compose_qualification.py \
    scripts/source_fingerprint.py /app/scripts/

RUN addgroup --system spell && adduser --system --ingroup spell spell \
    && chown -R spell:spell /app

USER spell

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
