FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

LABEL org.opencontainers.image.base.name="python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280" \
    io.openbexi.spell.bundle-builder-profile="spell-v11-dual-network-none-builder/1"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY backend/requirements.hashes.lock /tmp/requirements.hashes.lock
RUN python -m pip install --require-hashes -r /tmp/requirements.hashes.lock \
    && apt-get purge -y --allow-remove-essential perl-base \
    && rm -f /tmp/requirements.hashes.lock

COPY backend /app/backend
COPY compose.yaml /app/compose.yaml
COPY contracts/v10 /app/contracts/v10
COPY contracts/v11 /app/contracts/v11
COPY spell /app/spell
COPY procedures /app/procedures
COPY scripts/issue_dev_token.py scripts/qualify_v03.py \
    scripts/qualify_browser_stream_server.py scripts/compose_qualification.py \
    scripts/source_fingerprint.py scripts/seed_observation_v07.py /app/scripts/

RUN groupadd --gid 10001 spell \
    && useradd --uid 10001 --gid spell --no-create-home \
        --shell /usr/sbin/nologin spell \
    && mkdir -p /var/lib/openbexi-spell/data \
        /var/lib/openbexi-spell/migration-backups \
        /var/lib/openbexi-spell/builder/requests \
        /var/lib/openbexi-spell/builder/responses-a \
        /var/lib/openbexi-spell/builder/responses-b \
        /var/lib/openbexi-spell/builder/responses \
    && chown -R spell:spell /var/lib/openbexi-spell \
    && chown -R spell:spell /app

USER 10001:10001

EXPOSE 8000

ENTRYPOINT ["python", "/app/backend/credential_bootstrap.py"]
CMD ["python", "-m", "uvicorn", "backend.app:app", "--host", "spell-api", "--port", "8000"]
