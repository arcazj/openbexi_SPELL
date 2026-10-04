FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280 AS zlib-security-build
COPY scripts/build_zlib_v12.sh /tmp/build_zlib_v12.sh
RUN sh /tmp/build_zlib_v12.sh

FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

COPY --from=zlib-security-build /tmp/zlib-fixed.deb /tmp/zlib-fixed.deb
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libc6=2.41-12+deb13u4 libssl3t64=3.5.7-1~deb13u3 \
        libpcre2-8-0=10.46-1~deb13u3 libsqlite3-0=3.46.1-7+deb13u2 \
    && dpkg -i /tmp/zlib-fixed.deb && ldconfig \
    && rm -f /tmp/zlib-fixed.deb && rm -rf /var/lib/apt/lists/*


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
COPY dss /app/dss
COPY contracts/dss /app/contracts/dss
COPY compose.yaml /app/compose.yaml
COPY contracts/v10 /app/contracts/v10
COPY contracts/v11 /app/contracts/v11
COPY contracts/v12 /app/contracts/v12
COPY contracts/v13 /app/contracts/v13
COPY contracts/v14 /app/contracts/v14
COPY contracts/v15 /app/contracts/v15
COPY contracts/v16 /app/contracts/v16
COPY contracts/v17 /app/contracts/v17
COPY contracts/v18 /app/contracts/v18
COPY contracts/v19 /app/contracts/v19
COPY spell /app/spell
COPY procedures /app/procedures
COPY scripts/issue_dev_token.py scripts/qualify_v03.py \
    scripts/qualify_browser_stream_server.py scripts/compose_qualification.py \
    scripts/source_fingerprint.py scripts/seed_observation_v07.py scripts/seed_dss_v19.py \
    scripts/build_zlib_v12.sh /app/scripts/

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
