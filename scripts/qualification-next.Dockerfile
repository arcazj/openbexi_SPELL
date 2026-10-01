FROM docker:29.7.2-cli@sha256:3f4743208d2338c934d7b8bcfbe1bb54c0b2355c510ad5e0f31c0c4a54bd704e AS docker-cli
FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DATABASE_URL=sqlite:////tmp/spell-import.db
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.hashes.lock /tmp/backend.lock
COPY driver_host/pki-requirements.hashes.lock /tmp/pki.lock
COPY contracts/generator-requirements.hashes.lock /tmp/generator.lock
COPY scripts/supply-chain-requirements.hashes.lock /tmp/supply.lock
RUN python -m pip install --require-hashes -r /tmp/backend.lock -r /tmp/pki.lock \
    -r /tmp/generator.lock -r /tmp/supply.lock \
    && rm /tmp/*.lock
WORKDIR /workspace
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/ /usr/local/libexec/docker/cli-plugins/
RUN git config --global --add safe.directory /workspace
ENTRYPOINT ["python"]
