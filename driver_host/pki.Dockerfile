FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

ARG SPELL_PACKAGE_VERSION=0.4.0
LABEL org.openbexi.spell.scope="candidate-a-local-synthetic-simulator" \
      org.openbexi.spell.component="pki-init" \
      org.openbexi.spell.package.version="${SPELL_PACKAGE_VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY driver_host/pki-requirements.hashes.lock /tmp/pki-requirements.hashes.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/pki-requirements.hashes.lock \
    && rm -f /tmp/pki-requirements.hashes.lock \
    && apt-get purge -y --allow-remove-essential perl-base

COPY spell /app/spell
COPY driver_host /app/driver_host

ENTRYPOINT ["python", "-m", "driver_host.pki"]
CMD ["--client-dir", "/run/spell-driver-client-source", "--server-dir", "/run/spell-driver-server", "--client-uid", "0", "--client-gid", "0", "--server-uid", "10002", "--server-gid", "10002"]
