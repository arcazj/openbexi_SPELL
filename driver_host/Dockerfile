FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

ARG SPELL_PACKAGE_VERSION=0.4.0
LABEL org.openbexi.spell.scope="candidate-a-local-synthetic-simulator" \
      org.openbexi.spell.component="spell-driver" \
      org.openbexi.spell.package.version="${SPELL_PACKAGE_VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY driver_host/requirements.hashes.lock /tmp/requirements.hashes.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.hashes.lock \
    && rm -f /tmp/requirements.hashes.lock \
    && apt-get purge -y --allow-remove-essential perl-base \
    && groupadd --gid 10002 spell-driver \
    && useradd --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin spell-driver \
    && mkdir -p /etc/spell-driver \
    && printf '{}\n' > /etc/spell-driver/host.json \
    && chmod 0444 /etc/spell-driver/host.json \
    && mkdir -p /var/lib/spell-driver \
    && chown 10002:10002 /var/lib/spell-driver

COPY spell /app/spell
COPY driver_host /app/driver_host

USER 10002:10002

STOPSIGNAL SIGINT

ENTRYPOINT ["python", "-m", "driver_host.server"]
CMD ["--config", "/etc/spell-driver/host.json", "--journal", "/var/lib/spell-driver/driver.sqlite", "--credential-dir", "/run/spell-driver-server"]
