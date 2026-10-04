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
COPY dss /app/dss
COPY contracts/dss /app/contracts/dss

USER 10002:10002

STOPSIGNAL SIGINT

ENTRYPOINT ["python", "-m", "driver_host.server"]
CMD ["--config", "/etc/spell-driver/host.json", "--journal", "/var/lib/spell-driver/driver.sqlite", "--credential-dir", "/run/spell-driver-server"]
