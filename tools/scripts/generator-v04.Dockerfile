FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace
COPY contracts/generator-requirements.hashes.lock /tmp/generator-requirements.hashes.lock
RUN python -m pip install --require-hashes -r /tmp/generator-requirements.hashes.lock \
    && rm -f /tmp/generator-requirements.hashes.lock
COPY . /workspace

RUN groupadd --gid 10004 spell-generator \
    && useradd --uid 10004 --gid 10004 --no-create-home --shell /usr/sbin/nologin spell-generator \
    && chown -R 10004:10004 /workspace

USER 10004:10004
ENTRYPOINT ["python", "scripts/supply_chain_v04.py", "--root", "/workspace", "probe-sc-004"]
