FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SPELL_QUALIFICATION_RELEASE=v0.8.0

WORKDIR /qualification-source

COPY backend/requirements.hashes.lock /tmp/backend.lock
COPY driver_host/pki-requirements.hashes.lock /tmp/pki.lock
COPY contracts/generator-requirements.hashes.lock /tmp/generator.lock
RUN python -m pip install --require-hashes \
        -r /tmp/backend.lock \
        -r /tmp/pki.lock \
        -r /tmp/generator.lock \
    && rm -f /tmp/backend.lock /tmp/pki.lock /tmp/generator.lock

COPY . /qualification-source

RUN addgroup --system spell \
    && adduser --system --ingroup spell spell \
    && mkdir -p /qualification-output \
    && chown -R spell:spell /qualification-source /qualification-output

ENV SPELL_QUALIFICATION_SOURCE_ROOT=/qualification-source \
    DATABASE_URL=sqlite:////tmp/spell-qualification-import.db
USER spell
