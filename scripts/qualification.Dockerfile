FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /qualification-source

COPY backend/requirements.hashes.lock /tmp/requirements.hashes.lock
RUN python -m pip install --require-hashes -r /tmp/requirements.hashes.lock

COPY backend /qualification-source/backend
COPY frontend /qualification-source/frontend
COPY procedures /qualification-source/procedures
COPY proxy /qualification-source/proxy
COPY scripts /qualification-source/scripts
COPY security /qualification-source/security
COPY .dockerignore compose.yaml pyproject.toml /qualification-source/

RUN addgroup --system spell && adduser --system --ingroup spell spell \
    && mkdir -p /qualification-output \
    && chown -R spell:spell /qualification-source /qualification-output

ENV SPELL_QUALIFICATION_SOURCE_ROOT=/qualification-source \
    DATABASE_URL=sqlite:////tmp/spell-qualification-import.db
USER spell
