FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /qualification-source

COPY backend/requirements.hashes.lock /tmp/requirements.hashes.lock
COPY driver_host/pki-requirements.hashes.lock /tmp/pki-requirements.hashes.lock
COPY contracts/generator-requirements.hashes.lock /tmp/generator-requirements.hashes.lock
RUN python -m pip install --require-hashes \
        -r /tmp/requirements.hashes.lock \
        -r /tmp/pki-requirements.hashes.lock \
        -r /tmp/generator-requirements.hashes.lock \
    && rm -f /tmp/requirements.hashes.lock /tmp/pki-requirements.hashes.lock \
        /tmp/generator-requirements.hashes.lock

COPY backend /qualification-source/backend
COPY contracts /qualification-source/contracts
COPY driver_host /qualification-source/driver_host
COPY spell /qualification-source/spell
COPY frontend /qualification-source/frontend
COPY procedures /qualification-source/procedures
COPY proxy /qualification-source/proxy
COPY scripts /qualification-source/scripts
COPY security /qualification-source/security
COPY .dockerignore .env.example .gitattributes .gitignore compose.yaml pyproject.toml \
    README.md PROMPT_History.md PROJECT_ROADMAP.md SPELL_v0.4_Release.md \
    VERSION_TIMELINE.md LICENSE NOTICE PROMPT_Instructions.md \
    SPELL_v0.4_Pre-Implementation.md Test_and_Integration.md PROVENANCE.md \
    SPELL_DOCUMENTATION_REVIEW.md \
    /qualification-source/
COPY NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI \
    /qualification-source/NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI
COPY SPELL-DOCUMENTATION /qualification-source/SPELL-DOCUMENTATION

RUN addgroup --system spell && adduser --system --ingroup spell spell \
    && mkdir -p /qualification-output \
    && chown -R spell:spell /qualification-source /qualification-output

ENV SPELL_QUALIFICATION_SOURCE_ROOT=/qualification-source \
    DATABASE_URL=sqlite:////tmp/spell-qualification-import.db
USER spell
