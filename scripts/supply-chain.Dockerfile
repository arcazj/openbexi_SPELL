FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280 AS source

WORKDIR /workspace
COPY . /workspace
RUN python scripts/source_fingerprint.py --root /workspace > /source-fingerprint

FROM source AS python-audit
ARG AUDIT_NONCE
RUN echo "$AUDIT_NONCE" > /audit-nonce \
    && python -m pip install --quiet pip-audit==2.10.0 \
    && pip-audit -r /workspace/backend/requirements.hashes.lock \
    && python /workspace/scripts/audit_starlette_exposure.py \
    && touch /python-audit-passed

FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS frontend-audit

ARG AUDIT_NONCE
WORKDIR /workspace/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN echo "$AUDIT_NONCE" > /audit-nonce \
    && npm audit --package-lock-only --audit-level=low \
    && touch /frontend-audit-passed

FROM source
COPY --from=python-audit /python-audit-passed /
COPY --from=frontend-audit /frontend-audit-passed /
ENTRYPOINT ["cat", "/source-fingerprint"]
