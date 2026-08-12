FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280 AS source

WORKDIR /workspace
COPY . /workspace
RUN python scripts/source_fingerprint_v04.py --root /workspace > /source-fingerprint \
    && python scripts/supply_chain_v04.py --root /workspace validate-locks > /lock-validation.json \
    && touch /lock-validation-passed

FROM source AS supply-tools
COPY scripts/supply-chain-requirements.hashes.lock /tmp/supply-chain-requirements.hashes.lock
RUN python -m pip install --quiet --require-hashes -r /tmp/supply-chain-requirements.hashes.lock \
    && rm -f /tmp/supply-chain-requirements.hashes.lock \
    && python /workspace/scripts/validate_cyclonedx_v04.py self-test

FROM supply-tools AS python-audit
ARG AUDIT_NONCE
RUN mkdir /audit-results \
    && echo "$AUDIT_NONCE" > /audit-nonce \
    && pip-audit --require-hashes -r /workspace/backend/requirements.hashes.lock \
        --format json --output /audit-results/pip-audit-backend.json \
    && pip-audit --require-hashes -r /workspace/driver_host/requirements.hashes.lock \
        --format json --output /audit-results/pip-audit-driver.json \
    && pip-audit --require-hashes -r /workspace/driver_host/pki-requirements.hashes.lock \
        --format json --output /audit-results/pip-audit-pki.json \
    && pip-audit --require-hashes -r /workspace/contracts/generator-requirements.hashes.lock \
        --format json --output /audit-results/pip-audit-generator.json \
    && pip-audit --require-hashes -r /workspace/scripts/supply-chain-requirements.hashes.lock \
        --format json --output /audit-results/pip-audit-supply.json \
    && python /workspace/scripts/audit_starlette_exposure.py --json \
        > /audit-results/starlette-policy.json \
    && python -c 'import importlib.metadata,json,platform; print(json.dumps({"pip_audit":importlib.metadata.version("pip-audit"),"python":platform.python_version()},sort_keys=True,separators=(",",":")))' \
        > /audit-results/python-tools.json \
    && touch /python-audit-passed

FROM supply-tools AS sbom-validator
RUN mkdir /validation && chown 10004:10004 /validation
USER 10004:10004
WORKDIR /validation
ENTRYPOINT ["python", "/workspace/scripts/validate_cyclonedx_v04.py", "validate", "--directory", "/validation"]

FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS node-audit
ARG AUDIT_NONCE
WORKDIR /workspace/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN mkdir /audit-results \
    && echo "$AUDIT_NONCE" > /audit-nonce \
    && npm audit --package-lock-only --audit-level=high --json \
        > /audit-results/npm-audit.json \
    && node -e 'const {execFileSync}=require("node:child_process"); process.stdout.write(JSON.stringify({node:process.version,npm:execFileSync("npm",["--version"],{encoding:"utf8"}).trim()})+"\n")' \
        > /audit-results/node-tools.json \
    && touch /node-audit-passed

FROM source
COPY --from=python-audit /python-audit-passed /
COPY --from=node-audit /node-audit-passed /
COPY --from=python-audit /audit-results/ /supply-provenance/
COPY --from=node-audit /audit-results/ /supply-provenance/
ENTRYPOINT ["python", "scripts/supply_chain_v04.py", "--root", "/workspace", "probe-sc-001"]
