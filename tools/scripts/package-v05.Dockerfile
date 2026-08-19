FROM python:3.13-slim@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /workspace
COPY . /workspace

RUN groupadd --gid 10003 spell-package \
    && useradd --uid 10003 --gid spell-package --no-create-home \
        --shell /usr/sbin/nologin spell-package \
    && mkdir -p /workspace/artifacts/v0.5 \
    && chown -R spell-package:spell-package /workspace/artifacts/v0.5

USER 10003:10003

CMD ["python", "scripts/build_reproducible_v05.py", "--output", "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz"]
