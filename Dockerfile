FROM cgr.dev/chainguard/python:latest-dev@sha256:4e2adecf67a1d18773c55b5526b47436392b9816ae6b8d92575979a2ab9de8b2 AS build

USER root
ENV PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY pyproject.toml README.md LICENSE.txt requirements-build.lock requirements-runtime.lock ./
COPY src ./src
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install \
        --require-hashes \
        --requirement requirements-build.lock \
    && /opt/venv/bin/python -m pip install \
        --no-build-isolation \
        --require-hashes \
        --requirement requirements-runtime.lock \
    && /opt/venv/bin/python -m pip install \
        --no-build-isolation \
        --no-deps \
        . \
    && /opt/venv/bin/python -m pip uninstall --yes pip setuptools wheel

FROM cgr.dev/chainguard/python:latest@sha256:f47d995d001c1f949d560b1158d7f3ae556aad75a1044e72a125c900c1f05332

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --from=build --chown=65532:65532 /opt/venv /opt/venv
COPY config ./config
COPY data ./data
COPY content ./content
COPY brand ./brand
COPY site ./site
COPY artifacts/launch/short-001-storyboard.json ./artifacts/launch/short-001-storyboard.json
COPY artifacts/launch/remedialhq-launch-short-visual-prototype.mp4 ./artifacts/launch/remedialhq-launch-short-visual-prototype.mp4

USER 65532:65532
ENTRYPOINT ["/opt/venv/bin/python", "-m", "remedialhq.cli"]
CMD ["--help"]
