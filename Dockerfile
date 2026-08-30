FROM python:3.12-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN sed -ri \
        's|URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20260824T000000Z|; s|URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/20260824T000000Z|' \
        /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\n' \
        > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419~deb12u1 \
        ffmpeg=7:5.1.9-0+deb12u1 \
        fonts-dejavu-core=2.37-6 \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system app \
    && adduser --system --ingroup app app

WORKDIR /app
COPY pyproject.toml README.md requirements-build.lock requirements-production.lock ./
COPY src ./src
COPY config ./config
COPY data ./data
COPY content ./content
COPY brand ./brand
COPY site ./site
COPY artifacts/launch/short-001-storyboard.json ./artifacts/launch/short-001-storyboard.json
COPY artifacts/launch/remedialhq-launch-short-visual-prototype.mp4 ./artifacts/launch/remedialhq-launch-short-visual-prototype.mp4
RUN pip install --require-hashes --requirement requirements-build.lock \
    && pip install --require-hashes --requirement requirements-production.lock \
    && pip install --no-build-isolation --no-deps .
RUN chown -R app:app /app
USER app
ENTRYPOINT ["remedialhq"]
CMD ["--help"]
