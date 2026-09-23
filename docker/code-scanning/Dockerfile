FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md NOTICE.md ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels ".[ai,observability]"

FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 plaidnox \
    && useradd --uid 10001 --gid plaidnox --create-home --shell /usr/sbin/nologin plaidnox \
    && install --directory --owner=plaidnox --group=plaidnox /var/lib/plaidnox/output

COPY --from=builder /wheels /wheels
RUN python -m pip install /wheels/* && rm -rf /wheels

USER 10001:10001
WORKDIR /home/plaidnox
ENTRYPOINT ["plaidnox-sast"]
CMD ["--help"]
