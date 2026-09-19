# secman_intra_mon — Linux runtime with all supported scanner tools.
#
# Build:  docker build -t secman-intra-mon .
# Run:    docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
#           secman-intra-mon capabilities
#
# Host networking + NET_RAW are needed for ARP discovery and masscan;
# without them the tool degrades to ICMP/TCP discovery (see docs/DOCKER.md).

FROM python:3.12-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        arp-scan \
        dnsutils \
        fping \
        iproute2 \
        iputils-ping \
        masscan \
        nmap \
        traceroute \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

# Dependency layer first for build caching.
COPY pyproject.toml uv.lock .python-version README.md ./
RUN uv sync --locked --no-dev --no-install-project

COPY src ./src
RUN uv sync --locked --no-dev

ENV PATH="/app/.venv/bin:$PATH"

# Runs unprivileged by default; grant NET_RAW/NET_ADMIN at `docker run` time
# when raw-packet scanning is wanted (setpriv keeps file caps of nmap etc.).
RUN useradd --system --uid 10001 --create-home intramon \
    && chown -R intramon /app
USER intramon

ENTRYPOINT ["secman-intra-mon"]
CMD ["--help"]
