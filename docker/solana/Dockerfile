FROM debian:bookworm-slim

# Keep in sync with .github/workflows/ci.yml (`agave-install init <version>`)
# and solana/ (Anchor/Agave toolchain).
ARG AGAVE_VERSION=4.1.1

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  bzip2 \
  libssl3 \
  && rm -rf /var/lib/apt/lists/*

RUN sh -c "$(curl -sSfL https://release.anza.xyz/v${AGAVE_VERSION}/install)"

ENV PATH=/root/.local/share/solana/install/active_release/bin:$PATH

RUN solana --version && solana-test-validator --version

ENTRYPOINT ["solana-test-validator"]
