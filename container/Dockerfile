# Lockward container image. Built by .github/workflows/container.yml from the
# Sigstore-verified release archives; nothing is compiled here.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETOS
ARG TARGETARCH
COPY dist/${TARGETOS}_${TARGETARCH}/lockward /usr/local/bin/lockward

LABEL org.opencontainers.image.title="lockward" \
      org.opencontainers.image.description="Lockfile and policy gate for AI agent skills, MCP servers, hooks and rules" \
      org.opencontainers.image.source="https://github.com/Breaktroughf1/lockward" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /src
ENTRYPOINT ["/usr/local/bin/lockward"]
CMD ["--help"]
