# syntax=docker/dockerfile:1
# The release image: a static binary on distroless, non-root, nothing else. The binaries
# are built beforehand per architecture (tools/dist-bin.sh, or the release workflow on a
# native runner) into dist/bin/linux-<arch>/, so `docker buildx build --platform
# linux/amd64,linux/arm64` only assembles. Dockerfile.source builds from source instead.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG TARGETARCH
ARG VERSION=dev
LABEL org.opencontainers.image.title="iohr-agent" \
      org.opencontainers.image.description="InOrbit agent: dials out, obeys a local policy, runs checks in your network" \
      org.opencontainers.image.source="https://github.com/inorbithr/dataplane" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="InOrbit d.o.o." \
      org.opencontainers.image.version="${VERSION}"
COPY --chmod=0555 dist/bin/linux-${TARGETARCH}/iohr-agent /usr/bin/iohr-agent
USER 65532:65532
ENV IOHR_AGENT_CONFIG=/etc/iohr-agent/agent.toml
ENTRYPOINT ["/usr/bin/iohr-agent"]
CMD ["run", "--json-logs"]
