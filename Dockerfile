# syntax=docker/dockerfile:1.7

# The build stage always runs on the build host's native architecture and
# cross-compiles with Go, so multi-arch images need no QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOARM="${TARGETVARIANT#v}" CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/pihole-mcp ./cmd/pihole-mcp

FROM gcr.io/distroless/static:nonroot
ARG VERSION=dev
ARG COMMIT=none
LABEL org.opencontainers.image.title="pihole-mcp" \
      org.opencontainers.image.description="MCP server for Pi-hole v6: DNS usage analysis, block-list assessment and guarded changes" \
      org.opencontainers.image.source="https://github.com/salehparsa/pihole-mcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
# The image serves Streamable HTTP by default. For stdio use:
#   docker run -i --rm -e MCP_TRANSPORT=stdio -e PIHOLE_URL=... -e PIHOLE_APP_PASSWORD=... <image>
ENV MCP_TRANSPORT=http \
    MCP_LISTEN=:8765
COPY --from=build /out/pihole-mcp /pihole-mcp
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.md /licenses/
EXPOSE 8765
USER nonroot:nonroot
# distroless has no shell, so there is no HEALTHCHECK instruction; use
# `healthcheck: test: ["CMD", "/pihole-mcp", "healthcheck"]` in compose.
ENTRYPOINT ["/pihole-mcp"]
