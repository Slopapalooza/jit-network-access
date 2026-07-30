# Build:  docker build -t jitaccess-authorizer:0.1.0 -f authorizer/Dockerfile .
# Run:    docker run --rm -p 127.0.0.1:8998:8998 \
#             -v "$PWD/config.json:/etc/jitaccess/config.json:ro" \
#             jitaccess-authorizer:0.1.0
#
# Context is the REPO ROOT, because the module needs ../core/go.

# Matches the `toolchain` directive in authorizer/go.mod. It used to say 1.24,
# which is the `go` directive — the older of the two — so this image built
# against a different stdlib than CI tested and than govulncheck cleared. Keep
# these in step: the toolchain line is the one that decides.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY core/go/ ./core/go/
COPY authorizer/ ./authorizer/
WORKDIR /src/authorizer
# version is injected so `-version` and the startup log say something truthful
# in a container; it defaults to the value in main.go otherwise.
ARG VERSION=dev
# Static, no cgo — the result runs on scratch/distroless.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/jitaccess-authorizer .

# distroless: no shell, no package manager, nothing to pivot to if the process
# is ever compromised. The Authorizer needs no filesystem beyond its config.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/jitaccess-authorizer /usr/local/bin/jitaccess-authorizer
USER nonroot:nonroot
EXPOSE 8998
ENTRYPOINT ["/usr/local/bin/jitaccess-authorizer"]
CMD ["-config", "/etc/jitaccess/config.json"]
