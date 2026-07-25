# Build:  docker build -t jitaccess-authorizer:0.1.0 -f authorizer/Dockerfile .
# Run:    docker run --rm -p 127.0.0.1:8998:8998 \
#             -v "$PWD/config.json:/etc/jitaccess/config.json:ro" \
#             jitaccess-authorizer:0.1.0
#
# Context is the REPO ROOT, because the module needs ../core/go.

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY core/go/ ./core/go/
COPY authorizer/ ./authorizer/
WORKDIR /src/authorizer
# Static, no cgo — the result runs on scratch/distroless.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/jitaccess-authorizer .

# distroless: no shell, no package manager, nothing to pivot to if the process
# is ever compromised. The Authorizer needs no filesystem beyond its config.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/jitaccess-authorizer /usr/local/bin/jitaccess-authorizer
USER nonroot:nonroot
EXPOSE 8998
ENTRYPOINT ["/usr/local/bin/jitaccess-authorizer"]
CMD ["-config", "/etc/jitaccess/config.json"]
