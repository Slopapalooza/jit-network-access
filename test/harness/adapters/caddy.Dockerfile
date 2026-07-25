# Caddy with the jit_access handler compiled in. Context = repo root.
FROM golang:1.25-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY core/go/ ./core/go/
COPY adapters/caddy/ ./adapters/caddy/
WORKDIR /src/adapters/caddy
RUN CGO_ENABLED=0 go build -trimpath -o /out/caddy ./cmd/caddy-jit

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/caddy /usr/bin/caddy
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
