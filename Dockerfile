# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -trimpath \
    -ldflags="-s -w -X github.com/encrypt0r/ingestor/internal/version.Version=${VERSION}" \
    -o /out/ingestor .

FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app

WORKDIR /app
COPY --from=build --chown=app:app /out/ingestor /app/ingestor
COPY --from=build --chown=app:app /src/templates /app/templates
RUN mkdir -p /app/uploads /data \
    && chown -R app:app /app /data

# The container always listens on all interfaces; the host port is mapped by
# docker-compose (or `docker run -p`). SQLite and uploads live on volumes.
ENV host=0.0.0.0 \
    port=8080 \
    db_path=/data/ingestor.db \
    upload_dir=uploads

VOLUME ["/data", "/app/uploads"]
EXPOSE 8080
USER app

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/app/ingestor"]
