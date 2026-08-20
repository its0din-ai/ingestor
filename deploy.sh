#!/usr/bin/env bash
set -euo pipefail

# deploy.sh — build a static binary and deploy ingestor (binary, templates,
# and .env) to a target directory or remote host.

APP="ingestor"
BUILD_DIR="dist"
TEMPLATES="templates"
ENV_FILE=".env"
ENV_EXAMPLE=".env.example"

# Remote deployment (optional). Leave DEPLOY_HOST empty for local-only.
#   DEPLOY_HOST="user@host" DEPLOY_PATH="/opt/ingestor" ./deploy.sh
DEPLOY_HOST="${DEPLOY_HOST:-}"
DEPLOY_PATH="${DEPLOY_PATH:-/opt/$APP}"

usage() {
  echo "Usage: ./deploy.sh [build|deploy|systemd]"
  echo "  build    Build a static binary into $BUILD_DIR/ (default)"
  echo "  deploy   Build, then copy to \$DEPLOY_PATH (local or remote via \$DEPLOY_HOST)"
  echo "  systemd  Emit a systemd unit for ingestor"
}

build() {
  echo "==> Building static binary ($(go version | awk '{print $3}'))"
  mkdir -p "$BUILD_DIR"
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUILD_DIR/$APP" .
  echo "==> Copying templates"
  rm -rf "$BUILD_DIR/$TEMPLATES"
  cp -R "$TEMPLATES" "$BUILD_DIR/"
  if [[ -f "$ENV_FILE" ]]; then
    echo "==> Copying $ENV_FILE"
    cp "$ENV_FILE" "$BUILD_DIR/$ENV_FILE"
  else
    echo "==> Copying $ENV_EXAMPLE (no .env present)"
    cp "$ENV_EXAMPLE" "$BUILD_DIR/$ENV_EXAMPLE"
  fi
  echo "==> Build complete: $BUILD_DIR/$APP"
}

sync_files() {
  local src dst
  src="$1"
  dst="$2"
  if [[ -n "$DEPLOY_HOST" ]]; then
    rsync -av --delete "$src" "$DEPLOY_HOST:$dst"
  else
    mkdir -p "$dst"
    rsync -av --delete "$src" "$dst"
  fi
}

deploy() {
  build
  echo "==> Deploying to ${DEPLOY_HOST:+$DEPLOY_HOST:}$DEPLOY_PATH"
  sync_files "$BUILD_DIR/" "$DEPLOY_PATH/"
  echo "==> Deployed."
  echo "    If this is a new install, copy $DEPLOY_PATH/$ENV_EXAMPLE to $DEPLOY_PATH/$ENV_FILE and set your secrets."
}

systemd_unit() {
  cat <<EOF
[Unit]
Description=ingestor secure file upload server
After=network.target

[Service]
Type=simple
User=${SERVICE_USER:-ingestor}
WorkingDirectory=${DEPLOY_PATH}
ExecStart=${DEPLOY_PATH}/${APP}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

case "${1:-build}" in
  build)
    build
    ;;
  deploy)
    deploy
    ;;
  systemd)
    systemd_unit
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "Unknown command: $1" >&2
    usage
    exit 1
    ;;
esac
