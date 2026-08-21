#!/usr/bin/env bash
set -euo pipefail

# deploy.sh — build, deploy, and run ingestor in the background with
# auto-restart. Running it with no arguments rebuilds, redeploys, and
# (re)starts the app so it keeps serving forever.
# Deploys into the project root by default (override via DEPLOY_PATH). The
# sync never deletes anything on the destination.

APP="ingestor"
BUILD_DIR="dist"
TEMPLATES="templates"
ENV_FILE=".env"
ENV_EXAMPLE=".env.example"
PID_FILE=".ingestor.pid"
LOG_FILE="ingestor.log"

# Remote deployment (optional). Leave DEPLOY_HOST empty for local-only.
#   DEPLOY_HOST="user@host" DEPLOY_PATH="/opt/ingestor" ./deploy.sh
DEPLOY_HOST="${DEPLOY_HOST:-}"
# Default the deploy dir to the project root (where this script lives) so a
# plain `./deploy.sh` self-hosts from the checkout. Override with DEPLOY_PATH
# to deploy elsewhere. Never guess a path like $HOME/ingestor: if that equals
# the project root, a --delete sync would destroy the source tree.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_PATH="${DEPLOY_PATH:-$PROJECT_ROOT}"

usage() {
  echo "Usage: ./deploy.sh [build|deploy|run|stop|restart|status|logs|systemd]"
  echo "  (no args)  build + deploy + run in background (auto-restart)"
  echo "  build      Build a static binary into $BUILD_DIR/"
  echo "  deploy     Build, then copy to \$DEPLOY_PATH (local or remote via \$DEPLOY_HOST)"
  echo "  run        Build + deploy + (re)start the supervised background process"
  echo "  stop       Stop the background process"
  echo "  restart    Stop + start (no rebuild)"
  echo "  status     Show whether the app is running"
  echo "  logs       Tail the app log"
  echo "  systemd    Emit a systemd unit for ingestor"
}

# ensure_jwt_secret makes sure the source .env has a compliant JWT signing
# key (>= 64 bytes), generating and persisting one if missing or too short.
ensure_jwt_secret() {
  if [[ ! -f "$ENV_FILE" ]]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
  fi
  local secret
  secret="$(grep -E '^jwt_secret=' "$ENV_FILE" | tail -1 | cut -d= -f2-)" || true
  if [[ -z "$secret" || "$(printf %s "$secret" | wc -c | tr -d ' ')" -lt 64 ]]; then
    secret="$(openssl rand -hex 64)"
    grep -v '^jwt_secret=' "$ENV_FILE" > "$ENV_FILE.tmp" || true
    printf 'jwt_secret=%s\n' "$secret" >> "$ENV_FILE.tmp"
    mv "$ENV_FILE.tmp" "$ENV_FILE"
    echo "==> Generated jwt_secret in $ENV_FILE"
  fi
}

build() {
  ensure_jwt_secret
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

# sync_files pushes the build artifacts into the deploy directory. It never
# deletes anything on the destination (no --delete): the deploy dir may hold
# the source checkout, uploaded data, or the SQLite DB, and those must never
# be wiped by a redeploy. Stale build files are simply overwritten.
sync_files() {
  local src dst
  src="$1"
  dst="$2"

  # Safety guard: refuse to sync a directory onto itself or into a
  # subdirectory of itself. This makes it impossible for a deploy to consume
  # the build output it is meant to produce.
  local src_abs dst_abs
  src_abs="$(cd "$src" && pwd)"
  mkdir -p "$dst"
  dst_abs="$(cd "$dst" && pwd)"
  if [[ "$src_abs" == "$dst_abs" ]]; then
    echo "ERROR: deploy dir is the build dir itself ($src_abs); refusing to sync." >&2
    exit 1
  fi
  if [[ "$dst_abs" == "$src_abs/"* ]]; then
    echo "ERROR: deploy dir is inside the build dir ($src_abs); refusing to sync." >&2
    exit 1
  fi

  if [[ -n "$DEPLOY_HOST" ]]; then
    rsync -av "$src" "$DEPLOY_HOST:$dst"
  else
    rsync -av "$src" "$dst"
  fi
}

deploy() {
  build
  echo "==> Deploying to ${DEPLOY_HOST:+$DEPLOY_HOST:}$DEPLOY_PATH"
  sync_files "$BUILD_DIR/" "$DEPLOY_PATH/"
  echo "==> Deployed."
  echo "    If this is a new install, copy $DEPLOY_PATH/$ENV_EXAMPLE to $DEPLOY_PATH/$ENV_FILE and set your secrets."
}

remote_cmd() {
  ssh "$DEPLOY_HOST" "$1"
}

run_remote() {
  local run_dir="$DEPLOY_PATH"
  stop
  echo "==> Starting supervised process on $DEPLOY_HOST"
  remote_cmd "cd '$run_dir' && nohup sh -c 'while true; do ./$APP >> $LOG_FILE 2>&1; sleep 2; done' >/dev/null 2>&1 & echo \$! > '$run_dir/$PID_FILE'"
  echo "==> Started. PID on remote host:"
  remote_cmd "cat '$run_dir/$PID_FILE'"
}

run_local() {
  local run_dir="$DEPLOY_PATH"
  if [[ ! -w "$run_dir" ]]; then
    echo "ERROR: $run_dir is not writable by $(id -un)." >&2
    echo "       Run deploy.sh as root, or set DEPLOY_PATH to a user-writable directory." >&2
    exit 1
  fi
  stop
  echo "==> Starting supervised process in $run_dir"
  (
    cd "$run_dir"
    nohup sh -c "while true; do ./$APP >> $LOG_FILE 2>&1; sleep 2; done" >/dev/null 2>&1 &
    echo $! > "$run_dir/$PID_FILE"
  )
  sleep 1
  if [[ -f "$run_dir/$PID_FILE" ]]; then
    echo "==> Started. Supervisor PID: $(cat "$run_dir/$PID_FILE")"
  fi
}

run() {
  deploy
  if [[ -n "$DEPLOY_HOST" ]]; then
    run_remote
  else
    run_local
  fi
}

stop() {
  if [[ -n "$DEPLOY_HOST" ]]; then
    remote_cmd "if [ -f '$DEPLOY_PATH/$PID_FILE' ]; then kill \$(cat '$DEPLOY_PATH/$PID_FILE') 2>/dev/null || true; fi; pkill -f '$DEPLOY_PATH/$APP' 2>/dev/null || true"
  else
    local spid
    if [[ -f "$DEPLOY_PATH/$PID_FILE" ]]; then
      spid="$(cat "$DEPLOY_PATH/$PID_FILE")"
      # Kill the supervised app before its supervisor loop restarts it.
      pkill -P "$spid" 2>/dev/null || true
      kill "$spid" 2>/dev/null || true
      rm -f "$DEPLOY_PATH/$PID_FILE"
    fi
    pkill -f "$DEPLOY_PATH/$APP" 2>/dev/null || true
    pkill -f "\./$APP" 2>/dev/null || true
  fi
  echo "==> Stopped."
}

restart() {
  if [[ -n "$DEPLOY_HOST" ]]; then
    run_remote
  else
    run_local
  fi
}

status() {
  if [[ -n "$DEPLOY_HOST" ]]; then
    remote_cmd "if [ -f '$DEPLOY_PATH/$PID_FILE' ] && kill -0 \$(cat '$DEPLOY_PATH/$PID_FILE') 2>/dev/null; then echo running; else echo stopped; fi"
    return
  fi
  if [[ -f "$DEPLOY_PATH/$PID_FILE" ]] && kill -0 "$(cat "$DEPLOY_PATH/$PID_FILE")" 2>/dev/null; then
    echo "running (supervisor PID $(cat "$DEPLOY_PATH/$PID_FILE"))"
  else
    echo "stopped"
  fi
}

logs() {
  if [[ -n "$DEPLOY_HOST" ]]; then
    remote_cmd "tail -n 50 -f '$DEPLOY_PATH/$LOG_FILE'"
  else
    tail -n 50 -f "$DEPLOY_PATH/$LOG_FILE"
  fi
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

case "${1:-run}" in
  build)
    build
    ;;
  deploy)
    deploy
    ;;
  run)
    run
    ;;
  stop)
    stop
    ;;
  restart)
    restart
    ;;
  status)
    status
    ;;
  logs)
    logs
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
