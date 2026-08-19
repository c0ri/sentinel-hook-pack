#!/bin/bash
# setup.sh -- optional local SlopScan backend for the slopscan hook.
#
# The slopscan hook needs something to query. This script implements the
# consent-gated flow: explain what SlopScan is and that it needs Docker,
# ask before doing anything, check for Docker, offer to install Docker
# only via its own official convenience script (not a custom install we
# invented), build the SlopScan image from a fresh clone of the public
# repo (not a pulled prebuilt image -- keeps trust anchored to source the
# user can read), run it, and write the resulting URL to a config file the
# hook reads at runtime. Any failure/decline point aborts *this hook only*
# with a clear reason -- install.sh continues with the rest of the pack.
set -euo pipefail

NONINTERACTIVE="${NONINTERACTIVE:-0}"
CONFIG_DIR="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}"
CONFIG_FILE="$CONFIG_DIR/slopscan.env"
CLONE_DIR="${SLOPSCAN_CLONE_DIR:-$HOME/.local/share/sentinel-hook-pack/SlopScan}"
CONTAINER_NAME="sentinel-hook-pack-slopscan"
IMAGE_TAG="sentinel-hook-pack/slopscan:local"
DEFAULT_PORT=8765

say()  { echo "==> $*"; }
warn() { echo "!!  $*" >&2; }

# ── 0. Already configured? ──────────────────────────────────────────────
if [ -n "${SLOPSCAN_URL:-}" ]; then
  say "SLOPSCAN_URL already set in the environment ($SLOPSCAN_URL) -- leaving it alone."
  exit 0
fi
if [ -f "$CONFIG_FILE" ]; then
  say "$CONFIG_FILE already exists -- leaving it alone. Delete it first to reconfigure."
  exit 0
fi

# ── 1. Explain, ask ──────────────────────────────────────────────────────
cat <<'EXPLAIN'
The slopscan hook checks packages you install against SlopScan, an
open-source package-hallucination / slopsquatting detector
(github.com/c0ri/SlopScan). It needs a backend to query -- this script can
build and run one locally in Docker (a small FastAPI service, no
database, nothing else required).
EXPLAIN

if [ "$NONINTERACTIVE" = "1" ]; then
  if [ "${WITH_SLOPSCAN_DOCKER:-0}" != "1" ]; then
    warn "Non-interactive and --with-slopscan-docker not passed -- skipping local SlopScan setup."
    warn "The slopscan hook will install but silently allow everything until SLOPSCAN_URL is set."
    exit 1
  fi
else
  read -r -p "Set up a local SlopScan backend now? [y/N] " reply
  [[ "${reply:-}" =~ ^[Yy] ]] || { say "Skipping -- the slopscan hook will install but silently allow everything until SLOPSCAN_URL is set."; exit 1; }
fi

# ── 2. Docker present? ───────────────────────────────────────────────────
docker_ready() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

if ! docker_ready; then
  if command -v docker >/dev/null 2>&1; then
    warn "docker is installed but the daemon isn't reachable (not running, or you're not in the docker group)."
    warn "Start Docker and re-run this script."
    exit 1
  fi

  OS="$(uname -s 2>/dev/null || echo unknown)"
  if [ "$OS" != "Linux" ]; then
    warn "Docker isn't installed and this is not Linux -- no safe unattended installer for macOS/Windows."
    warn "Install Docker Desktop yourself: https://www.docker.com/products/docker-desktop/"
    warn "Then re-run this script."
    exit 1
  fi

  say "Docker isn't installed."
  if [ "$NONINTERACTIVE" = "1" ]; then
    warn "Non-interactive -- won't install Docker unattended. Install it yourself: https://get.docker.com"
    exit 1
  fi
  read -r -p "Install it now via Docker's own official convenience script (get.docker.com)? [y/N] " reply
  if [[ ! "${reply:-}" =~ ^[Yy] ]]; then
    say "Skipping -- install Docker yourself later and re-run this script."
    exit 1
  fi

  tmp_installer="$(mktemp)"
  curl -fsSL https://get.docker.com -o "$tmp_installer"
  if [ "$(id -u)" = "0" ]; then
    sh "$tmp_installer"
  else
    sudo sh "$tmp_installer"
  fi
  rm -f "$tmp_installer"

  if ! docker_ready; then
    warn "Docker install finished but the daemon still isn't reachable (may need a new shell/group membership, e.g. 'newgrp docker')."
    warn "Re-run this script after that."
    exit 1
  fi
  say "Docker is ready."
fi

# ── 3. Port check ────────────────────────────────────────────────────────
PORT="$DEFAULT_PORT"
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
  say "$CONTAINER_NAME is already running -- reusing it."
  EXISTING_PORT="$(docker port "$CONTAINER_NAME" 8765/tcp 2>/dev/null | head -1 | sed -E 's/.*:([0-9]+)$/\1/')"
  [ -n "$EXISTING_PORT" ] && PORT="$EXISTING_PORT"
else
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    exec 3>&- 3<&-
    warn "Port $PORT is already in use."
    if [ "$NONINTERACTIVE" = "1" ]; then
      PORT=$((PORT + 1))
      warn "Using $PORT instead (non-interactive)."
    else
      read -r -p "Port to use instead [$((PORT + 1))]: " alt_port
      PORT="${alt_port:-$((PORT + 1))}"
    fi
  fi

  # ── 4. Clone + build (source, not a pulled image) ──────────────────────
  mkdir -p "$(dirname "$CLONE_DIR")"
  if [ -d "$CLONE_DIR/.git" ]; then
    say "SlopScan already cloned at $CLONE_DIR -- pulling latest..."
    (cd "$CLONE_DIR" && git pull)
  else
    say "Cloning SlopScan into $CLONE_DIR ..."
    git clone https://github.com/c0ri/SlopScan.git "$CLONE_DIR"
  fi

  say "Building the image locally (docker build, not a pulled image)..."
  docker build -t "$IMAGE_TAG" "$CLONE_DIR"

  say "Starting the container on port $PORT..."
  docker run -d --restart unless-stopped --name "$CONTAINER_NAME" \
    -p "127.0.0.1:$PORT:8765" "$IMAGE_TAG" >/dev/null
fi

# ── 5. Write config for the hook to read ────────────────────────────────
mkdir -p "$CONFIG_DIR"
echo "SLOPSCAN_URL=http://127.0.0.1:$PORT" > "$CONFIG_FILE"
say "SlopScan running at http://127.0.0.1:$PORT -- config written to $CONFIG_FILE"

sleep 1
if curl -fsS "http://127.0.0.1:$PORT/check/pypi/requests" >/dev/null 2>&1; then
  say "Verified reachable and responding."
else
  warn "Container started but didn't respond to a quick check yet -- give it a few seconds, it may still be starting up."
fi
