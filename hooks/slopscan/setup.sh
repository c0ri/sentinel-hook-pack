#!/bin/bash
# setup.sh -- optional local SlopScan backend for the slopscan hook.
#
# The slopscan hook needs something to query. This script implements the
# consent-gated flow: explain what SlopScan is, ask before doing anything,
# let the user pick how to run it (Docker or a plain Python venv -- see
# the "Backend choice" comment below for why both exist), build/install
# from a fresh clone of the public repo (never a pulled image or wheel --
# keeps trust anchored to source the user can read), run it, and write the
# resulting URL to a config file the hook reads at runtime. Any
# failure/decline point aborts *this hook only* with a clear reason --
# install.sh continues with the rest of the pack.
set -euo pipefail

NONINTERACTIVE="${NONINTERACTIVE:-0}"
CONFIG_DIR="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}"
CONFIG_FILE="$CONFIG_DIR/slopscan.env"
CLONE_DIR="${SLOPSCAN_CLONE_DIR:-$HOME/.local/share/sentinel-hook-pack/SlopScan}"
CONTAINER_NAME="sentinel-hook-pack-slopscan"
IMAGE_TAG="sentinel-hook-pack/slopscan:local"
SYSTEMD_UNIT_NAME="sentinel-hook-pack-slopscan.service"
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

# ── 1. Explain, ask whether to set anything up at all ───────────────────
cat <<'EXPLAIN'
The slopscan hook checks packages you install against SlopScan, an
open-source package-hallucination / slopsquatting detector
(github.com/c0ri/SlopScan) -- a small FastAPI service, no database,
nothing else required. It needs a backend to query; this script can set
one up locally, either in Docker or a plain Python virtualenv.
EXPLAIN

if [ "$NONINTERACTIVE" = "1" ]; then
  if [ "${WITH_SLOPSCAN_DOCKER:-0}" = "1" ]; then
    BACKEND=docker
  elif [ "${WITH_SLOPSCAN_PIP:-0}" = "1" ]; then
    BACKEND=pip
  else
    warn "Non-interactive and neither --with-slopscan-docker nor --with-slopscan-pip was passed -- skipping local SlopScan setup."
    warn "The slopscan hook will install but silently allow everything until SLOPSCAN_URL is set."
    exit 1
  fi
else
  echo
  echo "How do you want to run it?"
  echo "  1) Docker -- auto-restarts on crash and reboot ('docker run --restart unless-stopped'), needs Docker installed"
  echo "  2) Python venv + pip -- no Docker dependency, but you're responsible for keeping it running (we'll set up a systemd --user service on Linux where possible; elsewhere it's a plain background process)"
  echo "  3) Skip"
  read -r -p "Choice [3]: " choice
  case "${choice:-3}" in
    1) BACKEND=docker ;;
    2) BACKEND=pip ;;
    *) say "Skipping -- the slopscan hook will install but silently allow everything until SLOPSCAN_URL is set."; exit 1 ;;
  esac
fi

# ── Backend choice, in short: Docker's `--restart unless-stopped` is the
# nicer default (survives crashes and reboots with zero extra setup), but
# forcing a Docker install on someone who doesn't already have it is a big
# ask for a service this light (SlopScan's own quickstart is just `pip
# install` + `uvicorn`). So both paths exist and the user picks. ─────────

# ── Shared: clone/pull the public repo (source, never a pulled artifact) ─
clone_slopscan() {
  mkdir -p "$(dirname "$CLONE_DIR")"
  if [ -d "$CLONE_DIR/.git" ]; then
    say "SlopScan already cloned at $CLONE_DIR -- pulling latest..."
    (cd "$CLONE_DIR" && git pull)
  else
    say "Cloning SlopScan into $CLONE_DIR ..."
    git clone https://github.com/c0ri/SlopScan.git "$CLONE_DIR"
  fi
}

# ── Shared: pick a free port, reusing an already-running instance's port
# if we find one for the chosen backend. ─────────────────────────────────
pick_port() {
  # $1 = "reuse" port to check first (already-running instance), optional
  local port="${1:-$DEFAULT_PORT}"
  if [ "$port" = "$DEFAULT_PORT" ] && (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    exec 3>&- 3<&-
    warn "Port $port is already in use."
    if [ "$NONINTERACTIVE" = "1" ]; then
      port=$((port + 1))
      warn "Using $port instead (non-interactive)."
    else
      read -r -p "Port to use instead [$((port + 1))]: " alt_port
      port="${alt_port:-$((port + 1))}"
    fi
  fi
  echo "$port"
}

write_config_and_verify() {
  # $1 = port
  local port="$1"
  mkdir -p "$CONFIG_DIR"
  echo "SLOPSCAN_URL=http://127.0.0.1:$port" > "$CONFIG_FILE"
  say "SlopScan running at http://127.0.0.1:$port -- config written to $CONFIG_FILE"
  sleep 1
  if curl -fsS "http://127.0.0.1:$port/check/pypi/requests" >/dev/null 2>&1; then
    say "Verified reachable and responding."
  else
    warn "Started but didn't respond to a quick check yet -- give it a few seconds, it may still be starting up."
  fi
}

# ── Docker backend ────────────────────────────────────────────────────────
setup_docker() {
  docker_ready() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

  if ! docker_ready; then
    if command -v docker >/dev/null 2>&1; then
      warn "docker is installed but the daemon isn't reachable (not running, or you're not in the docker group)."
      warn "Start Docker and re-run this script."
      exit 1
    fi

    local os
    os="$(uname -s 2>/dev/null || echo unknown)"
    if [ "$os" != "Linux" ]; then
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
      say "Skipping -- install Docker yourself later and re-run this script, or re-run and choose the pip option instead."
      exit 1
    fi

    local tmp_installer
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

  local port
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    say "$CONTAINER_NAME is already running -- reusing it."
    port="$(docker port "$CONTAINER_NAME" 8765/tcp 2>/dev/null | head -1 | sed -E 's/.*:([0-9]+)$/\1/')"
    [ -n "$port" ] || port="$DEFAULT_PORT"
  else
    port="$(pick_port "$DEFAULT_PORT")"
    clone_slopscan
    say "Building the image locally (docker build, not a pulled image)..."
    docker build -t "$IMAGE_TAG" "$CLONE_DIR"
    say "Starting the container on port $port (--restart unless-stopped: survives crashes and reboots without further setup)..."
    docker run -d --restart unless-stopped --name "$CONTAINER_NAME" \
      -p "127.0.0.1:$port:8765" "$IMAGE_TAG" >/dev/null
  fi

  write_config_and_verify "$port"
}

# ── Pip/venv backend ─────────────────────────────────────────────────────
setup_pip() {
  command -v python3 >/dev/null 2>&1 || { warn "python3 not found -- can't use the pip/venv backend. Install Python 3 or re-run and choose Docker instead."; exit 1; }

  clone_slopscan

  local venv_dir="$CLONE_DIR/venv"
  if [ ! -x "$venv_dir/bin/python" ]; then
    say "Creating a virtualenv at $venv_dir..."
    python3 -m venv "$venv_dir"
  fi
  say "Installing dependencies (no system packages touched -- isolated to this venv)..."
  "$venv_dir/bin/pip" install -q --upgrade pip
  "$venv_dir/bin/pip" install -q -r "$CLONE_DIR/requirements.txt"

  local port
  port="$(pick_port "$DEFAULT_PORT")"

  local os
  os="$(uname -s 2>/dev/null || echo unknown)"
  if [ "$os" = "Linux" ] && command -v systemctl >/dev/null 2>&1 && [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    say "Setting up a systemd --user service so this restarts on crash automatically..."
    local unit_dir="$HOME/.config/systemd/user"
    mkdir -p "$unit_dir"
    cat > "$unit_dir/$SYSTEMD_UNIT_NAME" <<EOF
[Unit]
Description=sentinel-hook-pack SlopScan backend

[Service]
WorkingDirectory=$CLONE_DIR
ExecStart=$venv_dir/bin/python -m uvicorn main:app --host 127.0.0.1 --port $port
Restart=on-failure

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now "$SYSTEMD_UNIT_NAME"
    say "Running as a systemd --user service ($SYSTEMD_UNIT_NAME) -- restarts on crash."
    say "To also survive full reboots without you being logged in: sudo loginctl enable-linger $USER"
    say "(That's a system-level change, so it's not run automatically here -- your call.)"
  else
    warn "No systemd --user available on this system -- falling back to a plain background process."
    warn "It will NOT survive a crash or reboot; you'll need to restart it yourself:"
    warn "  (cd $CLONE_DIR && $venv_dir/bin/python -m uvicorn main:app --host 127.0.0.1 --port $port)"
    mkdir -p "$CONFIG_DIR"
    # uvicorn resolves "main:app" as a module import relative to the CURRENT
    # working directory, not the venv's location -- without this cd, it runs
    # from wherever install.sh happened to be invoked from (never $CLONE_DIR)
    # and fails with "Could not import module main", silently, since nohup
    # already detached stderr to the log file the user isn't watching.
    (
      cd "$CLONE_DIR"
      nohup "$venv_dir/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "$port" \
        > "$CONFIG_DIR/slopscan.log" 2>&1 &
      disown
    )
    say "Started in the background -- logs at $CONFIG_DIR/slopscan.log"
  fi

  write_config_and_verify "$port"
}

case "$BACKEND" in
  docker) setup_docker ;;
  pip)    setup_pip ;;
esac
