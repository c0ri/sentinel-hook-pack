#!/bin/bash
# install.sh -- bundle installer for sentinel-hook-pack.
#
# For each hook under hooks/<name>/:
#   1. Ask before installing (unless --yes or --hooks= named it explicitly).
#   2. If it needs a backend (manifest.yaml: requires_backend: true), run
#      its setup.sh first; a decline/failure there skips just that hook
#      and continues with the rest of the pack.
#   3. Copy its script into place, merge its wiring.json into
#      settings.json (idempotent -- safe to re-run), sign it.
#
# --hooks=name1,name2 installs only the named hook directories (matched
# against the hooks/<name>/ dirname, e.g. --hooks=secrets_detect,slopscan)
# and skips the per-hook prompt for anything in the list -- an explicit
# name is itself the "yes, install this one" answer. Anything not in the
# list is skipped outright, no prompt. Omit --hooks entirely to keep the
# default behavior (prompt for every hook, or --yes for all of them).
#
# hook_guard (HMAC signing) is not vendored here -- it's bootstrapped from
# claude-hookscanner (github.com/c0ri/claude-hookscanner), the one
# canonical copy of that logic.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_SRC_DIR="$REPO_DIR/hooks"
TARGET_HOOKS_DIR="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}"
TARGET_SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
export NONINTERACTIVE=0
export WITH_SLOPSCAN_DOCKER=0
export WITH_SLOPSCAN_PIP=0
HOOKS_FILTER=""
UNINSTALL=0
WITH_SIGNER=0

for arg in "$@"; do
  case "$arg" in
    --yes|-y) NONINTERACTIVE=1 ;;
    --with-slopscan-docker) WITH_SLOPSCAN_DOCKER=1 ;;
    --with-slopscan-pip) WITH_SLOPSCAN_PIP=1 ;;
    --hooks=*) HOOKS_FILTER="${arg#--hooks=}" ;;
    --uninstall) UNINSTALL=1 ;;
    --with-signer) WITH_SIGNER=1 ;;
    --help|-h)
      echo "usage: install.sh [--yes] [--hooks=name1,name2,...] [--with-slopscan-docker | --with-slopscan-pip]"
      echo "       install.sh --uninstall [--yes] [--hooks=name1,name2,...] [--with-signer]"
      echo "  --hooks=       install/uninstall only the named hooks/<name>/ dirs (skips the per-hook prompt); omit for all"
      echo "  --uninstall    remove previously-installed hooks instead of installing"
      echo "  --with-signer  (uninstall only) also uninstall claude-hookscanner (the HMAC signer) -- off by"
      echo "                 default since it's a shared dependency other hooks outside this pack may use"
      echo "Env overrides: CLAUDE_HOOKS_DIR, CLAUDE_SETTINGS"
      exit 0
      ;;
  esac
done
export NONINTERACTIVE WITH_SLOPSCAN_DOCKER WITH_SLOPSCAN_PIP

hook_is_selected() {
  # $1 = hook dirname (e.g. "secrets_detect"). Empty HOOKS_FILTER means "all".
  [ -z "$HOOKS_FILTER" ] && return 0
  local IFS=,
  local wanted
  for wanted in $HOOKS_FILTER; do
    [ "$wanted" = "$1" ] && return 0
  done
  return 1
}

say()  { echo "==> $*"; }
warn() { echo "!!  $*" >&2; }

OS="$(uname -s 2>/dev/null || echo unknown)"
IS_MACOS=0
[ "$OS" = "Darwin" ] && IS_MACOS=1

if ! command -v jq >/dev/null 2>&1; then
  warn "jq is required and wasn't found."
  [ "$IS_MACOS" = "1" ] && warn "On macOS: brew install jq"
  exit 1
fi
command -v git >/dev/null 2>&1 || { warn "git is required and wasn't found."; exit 1; }

manifest_get() {
  # $1 = manifest.yaml path  $2 = scalar key -- only handles the flat
  # scalar fields this installer needs (name/status/fail_mode/
  # requires_backend/setup_script), not the multi-line description block.
  # An optional field (requires_backend/setup_script) that's simply absent
  # from a given manifest makes grep return no match (exit 1) -- under
  # `set -o pipefail` that would kill the whole script, so swallow it and
  # return an empty string instead, same as "field not set."
  grep -E "^$2:" "$1" 2>/dev/null | head -1 | sed -E "s/^$2:[[:space:]]*//" || true
}

# ── --uninstall ───────────────────────────────────────────────────────────
# Removes a hook's wiring from settings.json and its script from
# TARGET_HOOKS_DIR. Deliberately does NOT touch the HMAC signer
# (claude-hookscanner) by default -- it's a shared dependency other hooks
# outside this pack may rely on, so removing it is only ever an explicit
# --with-signer choice, never a side effect of removing one hook.
teardown_slopscan_backend() {
  local config_file="$TARGET_HOOKS_DIR/slopscan.env"
  local pid_file="$TARGET_HOOKS_DIR/slopscan.pid"
  local container_name="sentinel-hook-pack-slopscan"
  local image_tag="sentinel-hook-pack/slopscan:local"
  local systemd_unit="sentinel-hook-pack-slopscan.service"
  local unit_file="$HOME/.config/systemd/user/$systemd_unit"
  # Default clone dir, overridden below if setup.sh recorded a different one
  # (e.g. a custom SLOPSCAN_CLONE_DIR at install time) -- read back what was
  # actually configured rather than re-guessing, same discipline
  # claude-hookscanner's own uninstall uses for its key path. Mirrors
  # setup.sh's own CLAUDE_HOOKS_DIR-tracking default (only reached if
  # slopscan.env itself is missing, e.g. install was interrupted).
  local clone_dir
  if [ -n "${CLAUDE_HOOKS_DIR:-}" ]; then
    clone_dir="$(dirname "$CLAUDE_HOOKS_DIR")/slopscan-src"
  else
    clone_dir="$HOME/.local/share/sentinel-hook-pack/SlopScan"
  fi

  if [ -f "$config_file" ]; then
    local recorded_clone_dir
    recorded_clone_dir="$(grep -E '^SLOPSCAN_CLONE_DIR=' "$config_file" 2>/dev/null | head -1 | cut -d= -f2- || true)"
    [ -n "$recorded_clone_dir" ] && clone_dir="$recorded_clone_dir"
  fi

  say "  Tearing down slopscan's local backend..."

  if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$container_name"; then
    say "    Stopping/removing Docker container $container_name..."
    docker rm -f "$container_name" >/dev/null 2>&1 || warn "    Couldn't remove Docker container $container_name -- may need manual cleanup."
    docker image inspect "$image_tag" >/dev/null 2>&1 && docker rmi "$image_tag" >/dev/null 2>&1
  fi

  if [ -f "$unit_file" ] && command -v systemctl >/dev/null 2>&1; then
    say "    Stopping/disabling systemd --user service $systemd_unit..."
    systemctl --user disable --now "$systemd_unit" >/dev/null 2>&1 || warn "    Couldn't stop/disable $systemd_unit -- may need manual cleanup."
    rm -f "$unit_file"
    systemctl --user daemon-reload 2>/dev/null || true
  fi

  if [ -f "$pid_file" ]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      say "    Stopping background process $pid..."
      kill "$pid" 2>/dev/null || warn "    Couldn't stop process $pid -- may need manual cleanup."
    fi
    rm -f "$pid_file"
  fi

  # Only ever remove a directory that actually looks like our clone
  # (has its own .git), never blindly rm -rf a recorded path.
  if [ -d "$clone_dir/.git" ]; then
    say "    Removing cloned SlopScan checkout at $clone_dir..."
    rm -rf "$clone_dir"
  fi

  rm -f "$config_file" "$TARGET_HOOKS_DIR/slopscan.log"
}

if [ "$UNINSTALL" = "1" ]; then
  if [ ! -f "$TARGET_SETTINGS" ]; then
    warn "$TARGET_SETTINGS not found -- nothing to uninstall."
    exit 0
  fi

  for hook_dir in "$HOOKS_SRC_DIR"/*/; do
    hook_dir="${hook_dir%/}"
    hook_dirname="$(basename "$hook_dir")"
    manifest="$hook_dir/manifest.yaml"
    [ -f "$manifest" ] || continue
    hook_is_selected "$hook_dirname" || continue

    name=$(manifest_get "$manifest" "name")
    target="$TARGET_HOOKS_DIR/$name"

    if [ ! -f "$target" ]; then
      say "SKIP $name -- not installed at $target"
      continue
    fi

    echo
    say "== $name =="
    if [ "$NONINTERACTIVE" != "1" ] && [ -z "$HOOKS_FILTER" ]; then
      read -r -p "Uninstall $name? [y/N] " reply
      if [[ ! "${reply:-}" =~ ^[Yy] ]]; then
        say "Skipping $name."
        continue
      fi
    fi

    tmp=$(mktemp)
    jq --arg name "$name" '
      .hooks //= {} |
      .hooks |= (
        with_entries(.value |= map(select((.hooks // []) | any(.command? // "" | endswith($name)) | not)))
        | with_entries(select(.value | length > 0))
      )
    ' "$TARGET_SETTINGS" > "$tmp"
    mv "$tmp" "$TARGET_SETTINGS"
    say "  Removed wiring for $name from $TARGET_SETTINGS"

    rm -f "$target"
    say "  Removed $target"

    if [ "$hook_dirname" = "slopscan" ]; then
      teardown_slopscan_backend
    fi
  done

  if [ "$WITH_SIGNER" = "1" ] && [ "$IS_MACOS" = "1" ]; then
    echo
    warn "macOS: claude-hookscanner doesn't support macOS yet -- skipping --with-signer."
    warn "If you installed it anyway, remove it yourself: $HOME/.local/share/claude-hookscanner"
  elif [ "$WITH_SIGNER" = "1" ]; then
    echo
    scanner_dir="$HOME/.local/share/claude-hookscanner"
    if [ -x "$scanner_dir/install.sh" ]; then
      say "Uninstalling claude-hookscanner (the HMAC signer)..."
      uninstall_args=(--uninstall)
      [ "$NONINTERACTIVE" = "1" ] && uninstall_args+=(--yes)
      (cd "$scanner_dir" && ./install.sh "${uninstall_args[@]}")
    else
      warn "claude-hookscanner not found at $scanner_dir -- can't uninstall the signer automatically."
      warn "Run its own --uninstall from wherever you installed it, if anywhere else."
    fi
  fi

  echo
  if jq -e . "$TARGET_SETTINGS" > /dev/null; then
    say "settings.json is valid JSON."
  else
    warn "$TARGET_SETTINGS failed JSON validation -- check it by hand before trusting it."
  fi
  say "Done."
  exit 0
fi

# ── 1. Signer bootstrap ─────────────────────────────────────────────────
find_sign_hook() {
  local candidate
  candidate=$(command -v sign-hook.sh 2>/dev/null) && { echo "$candidate"; return 0; }
  [ -x "$HOME/.local/bin/sign-hook.sh" ] && { echo "$HOME/.local/bin/sign-hook.sh"; return 0; }
  return 1
}

SIGN_HOOK="$(find_sign_hook || true)"
if [ -z "$SIGN_HOOK" ] && [ "$IS_MACOS" = "1" ]; then
  say "macOS: HMAC hook-signing (claude-hookscanner) isn't supported yet --"
  say "it depends on Linux-only tools (GNU date, sha256sum, bash4+). Hooks"
  say "below will install unsigned, which still works normally -- they'll"
  say "just show up as flagged findings in any hook-integrity scan until"
  say "macOS signing support ships. Follow along:"
  say "https://github.com/c0ri/claude-hookscanner"
  echo
fi
if [ -z "$SIGN_HOOK" ] && [ "$IS_MACOS" != "1" ]; then
  say "No HMAC signer (sign-hook.sh) found -- hooks will install unsigned and"
  say "show up as flagged findings in any hook-integrity scan until signed."
  echo
  if [ "$NONINTERACTIVE" != "1" ] && [ -t 0 ]; then
    read -r -p "Install claude-hookscanner now to set up signing? [y/N] " reply
  else
    reply="n"
    [ "$NONINTERACTIVE" = "1" ] && say "Non-interactive -- skipping claude-hookscanner install, hooks below will be unsigned."
  fi
  if [[ "${reply:-}" =~ ^[Yy] ]]; then
    scanner_dir="$HOME/.local/share/claude-hookscanner"
    if [ -d "$scanner_dir/.git" ]; then
      say "claude-hookscanner already cloned at $scanner_dir -- pulling latest..."
      (cd "$scanner_dir" && git pull)
    else
      say "Cloning claude-hookscanner into $scanner_dir ..."
      mkdir -p "$(dirname "$scanner_dir")"
      git clone https://github.com/c0ri/claude-hookscanner.git "$scanner_dir"
    fi
    if (cd "$scanner_dir" && ./install.sh --yes); then
      SIGN_HOOK="$(find_sign_hook || true)"
      if [ -n "$SIGN_HOOK" ]; then
        say "Signer found at: $SIGN_HOOK"
      else
        warn "claude-hookscanner installed but sign-hook.sh still wasn't found (PATH may need a new shell)."
      fi
    else
      warn "claude-hookscanner install failed -- continuing without signing."
    fi
  fi
  echo
fi

# ── 2. Prep target settings ─────────────────────────────────────────────
mkdir -p "$TARGET_HOOKS_DIR"
if [ ! -f "$TARGET_SETTINGS" ]; then
  mkdir -p "$(dirname "$TARGET_SETTINGS")"
  echo '{}' > "$TARGET_SETTINGS"
  say "Created empty $TARGET_SETTINGS"
fi
tmp=$(mktemp)
jq '.hooks //= {}' "$TARGET_SETTINGS" > "$tmp" && mv "$tmp" "$TARGET_SETTINGS"

# ── 3. Install loop ──────────────────────────────────────────────────────
for hook_dir in "$HOOKS_SRC_DIR"/*/; do
  hook_dir="${hook_dir%/}"
  hook_dirname="$(basename "$hook_dir")"
  manifest="$hook_dir/manifest.yaml"
  wiring="$hook_dir/wiring.json"
  [ -f "$manifest" ] || { warn "SKIP $hook_dir -- no manifest.yaml"; continue; }

  if ! hook_is_selected "$hook_dirname"; then
    say "SKIP $hook_dirname -- not in --hooks= list"
    continue
  fi

  name=$(manifest_get "$manifest" "name")
  status=$(manifest_get "$manifest" "status")
  requires_backend=$(manifest_get "$manifest" "requires_backend")
  setup_script=$(manifest_get "$manifest" "setup_script")
  script_src="$hook_dir/$name"

  echo
  say "== $name =="
  if [ "$status" = "stub" ] || [ "$status" = "needs-generalization" ]; then
    warn "manifest status is '$status' -- this hook isn't finished yet, installing it will fail open (no-op allow) until it is."
  fi

  if [ ! -f "$script_src" ]; then
    warn "SKIP $name -- script not found at $script_src"
    continue
  fi

  if [ "$NONINTERACTIVE" != "1" ] && [ -z "$HOOKS_FILTER" ]; then
    read -r -p "Install $name? [Y/n] " reply
    if [[ "${reply:-Y}" =~ ^[Nn] ]]; then
      say "Skipping $name."
      continue
    fi
  fi

  if [ "$requires_backend" = "true" ] && [ -n "$setup_script" ]; then
    if ! "$hook_dir/$setup_script"; then
      warn "Backend setup for $name was skipped or failed -- not installing this hook. The rest of the pack continues."
      continue
    fi
  fi

  cp "$script_src" "$TARGET_HOOKS_DIR/$name"
  chmod 755 "$TARGET_HOOKS_DIR/$name"
  say "Installed $name -> $TARGET_HOOKS_DIR/$name"

  if [ ! -f "$wiring" ]; then
    say "No wiring.json for $name -- script is in place but not registered in $TARGET_SETTINGS."
    continue
  fi

  count=$(jq 'length' "$wiring")
  for i in $(seq 0 $((count - 1))); do
    event=$(jq -r ".[$i].event" "$wiring")
    # Token-safe path rewrite: only replace the token that IS this hook's
    # filename (ends with /$name or is exactly $name) -- a blind
    # substring replace would also eat the interpreter or a leading
    # env-var assignment sharing the same quoted string.
    entry=$(jq -c --arg name "$name" --arg target "$TARGET_HOOKS_DIR/$name" '
      .entry.hooks |= map(
        .command |= (
          split(" ")
          | map(if test("(^|/)" + $name + "$") then $target else . end)
          | join(" ")
        )
      ) | .entry
    ' <(jq -c ".[$i]" "$wiring"))

    tmp=$(mktemp)
    # Match on BOTH name and exact matcher -- matching name alone would
    # wipe out a hook (like block_secret_files) registered under two
    # different matchers when processing the second wiring entry in the
    # same run.
    jq --arg event "$event" --argjson entry "$entry" --arg name "$name" '
      .hooks[$event] //= [] |
      .hooks[$event] |= (
        map(select(
          ((.matcher == $entry.matcher) and ((.hooks // []) | any(.command? // "" | endswith($name))))
          | not
        ))
      ) + [$entry]
    ' "$TARGET_SETTINGS" > "$tmp"
    mv "$tmp" "$TARGET_SETTINGS"
    matcher=$(echo "$entry" | jq -r '.matcher // "?"')
    say "  Wired into $event / matcher=$matcher"
  done

  if [ -n "$SIGN_HOOK" ]; then
    "$SIGN_HOOK" "$TARGET_HOOKS_DIR/$name"
  else
    say "  Installed unsigned (no signer available) -- $TARGET_HOOKS_DIR/$name"
  fi
done

echo
if jq -e . "$TARGET_SETTINGS" > /dev/null; then
  say "settings.json is valid JSON."
else
  warn "$TARGET_SETTINGS failed JSON validation -- check it by hand before trusting it."
fi
say "Done. Open /hooks once (or start a new session) for the settings watcher to pick up the change."
