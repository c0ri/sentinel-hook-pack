#!/bin/bash
# install.sh -- bundle installer for sentinel-hook-pack.
#
# For each hook under hooks/<name>/:
#   1. Ask before installing (unless --yes).
#   2. If it needs a backend (manifest.yaml: requires_backend: true), run
#      its setup.sh first; a decline/failure there skips just that hook
#      and continues with the rest of the pack.
#   3. Copy its script into place, merge its wiring.json into
#      settings.json (idempotent -- safe to re-run), sign it.
#
# hook_guard (HMAC signing) is not vendored here -- it's bootstrapped from
# claude-hookscanner (github.com/c0ri/claude-hookscanner), the one
# canonical copy of that logic, same pattern proven in do-hosting's
# claude-hooks installer.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_SRC_DIR="$REPO_DIR/hooks"
TARGET_HOOKS_DIR="${CLAUDE_HOOKS_DIR:-$HOME/.claude/hooks}"
TARGET_SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
export NONINTERACTIVE=0
export WITH_SLOPSCAN_DOCKER=0

for arg in "$@"; do
  case "$arg" in
    --yes|-y) NONINTERACTIVE=1 ;;
    --with-slopscan-docker) WITH_SLOPSCAN_DOCKER=1 ;;
    --help|-h)
      echo "usage: install.sh [--yes] [--with-slopscan-docker]"
      echo "Env overrides: CLAUDE_HOOKS_DIR, CLAUDE_SETTINGS"
      exit 0
      ;;
  esac
done
export NONINTERACTIVE WITH_SLOPSCAN_DOCKER

say()  { echo "==> $*"; }
warn() { echo "!!  $*" >&2; }

command -v jq >/dev/null 2>&1 || { warn "jq is required and wasn't found."; exit 1; }
command -v git >/dev/null 2>&1 || { warn "git is required and wasn't found."; exit 1; }

manifest_get() {
  # $1 = manifest.yaml path  $2 = scalar key -- only handles the flat
  # scalar fields this installer needs (name/status/fail_mode/
  # requires_backend/setup_script), not the multi-line description block.
  grep -E "^$2:" "$1" 2>/dev/null | head -1 | sed -E "s/^$2:[[:space:]]*//"
}

# ── 1. Signer bootstrap ─────────────────────────────────────────────────
find_sign_hook() {
  local candidate
  candidate=$(command -v sign-hook.sh 2>/dev/null) && { echo "$candidate"; return 0; }
  [ -x "$HOME/.local/bin/sign-hook.sh" ] && { echo "$HOME/.local/bin/sign-hook.sh"; return 0; }
  return 1
}

SIGN_HOOK="$(find_sign_hook || true)"
if [ -z "$SIGN_HOOK" ]; then
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
      [ -n "$SIGN_HOOK" ] && say "Signer found at: $SIGN_HOOK" || warn "claude-hookscanner installed but sign-hook.sh still wasn't found (PATH may need a new shell)."
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
  manifest="$hook_dir/manifest.yaml"
  wiring="$hook_dir/wiring.json"
  [ -f "$manifest" ] || { warn "SKIP $hook_dir -- no manifest.yaml"; continue; }

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

  if [ "$NONINTERACTIVE" != "1" ]; then
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
    # env-var assignment sharing the same quoted string. Same fix already
    # proven in do-hosting's claude-hooks installer.
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
    # same run. Same fix already proven in do-hosting's installer.
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
