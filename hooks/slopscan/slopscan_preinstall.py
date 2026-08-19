#!/usr/bin/env python3
"""PreToolUse/Bash hook: check npm/pip/uv package installs against SlopScan
before they run.

STUB -- not yet promoted. See sentinel-hook-pack's build plan, step 2: the
command-parsing logic (INSTALL_PATTERNS, extract_packages, requirements-
file following, shell-redirection-token guard) ports over from the fleet
original as-is. What has to change is the backend address -- read it from
SLOPSCAN_URL (env var) or ~/.claude/hooks/slopscan.env (written by
setup.sh), default to http://127.0.0.1:8765 only as a last resort, and
fail open (silent allow) if unset/unreachable, same as the fleet original.

Fails open (always allows) until the real logic + config lookup lands.
"""
import json
import sys


def main() -> None:
    try:
        json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        pass
    # Stub: no detection logic yet -- explicit no-op allow, not a bug.
    sys.exit(0)


if __name__ == "__main__":
    main()
