#!/usr/bin/env python3
"""PreToolUse hook (Write/Edit/MultiEdit + Bash): redact/deny vendor-style
secret tokens before they land on disk or run in a command.

STUB -- not yet implemented. See sentinel-hook-pack's build plan, step 2
("write secrets_detect (new)"): reuse Sentinel's existing vendor-token
regex set rather than forking a second copy; Write/Edit/MultiEdit path
should redact via hookSpecificOutput.updatedInput and allow the (now
redacted) call to proceed; the Bash path can only allow/deny (no output
mutation exists at that stage), so it should deny on a high-confidence
match and explain why.

Fails open (always allows, unmodified) until real detection logic lands --
never becomes a silent block on a stub.
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
