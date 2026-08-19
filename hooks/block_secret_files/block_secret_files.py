#!/usr/bin/env python3
"""PreToolUse hook (Bash + Read): block direct access to secret-bearing
files so raw secret material never lands in the transcript.

STUB -- not yet promoted. See sentinel-hook-pack's build plan, step 2:
port the path-pattern/verb matching logic from the fleet-local original
as-is (it's already generic), but rewrite the docstring to drop real
incident/service names -- generic "prompted by real credential leaks via
Read/cat on secret-bearing files" framing only, nothing fleet-specific.

Fails open (always allows) until the real matching logic lands.
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
