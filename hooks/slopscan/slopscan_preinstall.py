#!/usr/bin/env python3
"""PreToolUse/Bash hook: check npm/pnpm/yarn/pip/uv package installs against
a local SlopScan backend (package-hallucination / slopsquatting detection,
github.com/c0ri/SlopScan) before they run.

Reads the backend address from the SLOPSCAN_URL env var, falling back to
$CLAUDE_HOOKS_DIR/slopscan.env (default ~/.claude/hooks/slopscan.env,
written by this pack's setup.sh when it provisions a local backend). If
neither is set, or the backend doesn't respond, this fails open (silent
allow) -- a missing/unreachable SlopScan should never block an install.
"""
import json
import os
import pathlib
import re
import shlex
import sys
import urllib.error
import urllib.request

# Optional path prefix (.venv/bin/pip, /usr/bin/pip3, ./node_modules/.bin/npm, ...)
# ahead of the actual binary name -- without this, any venv-relative or
# absolute-path invocation slipped past every pattern below silently.
_PATH_PREFIX = r"(?:\S*/)?"

INSTALL_PATTERNS = [
    (re.compile(rf"^{_PATH_PREFIX}npm\s+(?:install|i|add)\b"), "npm"),
    (re.compile(rf"^{_PATH_PREFIX}pnpm\s+(?:install|i|add)\b"), "npm"),
    (re.compile(rf"^{_PATH_PREFIX}yarn\s+add\b"), "npm"),
    (re.compile(rf"^{_PATH_PREFIX}pip3?\s+install\b"), "pypi"),
    (re.compile(rf"^{_PATH_PREFIX}python3?\s+-m\s+pip\s+install\b"), "pypi"),
    (re.compile(rf"^{_PATH_PREFIX}uv\s+add\b"), "pypi"),
    (re.compile(rf"^{_PATH_PREFIX}uv\s+pip\s+install\b"), "pypi"),
]

FLAG_VALUE_TAKING = {
    "-r", "--requirement", "--index-url", "-i", "--extra-index-url",
    "--target", "-t", "--prefix", "--find-links", "-f",
}

REQUIREMENTS_FLAGS = {"-r", "--requirement"}
_MAX_REQ_FILE_BYTES = 65536
_MAX_REQ_DEPTH = 5


def split_segments(command: str) -> list[str]:
    # crude split on shell chaining — good enough for detecting install subcommands
    parts = re.split(r"&&|;|\|\|?|\n", command)
    return [p.strip() for p in parts if p.strip()]


def strip_version(pkg: str, ecosystem: str) -> str:
    if ecosystem == "npm":
        if pkg.startswith("@"):
            rest = pkg[1:]
            if "@" in rest:
                rest = rest.split("@", 1)[0]
            return "@" + rest
        return pkg.split("@", 1)[0]
    # pypi
    return re.split(r"(==|>=|<=|~=|!=|>|<|\[)", pkg, 1)[0]


def _parse_requirements_text(text: str, ecosystem: str) -> list[str]:
    packages = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-e", "--editable")):
            continue  # local/VCS editable install — not a registry name
        if line.startswith("-"):
            continue  # a pip option line (--index-url, -r other.txt, etc.), handled separately below
        line = line.split(";", 1)[0].strip()  # PEP 508 environment marker
        if not line:
            continue
        if "://" in line or line.startswith("git+"):
            continue  # VCS/URL requirement — not a registry name
        packages.append(strip_version(line, ecosystem))
    return packages


def _read_requirements_file(path: str, ecosystem: str, cwd: str, depth: int = 0) -> list[str]:
    """Read a -r/--requirement target and extract the package names it lists,
    following nested -r references up to _MAX_REQ_DEPTH. Fails silently (empty
    list) on anything unreadable/oversized -- consistent with this hook's
    fail-open posture elsewhere; a missing/bad file just means fewer packages
    get checked, not a blocked install."""
    if depth >= _MAX_REQ_DEPTH:
        return []
    try:
        p = pathlib.Path(path)
        if not p.is_absolute():
            p = pathlib.Path(cwd) / p
        if p.stat().st_size > _MAX_REQ_FILE_BYTES:
            return []
        text = p.read_text(errors="replace")
    except Exception:
        return []

    packages = _parse_requirements_text(text, ecosystem)

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        for flag in ("-r ", "--requirement "):
            if line.startswith(flag):
                nested = line[len(flag):].strip()
                if nested:
                    packages.extend(_read_requirements_file(nested, ecosystem, str(p.parent), depth + 1))
    return packages


def extract_packages(segment: str, ecosystem: str, cwd: str) -> list[str]:
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return []

    # drop the leading command tokens (npm/pip/uv ... install/add/i)
    idx = 0
    for i, tok in enumerate(tokens):
        if tok in ("install", "i", "add"):
            idx = i + 1
            break
    tokens = tokens[idx:]

    packages = []
    pending_value_flag = None
    for tok in tokens:
        if pending_value_flag is not None:
            if pending_value_flag in REQUIREMENTS_FLAGS:
                packages.extend(_read_requirements_file(tok, ecosystem, cwd))
            pending_value_flag = None
            continue
        if tok.startswith("-"):
            flag_part, sep, value_part = tok.partition("=")
            if sep and flag_part in FLAG_VALUE_TAKING:
                if flag_part in REQUIREMENTS_FLAGS:
                    packages.extend(_read_requirements_file(value_part, ecosystem, cwd))
                continue
            if tok in FLAG_VALUE_TAKING:
                pending_value_flag = tok
            continue
        if re.match(r"^&?\d*(>>?|<)", tok):
            continue  # shell redirection (e.g. "2>&1", "2>/dev/null", ">out.log") — not a package name
        if tok.startswith(".") or tok.startswith("/") or "://" in tok or tok.startswith("git+"):
            continue  # local path / URL / VCS ref — not a registry name SlopScan can check
        if tok.endswith((".txt", ".whl", ".tar.gz", ".cfg", ".toml")):
            continue
        packages.append(strip_version(tok, ecosystem))
    return packages


def collect_targets(command: str, cwd: str) -> list[dict]:
    targets = []
    seen = set()
    for segment in split_segments(command):
        for pattern, ecosystem in INSTALL_PATTERNS:
            if pattern.match(segment):
                for pkg in extract_packages(segment, ecosystem, cwd):
                    key = (ecosystem, pkg)
                    if key not in seen:
                        seen.add(key)
                        targets.append({"ecosystem": ecosystem, "name": pkg})
                break
    return targets


def _slopscan_url() -> str | None:
    url = os.environ.get("SLOPSCAN_URL")
    if url:
        return url.rstrip("/")

    hooks_dir = pathlib.Path(os.environ.get("CLAUDE_HOOKS_DIR", pathlib.Path.home() / ".claude" / "hooks"))
    config_file = hooks_dir / "slopscan.env"
    try:
        for line in config_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("SLOPSCAN_URL="):
                return line.split("=", 1)[1].strip().rstrip("/")
    except Exception:
        pass

    return None


def query_slopscan(packages: list[dict]) -> list[dict] | None:
    if not packages:
        return None
    url = _slopscan_url()
    if not url:
        return None  # not configured — fail open, this hook is a no-op until setup.sh runs

    packages = packages[:20]
    payload = json.dumps({"packages": packages}).encode("utf-8")
    request = urllib.request.Request(
        f"{url}/check/batch",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body["results"]
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError, OSError):
        return None  # backend unreachable/misbehaving — fail open, don't block installs on network issues


def allow(message: str | None = None):
    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}
    if message:
        out["systemMessage"] = message
    print(json.dumps(out))
    sys.exit(0)


def ask(reason: str):
    print(json.dumps({
        "systemMessage": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        },
    }))
    sys.exit(0)


def deny(reason: str):
    print(json.dumps({
        "systemMessage": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }))
    sys.exit(0)


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # can't parse — don't block

    command = data.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)
    cwd = data.get("cwd", ".")

    targets = collect_targets(command, cwd)
    if not targets:
        sys.exit(0)  # not an install command, or no checkable package names found

    results = query_slopscan(targets)
    if results is None:
        sys.exit(0)  # SlopScan not configured or unreachable — fail open

    dangerous = [r for r in results if r.get("risk") == "DANGEROUS" or r.get("found") is False]
    suspicious = [r for r in results if r.get("risk") == "SUSPICIOUS"]

    if dangerous:
        names = ", ".join(r.get("package", "?") for r in dangerous)
        flags = "; ".join(f for r in dangerous for f in r.get("flags", []))
        deny(f"[slopscan] BLOCKED — dangerous/nonexistent package(s): {names}. {flags}")
        return

    if suspicious:
        names = ", ".join(r.get("package", "?") for r in suspicious)
        flags = "; ".join(f for r in suspicious for f in r.get("flags", []))
        ask(f"[slopscan] Suspicious package(s) flagged: {names}. {flags}")
        return

    allow()


if __name__ == "__main__":
    main()
