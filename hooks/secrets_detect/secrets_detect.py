#!/usr/bin/env python3
"""PreToolUse hook (Write/Edit/MultiEdit + Bash): redact/deny vendor-style
secret tokens before they land on disk or run in a command.

Write/Edit/MultiEdit: redacts secret-shaped values in place via
hookSpecificOutput.updatedInput before the write ever touches disk -- the
call still proceeds, just with the secret replaced by a placeholder like
[ANTHROPIC_KEY] or [ENV_SECRET].

Bash: PreToolUse only sees the command string, and there is no
output-mutation mechanism at that stage -- so a high-confidence
secret-shaped token in a command denies the call outright instead of trying
to rewrite it.

Detection logic (SecretDetector below) is a hand-synced copy of Sentinel
Engine's secret_detector.py -- inlined here (rather than imported) because
this pack's installer copies one file per hook, and vendored (rather than a
package dependency) so this hook has zero install-time dependencies of its
own. If the upstream patterns change, re-sync by hand.
"""
import json
import re
import sys
from dataclasses import dataclass


@dataclass
class SecretResult:
    hits: list[tuple[str, str]]  # [(secret_type, matched_value), ...]
    redacted_text: str


class SecretDetector:
    """Detects and redacts leaked API keys, tokens, and credentials.

    Two detection passes (env var assignments first, then known shapes):

    Pass 1 -- Env var assignments (case-insensitive). Catches lines like
    STRIPE_SECRET_KEY=sk_live_... and redacts the value while preserving
    the variable name: STRIPE_SECRET_KEY=[ENV_SECRET]. Sensitive keywords:
    KEY, SECRET, TOKEN, PASSWORD, PASS, AUTH, CRED, CERT, PRIVATE, WEBHOOK,
    APIKEY. A name that is exactly the keyword matches too (plural
    allowed).

    Values in _BENIGN_VALUES are left alone -- otherwise every SSH option
    with "Key" in its name (StrictHostKeyChecking=no) would have its value
    replaced, for no security benefit.

    Pass 2 -- Known API key shapes (most-specific to least-specific).
    Catches bare secrets even without an assignment context. Order
    matters: sk-ant- and sk-proj- must fire before the generic sk-
    pattern. Pass 2 runs on the already-redacted text so env-var hits from
    pass 1 never double-fire in pass 2.
    """

    _SENSITIVE = r'KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|CRED|CERT|PRIVATE|WEBHOOK|APIKEY'

    _ENV_SECRET = re.compile(
        rf'((?:[A-Z][A-Z0-9_]*(?:{_SENSITIVE})[A-Z0-9_]*|(?:{_SENSITIVE})S?)=)(\S+)',
        re.IGNORECASE,
    )

    _BENIGN_VALUES = frozenset({
        'yes', 'no', 'true', 'false', 'on', 'off',
        'none', 'null', 'auto', 'default', 'accept-new',
        '0', '1',
    })

    _KNOWN: list[tuple[re.Pattern, str, str]] = [
        (re.compile(r'sk-ant-[a-zA-Z0-9\-_]{20,}'),       '[ANTHROPIC_KEY]',  'anthropic_key'),
        (re.compile(r'sk-proj-[a-zA-Z0-9\-_]{20,}'),      '[OPENAI_KEY]',     'openai_key'),
        (re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),         '[STRIPE_KEY]',     'stripe_key'),
        (re.compile(r'sk_test_[a-zA-Z0-9]{24,}'),         '[STRIPE_KEY]',     'stripe_key'),
        (re.compile(r'sk-[a-zA-Z0-9]{48}'),               '[OPENAI_KEY]',     'openai_key'),
        (re.compile(r'ghp_[a-zA-Z0-9]{36}'),              '[GITHUB_TOKEN]',   'github_token'),
        (re.compile(r'github_pat_[a-zA-Z0-9_]{82}'),      '[GITHUB_TOKEN]',   'github_token'),
        (re.compile(r'gho_[a-zA-Z0-9]{36}'),              '[GITHUB_TOKEN]',   'github_token'),
        (re.compile(r'gh[us]_[a-zA-Z0-9]{36}'),           '[GITHUB_TOKEN]',   'github_token'),
        (re.compile(r'ghr_[a-zA-Z0-9]{76}'),              '[GITHUB_TOKEN]',   'github_token'),
        (re.compile(r'xox[baprs]-[\d]+-[\da-zA-Z\-]+'),   '[SLACK_TOKEN]',    'slack_token'),
        (re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Z]{8,10}/B[0-9A-Z]{8,10}/[0-9A-Za-z]{24}'),
                                                           '[SLACK_WEBHOOK]',  'slack_webhook'),
        (re.compile(r'AKIA[0-9A-Z]{16}'),                 '[AWS_ACCESS_KEY]', 'aws_access_key'),
        (re.compile(r'Bearer\s+[A-Za-z0-9\-_.]{20,}'),   'Bearer [BEARER_TOKEN]', 'bearer_token'),
        (re.compile(r'(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}'),
                                                          'Authorization: Basic [BASIC_AUTH]', 'basic_auth'),
        (re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}'),      '[TELEGRAM_BOT_TOKEN]', 'telegram_bot_token'),
        (re.compile(r'rk_live_[a-zA-Z0-9]{24,}'),         '[STRIPE_KEY]',     'stripe_key'),
        (re.compile(r'dop_v1_[a-f0-9]{64}'),              '[DIGITALOCEAN_TOKEN]', 'digitalocean_token'),
        (re.compile(r'doo_v1_[a-f0-9]{64}'),              '[DIGITALOCEAN_TOKEN]', 'digitalocean_token'),
        (re.compile(r'AIza[0-9A-Za-z\-_]{35}'),           '[GCP_API_KEY]',    'gcp_api_key'),
        (re.compile(r'npm_[A-Za-z0-9]{36}'),              '[NPM_TOKEN]',      'npm_token'),
        (re.compile(r'dckr_pat_[A-Za-z0-9_\-]{27}'),      '[DOCKERHUB_TOKEN]', 'dockerhub_token'),
        (re.compile(r'glpat-[A-Za-z0-9\-_]{20}'),         '[GITLAB_TOKEN]',   'gitlab_token'),
        (re.compile(r'[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}'),
                                                           '[DISCORD_TOKEN]',  'discord_token'),
        (re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{60,}'),
                                                           '[DISCORD_WEBHOOK]', 'discord_webhook'),
        (re.compile(r'hf_[A-Za-z0-9]{34,39}'),            '[HUGGINGFACE_TOKEN]', 'huggingface_token'),
        (re.compile(r'r8_[A-Za-z0-9]{40}'),               '[REPLICATE_TOKEN]', 'replicate_token'),
        (re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
                                                           '[JWT]',            'jwt'),
        (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.DOTALL),
                                                           '[PRIVATE_KEY]',    'private_key'),
        (re.compile(r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^:/\s]+:[^@/\s]+@[^\s'\"]+"),
                                                           '[CONNECTION_STRING]', 'connection_string'),
    ]

    def scan(self, text: str) -> SecretResult:
        hits: list[tuple[str, str]] = []
        redacted = text

        for m in self._ENV_SECRET.finditer(text):
            value = m.group(2)
            if value.lower() in self._BENIGN_VALUES:
                continue
            full_match = m.group(0)
            name_eq = m.group(1)
            hits.append(('env_secret', full_match))
            redacted = redacted.replace(full_match, name_eq + '[ENV_SECRET]', 1)

        for pattern, placeholder, type_name in self._KNOWN:
            for m in pattern.finditer(redacted):
                matched = m.group()
                hits.append((type_name, matched))
                redacted = redacted.replace(matched, placeholder, 1)

        return SecretResult(hits=hits, redacted_text=redacted)


_detector = SecretDetector()


def _allow(updated_input=None):
    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}
    if updated_input is not None:
        out["hookSpecificOutput"]["updatedInput"] = updated_input
    print(json.dumps(out))
    sys.exit(0)


def _deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def _handle_write(tool_input):
    content = tool_input.get("content", "")
    if not content:
        return
    result = _detector.scan(content)
    if not result.hits:
        return
    updated = dict(tool_input)
    updated["content"] = result.redacted_text
    _allow(updated)


def _handle_edit(tool_input):
    new_string = tool_input.get("new_string", "")
    if not new_string:
        return
    result = _detector.scan(new_string)
    if not result.hits:
        return
    updated = dict(tool_input)
    updated["new_string"] = result.redacted_text
    _allow(updated)


def _handle_multi_edit(tool_input):
    edits = tool_input.get("edits") or []
    if not edits:
        return
    any_hit = False
    new_edits = []
    for edit in edits:
        new_string = edit.get("new_string", "")
        if new_string:
            result = _detector.scan(new_string)
            if result.hits:
                any_hit = True
                edit = dict(edit)
                edit["new_string"] = result.redacted_text
        new_edits.append(edit)
    if not any_hit:
        return
    updated = dict(tool_input)
    updated["edits"] = new_edits
    _allow(updated)


def _handle_bash(tool_input):
    command = tool_input.get("command", "")
    if not command:
        return
    result = _detector.scan(command)
    if not result.hits:
        return
    types = ", ".join(sorted({t for t, _ in result.hits}))
    _deny(
        f"Blocked: command contains what looks like a live secret ({types}). "
        "PreToolUse can only allow or deny a Bash command, not redact it in "
        "place -- remove the literal secret from the command (read it from an "
        "env var the shell expands instead of hardcoding it) and retry."
    )


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input", {}) or {}

    if tool_name == "Write":
        _handle_write(tool_input)
    elif tool_name == "Edit":
        _handle_edit(tool_input)
    elif tool_name == "MultiEdit":
        _handle_multi_edit(tool_input)
    elif tool_name == "Bash":
        _handle_bash(tool_input)

    sys.exit(0)


if __name__ == "__main__":
    main()
