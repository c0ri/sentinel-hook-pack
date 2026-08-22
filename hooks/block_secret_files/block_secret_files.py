#!/usr/bin/env python3
"""PreToolUse hook (Bash + Read): deny access to files that dump raw secrets
into the transcript.

Reading a secret-bearing file's raw contents (via `Read`, or `cat`/`grep`/etc.
in `Bash`) puts that secret straight into the conversation transcript, which
has caused real credential leaks and required rotating live keys. Memory-based
"don't do this" rules depend on being recalled every session, forever -- this
makes it structurally impossible instead.
"""
import json
import re
import sys

SECRET_PATH_PATTERNS = [
    r'(^|/)\.env(\.(?!example$|sample$|template$|dist$)[A-Za-z0-9_-]+)?$',
    r'(^|/)id_rsa(?!\.pub$)([.-][A-Za-z0-9_-]+)?$',
    r'(^|/)id_ed25519(?!\.pub$)([.-][A-Za-z0-9_-]+)?$',
    r'\.pem$',
    r'(^|/)credentials\.json$',
    r'(^|/)secrets\.[A-Za-z0-9]+$',
    r'\.key$',
    r'(^|/)frp\w*\.toml$',
    r'(^|/)etc/shadow$',
    r'(^|/)etc/gshadow$',
    r'(^|/)\.bashrc$',
    r'(^|/)\.bash_profile$',
    r'(^|/)\.profile$',
    r'(^|/)\.zshrc$',
]

DANGEROUS_VERBS = re.compile(r'\b(cat|head|tail|sed|less|more|od|xxd|hexdump|strings|awk|nl|tac)\b')
GREP_WORD = re.compile(r'\bgrep\b')
GREP_C_FLAG = re.compile(r'\bgrep\b[^|;&]*(-[A-Za-z]*c[A-Za-z]*)\b')

# Narrow carve-out: `cut -d= -f1 <secret-file>` only ever emits KEY names (the text
# before "="), never values -- so a pipeline segment matching this exactly is safe
# regardless of what happens downstream (e.g. `cut -d= -f1 .env | grep -i from` can't
# leak a value, since grep never sees one). Field selector must be exactly "1", not a
# range or list like "1,2"/"1-3" (the negative lookahead blocks those), since anything
# beyond field 1 can include the value.
CUT_KEY_ONLY_SEGMENT = re.compile(
    r"""\bcut\b(?=.*(-d\s*=|-d\s*['"]=['"]))(?=.*-f\s*1\b(?![,\-]))"""
)
# `cut` was never in DANGEROUS_VERBS, so e.g. `cut -d= -f2 .env` (the VALUE field) was
# never actually blocked by the verb list below -- only caught here, explicitly, when
# a secret-path segment uses cut in any form OTHER than the safe key-only pattern above.
CUT_WORD = re.compile(r'\bcut\b')


def is_secret_path(path):
    # Patterns below are anchored on "/" as the separator. Claude Code's Read
    # tool passes file_path in native OS form -- backslash-separated on
    # Windows -- so without this normalization every pattern silently fails
    # to match there. A no-op on Linux/macOS, where Read never passes
    # backslash-separated paths.
    path = path.strip().replace('\\', '/')
    return any(re.search(pat, path, re.IGNORECASE) for pat in SECRET_PATH_PATTERNS)


def _segment_candidates(seg):
    tokens = re.findall(r'[^\s|;&]+', seg)
    return [t.strip('\'"') for t in tokens if is_secret_path(t.strip('\'"'))]


def bash_command_blocked_path(cmd):
    # Split into pipeline/sequential-command segments (same separator set the
    # original tokenizer treated as boundaries) so the cut-key-only carve-out below
    # only ever applies to a segment that is EXCLUSIVELY that safe pattern -- not to
    # `cut -d= -f1 .env; cat .env`, where a substring match on the first clause would
    # otherwise wrongly cover the unsafe second clause chained after it.
    segments = re.split(r'[|;&]+', cmd)
    secret_segments = [(seg, _segment_candidates(seg)[0]) for seg in segments if _segment_candidates(seg)]

    if not secret_segments:
        return None

    if all(CUT_KEY_ONLY_SEGMENT.search(seg) for seg, _ in secret_segments):
        return None

    if any(CUT_WORD.search(seg) and not CUT_KEY_ONLY_SEGMENT.search(seg) for seg, _ in secret_segments):
        return next(path for seg, path in secret_segments if CUT_WORD.search(seg) and not CUT_KEY_ONLY_SEGMENT.search(seg))

    has_dangerous_verb = bool(DANGEROUS_VERBS.search(cmd))
    grep_dangerous = bool(GREP_WORD.search(cmd)) and not bool(GREP_C_FLAG.search(cmd))

    if has_dangerous_verb or grep_dangerous:
        return secret_segments[0][1]
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    tool_name = data.get('tool_name')
    tool_input = data.get('tool_input', {}) or {}

    blocked_path = None
    if tool_name == 'Read':
        fp = tool_input.get('file_path', '') or ''
        if is_secret_path(fp):
            blocked_path = fp
    elif tool_name == 'Bash':
        cmd = tool_input.get('command', '') or ''
        blocked_path = bash_command_blocked_path(cmd)

    if blocked_path:
        result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"Blocked: '{blocked_path}' matches a secret-bearing file pattern "
                    "(.env/.pem/id_rsa/id_ed25519/credentials.json/secrets.*/.key/frp*.toml, "
                    "/etc/shadow, /etc/gshadow). "
                    "Reading raw contents of this kind of file into the transcript has caused "
                    "real credential leaks before and required rotating multiple live keys. "
                    "Use presence/format-only checks instead: `cut -d= -f1 <file>` to list key "
                    "names, `grep -c PATTERN <file>` to check presence/count (not bare grep), "
                    "`file <file>` for encoding. To compare a value, read it internally in a "
                    "script and print only a boolean or a few masked characters, never the raw "
                    "value."
                ),
            }
        }
        print(json.dumps(result))

    sys.exit(0)


if __name__ == '__main__':
    main()
