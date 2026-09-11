from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).parent.parent / "hooks" / "secrets_detect" / "secrets_detect.py"


def run_hook(payload: dict) -> dict | None:
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)


def test_write_redacts_env_secret_and_allows():
    result = run_hook({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/tmp/x.env",
            "content": "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD\nSTRICT=no\n",
        },
    })
    assert result is not None
    out = result["hookSpecificOutput"]
    assert out["permissionDecision"] == "allow"
    redacted = out["updatedInput"]["content"]
    assert "sk-ant-" not in redacted
    assert "ANTHROPIC_API_KEY=[ENV_SECRET]" in redacted
    assert "STRICT=no" in redacted  # benign value untouched


def test_write_known_shape_without_assignment_context():
    result = run_hook({
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/x.py", "content": 'TOKEN = "ghp_' + "a" * 36 + '"'},
    })
    assert result is not None
    redacted = result["hookSpecificOutput"]["updatedInput"]["content"]
    assert "[GITHUB_TOKEN]" in redacted
    assert "ghp_" not in redacted


def test_write_ignores_key_shaped_python_kwargs():
    # sort_keys=True / key=[ENV_SECRET] are ordinary code, not env-style secret
    # assignments -- the value is too short/wrong-shaped to be a real
    # secret, and an unbounded \S+ here used to swallow trailing syntax
    # (e.g. "True))") and corrupt the file.
    result = run_hook({
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/tmp/x.py",
            "content": (
                "path.write_text(json.dumps(data, indent=2, sort_keys=[ENV_SECRET]
                "rows.sort(key=[ENV_SECRET] r: (r['cmd'], r['ip']))\n"
            ),
        },
    })
    assert result is None


def test_write_does_not_merge_across_a_second_equals():
    # the value charset allows a trailing "=" or "==" for base64 padding,
    # but must not let a match span into an unrelated second "name=value"
    # pair that happens to follow closely.
    result = run_hook({
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/x.py", "content": "print(key, sort_keys=True)"},
    })
    assert result is None


def test_write_no_secret_is_silent_noop():
    result = run_hook({
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/x.txt", "content": "just some normal text, nothing secret here"},
    })
    assert result is None


def test_edit_redacts_new_string():
    result = run_hook({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "/tmp/x.py",
            "old_string": "OLD",
            "new_string": "STRIPE_SECRET_KEY=sk_live_" + "a" * 24,
        },
    })
    assert result is not None
    updated = result["hookSpecificOutput"]["updatedInput"]
    assert updated["old_string"] == "OLD"
    assert "[ENV_SECRET]" in updated["new_string"] or "[STRIPE_KEY]" in updated["new_string"]
    assert "sk_live_" not in updated["new_string"]


def test_multi_edit_redacts_only_offending_edits():
    result = run_hook({
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": "/tmp/x.py",
            "edits": [
                {"old_string": "A", "new_string": "totally fine"},
                {"old_string": "B", "new_string": "AWS_ACCESS_KEY_ID=AKIA" + "A" * 16},
            ],
        },
    })
    assert result is not None
    edits = result["hookSpecificOutput"]["updatedInput"]["edits"]
    assert edits[0]["new_string"] == "totally fine"
    assert "AKIA" not in edits[1]["new_string"]


def test_bash_denies_on_secret_shaped_token():
    result = run_hook({
        "tool_name": "Bash",
        "tool_input": {"command": 'curl -H "Authorization: Bearer sk-ant-api03-' + "a" * 30 + '" https://api.anthropic.com'},
    })
    assert result is not None
    out = result["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "anthropic_key" in out["permissionDecisionReason"]


def test_bash_allows_ordinary_command():
    result = run_hook({"tool_name": "Bash", "tool_input": {"command": "ls -la /tmp"}})
    assert result is None


def test_malformed_stdin_fails_open():
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input="not json",
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""
