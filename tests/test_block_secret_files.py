import json
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).parent.parent / "hooks" / "block_secret_files" / "block_secret_files.py"


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


def test_read_env_file_denied():
    result = run_hook({"tool_name": "Read", "tool_input": {"file_path": "/root/.env"}})
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_read_env_example_allowed():
    result = run_hook({"tool_name": "Read", "tool_input": {"file_path": "/root/.env.example"}})
    assert result is None


def test_read_ordinary_file_allowed():
    result = run_hook({"tool_name": "Read", "tool_input": {"file_path": "/root/README.md"}})
    assert result is None


def test_bash_cat_env_denied():
    result = run_hook({"tool_name": "Bash", "tool_input": {"command": "cat /root/.env"}})
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bash_cut_key_only_allowed():
    result = run_hook({"tool_name": "Bash", "tool_input": {"command": "cut -d= -f1 /root/.env"}})
    assert result is None


def test_bash_cut_value_field_denied():
    result = run_hook({"tool_name": "Bash", "tool_input": {"command": "cut -d= -f2 /root/.env"}})
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bash_grep_count_flag_allowed():
    result = run_hook({"tool_name": "Bash", "tool_input": {"command": "grep -c API_KEY /root/.env"}})
    assert result is None


def test_bash_grep_bare_denied():
    result = run_hook({"tool_name": "Bash", "tool_input": {"command": "grep API_KEY /root/.env"}})
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bash_chained_cut_then_cat_denied():
    # A safe cut-key-only clause chained with an unsafe cat must still deny —
    # regression guard for the segment-scoped carve-out.
    result = run_hook({"tool_name": "Bash", "tool_input": {"command": "cut -d= -f1 /root/.env; cat /root/.env"}})
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bash_ordinary_command_allowed():
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
