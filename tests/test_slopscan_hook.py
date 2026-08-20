import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

HOOK = Path(__file__).parent.parent / "hooks" / "slopscan" / "slopscan_preinstall.py"


class _FakeSlopScan(BaseHTTPRequestHandler):
    results_by_test = {}

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(length))
        results = [
            self.results_by_test.get(p["name"], {"package": p["name"], "ecosystem": p["ecosystem"], "risk": "SAFE", "found": True, "flags": []})
            for p in body["packages"]
        ]
        out = json.dumps({"results": results}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.fixture
def fake_backend():
    server = HTTPServer(("127.0.0.1", 0), _FakeSlopScan)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


def run_hook(payload: dict, env: dict | None = None) -> dict | None:
    full_env = dict(os.environ)
    full_env.pop("SLOPSCAN_URL", None)
    full_env.pop("CLAUDE_HOOKS_DIR", None)
    if env:
        full_env.update(env)
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        env=full_env,
    )
    assert proc.returncode == 0, proc.stderr
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)


def test_non_install_command_is_noop():
    result = run_hook({"tool_input": {"command": "ls -la /tmp"}, "cwd": "/tmp"})
    assert result is None


def test_no_backend_configured_fails_open(tmp_path):
    # CLAUDE_HOOKS_DIR points somewhere with no slopscan.env, and SLOPSCAN_URL unset
    result = run_hook(
        {"tool_input": {"command": "pip install requests"}, "cwd": "/tmp"},
        env={"CLAUDE_HOOKS_DIR": str(tmp_path)},
    )
    assert result is None


def test_backend_safe_result_allows_explicitly(fake_backend):
    # Unlike the other two hooks' silent no-op, this one emits an explicit
    # allow decision once packages were actually checked against a backend.
    result = run_hook(
        {"tool_input": {"command": "pip install requests"}, "cwd": "/tmp"},
        env={"SLOPSCAN_URL": fake_backend},
    )
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_backend_dangerous_denies(fake_backend):
    _FakeSlopScan.results_by_test = {
        "totally-fake-pkg": {"package": "totally-fake-pkg", "ecosystem": "pypi", "risk": "DANGEROUS", "found": False, "flags": ["nonexistent package"]}
    }
    try:
        result = run_hook(
            {"tool_input": {"command": "pip install totally-fake-pkg"}, "cwd": "/tmp"},
            env={"SLOPSCAN_URL": fake_backend},
        )
    finally:
        _FakeSlopScan.results_by_test = {}
    assert result is not None
    out = result["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "totally-fake-pkg" in out["permissionDecisionReason"]


def test_backend_suspicious_asks(fake_backend):
    _FakeSlopScan.results_by_test = {
        "sketchy-pkg": {"package": "sketchy-pkg", "ecosystem": "npm", "risk": "SUSPICIOUS", "found": True, "flags": ["new repo, low stars"]}
    }
    try:
        result = run_hook(
            {"tool_input": {"command": "npm install sketchy-pkg"}, "cwd": "/tmp"},
            env={"SLOPSCAN_URL": fake_backend},
        )
    finally:
        _FakeSlopScan.results_by_test = {}
    assert result is not None
    out = result["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask"
    assert "sketchy-pkg" in out["permissionDecisionReason"]


def test_slopscan_env_config_file_used(fake_backend, tmp_path):
    (tmp_path / "slopscan.env").write_text(f"SLOPSCAN_URL={fake_backend}\n")
    _FakeSlopScan.results_by_test = {
        "totally-fake-pkg": {"package": "totally-fake-pkg", "ecosystem": "pypi", "risk": "DANGEROUS", "found": False, "flags": ["nonexistent"]}
    }
    try:
        result = run_hook(
            {"tool_input": {"command": "pip install totally-fake-pkg"}, "cwd": "/tmp"},
            env={"CLAUDE_HOOKS_DIR": str(tmp_path)},
        )
    finally:
        _FakeSlopScan.results_by_test = {}
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_unreachable_backend_fails_open():
    result = run_hook(
        {"tool_input": {"command": "pip install requests"}, "cwd": "/tmp"},
        env={"SLOPSCAN_URL": "http://127.0.0.1:1"},
    )
    assert result is None


def test_extracts_multiple_ecosystems_from_chained_command(fake_backend):
    _FakeSlopScan.results_by_test = {
        "left-pad-clone": {"package": "left-pad-clone", "ecosystem": "npm", "risk": "DANGEROUS", "found": False, "flags": ["nonexistent"]}
    }
    try:
        result = run_hook(
            {"tool_input": {"command": "pip install requests && npm install left-pad-clone"}, "cwd": "/tmp"},
            env={"SLOPSCAN_URL": fake_backend},
        )
    finally:
        _FakeSlopScan.results_by_test = {}
    assert result is not None
    assert "left-pad-clone" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_requirements_file_is_followed(fake_backend, tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n# a comment\ntotally-fake-pkg>=1.0\n-e ./local-pkg\n")
    _FakeSlopScan.results_by_test = {
        "totally-fake-pkg": {"package": "totally-fake-pkg", "ecosystem": "pypi", "risk": "DANGEROUS", "found": False, "flags": ["nonexistent"]}
    }
    try:
        result = run_hook(
            {"tool_input": {"command": "pip install -r requirements.txt"}, "cwd": str(tmp_path)},
            env={"SLOPSCAN_URL": fake_backend},
        )
    finally:
        _FakeSlopScan.results_by_test = {}
    assert result is not None
    assert "totally-fake-pkg" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_local_path_install_not_checked(fake_backend):
    # `pip install .` / `pip install ./local-dir` has no registry name to check
    result = run_hook(
        {"tool_input": {"command": "pip install ./my-local-package"}, "cwd": "/tmp"},
        env={"SLOPSCAN_URL": fake_backend},
    )
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
