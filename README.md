# sentinel-hook-pack

🚧 **Early scaffold — not ready to install yet.** Structure and wiring are in
place; hook logic is still being written/generalized. Don't point
`install.sh` at a real `settings.json` until this banner is gone.

Free, local, pre-inference [Claude Code](https://claude.com/claude-code)
hooks that stop problems before they hit disk or leave your machine — the
complement to [Sentinel AI Firewall](https://sentinelaifirewall.com)'s live
`/v1/scrub` proxy. The hook pack stops what shouldn't have been typed in the
first place; Sentinel catches what gets through anyway.

Built by the team behind Sentinel AI Firewall and
[SlopScan](https://github.com/c0ri/SlopScan).

## What's in the pack

| Hook | Stage | What it does |
|---|---|---|
| `secrets_detect` | `PreToolUse` on `Write`/`Edit`/`MultiEdit` and `Bash` | Redacts vendor-style secret tokens from content about to be written to disk; blocks Bash commands carrying an obvious secret-shaped token. |
| `slopscan` | `PreToolUse` on `Bash` | Checks npm/pip/uv package installs against [SlopScan](https://github.com/c0ri/SlopScan) (package-hallucination / slopsquatting detection) before they run. |
| `block_secret_files` | `PreToolUse` on `Bash` and `Read` | Blocks direct reads of secret-bearing files (`.env`, `.pem`, `id_rsa`, `/etc/shadow`, etc.) that would otherwise land raw in the transcript. |

Every hook installed by this pack is HMAC-signed via
[claude-hookscanner](https://github.com/c0ri/claude-hookscanner) — a
dependency this installer bootstraps automatically if you don't already have
a signer, not a second copy of that logic.

## What this does *not* replace

This is local, best-effort, pattern-based protection that runs before a tool
call completes. It is not:

- **Real-time enforcement across a whole conversation** — Sentinel's proxy
  inspects and scores every request/response in the loop, not just file
  writes and shell commands.
- **RAG/context poisoning defense** — these hooks look at what Claude is
  about to *do*, not at the trustworthiness of content it already read.
- **Multi-provider coverage** — this pack is Claude Code-specific; Sentinel
  sits in front of multiple model providers.

If you want that layer, that's what Sentinel AI Firewall is for. This pack
is free and stands on its own either way.

## Install

```bash
git clone https://github.com/c0ri/sentinel-hook-pack.git
cd sentinel-hook-pack
./install.sh
```

`install.sh` will:
1. Look for an HMAC signer (`sign-hook.sh` from claude-hookscanner) on your
   `PATH`; offer to install claude-hookscanner if none is found.
2. For each hook in `hooks/`, ask before installing, copy its script into
   `~/.claude/hooks/`, and merge its wiring into `~/.claude/settings.json`
   (idempotent — safe to re-run).
3. The `slopscan` hook additionally needs a backend service to query. If one
   isn't already configured, `install.sh` explains what
   [SlopScan](https://github.com/c0ri/SlopScan) is and lets you choose how to
   run it locally (`hooks/slopscan/setup.sh`) — entirely optional; declining
   just leaves that one hook out:
   - **Docker** — `docker run --restart unless-stopped`, so it survives
     crashes and reboots with no further setup. Needs Docker; offers to
     install it via Docker's own official script if it's missing on Linux
     (no unattended install on macOS/Windows — Docker Desktop needs a GUI
     installer there).
   - **Python venv + pip** — no Docker dependency at all (SlopScan itself
     needs nothing but `pip install` + `uvicorn`). On Linux this sets up a
     `systemd --user` service (`Restart=on-failure`) for you; elsewhere it's
     a plain background process you'd need to restart yourself after a
     crash or reboot.
4. Sign everything it installs.

Non-interactive: `./install.sh --yes` (accepts every prompt, and sets up
SlopScan via `--with-slopscan-docker` or `--with-slopscan-pip` if one of
those is also passed — otherwise that hook is skipped).

Env overrides: `CLAUDE_HOOKS_DIR`, `CLAUDE_SETTINGS`.

## License

Apache 2.0, see `LICENSE`.
