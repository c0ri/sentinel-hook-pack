# sentinel-hook-pack

Free, local, pre-inference [Claude Code](https://claude.com/claude-code)
hooks that stop problems before they hit disk or leave your machine — the
complement to [Sentinel AI Firewall](https://sentinelaifirewall.com)'s live
`/v1/scrub` proxy. The hook pack stops what shouldn't have been typed in the
first place; Sentinel catches what gets through anyway.

Built by the team behind Sentinel AI Firewall and
[SlopScan](https://github.com/c0ri/SlopScan).

## The problem

A live network security layer (Sentinel AI Firewall included) sits in front
of the model API — it sees what goes out and what comes back. It can't see
what happens *between* those calls, on your own machine: a session reading
`.env` straight into its transcript, an assistant response about to write a
half-remembered API key into a config file, a `pip install` for a package
name that sounds plausible but doesn't exist. By the time any of that would
show up in a network layer's view, it's already on disk, already in the
transcript, or already run. These hooks run locally, before the tool call
that would do the damage completes — closer to the source, cheaper to check,
no network round-trip required.

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

**macOS:** all three hooks and `install.sh` itself work fine on macOS.
Signing doesn't yet — `claude-hookscanner` currently depends on Linux-only
tools, so on macOS `install.sh` skips the signer bootstrap automatically and
installs hooks unsigned (they still work; they just won't show as verified
in a hook-integrity scan until macOS signing support ships).

## How each hook works

### `secrets_detect`

Runs on every `Write`, `Edit`, `MultiEdit`, and `Bash` call, and looks at the
actual content about to be written or run — not just the file path.

Two detection passes: first, any `NAME=value` assignment where `NAME`
contains a sensitive keyword (`KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASS`,
`AUTH`, `CRED`, `CERT`, `PRIVATE`, `WEBHOOK`, `APIKEY` — plural and decorated
forms too, so `MY_PASSWORD=`, `password=`, and `apikeys=` all match, while a
harmless value like `StrictHostKeyChecking=no` doesn't get touched). Second,
a library of known vendor token shapes — Anthropic, OpenAI, Stripe, GitHub,
Slack, AWS, GCP, DigitalOcean, npm, Docker Hub, GitLab, Discord, HuggingFace,
Replicate, Telegram bot tokens, generic `Bearer`/`Basic` auth headers, JWTs,
PEM/SSH private key blocks, and database connection strings with embedded
credentials — so a bare secret gets caught even with no `NAME=` around it at
all.

For `Write`/`Edit`/`MultiEdit`, Claude Code lets a `PreToolUse` hook rewrite
the tool call before it runs, so the match gets redacted in place and the
call still goes through — `ANTHROPIC_API_KEY=sk-ant-api03-...` becomes
`ANTHROPIC_API_KEY=[ENV_SECRET]` on disk, nothing else about the write
changes. `Bash` has no such rewrite mechanism at that stage — only allow or
deny — so a command carrying a secret-shaped token gets blocked outright
with an explanation, rather than silently mangled.

### `block_secret_files`

Runs on `Read` and `Bash`, and blocks *reading* secret-bearing files
outright — `.env` (but not `.env.example`/`.sample`/`.template`/`.dist`), `.pem`,
`id_rsa`/`id_ed25519`, `credentials.json`, `secrets.*`, `.key`, `frp*.toml`,
`/etc/shadow`, `/etc/gshadow`, and shell rc files. The point isn't that the
file can't be touched at all — it's that dumping its *raw contents* into the
conversation transcript is what turns a local secret into something that
now lives in chat history, logs, and potentially a future response.

On `Bash`, this isn't just a filename block — it looks at what the command
actually does with a matched path. `cat .env`, `grep API_KEY .env`, and
`less .env` are blocked; `cut -d= -f1 .env` (which only ever prints key
*names*, never values) and `grep -c PATTERN .env` (a count, not the match
text) are allowed, since neither can leak an actual secret value. That
carve-out is narrow on purpose — chaining a safe command with an unsafe one
(`cut -d= -f1 .env; cat .env`) still gets blocked, because the check looks
at the whole command, not just the first clause.

### `slopscan`

Runs on `Bash`, and checks `npm`/`pnpm`/`yarn`/`pip`/`uv` install commands
(including packages listed in a `-r requirements.txt`, following nested
`-r` references) against [SlopScan](https://github.com/c0ri/SlopScan) before
they run — catching typosquats and, notably, *hallucinated* package names: a
model confidently suggesting `pip install requests-oauth-utils` when no such
package exists is a real, observed failure mode, and installing whatever a
squatter registered at that exact name is a real supply-chain risk.

This is the one hook in the pack that needs something to talk to. A command
with nothing installable in it (or one SlopScan wasn't asked about at all,
because it's not configured) is a true no-op — no output at all. Once a
package name actually gets checked, though, the result is explicit either
way: `SAFE` allows the install to proceed, `DANGEROUS` (nonexistent or
explicitly flagged packages) denies it with the reason, and `SUSPICIOUS`
asks you to confirm rather than blocking outright. If SlopScan isn't
configured or isn't reachable, this hook fails open — it never blocks an
install just because its backend is down.

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

## What this does *not* protect against

Each hook is pattern-based, and every pattern list is finite:

- `secrets_detect` catches known vendor token *shapes* and generic
  `KEY=`/`SECRET=`/etc. assignments — a custom internal secret format that
  doesn't look like any of those (no recognizable prefix, not assigned via
  `NAME=value`) can slip through. It also only sees `Write`/`Edit`/
  `MultiEdit`/`Bash` — a secret typed directly into chat as prose isn't a
  tool call at all, so this hook never sees it.
- `block_secret_files` only blocks the file *paths* and command *verbs* it
  knows about. A secret saved under a name that doesn't match any pattern
  (`prod_stuff.txt`, say) or read via a tool this hook doesn't cover isn't
  caught.
- `slopscan` is only as good as its backend's data, needs one running to do
  anything at all, and fails open when it's unreachable — by design, so a
  down backend never blocks a legitimate install, but that also means it's
  not a hard guarantee.

None of the three talk to each other or share state — each makes its own
allow/deny call independently, so a gap in one isn't covered by another.
This is defense-in-depth against common, observed failure modes, not a
completeness guarantee.

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

Only want some of the hooks? `./install.sh --hooks=secrets_detect,slopscan`
installs just the named ones (no prompt for those — naming a hook is itself
the "yes"); omit the flag to be asked about each hook individually, or
combine it with `--yes` for a fully non-interactive partial install.

Env overrides: `CLAUDE_HOOKS_DIR`, `CLAUDE_SETTINGS`.

### Uninstall

```bash
./install.sh --uninstall
```

For each installed hook, asks before removing it, then removes its wiring
from `settings.json` and its script from `~/.claude/hooks/`. Same `--yes`
and `--hooks=name1,name2` flags as install work here too — `--hooks=` skips
the prompt for the named hooks, same as it does on install.

Uninstalling `slopscan` also tears down whatever local backend `setup.sh`
set up for it — stops and removes the Docker container/image, or disables
the `systemd --user` service, or kills the background process, whichever
one is actually running — and removes the cloned SlopScan checkout and its
config/log files. It reads back what was actually configured (recorded in
`slopscan.env` at setup time) rather than guessing, so this works correctly
even with a custom `SLOPSCAN_CLONE_DIR`.

The HMAC signer (`claude-hookscanner`) is **not** touched by default, even
if you uninstall every hook — it's a shared dependency other hooks outside
this pack may rely on, so removing it is never a side effect. Pass
`--with-signer` if you want that uninstalled too:

```bash
./install.sh --uninstall --with-signer
```

## License

Apache 2.0, see `LICENSE`.
