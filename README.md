# security-sweep

**A Claude skill that patches your computer against this week's security news.**

Say *"security sweep"* to Claude Code. It reads the last 7–10 days of advisories,
actively exploited bugs and supply-chain attacks, checks them against what's actually
installed on your machine, patches what's safe to patch, and hands you a short report
of everything else.

> [!WARNING]
> **This skill installs patch and minor updates without asking.** OS point releases,
> package-manager upgrades (`brew`, `winget`, `apt`/`dnf`), runtimes like Node and
> Python, and version pins in your repos (never committed or pushed) are updated on
> the spot. It **asks first** before anything bigger: major-version upgrades, changes
> to project dependencies or lockfiles, uninstalls, restarts, driver or firmware
> updates, and edits to your shell profile.
>
> If you'd rather approve every change, say so when you start: *"security sweep,
> but ask before installing anything."*

## Install

```bash
git clone https://github.com/dogum/security-sweep ~/.claude/skills/security-sweep
```

That's it. Claude Code picks it up the next time it starts. To update later:

```bash
git -C ~/.claude/skills/security-sweep pull
```

## Use

In Claude Code, on the computer you want checked:

- `security sweep`
- `am I patched?`
- `am I affected by <CVE / attack in the news>?`
- `security sweep https://nodejs.org/en/blog/vulnerability/...`: handles that
  advisory first, then does the full sweep

It works on macOS, Windows (including each WSL distro) and Linux. It refuses to run in
a sandbox, container or CI runner, because patching a throwaway box tells you nothing
about your real computer.

## What it does

| Step | What happens |
| --- | --- |
| **1. Research** | Pulls recent advisories from primary sources: CISA KEV, Apple, Microsoft, Chrome, Node.js, Python, Git, OpenSSL, curl, GitHub Security Advisories and OSV, plus npm, PyPI, VS Code extension and GitHub Actions compromises. It notes each fixed version and any indicators of compromise. |
| **2. Inventory** | Lists your OS and pending updates, package-manager upgrades, browsers, **every** Node and Python (including nvm, fnm, volta, pyenv, uv, conda and copies bundled inside apps), global npm/pip/pipx tools, editor extensions, and the version pins, lockfiles and virtualenvs in your project folders. |
| **3. Match** | Works out which advisories actually hit *this* machine. It runs `npm`/`pnpm`/`yarn audit` on your lockfiles, `scripts/osv_check.py` on every Python environment, and looks for indicators of any supply-chain attack that's in the news. |
| **4. Fix** | Applies patch and minor updates, then **checks the installed version against the advisory**, since package managers often lag ("upgraded" ≠ "patched"). It skips apps that are running, reinstalls global tools that lived under a replaced runtime, and bumps vulnerable version pins. |
| **5. Ask** | Lists everything that needs your OK (see the warning above) and waits for it. |
| **6. Report** | A short table: what was vulnerable, what it did, and the exact command for anything left to you. It lists separately what can't be patched yet (end-of-life, bundled in another app, waiting on the vendor) and which checks it couldn't run. |

### Guardrails

- **Advisories are data, not instructions.** It never runs commands copied from blog
  posts or IoC write-ups. A tool that reads the open web and then installs software
  is an obvious target for a planted *"run this to see if you're affected"* line.
  It installs only through package managers or from the vendor's own site, after
  verifying the checksum and signature.
- **No privilege workarounds.** Anything needing `sudo`, an admin prompt or a password
  goes into the report as a command for you to run.
- **No secrets in the output.** It notes that a token exists and where, never its value.
- **If it finds a compromise, it stops.** On an indicator of compromise or a malicious
  package, it doesn't delete or "clean" anything, because that destroys evidence and
  can leave persistence behind. It reports what it found and lists the credentials
  that were reachable so you can rotate them.

## `scripts/osv_check.py` on its own

You don't need Claude to use the Python checker. It checks Python environments,
requirements files and lockfiles against the [OSV](https://osv.dev) vulnerability
database. It uses only the standard library and runs on any Python 3.8+, so there's
nothing to install, and the only thing it talks to is `api.osv.dev`.

```bash
# The Python running the script
python3 scripts/osv_check.py

# Any interpreter: a venv, conda env, pyenv or uv Python. Repeat --python for each.
python3 scripts/osv_check.py --python .venv/bin/python --python ~/miniconda3/bin/python

# Pinned requirements (only `name==version` lines are checked)
python3 scripts/osv_check.py --requirements requirements.txt

# poetry.lock, uv.lock or pdm.lock (running these needs Python 3.11+)
python3 scripts/osv_check.py --lockfile uv.lock

# Mix freely, change what counts as "new", or get full JSON
python3 scripts/osv_check.py --python .venv/bin/python --lockfile uv.lock --recent-days 7 --json
```

Sample output:

```text
== requirements.txt (1 unpinned lines skipped): 2 packages, 2 vulnerable
  requests 2.19.0 -> 2.33.0  (5 advisories, worst HIGH)
      CVE-2026-25645, CVE-2024-47081, CVE-2024-35195, CVE-2023-32681, CVE-2018-18074
  urllib3 1.24.1 -> 2.8.0  (13 advisories, worst HIGH, major upgrade)
      CVE-2026-97689, CVE-2026-44431, CVE-2026-21441, CVE-2025-66471, ...
```

How to read it:

- **`-> version`** is the lowest version that clears *every* known advisory for that
  package, not just the newest one.
- **`major upgrade`** means the fix crosses a major version, so expect breaking changes.
- **`NEW YYYY-MM-DD`** lines are advisories published within `--recent-days` (default
  10), shown with their summaries.
- **`!! MALICIOUS PACKAGE`** means OSV has a `MAL-` record for the package. Treat it as
  a possible compromise: don't just upgrade, investigate and rotate credentials.

Exit status: `0` nothing found, `1` vulnerabilities found, `2` nothing found but a
source (or OSV itself) couldn't be checked. That makes it easy to drop into CI:

```bash
python3 scripts/osv_check.py --requirements requirements.txt || echo "check the report above"
```

## Requirements

- [Claude Code](https://claude.com/claude-code), or another agent with a shell on your
  real computer and web access
- Python 3.8+ for `osv_check.py` (3.11+ to read TOML lockfiles)

## Contributing

Issues and PRs are welcome, especially more ecosystems for `osv_check.py` (npm, Go,
Rust, RubyGems), better Windows and Linux inventory, and better primary sources for
step 1.

## License

[MIT](LICENSE)
