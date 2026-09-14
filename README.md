# agentscan

Static security scanner for AI-agent configuration. Point it at a repo and it
flags the misconfigurations that turn a coding agent into a liability: MCP
servers that are remote code execution by design, permission bypass flags,
wildcard tool grants, auto-run hooks, leaked API keys, and `CLAUDE.md` rules
that tell the model to obey untrusted content.

No API keys. No network calls. No dependencies. Pure static analysis of files
you already have. Runs in well under a second on a normal repo.

```
$ agentscan .

 CRITICAL AS001  permissions.defaultMode set to bypassPermissions
          .claude/settings.json:3
          fix: Use 'default' or 'acceptEdits'; never ship bypassPermissions.
 CRITICAL AS001  MCP server 'shell' executes an arbitrary shell command
          .mcp.json:4
 CRITICAL AS004  Hardcoded secret (Anthropic API key)
          .claude/settings.json:14
 HIGH     AS002  MCP filesystem server rooted at a broad path (/Users/dev)
 ...
Summary: CRITICAL:6  HIGH:2  MEDIUM:8
```

## Why

Agent configs are becoming an attack surface nobody scans. A single
`.mcp.json` can hand a model shell access; a `CLAUDE.md` can instruct it to run
whatever a scraped web page tells it to. These files sail through normal code
review because they don't look like code. `agentscan` gives them a linter.

## Install

```bash
pip install agentscan      # once published to PyPI
# or, from source:
pipx install .
```

## Usage

```bash
agentscan .                          # scan the current repo
agentscan path/to/project            # scan a directory
agentscan .mcp.json                  # scan a single file
agentscan . --format json            # machine-readable
agentscan . --format markdown -o report.md
agentscan . --min-severity HIGH      # hide the noise
agentscan . --fail-on CRITICAL       # CI gate: non-zero exit on criticals
```

Exit code is non-zero when a finding at or above `--fail-on` (default `HIGH`)
is present, so it drops straight into CI.

```yaml
# .github/workflows/agent-security.yml
- run: pipx run agentscan . --fail-on HIGH
```

## What it detects

| Rule | Severity | What it catches |
|------|----------|-----------------|
| AS001 | Critical | Permission bypass (`bypassPermissions`, `--dangerously-skip-permissions`), wildcard `Bash(*)`, shell-command MCP servers |
| AS002 | High | MCP filesystem server rooted at `/`, `$HOME`, or a user home |
| AS003 | High | Hooks that auto-run shell commands on tool events |
| AS004 | Critical | Hardcoded API keys / tokens in agent config (redacted in output) |
| AS005 | Medium | Instruction files that disable human confirmation ("without asking", "auto-approve") |
| AS006 | Medium | External content routed to actions with no injection boundary |
| AS007 | Medium | Unpinned `npx -y` MCP packages; remote MCP endpoints |
| AS008 | Medium | Wildcard tool permissions |
| AS009 | Medium | `alwaysAllow` / `autoApprove` MCP tool lists |

Covers Claude Code (`CLAUDE.md`, `.claude/settings.json`, `.mcp.json`),
`claude_desktop_config.json`, Cursor, Cline/Roo, Windsurf, and Copilot
instruction files.

## agentscan Pro

The open-source core catches the common, high-severity mistakes. **Pro** adds
the rule packs teams asked for:

- Expanded MCP threat rules (30+ known-risky server patterns, supply-chain checks)
- Ready-to-drop **GitHub Action** with PR annotations and a security gate
- HTML report template for audits and client deliverables
- The 20-page agent-config threat model the rules are built on

One-time purchase, no subscription → **[get Pro](https://ppradyoth.gumroad.com/l/agentscan-pro)**

If this tool saved you an incident, [sponsor the work](https://github.com/sponsors/ppradyoth).

## License

MIT. Use it, ship it, fold it into your pipeline.
