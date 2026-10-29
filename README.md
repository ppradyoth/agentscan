# AI Agent Scan

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
pipx install git+https://github.com/ppradyoth/agentscan
```

## Usage

```bash
agentscan .                          # scan the current repo
agentscan path/to/project            # scan a directory
agentscan .mcp.json                  # scan a single file
agentscan . --format json            # machine-readable
agentscan . --format markdown -o report.md
agentscan . --min-severity HIGH      # hide the noise
agentscan . --min-confidence medium  # drop low-confidence heuristics
agentscan . --format sarif -o agentscan.sarif   # GitHub code scanning
agentscan . --fail-on CRITICAL       # CI gate: non-zero exit on criticals
```

Exit code is non-zero when a finding at or above `--fail-on` (default `HIGH`)
is present, so it drops straight into CI.

```yaml
# .github/workflows/agent-security.yml
- run: pip install git+https://github.com/ppradyoth/agentscan
- run: agentscan . --fail-on HIGH
```

## What it detects

| Rule | Severity | What it catches |
|------|----------|-----------------|
| AS001 | Critical / High | Permission bypass (`bypassPermissions`, `--dangerously-skip-permissions`), unrestricted `Bash`/`*` grants, interpreter, package-runner and shell-escape grants (`Bash(python:*)`, `Bash(npx:*)`, `Bash(find:*)`), MCP servers that expose a shell |
| AS002 | High | MCP filesystem server rooted at `/`, `$HOME`, a user home, a drive root |
| AS003 | High / Low | Hooks that `eval` dynamic input or pipe fetched code into a shell (High); other committed hooks, including ones that only read tool input, are Low |
| AS004 | Critical / High / Medium | Hardcoded credentials: provider-format keys (Anthropic, OpenAI, OpenRouter, GitHub, Slack, Notion, Context7, AWS, ...), credential-named fields with high-entropy values, credentials in URLs, private keys. Redacted in output |
| AS005 | Low | Instruction files that disable human confirmation (negation-aware, skips code fences) |
| AS006 | Low | External content routed to actions with no injection boundary (heuristic) |
| AS007 | Medium / Info | MCP servers launched from an unpinned package or image (`npx -y`, `bunx`, `uvx`, `pipx`, `docker run`; floating tags such as `@latest` and version ranges count as unpinned). Remote endpoints are Info |
| AS008 | Medium / Low | Wildcard tool permissions (`WebFetch(*)`, `Write(*)`); read-only wildcards are ignored |
| AS009 | Medium / Low | `alwaysAllow` / `autoApprove` lists; Medium only when a tool name implies side effects |
| AS010 | High / Info | MCP server over an unencrypted transport (`http://`, `ws://`); private-network and container hosts are Info |
| AS011 | Medium | `enableAllProjectMcpServers: true` (auto-trusts MCP servers a cloned repo declares) |
| AS012 | High | Invisible or bidirectional Unicode in instruction files and skills (rules-file backdoor) |
| AS013 | High | Skills, commands and agents whose `allowed-tools` pre-approve arbitrary execution |
| AS014 | Medium / Low | Project settings that run a command at session start (`apiKeyHelper`, `statusLine`, AWS helpers) or register extra plugin marketplaces |

Covers Claude Code (`CLAUDE.md`, `.claude/settings*.json`, `.mcp.json`, skills, commands, agents,
plugin `hooks.json`), Claude Desktop, Cursor (`mcp.json`, `.cursor/rules/*.mdc`), VS Code (`servers`,
`mcp.servers`), Cline/Roo, Windsurf, Gemini CLI, Codex (`config.toml`), Zed (`context_servers`),
Continue (list-style `mcpServers`), opencode (`mcp`, array `command`), Amazon Q, Kiro (`steering`),
and Copilot/AGENTS/guidelines instruction files. JSON with comments and trailing commas is parsed.
Backup copies (`*.bak`, `*.orig`, `~`) are scanned at full severity and marked `context: backup`,
because they still leak secrets; `.example`, `.template` and `.dist` copies are treated as fixtures.

### Confidence and context

Every finding carries a `confidence` (`high`, `medium`, `low`). File-level, structural checks
(unpinned launchers, interpreter grants, provider-format secrets, hidden Unicode) are `high`.
Prose rules and generic credential-field matches are `low` or `medium`. Filter with
`--min-confidence medium`.

Findings in paths that look like tests, fixtures, examples, docs, datasets or templates are
reported as `INFO` with `context: fixture`, so sample configs do not fail your CI. Use
`--include-fixtures` to see them at full severity. Only known agent config locations are
scanned by default; `--all-files` scans every JSON and YAML file.

### Known limits

- Static and heuristic: it reads files, it does not run servers or check whether a key is live.
- It does not know whether an unpinned package is pinned by your lockfile or a wrapper script.
- `AS003`, `AS005`, `AS006` and remote-endpoint findings are review prompts, not vulnerabilities.
- Recall has not been measured against a labelled corpus.

## Custom rules

Point `--rules` at a JSON file to add your own org-specific pattern checks
without forking the scanner:

```bash
agentscan . --rules my-org-rules.json
```

See `agentscan/rules.py` (`load_pattern_rules`) for the schema.

## License

MIT. Use it, ship it, fold it into your pipeline.
