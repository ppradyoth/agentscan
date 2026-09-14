from __future__ import annotations
import json
import os
import re
from typing import Iterator

from .model import Finding

# ---- helpers ---------------------------------------------------------------

def _line_of(raw: str, needle: str) -> int:
    idx = raw.find(needle)
    if idx < 0:
        return 0
    return raw.count("\n", 0, idx) + 1


def _walk(node, path=()):  # yields (path_tuple, value) for every node
    yield path, node
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, path + (str(k),))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, path + (f"[{i}]",))


def _find_keys(obj, key):  # yields values for every occurrence of `key`
    for path, node in _walk(obj):
        if isinstance(node, dict) and key in node:
            yield node[key]


# ---- secret detection ------------------------------------------------------

_SECRET_PATTERNS = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[0-9A-Za-z_]{40,}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
]
_GENERIC_SECRET = re.compile(
    r'(?i)"?(?:api[_-]?key|secret|token|password|access[_-]?key)"?\s*[:=]\s*"([^"]{12,})"'
)


def detect_secrets(raw: str, relpath: str) -> Iterator[Finding]:
    seen: set[str] = set()
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(raw):
            val = m.group(0)
            if val in seen:
                continue
            seen.add(val)
            yield Finding(
                "AS004", f"Hardcoded secret ({label})", "CRITICAL", relpath,
                _line_of(raw, val), _redact(val),
                "Move the credential to an environment variable or secret store; "
                "never commit live keys in agent config.",
            )
    for m in _GENERIC_SECRET.finditer(raw):
        val = m.group(1)
        if val in seen or _looks_placeholder(val):
            continue
        if not (re.search(r"[A-Za-z]", val) and re.search(r"\d", val)):
            continue
        seen.add(val)
        yield Finding(
            "AS004", "Hardcoded secret (generic key/token field)", "HIGH", relpath,
            _line_of(raw, val), f"{m.group(0)[:40]}...",
            "Reference the value via ${ENV_VAR} instead of inlining it in config.",
        )


def _redact(v: str) -> str:
    return v[:7] + "..." + v[-3:] if len(v) > 12 else v[:4] + "..."


def _looks_placeholder(v: str) -> bool:
    low = v.lower()
    return any(t in low for t in (
        "your", "example", "changeme", "placeholder", "xxxx", "<", "env:",
        "${", "dummy", "sample", "redacted",
    ))


# ---- instruction-file detectors -------------------------------------------

_AUTO_AUTH = re.compile(
    r"(?i)\b(without asking|do ?n'?t ask|no confirmation|without confirmation|"
    r"auto[- ]?approve|automatically approve|always (?:allow|run|execute)|"
    r"skip permission|bypass permission|run any command|yolo mode)\b"
)
_SRC = re.compile(
    r"(?i)\b(web ?page|website|the url|e-?mails?|resum[eé]|the issue|pull request|"
    r"pr body|comments?|search results?|scraped|fetched content|untrusted|"
    r"attached file|user-provided (?:file|document))\b"
)
_ACT = re.compile(
    r"(?i)\b(execute|run (?:the|any)|follow (?:the|its|these) instructions|"
    r"do what it says|comply with|obey|carry out|act on)\b"
)
_GUARD = re.compile(
    r"(?i)(not (?:be treated as |)instructions|treat .* as data|do not (?:treat|follow|obey|act)|"
    r"ignore any instructions|never (?:follow|execute) instructions|untrusted content)"
)


def detect_instructions(raw: str, relpath: str) -> Iterator[Finding]:
    for m in _AUTO_AUTH.finditer(raw):
        yield Finding(
            "AS005", "Agent instruction disables human confirmation", "MEDIUM",
            relpath, _line_of(raw, m.group(0)), m.group(0),
            "Remove blanket auto-approval language. Require confirmation for "
            "state-changing or irreversible actions.",
        )
    if _SRC.search(raw) and _ACT.search(raw) and not _GUARD.search(raw):
        m = _ACT.search(raw)
        yield Finding(
            "AS006", "External content routed to actions without an injection boundary",
            "MEDIUM", relpath, _line_of(raw, m.group(0)), m.group(0),
            "State explicitly that fetched/external content is untrusted data, "
            "not instructions, and must never be executed or obeyed.",
            heuristic=True,
        )


# ---- JSON config detectors -------------------------------------------------

_BYPASS_TEXT = re.compile(
    r"(?i)(--dangerously-skip-permissions|bypassPermissions|dangerouslySkipPermissions)"
)
_SHELLS = {"bash", "sh", "zsh", "/bin/bash", "/bin/sh", "/usr/bin/env"}
_HOME_ROOTS = re.compile(r"^(/|~|\$HOME|/Users/[^/]+|/home/[^/]+|/root)$")


def detect_json(raw: str, relpath: str) -> Iterator[Finding]:
    try:
        obj = json.loads(raw)
    except Exception:
        # still catch bypass flags in malformed/partial json
        for m in _BYPASS_TEXT.finditer(raw):
            yield Finding(
                "AS001", "Permission bypass flag enabled", "CRITICAL", relpath,
                _line_of(raw, m.group(0)), m.group(0),
                "Do not ship agent config with permission checks disabled.",
            )
        return

    for m in _BYPASS_TEXT.finditer(raw):
        yield Finding(
            "AS001", "Permission bypass flag enabled", "CRITICAL", relpath,
            _line_of(raw, m.group(0)), m.group(0),
            "Do not ship agent config with permission checks disabled.",
        )

    # Claude Code permissions block
    for perms in _find_keys(obj, "permissions"):
        if not isinstance(perms, dict):
            continue
        if str(perms.get("defaultMode", "")).lower() == "bypasspermissions":
            yield Finding(
                "AS001", "permissions.defaultMode set to bypassPermissions",
                "CRITICAL", relpath, _line_of(raw, "bypassPermissions"),
                "defaultMode: bypassPermissions",
                "Use 'default' or 'acceptEdits'; never ship bypassPermissions.",
            )
        for entry in perms.get("allow", []) or []:
            e = str(entry)
            if e in ("*", "Bash", "Bash(*)", "Bash(*:*)") or e.startswith("Bash(*"):
                yield Finding(
                    "AS001", f"Wildcard command permission allowed ({e})", "CRITICAL",
                    relpath, _line_of(raw, e), e,
                    "Scope allow-rules to specific commands, e.g. Bash(npm run test:*).",
                )
            elif e == "*" or e.endswith("(*)"):
                yield Finding(
                    "AS008", f"Wildcard tool permission ({e})", "MEDIUM", relpath,
                    _line_of(raw, e), e, "Replace wildcard with explicit tool scopes.",
                )

    # alwaysAllow / autoApprove (Cline, Roo, generic MCP clients)
    for key in ("alwaysAllow", "autoApprove"):
        for val in _find_keys(obj, key):
            if isinstance(val, list) and val:
                yield Finding(
                    "AS009", f"MCP tools auto-approved via {key}", "MEDIUM", relpath,
                    _line_of(raw, key), f"{key}: {val[:5]}",
                    "Remove auto-approval so tool calls require a human decision.",
                )

    # hooks that run shell on tool events
    for hooks in _find_keys(obj, "hooks"):
        if not isinstance(hooks, dict):
            continue
        for _, node in _walk(hooks):
            if isinstance(node, dict) and node.get("type") == "command" and node.get("command"):
                cmd = str(node["command"])
                yield Finding(
                    "AS003", "Hook auto-runs a shell command on agent tool events",
                    "HIGH", relpath, _line_of(raw, cmd[:30]), cmd[:80],
                    "Ensure hook commands can't be influenced by tool inputs; "
                    "avoid running untrusted-derived data in a shell.",
                )

    # mcpServers
    for servers in _find_keys(obj, "mcpServers"):
        if not isinstance(servers, dict):
            continue
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            yield from _check_mcp_server(name, spec, raw, relpath)


def _check_mcp_server(name, spec, raw, relpath) -> Iterator[Finding]:
    cmd = str(spec.get("command", ""))
    args = [str(a) for a in spec.get("args", []) or []]
    base = os.path.basename(cmd)

    if base in _SHELLS and any(a in ("-c", "-lc", "-e") for a in args):
        yield Finding(
            "AS001", f"MCP server '{name}' executes an arbitrary shell command",
            "CRITICAL", relpath, _line_of(raw, cmd), f"{cmd} {' '.join(args[:3])}",
            "Replace inline shell with a purpose-built server binary; a shell MCP "
            "server is remote code execution by design.",
        )

    if "server-filesystem" in " ".join(args) or "filesystem" in name.lower():
        for a in args:
            exp = os.path.expanduser(a)
            if _HOME_ROOTS.match(a) or a in ("/", "~") or exp in ("/",) or \
               (a.startswith("/") and a.count("/") == 1):
                yield Finding(
                    "AS002", f"MCP filesystem server '{name}' rooted at a broad path ({a})",
                    "HIGH", relpath, _line_of(raw, a), a,
                    "Scope the filesystem server to a specific project directory, "
                    "not $HOME or /.",
                )

    if base == "npx" or cmd.endswith("npx"):
        pkgs = [a for a in args if not a.startswith("-")]
        pkg = pkgs[0] if pkgs else ""
        last_seg = pkg.lstrip("@").split("/")[-1]
        unpinned = bool(pkg) and "@" not in last_seg
        if any(a in ("-y", "--yes") for a in args) and unpinned:
            yield Finding(
                "AS007", f"MCP server '{name}' runs an unpinned remote package via npx -y",
                "MEDIUM", relpath, _line_of(raw, "npx"),
                f"npx -y {pkg}",
                "Pin the package to an exact version and verify its publisher; "
                "npx -y fetches and executes the latest published code.",
            )

    url = spec.get("url") or spec.get("serverUrl")
    if isinstance(url, str) and re.match(r"^https?://", url) and \
       not re.search(r"://(localhost|127\.0\.0\.1|\[::1\])", url):
        yield Finding(
            "AS007", f"MCP server '{name}' connects to a remote endpoint",
            "MEDIUM", relpath, _line_of(raw, url), url,
            "Confirm the remote MCP endpoint is trusted; remote servers can inject "
            "tool results and instructions into the agent.",
            heuristic=True,
        )


# ---- pluggable pattern rules (org packs / agentscan Pro) --------------------

import fnmatch  # noqa: E402


def load_pattern_rules(paths):
    packs = []
    for p in paths or []:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for r in data.get("rules", data if isinstance(data, list) else []):
            r = dict(r)
            r["_re"] = re.compile(r["pattern"], re.MULTILINE)
            packs.append(r)
    return packs


def apply_pattern_rules(raw, relpath, filename, packs):
    for r in packs:
        glob = r.get("applies_to", "*")
        if glob != "*" and not fnmatch.fnmatch(filename, glob):
            continue
        for m in r["_re"].finditer(raw):
            yield Finding(
                r.get("id", "ASX00"), r.get("title", "Custom rule match"),
                r.get("severity", "MEDIUM").upper(), relpath,
                _line_of(raw, m.group(0)), m.group(0)[:80],
                r.get("remediation", "Review this pattern against your agent policy."),
                heuristic=bool(r.get("heuristic", False)),
            )
