from __future__ import annotations
import fnmatch
import json
import math
import os
import re
from typing import Iterator

from .model import Finding

# ---- helpers ---------------------------------------------------------------


def _line_of(raw: str, needle: str) -> int:
    if not needle:
        return 0
    idx = raw.find(needle)
    if idx < 0:
        esc = json.dumps(needle)[1:-1]
        idx = raw.find(esc) if esc != needle else -1
    if idx < 0:
        return 0
    return raw.count("\n", 0, idx) + 1


def _walk(node, path=()):  # yields (path_tuple, value) for every node, iteratively
    stack = [(path, node)]
    while stack:
        pth, cur = stack.pop()
        yield pth, cur
        if isinstance(cur, dict):
            stack.extend((pth + (str(k),), v) for k, v in reversed(list(cur.items())))
        elif isinstance(cur, list):
            stack.extend((pth + (f"[{i}]",), v) for i, v in reversed(list(enumerate(cur))))


def _find_keys(obj, key):  # yields values for every occurrence of `key`
    for _, node in _walk(obj):
        if isinstance(node, dict) and key in node:
            yield node[key]


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside of strings."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def parse_json_lenient(raw: str):
    try:
        return json.loads(raw)
    except Exception:
        pass
    try:
        return json.loads(strip_jsonc(raw.lstrip("﻿")))
    except Exception:
        return None


def _as_list(v) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        return [v]
    return []


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ---- secret detection ------------------------------------------------------

# (label, regex). Order matters: more specific prefixes first.
_SECRET_PATTERNS = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,512}")),
    ("OpenRouter API key", re.compile(r"sk-or-v1-[A-Za-z0-9]{32,512}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-|svcacct-|admin-)?(?!ant-|or-)[A-Za-z0-9_\-]{20,512}")),
    ("Context7 API key", re.compile(r"ctx7sk-[A-Za-z0-9\-]{20,512}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,512}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[0-9A-Za-z_]{40,512}")),
    ("GitLab token", re.compile(r"glpat-[0-9A-Za-z\-_]{20,512}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,512}")),
    ("Notion token", re.compile(r"\b(?:ntn_|secret_)[A-Za-z0-9]{30,512}")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,512}")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,512}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
]
_URL_CRED = re.compile(r"\b[a-z][a-z0-9+.\-]{0,20}://([^\s/:@\"']{1,128}):([^\s/@\"']{6,256})@[^\s/\"']{1,256}", re.I)

_SECRET_KEY = re.compile(
    r"(api[_\-]?key|apikey|secret|token|passwd|password|access[_\-]?key|private[_\-]?key|"
    r"auth(?:orization)?|credential|bearer)", re.I)
_NON_SECRET_KEY_SUFFIX = re.compile(
    r"(_|-)?(path|file|dir|url|uri|endpoint|name|id|env|header|headers|type|prefix|"
    r"count|limit|ttl|timeout|expiry|expires|mode|method|scheme|label|field|var|file_?path)$", re.I)

_DOC_VALUES = {
    "akiaiosfodnn7example", "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
}
_PLACEHOLDER_STRICT = (
    "example", "xxxx", "your", "placeholder", "changeme", "change-me", "dummy",
    "redacted", "<", "{{", "${", "$(", "env:", "insert", "replace",
)
_PLACEHOLDER_LOOSE = _PLACEHOLDER_STRICT + (
    "sample", "fake", "todo", "token_here", "key_here", "abc", "1234", "test",
    "secret", "password", "none", "null", "undefined", "foo", "bar",
)


def _is_env_ref(v: str) -> bool:
    return bool(re.match(r"^(\$\{?[A-Za-z_]|%[A-Za-z_]+%|\{\{|<[^>]+>$|env:)", v.strip()))


def _looks_placeholder(v: str, strict_only: bool = False) -> bool:
    low = v.lower()
    if low in _DOC_VALUES or _is_env_ref(v):
        return True
    toks = _PLACEHOLDER_STRICT if strict_only else _PLACEHOLDER_LOOSE
    if any(t in low for t in toks):
        return True
    if len(set(low)) <= 4:
        return True
    if re.fullmatch(r"(.{1,4})\1{3,}", low):
        return True
    return False


def _redact(v: str) -> str:
    return v[:6] + "..." + v[-2:] if len(v) > 14 else v[:3] + "..."


def _strip_auth_scheme(v: str) -> str:
    m = re.match(r"^(?:Bearer|Basic|Token|Bot)\s+(\S+)$", v.strip(), re.I)
    return m.group(1) if m else v.strip()


def _generic_secret_ok(key: str, val: str):
    """Return (severity, confidence) if key/value looks like a real inline credential."""
    k = key.lower()
    if not _SECRET_KEY.search(k) or _NON_SECRET_KEY_SUFFIX.search(k):
        return None
    v = _strip_auth_scheme(val)
    if len(v) < 16 or re.search(r"\s", v):
        return None
    if _looks_placeholder(v):
        return None
    if re.match(r"^(https?://|file:|\.{0,2}/|~|[A-Za-z]:[\\/])", v):
        return None
    if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)):
        return None
    ent = _entropy(v)
    if ent < 3.2:
        return None
    if len(v) >= 24 and ent >= 3.6:
        return "HIGH", "medium"
    return "MEDIUM", "low"


def _pattern_secret_hits(raw: str, relpath: str, seen: set) -> Iterator[Finding]:
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(raw):
            val = m.group(0)
            if val in seen:
                continue
            body = val.split("-", 2)[-1] if "-" in val else val
            if label != "Private key block":
                if _looks_placeholder(val, strict_only=True) or _entropy(body) < 3.0:
                    continue
            seen.add(val)
            yield Finding(
                "AS004", f"Hardcoded secret ({label})", "CRITICAL", relpath,
                _line_of(raw, val), _redact(val) if label != "Private key block" else val,
                "Move the credential to an environment variable or secret store, "
                "rotate it, and never commit live keys in agent config.",
                confidence="high",
            )
    for m in _URL_CRED.finditer(raw):
        pw = m.group(2)
        if _looks_placeholder(pw) or pw in seen:
            continue
        seen.add(pw)
        yield Finding(
            "AS004", "Credentials embedded in a URL", "HIGH", relpath,
            _line_of(raw, m.group(0)), re.sub(r":[^:@/]+@", ":***@", m.group(0)),
            "Pass credentials through environment variables or a secret store, not the URL.",
            confidence="medium",
        )


def _structured_secret_hits(obj, raw: str, relpath: str, seen: set) -> Iterator[Finding]:
    for path, node in _walk(obj):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str):
                    r = _generic_secret_ok(str(k), v)
                    if r and v not in seen:
                        seen.add(v)
                        yield _generic_finding(str(k), v, r, raw, relpath)
        elif isinstance(node, list) and path and path[-1] == "args":
            strs = [x for x in node if isinstance(x, str)]
            for i, a in enumerate(strs):
                m = re.match(r"^--?([A-Za-z0-9_\-]+)=(.+)$", a)
                if m:
                    key, val = m.group(1), m.group(2)
                elif a.startswith("-") and i + 1 < len(strs) and not strs[i + 1].startswith("-"):
                    key, val = a.lstrip("-"), strs[i + 1]
                else:
                    continue
                r = _generic_secret_ok(key, val)
                if r and val not in seen:
                    seen.add(val)
                    yield _generic_finding(key, val, r, raw, relpath)


def _generic_finding(key, val, r, raw, relpath) -> Finding:
    sev, conf = r
    return Finding(
        "AS004", "Hardcoded secret (credential field with high-entropy value)", sev,
        relpath, _line_of(raw, val), f"{key}: {_redact(_strip_auth_scheme(val))}",
        "Reference the value via an environment variable instead of inlining it in config.",
        confidence=conf,
    )


_TEXT_KV = re.compile(
    r"""^[ \t]*["']?([A-Za-z0-9_.\-]{1,100})["']?[ \t]*[:=][ \t]*["']?([^\s"'#,]{1,512})["']?[ \t]*(?:#[^\n]*)?$""", re.M)


def detect_secrets(raw: str, relpath: str, obj=None) -> Iterator[Finding]:
    seen: set[str] = set()
    yield from _pattern_secret_hits(raw, relpath, seen)
    if obj is not None:
        yield from _structured_secret_hits(obj, raw, relpath, seen)
    else:
        for m in _TEXT_KV.finditer(raw):
            key, val = m.group(1), m.group(2)
            r = _generic_secret_ok(key, val)
            if r and val not in seen:
                seen.add(val)
                yield _generic_finding(key, val, r, raw, relpath)


# ---- hidden-character (rules-file backdoor) detection ----------------------

_INVISIBLE = re.compile(
    "[​⁠⁢⁣⁤‪-‮⁦-⁩\U000e0000-\U000e007f]")
_ZWNJ_ASCII = re.compile(r"[A-Za-z0-9]‌[A-Za-z0-9]")
_BOM_MID = re.compile(r"(?<!^)﻿")


def detect_hidden_text(raw: str, relpath: str) -> Iterator[Finding]:
    hits = list(_INVISIBLE.finditer(raw)) + list(_ZWNJ_ASCII.finditer(raw))
    mid = list(_BOM_MID.finditer(raw[1:] if raw.startswith("﻿") else raw))
    hits += mid
    if not hits:
        return
    first = min(h.start() for h in hits)
    codes = sorted({f"U+{ord(c):04X}" for h in hits for c in h.group(0)
                    if not c.isalnum()})[:6]
    yield Finding(
        "AS012", "Invisible or bidirectional Unicode characters in agent instructions",
        "HIGH", relpath, raw.count("\n", 0, first) + 1,
        f"{len(hits)} hidden character(s): {', '.join(codes)}",
        "Remove hidden characters. They can smuggle instructions the human reviewer "
        "cannot see (rules-file backdoor).",
        confidence="high",
    )


# ---- instruction-file detectors -------------------------------------------

_AUTO_AUTH = re.compile(
    r"(?i)\b(without asking|do ?n'?t ask|no confirmation|without confirmation|"
    r"auto[- ]?approve|automatically approve|always (?:allow|run|execute)|"
    r"skip permission|bypass permission|run any command|yolo mode)\b"
)
_NEGATION_BEFORE = re.compile(
    r"(?i)(never|not|n't|avoid|forbid|forbidden|disallow|prohibit|must not|"
    r"should not|no need to ask|unless|except)\b[^.\n]{0,60}$")
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
    yield from detect_hidden_text(raw, relpath)
    yield from _pattern_secret_hits(raw, relpath, set())
    in_fence = False
    offset = 0
    for line in raw.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
        elif not in_fence:
            for m in _AUTO_AUTH.finditer(line):
                if _NEGATION_BEFORE.search(line[:m.start()]):
                    continue
                yield Finding(
                    "AS005", "Agent instruction disables human confirmation", "LOW",
                    relpath, raw.count("\n", 0, offset) + 1, m.group(0),
                    "Remove blanket auto-approval language. Require confirmation for "
                    "state-changing or irreversible actions.",
                    heuristic=True, confidence="low",
                )
                break
        offset += len(line)
    if _GUARD.search(raw):
        return
    para_start = 0
    for para in re.split(r"\n\s*\n", raw):
        src, act = _SRC.search(para), _ACT.search(para)
        if src and act and not _NEGATION_BEFORE.search(para[:act.start()].split("\n")[-1]):
            yield Finding(
                "AS006", "External content routed to actions without an injection boundary",
                "LOW", relpath, _line_of(raw, act.group(0)), act.group(0),
                "State explicitly that fetched/external content is untrusted data, "
                "not instructions, and must never be executed or obeyed.",
                heuristic=True, confidence="low",
            )
            break
        para_start += len(para) + 2


# ---- permission / grant analysis ------------------------------------------

_BYPASS_TEXT = re.compile(
    r"(?i)(--dangerously-skip-permissions|bypassPermissions|dangerouslySkipPermissions)"
)
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell",
           "powershell.exe", "pwsh", "pwsh.exe"}
_SHELL_FLAGS = {"-c", "-lc", "-ic", "-e", "/c", "/k", "-command", "-c:", "-encodedcommand"}
_HOME_ROOTS = re.compile(
    r"^(/|~/?|\$HOME/?|\$\{HOME\}/?|%USERPROFILE%[\\/]?|/Users|/Users/[^/]+/?|/home|"
    r"/home/[^/]+/?|/root/?|/mnt|/etc|/var|/usr|/opt|[A-Za-z]:[\\/]?|[A-Za-z]:[\\/]Users[\\/]?[^\\/]*[\\/]?)$")

_INTERPRETERS = {"python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php",
                 "sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "lua",
                 "osascript", "java", "dotnet"}
_PKG_RUNNERS = {"npx", "bunx", "uvx", "pipx", "pnpx", "npm exec", "pnpm dlx", "yarn dlx",
                "npm x", "uv run", "uv tool"}
_SHELL_ESCAPES = {"awk", "gawk", "find", "xargs", "env", "nohup", "ssh", "eval", "exec",
                  "sudo", "su"}
_NET_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "scp", "rsync"}
_READONLY_TOOLS = {"read", "grep", "glob", "ls", "notebookread", "todoread"}
_WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "webfetch", "websearch"}

_SHELL_MCP_NAME = re.compile(
    r"(?i)(mcp[-_]?(?:server[-_]?)?(?:shell|terminal|commands?|exec|bash|cmd)\b|"
    r"\b(?:shell|terminal|commands?|exec|bash)[-_]?(?:mcp|server)\b|desktop-?commander|iterm-?mcp)")


def classify_grant(entry: str):
    """Classify a permissions.allow / allowed-tools entry.

    Returns (rule_id, severity, confidence, title) or None if unremarkable.
    """
    e = entry.strip()
    if not e:
        return None
    m = re.match(r"^([A-Za-z_][\w\-]*)\s*(?:\((.*)\))?$", e)
    if e == "*":
        return ("AS001", "CRITICAL", "high", "Wildcard grant allows every tool (*)")
    if not m:
        return None
    tool, spec = m.group(1), m.group(2)
    tl = tool.lower()
    if tl == "bash" or tl == "shell":
        if spec is None or spec.strip() in ("*", "*:*", ""):
            return ("AS001", "CRITICAL", "high",
                    f"Unrestricted shell permission allowed ({e})")
        toks = [t for t in re.split(r"[\s:]+", spec.strip()) if t]
        cmd = os.path.basename(toks[0]).lower() if toks else ""
        rest = toks[1:]
        two = f"{cmd} {rest[0].lower()}" if rest else ""
        # arbitrary only when nothing but a wildcard (or inline code) follows the launcher
        bare = rest == [] or rest == ["*"]
        bare2 = rest[1:] == [] or rest[1:] == ["*"]
        inline = bool(rest) and rest[0].lower() in ("-c", "-e", "-lc", "/c", "-command")
        if toks and toks[0] == "*":
            return ("AS001", "CRITICAL", "high", f"Unrestricted shell permission allowed ({e})")
        if cmd in _INTERPRETERS and (bare or inline):
            return ("AS001", "HIGH", "high",
                    f"Interpreter grant allows arbitrary code execution ({e})")
        if (cmd in _PKG_RUNNERS and bare) or (two in _PKG_RUNNERS and bare2):
            return ("AS001", "HIGH", "high",
                    f"Package-runner grant allows arbitrary code execution ({e})")
        if cmd in _SHELL_ESCAPES and bare:
            return ("AS001", "HIGH", "medium",
                    f"Grant of a shell-escape capable tool ({e})")
        if cmd in _NET_TOOLS and bare:
            return ("AS008", "LOW", "medium", f"Network tool granted with wildcard arguments ({e})")
        return None
    if spec is not None and spec.strip() in ("*", ""):
        if tl in _READONLY_TOOLS:
            return None
        if tl in _WRITE_TOOLS:
            return ("AS008", "MEDIUM", "high", f"Wildcard tool permission ({e})")
        return ("AS008", "LOW", "medium", f"Wildcard tool permission ({e})")
    return None


_HOOK_DANGER = re.compile(
    r"(\$\{?CLAUDE_TOOL_INPUT|\$\{?TOOL_INPUT|\$\{?TOOL_ARGS|\beval\b|"
    r"\|\s*(?:ba|z)?sh\b|\bcurl\b[^|;]*\|\s*(?:ba|z)?sh|\bwget\b[^|;]*\|\s*(?:ba|z)?sh|"
    r"\bnc\s+-|/dev/tcp/)")
_RISKY_TOKENS = {"exec", "execute", "shell", "bash", "command", "cmd", "run", "write", "delete",
                 "remove", "edit", "create", "send", "post", "push", "deploy", "install", "kill",
                 "move", "rename", "upload", "drop", "update", "insert", "click", "navigate",
                 "evaluate", "eval", "append", "set", "put", "patch", "merge", "commit"}


def _risky_tool(name: str) -> bool:
    if name == "*":
        return True
    toks = re.split(r"[_\-\s.]+|(?<=[a-z])(?=[A-Z])", name)
    return any(t.lower() in _RISKY_TOKENS for t in toks if t)


# ---- JSON / TOML config detectors ------------------------------------------

_WRAPPER_DANGER = re.compile(
    r"(\beval\b|\bread\b|\$[@*0-9]|\$\{[@*0-9]|\bxargs\b|/dev/tcp|\bnc\b|\|\s*(?:ba|z)?sh\b)")

_SERVER_CONTAINER_KEYS = ("mcpServers", "mcp_servers", "context_servers", "servers")


def _is_server_spec(spec) -> bool:
    return isinstance(spec, dict) and any(
        k in spec for k in ("command", "url", "serverUrl", "httpUrl", "baseUrl"))


def detect_json(raw: str, relpath: str, obj=None) -> Iterator[Finding]:
    if obj is None:
        obj = parse_json_lenient(raw)
    if obj is None:
        for m in _BYPASS_TEXT.finditer(raw):
            yield Finding(
                "AS001", "Permission bypass flag enabled", "CRITICAL", relpath,
                _line_of(raw, m.group(0)), m.group(0),
                "Do not ship agent config with permission checks disabled.",
                confidence="medium",
            )
        return
    yield from _detect_structured(obj, raw, relpath)


def detect_toml(raw: str, relpath: str) -> Iterator[Finding]:
    try:
        import tomllib  # py311+
    except ImportError:
        return
    try:
        obj = tomllib.loads(raw)
    except Exception:
        return
    yield from _detect_structured(obj, raw, relpath)


def _detect_structured(obj, raw: str, relpath: str) -> Iterator[Finding]:
    emitted: set[tuple] = set()

    def once(key):
        if key in emitted:
            return False
        emitted.add(key)
        return True

    # bypass flags: structured keys and string values (not prose in descriptions)
    for _, node in _walk(obj):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("dangerouslySkipPermissions", "skipDangerousModePermissionPrompt") and v is True:
                    if once(("bypass", k)):
                        yield Finding(
                            "AS001", f"Permission prompts disabled ({k})", "CRITICAL",
                            relpath, _line_of(raw, k), f"{k}: true",
                            "Do not ship agent config with permission checks disabled.")
                if k == "enableAllProjectMcpServers" and v is True and once(("allmcp",)):
                    yield Finding(
                        "AS011", "Auto-trusts every MCP server declared by the project",
                        "MEDIUM", relpath, _line_of(raw, k), "enableAllProjectMcpServers: true",
                        "A cloned repository can then start arbitrary MCP servers without "
                        "approval. Enable named servers explicitly.",
                        confidence="high")
        elif isinstance(node, str) and node.lower() != "bypasspermissions" and \
                _BYPASS_TEXT.search(node) and len(node) < 300:
            m = _BYPASS_TEXT.search(node)
            if once(("bypassval", m.group(0).lower())):
                yield Finding(
                    "AS001", "Permission bypass flag enabled", "CRITICAL", relpath,
                    _line_of(raw, m.group(0)), m.group(0),
                    "Do not ship agent config with permission checks disabled.",
                    confidence="high")

    # permissions block
    for perms in _find_keys(obj, "permissions"):
        if not isinstance(perms, dict):
            continue
        if str(perms.get("defaultMode", "")).lower() in ("bypasspermissions",):
            if once(("defaultMode",)):
                yield Finding(
                    "AS001", "permissions.defaultMode set to bypassPermissions",
                    "CRITICAL", relpath, _line_of(raw, "bypassPermissions"),
                    "defaultMode: bypassPermissions",
                    "Use 'default' or 'acceptEdits'; never ship bypassPermissions.")
        for entry in _as_list(perms.get("allow")):
            if not isinstance(entry, str):
                continue
            c = classify_grant(entry)
            if c and once(("grant", entry)):
                rid, sev, conf, title = c
                yield Finding(
                    rid, title, sev, relpath, _line_of(raw, entry), entry,
                    "Scope allow-rules to specific commands, e.g. Bash(npm run test:*); "
                    "interpreters, package runners and shell-escape tools turn an "
                    "allow-rule into arbitrary execution.",
                    confidence=conf)

    # alwaysAllow / autoApprove
    for key in ("alwaysAllow", "autoApprove"):
        for val in _find_keys(obj, key):
            if val is True or (isinstance(val, list) and val):
                names = [str(x) for x in val] if isinstance(val, list) else ["*"]
                risky = [n for n in names if _risky_tool(n)]
                sev = "MEDIUM" if risky else "LOW"
                if once(("auto", key, tuple(names))):
                    yield Finding(
                        "AS009", f"MCP tools auto-approved via {key}", sev, relpath,
                        _line_of(raw, key), f"{key}: {names[:5]}",
                        "Remove auto-approval so tool calls with side effects require a "
                        "human decision." if risky else
                        "Auto-approved tools look read-only; confirm they cannot be "
                        "chained into side effects.",
                        confidence="medium" if risky else "low")

    # hooks that run shell on tool events
    for hooks in _find_keys(obj, "hooks"):
        if not isinstance(hooks, dict):
            continue
        for _, node in _walk(hooks):
            if isinstance(node, dict) and node.get("type") == "command" and node.get("command"):
                cmd = str(node["command"])
                if not once(("hook", cmd)):
                    continue
                danger = bool(_HOOK_DANGER.search(cmd))
                yield Finding(
                    "AS003",
                    "Hook builds a shell command from tool input or fetches code"
                    if danger else "Hook auto-runs a shell command on agent tool events",
                    "HIGH" if danger else "LOW", relpath, _line_of(raw, cmd[:30]), cmd[:80],
                    "Ensure hook commands can't be influenced by tool inputs; avoid "
                    "running untrusted-derived data in a shell." if danger else
                    "Committed hooks run on every contributor machine; review the script.",
                    confidence="high" if danger else "medium")

    # mcp servers
    for key in _SERVER_CONTAINER_KEYS:
        for servers in _find_keys(obj, key):
            if not isinstance(servers, dict):
                continue
            for name, spec in servers.items():
                if _is_server_spec(spec):
                    yield from _check_mcp_server(str(name), spec, raw, relpath, emitted)


# ---- MCP server checks -----------------------------------------------------

_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_PEP440_EXACT = re.compile(r"==\s*\d+(?:\.\d+)*(?:[a-zA-Z0-9.\-+]*)$")


def _split_npm_spec(spec: str):
    if spec.startswith("@"):
        rest = spec[1:]
        if "@" in rest:
            i = rest.index("@", rest.index("/") if "/" in rest else 0)
            return "@" + rest[:i], rest[i + 1:]
        return spec, ""
    if "@" in spec:
        name, ver = spec.split("@", 1)
        return name, ver
    return spec, ""


def _npm_unpinned(spec: str) -> str | None:
    """Return a reason string if unpinned, else None."""
    if re.match(r"^(git\+|https?://|github:|file:|\.{0,2}/)", spec):
        return None if "#" in spec and re.search(r"#[0-9a-f]{7,40}$", spec) else "unversioned source"
    name, ver = _split_npm_spec(spec)
    if not ver:
        return "no version"
    if _SEMVER.match(ver):
        return None
    if ver in ("latest", "next", "beta", "canary", "alpha", "rc"):
        return f"floating tag @{ver}"
    return f"version range @{ver}"


def _py_unpinned(args: list[str], runner: str) -> tuple[str, str] | None:
    pkg = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--from", "--with") and i + 1 < len(args):
            if a == "--from":
                pkg = args[i + 1]
                break
            i += 2
            continue
        if a.startswith("--from="):
            pkg = a.split("=", 1)[1]
            break
        if a.startswith("-"):
            i += 1
            continue
        pkg = a
        break
    if not pkg:
        return None
    if re.match(r"^(git\+|https?://|file:|\.{0,2}/)", pkg):
        return None if re.search(r"@[0-9a-f]{7,40}$", pkg) else (pkg, "unversioned source")
    if _PEP440_EXACT.search(pkg):
        return None
    if "@" in pkg:
        _, ver = pkg.split("@", 1)
        return None if _SEMVER.match(ver) else (pkg, f"floating version @{ver}")
    return (pkg, "no exact version (==)")


_DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name",
                       "--network", "--net", "-w", "--workdir", "-u", "--user", "--mount",
                       "--env-file", "--entrypoint", "-l", "--label", "--platform",
                       "--add-host", "--cap-add", "--memory", "-m", "--cpus", "--pull"}


def _docker_image(args: list[str]) -> str | None:
    if not args or args[0] != "run":
        return None
    i = 1
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            i += 1 if "=" in a or a not in _DOCKER_VALUE_FLAGS else 2
            continue
        return a
    return None


def _check_mcp_server(name, spec, raw, relpath, emitted) -> Iterator[Finding]:
    cmd = str(spec.get("command", ""))
    args = [str(a) for a in _as_list(spec.get("args")) if not isinstance(a, (dict, list))]
    base = os.path.basename(cmd).lower()
    if base.endswith((".cmd", ".exe", ".bat")):
        base = base.rsplit(".", 1)[0]
    joined = " ".join(args)

    if base in _SHELLS and any(a.lower() in _SHELL_FLAGS for a in args):
        script = " ".join(args)
        danger = bool(_WRAPPER_DANGER.search(script))
        yield Finding(
            "AS001", f"MCP server '{name}' is launched through an inline shell command",
            "HIGH" if danger else "LOW", relpath, _line_of(raw, cmd),
            f"{cmd} {' '.join(args[:3])}"[:100],
            "This shell evaluates input it did not receive from a fixed command line: "
            "remote code execution by design." if danger else
            "Shell wrapper around what looks like a fixed launch command; prefer "
            "invoking the server binary directly.",
            confidence="medium" if danger else "low")
    elif _SHELL_MCP_NAME.search(joined) or _SHELL_MCP_NAME.search(cmd) or \
            _SHELL_MCP_NAME.search(name):
        yield Finding(
            "AS001", f"MCP server '{name}' appears to expose shell execution to the model",
            "HIGH", relpath, _line_of(raw, name), f"{cmd} {joined}"[:100],
            "A shell or command-execution MCP server gives any prompt injection a "
            "shell. Remove it or confine it to a sandbox.",
            confidence="medium", heuristic=True)

    if "server-filesystem" in joined or "filesystem" in name.lower():
        for a in args:
            if a.startswith("-"):
                continue
            if _HOME_ROOTS.match(a):
                sev = "HIGH"
                yield Finding(
                    "AS002", f"MCP filesystem server '{name}' rooted at a broad path ({a})",
                    sev, relpath, _line_of(raw, a), a,
                    "Scope the filesystem server to a specific project directory, "
                    "not $HOME or /.",
                    confidence="high")

    eff = args
    runner = None
    if base in ("npx", "bunx", "pnpx"):
        runner = base
        auto = base != "npx" or any(a in ("-y", "--yes") for a in args)
        pkgs = [a for a in args if not a.startswith("-")]
        if base == "npx":
            eff = [a for a in args if a not in ("-y", "--yes")]
        why = _npm_unpinned(pkgs[0]) if pkgs else None
        if auto and pkgs and why:
            yield _unpinned(name, relpath, raw, f"{base}{' -y' if base == 'npx' else ''} {pkgs[0]}",
                            why, "package")
    elif base in ("pnpm", "yarn", "npm") and args[:1] in (["dlx"], ["exec"], ["x"]):
        pkgs = [a for a in args[1:] if not a.startswith("-")]
        why = _npm_unpinned(pkgs[0]) if pkgs else None
        if pkgs and why:
            yield _unpinned(name, relpath, raw, f"{base} {args[0]} {pkgs[0]}", why, "package")
    elif base in ("uvx", "pipx") or (base == "uv" and args[:2] == ["tool", "run"]) or \
            (base == "pipx" and args[:1] == ["run"]):
        rest = args[2:] if base == "uv" else (args[1:] if args[:1] == ["run"] else args)
        r = _py_unpinned(rest, base)
        if r:
            yield _unpinned(name, relpath, raw, f"{base} {r[0]}", r[1], "package")
    elif base == "docker":
        img = _docker_image(args)
        if img and "@sha256:" not in img:
            tag = img.rsplit(":", 1)[1] if ":" in img.split("/")[-1] else ""
            if not tag or tag == "latest":
                yield _unpinned(name, relpath, raw, f"docker run {img}",
                                "floating image tag" if tag else "no image tag", "image")
    elif base == "deno" and any(re.match(r"^https?://", a) for a in args):
        u = next(a for a in args if re.match(r"^https?://", a))
        if not re.search(r"@\d+\.\d+\.\d+", u):
            yield _unpinned(name, relpath, raw, f"deno run {u}", "remote module without version", "module")

    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or spec.get("baseUrl")
    if isinstance(url, str) and re.match(r"^(https?|wss?)://", url):
        local = re.search(r"://(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])([:/]|$)", url)
        if not local:
            if url.lower().startswith(("http://", "ws://")):
                yield Finding(
                    "AS010", f"MCP server '{name}' uses an unencrypted remote transport",
                    "HIGH", relpath, _line_of(raw, url), url,
                    "Use https:// so tool results and credentials cannot be read or "
                    "altered in transit.",
                    confidence="high")
            else:
                yield Finding(
                    "AS007", f"MCP server '{name}' connects to a remote endpoint",
                    "INFO", relpath, _line_of(raw, url), url,
                    "Confirm the remote MCP endpoint is trusted; remote servers can inject "
                    "tool results and instructions into the agent.",
                    heuristic=True, confidence="medium")


def _unpinned(name, relpath, raw, evidence, why, kind) -> Finding:
    return Finding(
        "AS007", f"MCP server '{name}' runs an unpinned remote {kind} ({why})",
        "MEDIUM", relpath, _line_of(raw, evidence.split()[-1]), evidence,
        "Pin to an exact version (or image digest) and verify the publisher; "
        "auto-run launchers fetch and execute whatever is currently published.",
        confidence="high")


# ---- skills / commands / agents frontmatter --------------------------------

def _frontmatter(raw: str):
    if not raw.startswith("---"):
        return None
    end = raw.find("\n---", 3)
    return raw[3:end] if end > 0 else None


def detect_frontmatter(raw: str, relpath: str) -> Iterator[Finding]:
    fm = _frontmatter(raw)
    if not fm:
        return
    m = re.search(r"(?im)^(allowed-tools|allowed_tools)\s*:\s*(.*(?:\n[ \t]+-.*)*)$", fm)
    if not m:
        return
    entries = re.findall(r"[A-Za-z_*][\w\-]*(?:\([^)]*\))?", m.group(2))
    seen: set[str] = set()
    for e in entries:
        c = classify_grant(e)
        if c and c[0] == "AS001" and e not in seen:
            seen.add(e)
            yield Finding(
                "AS013", f"Skill or command pre-approves arbitrary execution ({e})",
                c[1], relpath, _line_of(raw, e), e,
                "Scope pre-approved tools to specific commands. A skill loaded from "
                "untrusted content then runs with these permissions.",
                confidence=c[2])


# ---- pluggable pattern rules (org packs) ------------------------------------

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
                confidence=r.get("confidence", "medium"),
            )
