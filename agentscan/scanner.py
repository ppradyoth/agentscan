from __future__ import annotations
import os
import re

from .model import Report
from . import rules

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
             "build", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "site-packages"}

INSTRUCTION_NAMES = {
    "claude.md", "agents.md", "agent.md", "gemini.md", ".cursorrules",
    ".clinerules", ".windsurfrules", "copilot-instructions.md",
}
AGENT_CONFIG_NAMES = {
    "mcp.json", ".mcp.json", "mcp_config.json", "claude_desktop_config.json",
    "cline_mcp_settings.json", "settings.json", "settings.local.json", "config.toml",
    "managed-settings.json", ".claude.json",
}
AGENT_DIRS = {".claude", ".cursor", ".vscode", ".roo", ".cline", ".codeium", ".windsurf",
              ".gemini", ".codex", ".zed", ".continue", ".github"}
STRUCTURE_KEYS = ("mcpServers", "mcp_servers", "context_servers", "servers", "permissions",
                  "hooks", "alwaysAllow", "autoApprove", "dangerously", "bypassPermissions",
                  "enableAllProjectMcpServers", "skipDangerousModePermissionPrompt")
_JSON_NAME_HINT = re.compile(
    r"(mcp|claude|cursor|cline|roo|windsurf|codeium|gemini|codex|copilot|agent|settings)", re.I)
TEXT_SECRET_EXT = {".env", ".yaml", ".yml", ".ini", ".cfg"}
MAX_BYTES = 2_000_000

_FIXTURE_PATH = re.compile(
    r"(^|[\\/])(tests?|__tests__|fixtures?|testdata|test-data|examples?|samples?|datasets?|"
    r"benchmarks?|docs?|templates?|mocks?|e2e)([\\/]|$)|"
    r"\.(example|sample|template|dist)(\.[a-z]+)?$|[-_.](example|sample|template)\b",
    re.I)


def context_of(relpath: str) -> str:
    return "fixture" if _FIXTURE_PATH.search(relpath.replace("\\", "/")) else "config"


def _read(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def scan_path(root: str, rule_files=None, include_fixtures: bool = False,
              all_files: bool = False) -> Report:
    report = Report()
    packs = rules.load_pattern_rules(rule_files or [])
    if os.path.isfile(root):
        _scan_file(root, os.path.dirname(root) or ".", report, packs, include_fixtures, all_files)
        return report
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            _scan_file(os.path.join(dirpath, fn), root, report, packs, include_fixtures, all_files)
    return report


def _parent_dirs(path: str) -> set[str]:
    return {p.lower() for p in os.path.normpath(path).split(os.sep)[:-1]}


def _scan_file(path: str, root: str, report: Report, packs=None,
               include_fixtures: bool = False, all_files: bool = False) -> None:
    try:
        _scan_file_unsafe(path, root, report, packs, include_fixtures, all_files)
    except Exception as exc:  # one malformed file must never abort a scan
        report.errors.append((os.path.relpath(path, root), f"{type(exc).__name__}: {exc}"))


def _scan_file_unsafe(path: str, root: str, report: Report, packs=None,
                      include_fixtures: bool = False, all_files: bool = False) -> None:
    if os.path.islink(path):
        return
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    parents = _parent_dirs(os.path.relpath(path, root))
    in_agent_dir = bool(parents & AGENT_DIRS)
    is_instruction = name in INSTRUCTION_NAMES or name.endswith(".instructions.md")
    is_skill = name == "skill.md" or (in_agent_dir and ext == ".md" and
                                      bool(parents & {"commands", "agents", "skills"}))
    is_json = ext == ".json" and (all_files or name in AGENT_CONFIG_NAMES or in_agent_dir
                                 or bool(_JSON_NAME_HINT.search(name)))
    is_toml = ext == ".toml" and (name in AGENT_CONFIG_NAMES and in_agent_dir)
    is_text_secret = name.startswith(".env") or (ext in TEXT_SECRET_EXT and (in_agent_dir or all_files))
    if not (is_instruction or is_skill or is_json or is_toml or is_text_secret):
        return
    raw = _read(path)
    if raw is None:
        return
    report.files_scanned += 1
    rel = os.path.relpath(path, root)
    ctx = context_of(rel)
    found = []
    if is_json:
        obj = rules.parse_json_lenient(raw)
        if obj is not None and not any(k in raw for k in STRUCTURE_KEYS) and not all_files:
            found.extend(rules.detect_secrets(raw, rel, obj))
        else:
            found.extend(rules.detect_json(raw, rel, obj))
            if obj is not None:
                found.extend(rules.detect_secrets(raw, rel, obj))
            else:
                found.extend(rules.detect_secrets(raw, rel))
    if is_toml:
        found.extend(rules.detect_toml(raw, rel))
        found.extend(rules.detect_secrets(raw, rel))
    if is_instruction:
        found.extend(rules.detect_instructions(raw, rel))
    if is_skill:
        found.extend(rules.detect_frontmatter(raw, rel))
        found.extend(rules.detect_hidden_text(raw, rel))
    if is_text_secret:
        found.extend(rules.detect_secrets(raw, rel))
    if packs:
        found.extend(rules.apply_pattern_rules(raw, rel, os.path.basename(path), packs))
    for f in found:
        if ctx == "fixture" and not include_fixtures:
            f.context = "fixture"
            f.severity = "INFO"
        report.add(f)
