from __future__ import annotations
import os

from .model import Report
from . import rules

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
             "build", ".mypy_cache", ".pytest_cache", ".ruff_cache"}

INSTRUCTION_NAMES = {
    "claude.md", "agents.md", "agent.md", "gemini.md", ".cursorrules",
    ".clinerules", ".windsurfrules", "copilot-instructions.md",
}
JSON_EXT = {".json"}
SECRET_EXT = {".json", ".env", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
MAX_BYTES = 2_000_000


def _read(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def scan_path(root: str, rule_files=None) -> Report:
    report = Report()
    packs = rules.load_pattern_rules(rule_files or [])
    if os.path.isfile(root):
        _scan_file(root, os.path.dirname(root) or ".", report, packs)
        return report
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            _scan_file(os.path.join(dirpath, fn), root, report, packs)
    return report


def _scan_file(path: str, root: str, report: Report, packs=None) -> None:
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    is_instruction = name in INSTRUCTION_NAMES or name.endswith(".instructions.md")
    is_json = ext in JSON_EXT
    is_secret_scannable = ext in SECRET_EXT or is_instruction or name.startswith(".env")
    if not (is_instruction or is_json or is_secret_scannable):
        return
    raw = _read(path)
    if raw is None:
        return
    report.files_scanned += 1
    rel = os.path.relpath(path, root)
    if is_json and ("mcpServers" in raw or "permissions" in raw or "hooks" in raw
                    or "alwaysAllow" in raw or "autoApprove" in raw
                    or "dangerously" in raw or "bypassPermissions" in raw):
        for f in rules.detect_json(raw, rel):
            report.add(f)
    if is_instruction:
        for f in rules.detect_instructions(raw, rel):
            report.add(f)
    if is_secret_scannable:
        for f in rules.detect_secrets(raw, rel):
            report.add(f)
    if packs:
        for f in rules.apply_pattern_rules(raw, rel, os.path.basename(path), packs):
            report.add(f)
