from __future__ import annotations
import argparse
import sys

from . import __version__
from .model import SEVERITIES, SEV_RANK
from .report import render_json, render_markdown, render_terminal
from .scanner import scan_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agentscan",
        description="Scan AI-agent configs (MCP servers, CLAUDE.md, settings, hooks) "
                    "for security misconfigurations.",
    )
    p.add_argument("path", nargs="?", default=".", help="file or directory to scan")
    p.add_argument("--format", choices=["terminal", "json", "markdown"],
                   default="terminal")
    p.add_argument("--output", "-o", help="write report to a file instead of stdout")
    p.add_argument("--min-severity", choices=SEVERITIES, default="INFO",
                   help="hide findings below this severity")
    p.add_argument("--fail-on", choices=SEVERITIES, default="HIGH",
                   help="exit non-zero if any finding is at or above this severity")
    p.add_argument("--rules", nargs="*", default=[],
                   help="extra JSON rule pack(s) to load (agentscan Pro / org rules)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"agentscan {__version__}")
    args = p.parse_args(argv)

    report = scan_path(args.path, rule_files=args.rules)
    floor = SEV_RANK[args.min_severity]
    report.findings = [f for f in report.findings if SEV_RANK[f.severity] >= floor]

    if args.format == "json":
        text = render_json(report)
    elif args.format == "markdown":
        text = render_markdown(report)
    else:
        text = render_terminal(report, color=not args.no_color and not args.output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(text)

    return 1 if report.max_rank() >= SEV_RANK[args.fail_on] else 0


if __name__ == "__main__":
    raise SystemExit(main())
