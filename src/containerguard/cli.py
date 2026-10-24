"""Command-line interface for ContainerGuard."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from containerguard import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser and available subcommands."""
    parser = argparse.ArgumentParser(
        prog="containerguard",
        description="Scan container images and enforce configurable vulnerability policies.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan an image and evaluate its policy.")
    scan_parser.add_argument("image", help="Docker image reference, e.g. python:3.12-slim")
    scan_parser.add_argument("--policy", help="Path to a YAML policy file.")
    scan_parser.add_argument("--output-dir", default="reports", help="Directory for generated reports.")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze an existing Trivy JSON report.")
    analyze_parser.add_argument("report", help="Path to a saved Trivy JSON report.")
    analyze_parser.add_argument("--policy", help="Path to a YAML policy file.")
    analyze_parser.add_argument("--output-dir", default="reports", help="Directory for generated reports.")

    compare_parser = subparsers.add_parser("compare", help="Compare before-and-after scan reports.")
    compare_parser.add_argument("before", help="Path to the baseline report.")
    compare_parser.add_argument("after", help="Path to the newer report.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Implementations are intentionally delivered in later, testable phases.
    if args.command == "scan":
        parser.exit(2, "ContainerGuard: scan integration is not implemented yet (planned Phase 2/4).\n")
    if args.command == "analyze":
        parser.exit(2, "ContainerGuard: report analysis is not implemented yet (planned Phase 2).\n")
    if args.command == "compare":
        parser.exit(2, "ContainerGuard: report comparison is not implemented yet (planned Phase 3).\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
