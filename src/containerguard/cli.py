"""Command-line interface for ContainerGuard."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from containerguard import __version__
from containerguard.analysis import analyze_trivy_report, load_trivy_report, print_summary
from containerguard.errors import ContainerGuardError
from containerguard.scanner import scan_image


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser and available subcommands."""
    parser = argparse.ArgumentParser(
        prog="containerguard",
        description="Scan container images and summarize vulnerabilities reported by Trivy.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan an image and summarize its vulnerabilities.")
    scan_parser.add_argument("image", help="Docker image reference, e.g. python:3.12-slim")
    scan_parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for the raw Trivy JSON report (default: reports).",
    )

    analyze_parser = subparsers.add_parser("analyze", help="Analyze an existing Trivy JSON report.")
    analyze_parser.add_argument("report", help="Path to a saved Trivy JSON report.")

    compare_parser = subparsers.add_parser("compare", help="Compare before-and-after scan reports.")
    compare_parser.add_argument("before", help="Path to the baseline report.")
    compare_parser.add_argument("after", help="Path to the newer report.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            report_path = scan_image(args.image, args.output_dir)
            report = load_trivy_report(report_path)
            summary = analyze_trivy_report(report)
            print_summary(summary)
            print(f"Raw Trivy report saved to: {report_path}")
            return 0

        if args.command == "analyze":
            report = load_trivy_report(args.report)
            print_summary(analyze_trivy_report(report))
            return 0

        if args.command == "compare":
            raise ContainerGuardError(
                "Report comparison is planned for Phase 3 and is not implemented yet."
            )
    except ContainerGuardError as exc:
        print(f"ContainerGuard: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
