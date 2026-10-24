"""Command-line interface for ContainerGuard."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from containerguard import __version__
from containerguard.analysis import analyze_trivy_report, load_trivy_report, print_summary
from containerguard.errors import ContainerGuardError, ReportError
from containerguard.policy import evaluate_policy, load_policy
from containerguard.reports import compare_summaries, write_reports
from containerguard.scanner import scan_image


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser and available subcommands."""
    parser = argparse.ArgumentParser(
        prog="containerguard",
        description="Scan container images and summarize vulnerabilities reported by Trivy.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan an image and evaluate its security policy.")
    scan_parser.add_argument("image", help="Docker image reference, e.g. python:3.12-slim")
    scan_parser.add_argument("--policy", help="Path to a YAML policy file.")
    scan_parser.add_argument("--output-dir", default="reports", help="Directory for raw and formatted reports.")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a saved Trivy JSON report.")
    analyze_parser.add_argument("report", help="Path to a saved Trivy JSON report.")
    analyze_parser.add_argument("--policy", help="Path to a YAML policy file.")
    analyze_parser.add_argument("--output-dir", default="reports", help="Directory for formatted reports.")

    compare_parser = subparsers.add_parser("compare", help="Compare before-and-after scan reports.")
    compare_parser.add_argument("before", help="Path to the baseline Trivy JSON report.")
    compare_parser.add_argument("after", help="Path to the newer Trivy JSON report.")
    compare_parser.add_argument("--output-dir", default="reports", help="Directory for the comparison JSON report.")
    return parser


def _analyze_and_report(report: dict, policy_path: str | None, output_dir: str, stem: str) -> int:
    summary = analyze_trivy_report(report)
    policy = load_policy(policy_path)
    result = evaluate_policy(summary, policy)
    print_summary(summary)
    print(f"Policy: {'PASS' if result['passed'] else 'FAIL'} ({result['violation_count']} violation(s))")
    paths = write_reports(summary, result, output_dir, stem)
    for kind, path in paths.items():
        print(f"{kind.upper()} report: {path}")
    return 0 if result["passed"] else 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            report_path = scan_image(args.image, args.output_dir)
            print(f"Raw Trivy report saved to: {report_path}")
            return _analyze_and_report(
                load_trivy_report(report_path), args.policy, args.output_dir, report_path.stem
            )

        if args.command == "analyze":
            report_path = Path(args.report)
            return _analyze_and_report(
                load_trivy_report(report_path), args.policy, args.output_dir, report_path.stem
            )

        if args.command == "compare":
            before = analyze_trivy_report(load_trivy_report(args.before))
            after = analyze_trivy_report(load_trivy_report(args.after))
            result = compare_summaries(before, after)
            destination = Path(args.output_dir)
            try:
                destination.mkdir(parents=True, exist_ok=True)
                output = destination / "comparison.json"
                output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            except OSError as exc:
                raise ReportError(f"Could not write comparison report: {exc}") from exc
            print(f"Before: {result['before_image']} ({result['before_total']} findings)")
            print(f"After:  {result['after_image']} ({result['after_total']} findings)")
            print(f"Fixed: {result['fixed_count']}; new: {result['new_count']}; remaining: {result['remaining_count']}")
            print(f"Comparison JSON: {output}")
            return 0
    except ContainerGuardError as exc:
        print(f"ContainerGuard: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
