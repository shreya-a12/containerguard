"""Tests for the ContainerGuard command-line interface."""

import pytest

from containerguard.cli import build_parser, main


def test_root_help_lists_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "scan" in output
    assert "analyze" in output
    assert "compare" in output


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("scan", "scan an image"),
        ("analyze", "existing Trivy JSON report"),
        ("compare", "Compare before-and-after"),
    ],
)
def test_subcommands_are_available(command, expected):
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args([command, "--help"])
    assert exc.value.code == 0


def test_scan_requires_image():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["scan"])
    assert exc.value.code == 2


def test_analyze_requires_report():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["analyze"])
    assert exc.value.code == 2


def test_compare_requires_two_reports():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["compare", "before.json"])
    assert exc.value.code == 2
