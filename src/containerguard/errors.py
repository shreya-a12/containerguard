"""Typed exceptions used by the ContainerGuard CLI."""


class ContainerGuardError(Exception):
    """Base class for expected, user-facing ContainerGuard errors."""


class InputError(ContainerGuardError):
    """Raised when command input is invalid."""


class ConfigurationError(ContainerGuardError):
    """Raised when policy or application configuration is invalid."""


class ScannerError(ContainerGuardError):
    """Raised when the vulnerability scanner cannot complete successfully."""


class ReportError(ContainerGuardError):
    """Raised when a report cannot be read or written."""
