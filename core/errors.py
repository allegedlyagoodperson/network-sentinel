# core/errors.py
# ---------------------------------------------------------------
# Purpose: the project's own exception classes (FS.4). These are the ONLY
# classes in the whole project (Section 0.1 bans custom classes for data).
# A class here is just a named kind of error, so other modules can say
# "raise ContractError(...)" and callers can say "except ContractError".
# The tree below shows who inherits from whom.
# Uses: nothing (Python built-ins only).
#
#   NetworkSentinelError
#     |- ContractError, ConfigError, IngestionError, ReportError
#     |- DatabaseError
#          |- BrokenReferenceError, IncidentNotFound, InvalidStatusTransition


class NetworkSentinelError(Exception):
    """Parent of every error this project raises on purpose."""


class ContractError(NetworkSentinelError):
    """An event or alert was built with invalid values."""


class ConfigError(NetworkSentinelError):
    """The configuration dictionary is invalid."""


class IngestionError(NetworkSentinelError):
    """A whole file could not be processed."""


class ReportError(NetworkSentinelError):
    """A PDF report could not be built."""


class DatabaseError(NetworkSentinelError):
    """A SQLite operation failed or a reference does not exist."""


class BrokenReferenceError(DatabaseError):
    """A save would leave an alert or event reference that does not resolve."""


class IncidentNotFound(DatabaseError):
    """No incident exists with the requested ID."""


class InvalidStatusTransition(DatabaseError):
    """The requested incident status change is not allowed."""
