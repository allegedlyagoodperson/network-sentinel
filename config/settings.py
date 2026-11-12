# config/settings.py
# ---------------------------------------------------------------
# Purpose: the one configuration dictionary of Network Sentinel (FS.3.5).
# DEFAULT_CONFIG: every setting and its starting value.
# get_default_config: gives a fresh copy of the defaults.
# validate_config: checks a configuration, fills in missing keys, and
#     raises ConfigError when something is wrong.
# Only app.py and the dashboard import this file. Pipeline modules
# receive the config dictionary as a parameter instead.
# Uses: core/errors.py only (plus ipaddress and math from Python).

import ipaddress
import math

from core.errors import ConfigError

# These are teaching starting points, not security standards (decision D4).
DEFAULT_CONFIG = {
    "max_upload_mb": 10,
    "max_rows_per_file": 100000,
    "assume_utc": True,
    "trusted_ips": [],
    "auth_failed_threshold": 5,
    "auth_window_seconds": 300,
    "auth_success_after_failure_seconds": 300,
    "portscan_distinct_ports_threshold": 15,
    "portscan_window_seconds": 60,
    "reject_threshold": 20,
    "reject_window_seconds": 120,
    "volume_window_seconds": 300,
    "volume_min_bytes": 10000000,  # 10 MB means 10,000,000 bytes (decimal), NOT 10,485,760
    "volume_multiplier": 5.0,
    "volume_min_windows": 6,
    "volume_min_coverage": 0.5,
    "correlation_window_seconds": 900,
}

# Settings that must be whole numbers greater than zero.
_WHOLE_NUMBER_KEYS = [
    "max_upload_mb",
    "max_rows_per_file",
    "auth_failed_threshold",
    "auth_window_seconds",
    "auth_success_after_failure_seconds",
    "portscan_distinct_ports_threshold",
    "portscan_window_seconds",
    "reject_threshold",
    "reject_window_seconds",
    "volume_window_seconds",
    "volume_min_bytes",
    "volume_min_windows",
    "correlation_window_seconds",
]


def get_default_config() -> dict:
    """
    Purpose: give a fresh copy of the default settings.
    Inputs: none.
    Output: dict - all 17 settings with their default values.
    Steps:
        1. Copy DEFAULT_CONFIG into a new dictionary.
        2. Give the copy its own empty trusted_ips list, because a list is
           shared between copies unless we make a new one.
    Example: get_default_config()["volume_min_bytes"] -> 10000000.
    Errors: none.
    """
    config = dict(DEFAULT_CONFIG)
    config["trusted_ips"] = []
    return config


def _check_positive_whole_number(key, value):
    """Raise ConfigError unless value is a whole number greater than zero."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(key + " must be a whole number")
    if value <= 0:
        raise ConfigError(key + " must be greater than zero")


def _check_positive_number(key, value):
    """Raise ConfigError unless value is a real number greater than zero.
    Returns the value as a float."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(key + " must be a number")
    if not math.isfinite(value):
        raise ConfigError(key + " must be a finite number")
    if value <= 0:
        raise ConfigError(key + " must be greater than zero")
    return float(value)


def _clean_trusted_ips(value):
    """Check the trusted address list and return it in normalised text form,
    so it can be compared with the source_ip of events."""
    if not isinstance(value, list):
        raise ConfigError("trusted_ips must be a list")
    cleaned_addresses = []
    for address_text in value:
        if not isinstance(address_text, str):
            raise ConfigError("trusted_ips must contain only text")
        try:
            parsed_address = ipaddress.ip_address(address_text.strip())
        except ValueError as error:
            raise ConfigError("trusted_ips has an invalid address: " + repr(address_text)) from error
        cleaned_addresses.append(str(parsed_address))
    return cleaned_addresses


def validate_config(config: dict) -> dict:
    """
    Purpose: check a configuration and return a safe, complete copy.
    Inputs: config (dict) - may have only some of the 17 settings.
    Output: dict - a NEW dictionary with every setting. The input is not
        changed. volume_multiplier and volume_min_coverage are floats, and
        trusted_ips are written in normalised form.
    Steps:
        1. Check config is a dictionary with no unknown keys (a typo such as
           "auth_failed_treshold" would otherwise be silently ignored).
        2. Start from the defaults and copy the given values over them.
        3. Check the whole-number settings are whole numbers above zero.
        4. Check assume_utc is True or False.
        5. Check volume_multiplier is above zero and volume_min_coverage is
           above zero and at most 1 (it is a share).
        6. Check and normalise trusted_ips.
    Example: validate_config({"auth_failed_threshold": 3}) -> all defaults,
        except auth_failed_threshold is 3.
    Errors: ConfigError for any bad key, type or value.
    """
    if not isinstance(config, dict):
        raise ConfigError("config must be a dictionary")
    for key in config:
        if key not in DEFAULT_CONFIG:
            raise ConfigError("unknown setting: " + str(key))
    checked = get_default_config()
    for key in config:
        checked[key] = config[key]
    for key in _WHOLE_NUMBER_KEYS:
        _check_positive_whole_number(key, checked[key])
    if not isinstance(checked["assume_utc"], bool):
        raise ConfigError("assume_utc must be True or False")
    checked["volume_multiplier"] = _check_positive_number(
        "volume_multiplier", checked["volume_multiplier"]
    )
    checked["volume_min_coverage"] = _check_positive_number(
        "volume_min_coverage", checked["volume_min_coverage"]
    )
    if checked["volume_min_coverage"] > 1:
        raise ConfigError("volume_min_coverage is a share and must be at most 1")
    checked["trusted_ips"] = _clean_trusted_ips(checked["trusted_ips"])
    return checked
