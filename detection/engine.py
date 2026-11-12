# detection/engine.py
# ---------------------------------------------------------------
# Purpose: the one entry point of the analysis (FS.4): run_analysis runs the four
# detection rules, then the correlator, and returns everything the dashboard
# needs in one dictionary.
# run_analysis: the public function.
# _check_detection_config: checks the settings detection needs (detection may not
#     import config/settings.py, so it cannot call validate_config).
# Uses: core.contracts, core.errors, detection.auth_rules, detection.network_rules,
# detection.windowing and correlation.correlator (the only allowed cross-folder import).

import math

from core.contracts import utc_now
from core.errors import ConfigError
from correlation.correlator import correlate_alerts
from detection.auth_rules import detect_failed_logins
from detection.network_rules import (
    detect_port_scans,
    detect_repeated_rejections,
    detect_unusual_traffic_volume,
)
from detection.windowing import _get_trusted_ip_set

_WHOLE_NUMBER_KEYS = [
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


def _check_detection_config(config):
    """
    Purpose: refuse a configuration the rules cannot use, before any rule runs.
    Inputs: config (dict) - should hold the detection settings of FS.3.5.
    Output: none.
    Steps:
        1. Every whole-number setting must exist, be a whole number (not True or
           False) and be above zero.
        2. volume_multiplier must be a finite number above zero.
        3. volume_min_coverage must be above zero and at most 1 (it is a share).
        4. trusted_ips (if present) must be a list of valid addresses.
    Example: auth_failed_threshold = 0 -> ConfigError.
    Errors: ConfigError for any missing, mistyped or out-of-range setting.
    """
    if not isinstance(config, dict):
        raise ConfigError("config must be a dictionary")
    for key in _WHOLE_NUMBER_KEYS:
        if key not in config:
            raise ConfigError("missing setting: " + key)
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ConfigError(key + " must be a whole number greater than zero")
    for key in ["volume_multiplier", "volume_min_coverage"]:
        if key not in config:
            raise ConfigError("missing setting: " + key)
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ConfigError(key + " must be a number greater than zero")
    if config["volume_min_coverage"] > 1:
        raise ConfigError("volume_min_coverage is a share and must be at most 1")
    _get_trusted_ip_set(config)  # raises ConfigError for a bad address list


def _count_inputs(events, trusted_ips):
    """
    Purpose: count what happened to the input list, for the result and the notes.
    Inputs: events (list); trusted_ips (set of address text).
    Output: dict with analysed, ignored_trusted, not_dictionaries,
        duplicate_ids (all ints).
    Steps:
        1. Items that are not dictionaries are counted and set aside.
        2. A second event with an already-seen event_id is counted as a duplicate.
        3. Events from a trusted address are counted as ignored.
        4. Every other event counts as analysed.
    Example: 10 events, 2 from a trusted address -> analysed 8, ignored_trusted 2.
    Errors: none.
    """
    counts = {"analysed": 0, "ignored_trusted": 0, "not_dictionaries": 0, "duplicate_ids": 0}
    seen_ids = set()
    for event in events:
        if not isinstance(event, dict):
            counts["not_dictionaries"] = counts["not_dictionaries"] + 1
            continue
        event_id = event.get("event_id")
        if isinstance(event_id, str) and event_id in seen_ids:
            counts["duplicate_ids"] = counts["duplicate_ids"] + 1
            continue
        if isinstance(event_id, str):
            seen_ids.add(event_id)
        if event.get("source_ip") in trusted_ips:
            counts["ignored_trusted"] = counts["ignored_trusted"] + 1
        else:
            counts["analysed"] = counts["analysed"] + 1
    return counts


def _write_input_notes(counts):
    """Notes about input that was skipped, so nothing is dropped silently."""
    notes = []
    if counts["not_dictionaries"] > 0:
        notes.append(str(counts["not_dictionaries"]) + " items in the event list were not event dictionaries and were skipped.")
    if counts["duplicate_ids"] > 0:
        notes.append(str(counts["duplicate_ids"]) + " events repeated an event_id already in the list and were skipped.")
    return notes


def _alert_sort_key(alert):
    """Final order of the result: time_start, then rule_id, then alert_id (a tie-breaker)."""
    return (alert["time_start"], alert["rule_id"], alert["alert_id"])


def run_analysis(events: list, config: dict) -> dict:
    """
    Purpose: run all four detection rules and the correlator in the right order.
    Inputs:
        events (list of dict) - normalised events from ingestion, any order.
        config (dict) - the detection settings of FS.3.5.
    Output: dict with exactly these keys: alerts (base and correlated alerts,
        sorted by time_start then rule_id), base_alert_count (int),
        correlated_alert_count (int), notes (list of str), events_analysed
        (int, events not from trusted addresses), events_ignored_trusted (int),
        analysed_at (datetime, UTC).
    Steps:
        1. Check the configuration (ConfigError if it is unusable).
        2. Count the input and write notes for anything that was skipped.
        3. Run the four rules; collect their alerts and notes.
        4. Run the correlator on the base alerts.
        5. Give every alert the same detected_at (the time of this analysis);
           it is not part of any alert ID.
        6. Sort the alerts and return the result.
    Example: the Stage 0 sample files -> 4 base alerts, 1 correlated alert.
    Errors: ConfigError if config is invalid. Bad events never raise: they are skipped.
    """
    _check_detection_config(config)
    trusted_ips = _get_trusted_ip_set(config)
    counts = _count_inputs(events, trusted_ips)
    notes = _write_input_notes(counts)
    base_alerts = []
    for rule_function in [detect_failed_logins, detect_port_scans, detect_repeated_rejections, detect_unusual_traffic_volume]:
        rule_alerts, rule_notes = rule_function(events, config)
        base_alerts.extend(rule_alerts)
        notes.extend(rule_notes)
    correlated_alerts = correlate_alerts(base_alerts, events, config)
    all_alerts = base_alerts + correlated_alerts
    analysed_at = utc_now()
    for alert in all_alerts:
        alert["detected_at"] = analysed_at  # one analysis time for the whole run
    return {
        "alerts": sorted(all_alerts, key=_alert_sort_key),
        "base_alert_count": len(base_alerts),
        "correlated_alert_count": len(correlated_alerts),
        "notes": notes,
        "events_analysed": counts["analysed"],
        "events_ignored_trusted": counts["ignored_trusted"],
        "analysed_at": analysed_at,
    }
