# detection/windowing.py
# ---------------------------------------------------------------
# Purpose: the shared sliding-window helper and the small helpers every rule uses.
# find_bursts: finds groups of events (or distinct values) that reach a threshold
#     inside a time window, merging overlapping windows into one burst (C.6).
# _clean_events / _get_trusted_ip_set / _get_setting / _format_count: private
#     helpers (leading underscore) shared by auth_rules.py and network_rules.py.
# Uses: core/errors.py and the Python standard library only. It never imports
# config, streamlit, sqlite3, ingestion, storage, reporting or the dashboard.

import ipaddress
from datetime import datetime, timedelta

from core.errors import ConfigError


# ---------------------------------------------------------------
# find_bursts (public, FS.4)
# ---------------------------------------------------------------

def _check_burst_inputs(timestamps, values, threshold, window_seconds):
    """Raise ValueError if the arguments of find_bursts cannot make sense.
    (A bad threshold or window is a programming mistake, not bad data.)"""
    if values is not None and len(values) != len(timestamps):
        raise ValueError("timestamps and values must have the same length")
    if threshold < 1:
        raise ValueError("threshold must be 1 or more")
    if window_seconds < 0:
        raise ValueError("window_seconds must not be negative")


def _add_value(value_counts, value):
    """Count one more copy of value inside the current window."""
    if value in value_counts:
        value_counts[value] = value_counts[value] + 1
    else:
        value_counts[value] = 1


def _remove_value(value_counts, value):
    """Count one fewer copy of value. When none are left the value is forgotten,
    so len(value_counts) is always the number of DISTINCT values in the window."""
    value_counts[value] = value_counts[value] - 1
    if value_counts[value] == 0:
        del value_counts[value]


def _merge_ranges(trigger_ranges):
    """
    Purpose: merge triggering windows that share at least one event.
    Inputs: trigger_ranges (list of (first_index, last_index)) - in order, both
        ends inclusive.
    Output: list of (first_index, last_index) - one pair per burst.
    Steps:
        1. Start with the first range as the current burst.
        2. If the next range starts at or before the current burst's last
           index, they overlap: stretch the current burst.
        3. Otherwise store the current burst and start a new one.
    Example: [(0, 4), (1, 5), (9, 13)] -> [(0, 5), (9, 13)].
    Errors: none.
    """
    merged_bursts = []
    for first_index, last_index in trigger_ranges:
        if len(merged_bursts) > 0 and first_index <= merged_bursts[-1][1]:
            previous_first = merged_bursts[-1][0]
            previous_last = merged_bursts[-1][1]
            merged_bursts[-1] = (previous_first, max(previous_last, last_index))
        else:
            merged_bursts.append((first_index, last_index))
    return merged_bursts


def find_bursts(timestamps: list, values: list | None, threshold: int,
                window_seconds: int) -> list:
    """
    Purpose: find every burst: a stretch of events that reaches the threshold
        inside a time window. One long attack gives ONE burst, not hundreds.
    Inputs:
        timestamps (list of datetime) - timezone-aware, sorted oldest first.
            (Sorting is the caller's job; this function does not check it.)
        values (list or None) - None means "count the events". A list of the
            same length means "count DISTINCT values" (used for ports). The
            values must not be None themselves.
        threshold (int) - 1 or more. Inclusive: exactly threshold triggers.
        window_seconds (int) - 0 or more. Inclusive: two events exactly
            window_seconds apart still share a window.
    Output: list of (first_index, last_index) pairs, both inclusive, oldest
        burst first. Empty list if nothing triggers.
    Steps:
        1. Check the arguments.
        2. For each event, treat it as the RIGHT end of a window. Move the LEFT
           marker forward until the window is no longer than window_seconds.
        3. Count the events (or distinct values) between the two markers.
        4. If the count reaches the threshold, remember the pair of markers.
        5. Merge remembered windows that overlap (see _merge_ranges).
    Example: five events 10 s apart, threshold 5, window 300 -> [(0, 4)];
        the same events with threshold 6 -> [].
    Errors: ValueError if timestamps and values differ in length, if threshold
        is below 1, or if window_seconds is negative.
    """
    _check_burst_inputs(timestamps, values, threshold, window_seconds)
    window_length = timedelta(seconds=window_seconds)  # timedelta compares exactly, no rounding
    value_counts = {}
    left_index = 0
    trigger_ranges = []
    for right_index in range(len(timestamps)):
        if values is not None:
            _add_value(value_counts, values[right_index])
        while timestamps[right_index] - timestamps[left_index] > window_length:
            if values is not None:
                _remove_value(value_counts, values[left_index])
            left_index = left_index + 1
        if values is None:
            count_in_window = right_index - left_index + 1
        else:
            count_in_window = len(value_counts)
        if count_in_window >= threshold:
            trigger_ranges.append((left_index, right_index))
    return _merge_ranges(trigger_ranges)


# ---------------------------------------------------------------
# Private helpers shared by the rule files
# ---------------------------------------------------------------

def _get_setting(config, key):
    """Return config[key], or raise ConfigError saying which setting is missing.
    (Detection may not import config/settings.py, so it cannot fill defaults.)"""
    if not isinstance(config, dict) or key not in config:
        raise ConfigError("detection needs the setting: " + key)
    return config[key]


def _get_trusted_ip_set(config):
    """
    Purpose: turn config['trusted_ips'] into a set of normalised address text,
        so 'is this address trusted?' is one fast, exact check.
    Inputs: config (dict) - may have no trusted_ips key (then nobody is trusted).
    Output: set of str - addresses written the way the ipaddress module writes them.
    Steps:
        1. Read the list (missing key means an empty list).
        2. Normalise each address with ipaddress (the same form events use).
        3. Raise ConfigError for anything that is not an address.
    Example: {"trusted_ips": [" 10.0.0.1 "]} -> {"10.0.0.1"}.
    Errors: ConfigError if trusted_ips is not a list of valid addresses.
    """
    address_list = config.get("trusted_ips", []) if isinstance(config, dict) else []
    if not isinstance(address_list, list):
        raise ConfigError("trusted_ips must be a list")
    trusted_set = set()
    for address_text in address_list:
        # try/except: ipaddress raises ValueError for text that is not an address;
        # we turn that into the project's own ConfigError.
        try:
            trusted_set.add(str(ipaddress.ip_address(str(address_text).strip())))
        except ValueError as error:
            raise ConfigError("trusted_ips has an invalid address: " + repr(address_text)) from error
    return trusted_set


def _is_usable_event(event):
    """True for a dictionary event with an ID, an aware timestamp and a source
    address: the minimum every rule needs, and what an alert's evidence needs."""
    if not isinstance(event, dict):
        return False
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or event_id == "":
        return False
    source_ip = event.get("source_ip")
    if not isinstance(source_ip, str) or source_ip == "":
        return False
    timestamp = event.get("timestamp")
    return isinstance(timestamp, datetime) and timestamp.utcoffset() is not None


def _event_sort_key(event):
    """The one agreed time order: timestamp, then file name, then row number,
    then event_id. The last three only break ties, so the order is the same
    whatever order the caller listed the events in."""
    source_file = event.get("source_file")
    source_row = event.get("source_row")
    if not isinstance(source_file, str):
        source_file = ""
    if not isinstance(source_row, int):
        source_row = 0
    return (event["timestamp"], source_file, source_row, event["event_id"])


def _clean_events(events):
    """
    Purpose: give a rule a safe, ordered list to work on.
    Inputs: events (list) - whatever the caller passed in.
    Output: list of event dicts - only usable events, each event_id once (the
        first one wins), sorted in time order. The caller's list is untouched.
    Steps:
        1. Skip anything that is not a usable event (_is_usable_event).
        2. Skip a second event that carries an event_id already seen
           (make_alert would refuse an alert holding the same ID twice).
        3. Sort with _event_sort_key.
    Example: [event_b, junk, event_a, event_a_again] -> [event_a, event_b].
    Errors: none; bad input is skipped, never raised (FS.3.3).
    """
    seen_ids = set()
    cleaned = []
    for event in events:
        if not _is_usable_event(event):
            continue
        if event["event_id"] in seen_ids:
            continue
        seen_ids.add(event["event_id"])
        cleaned.append(event)
    return sorted(cleaned, key=_event_sort_key)


def _copy_settings(config, keys):
    """A new dictionary holding just the named settings: the evidence
    'rule_parameters', so an alert records the thresholds it was made with."""
    parameters = {}
    for key in keys:
        parameters[key] = _get_setting(config, key)
    return parameters


def _format_count(count, word, plural_word=None):
    """1 -> '1 second', 5 -> '5 seconds'. Pass plural_word for an irregular
    plural, for example _format_count(2, 'address', 'addresses')."""
    if count == 1:
        return "1 " + word
    if plural_word is None:
        plural_word = word + "s"
    return str(count) + " " + plural_word


def _format_time(value):
    """A datetime as readable UTC text, e.g. 2025-03-14 09:15:02 UTC."""
    return value.strftime("%Y-%m-%d %H:%M:%S") + " UTC"


def _whole_seconds_between(earlier, later):
    """Whole seconds from earlier to later, rounded down (never negative)."""
    return int((later - earlier).total_seconds())
