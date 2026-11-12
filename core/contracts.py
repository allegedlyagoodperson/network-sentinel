# core/contracts.py
# ---------------------------------------------------------------
# Purpose: the shared rules of Network Sentinel. Every other module builds
# events and alerts ONLY through the functions in this file.
# Constants: the allowed values and key lists (the project vocabulary).
# make_event / make_alert: build a valid event or alert, including its ID.
# make_event_id / make_alert_id / make_content_fingerprint / canonical_json:
#     the only place where IDs and canonical JSON text are created.
# validate_event / validate_alert: return a list of problems (empty = valid).
# datetime_to_iso / iso_to_datetime / utc_now: the time helpers.
# Uses: core/errors.py only (plus the Python standard library).

import hashlib
import ipaddress
import json
from datetime import datetime, timedelta, timezone

from core.errors import ContractError

# ---------------------------------------------------------------
# Constants (FS.3 and FS.4). Nobody changes these without the H.6 process.
# ---------------------------------------------------------------

# A float on purpose: the specification and the Stage 0 tests say 1.0.
CONTRACT_VERSION = 1.0

EVENT_TYPES = ["authentication", "network_connection"]
AUTH_STATUSES = ["success", "failure"]
NETWORK_STATUSES = ["allowed", "rejected"]
SEVERITIES = ["low", "medium", "high", "critical"]  # ordered low to critical
CONFIDENCES = ["low", "medium", "high"]
INCIDENT_STATUSES = ["open", "investigating", "resolved", "false_positive"]

# For each status: the statuses an incident is allowed to move to (C.3).
ALLOWED_STATUS_TRANSITIONS = {
    "open": ["investigating", "resolved", "false_positive"],
    "investigating": ["open", "resolved", "false_positive"],
    "resolved": ["investigating"],
    "false_positive": ["investigating"],
}

RULE_IDS = [
    "AUTH_BRUTE_FORCE",
    "NET_PORT_SCAN",
    "NET_REPEATED_REJECTS",
    "NET_HIGH_VOLUME",
    "CORR_AUTH_NET",
]

# The fifteen keys of an event, in the order the specification lists them.
EVENT_KEYS = [
    "event_id",
    "event_type",
    "timestamp",
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "username",
    "service",
    "status",
    "bytes_sent",
    "bytes_received",
    "source_file",
    "source_row",
    "raw_event",
]

# The thirteen keys of an alert.
ALERT_KEYS = [
    "alert_id",
    "rule_id",
    "title",
    "description",
    "severity",
    "confidence",
    "detected_at",
    "time_start",
    "time_end",
    "source_ip",
    "event_ids",
    "evidence",
    "recommended_action",
]

# The eleven keys that describe WHAT happened. Only these are hashed for the
# event ID. source_row, raw_event and event_id itself are never hashed.
EVENT_CONTENT_KEYS = [
    "event_type",
    "timestamp",
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "username",
    "service",
    "status",
    "bytes_sent",
    "bytes_received",
]

EVENT_ID_HEX_LENGTH = 16
MAX_DETAILED_SUCCESS_EVENTS = 10

# Private constants (the leading underscore means "only used in this file").
_REQUIRED_EVIDENCE_KEYS = ["rule_parameters", "observed", "explanation", "limitations"]
_CORRELATION_KEYS = [
    "link_key",
    "link_value",
    "linked_alert_ids",
    "gap_seconds",
    "destination_match",
    "match_conditions",
]
_ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%f+00:00"
_ISO_TEXT_LENGTH = 32  # for example 2025-03-14T09:15:02.000000+00:00
_FIRST_DATA_ROW = 2  # line 1 of a CSV file is the header
_MAX_RAW_VALUE_LENGTH = 500
_MAX_USERNAME_LENGTH = 100
_MAX_SERVICE_LENGTH = 30
_MAX_PROTOCOL_LENGTH = 10
_HEX_DIGITS = "0123456789abcdef"


# ---------------------------------------------------------------
# Small private helpers. Each one answers a single yes/no question.
# ---------------------------------------------------------------

def _is_whole_number(value):
    """True for an int. bool is excluded because True would count as 1."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_non_empty_text(value):
    """True for text that has at least one visible character."""
    return isinstance(value, str) and value.strip() != ""


def _is_list_of_text(value):
    """True for a list in which every item is text."""
    if not isinstance(value, list):
        return False
    for item in value:
        if not isinstance(item, str):
            return False
    return True


def _is_aware_utc(value):
    """True for a datetime that carries a timezone offset of exactly zero."""
    if not isinstance(value, datetime):
        return False
    offset = value.utcoffset()
    if offset is None:
        return False
    return offset == timedelta(0)


def _to_utc_if_aware(value):
    """Convert an aware datetime to UTC. Anything else is returned unchanged
    so that the validation step can report it."""
    if isinstance(value, datetime) and value.utcoffset() is not None:
        return value.astimezone(timezone.utc)
    return value


def _is_normalised_ip(text):
    """True if text is a valid IP address already written in the normalised
    form that the ipaddress module produces (IPv6: compressed, lowercase)."""
    if not isinstance(text, str):
        return False
    try:
        parsed_address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return str(parsed_address) == text


def _has_control_characters(text):
    """True if text contains an invisible control character (newline, tab...)."""
    for character in text:
        code = ord(character)
        if code < 32 or 127 <= code <= 159:
            return True
    return False


def _has_id_format(text, prefix):
    """True for text such as EVT-0123456789abcdef (prefix + 16 lowercase hex)."""
    if not isinstance(text, str) or not text.startswith(prefix):
        return False
    hex_part = text[len(prefix):]
    if len(hex_part) != EVENT_ID_HEX_LENGTH:
        return False
    for character in hex_part:
        if character not in _HEX_DIGITS:
            return False
    return True


def _hash_text(text):
    """SHA-256 of the text, as 64 hex characters. A hash is a fixed-size
    fingerprint: the same text always gives the same fingerprint."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------
# Time helpers (public)
# ---------------------------------------------------------------

def datetime_to_iso(value: datetime) -> str:
    """
    Purpose: turn a datetime into the project's one fixed text format.
    Inputs: value (datetime) - must be timezone-aware; any zone is accepted
        and converted to UTC first.
    Output: str - always 32 characters, six fractional digits, +00:00,
        for example 2025-03-14T09:15:02.000000+00:00.
    Steps:
        1. Refuse anything that is not an aware datetime.
        2. Convert to UTC.
        3. Format with a fixed pattern so every timestamp has the same width.
    Example: 2025-03-14 09:15:02 UTC -> "2025-03-14T09:15:02.000000+00:00".
    Errors: ValueError if value is not a datetime, is naive (no timezone),
        or has a year before 1000 (the text would not be fixed width).
    """
    if not isinstance(value, datetime):
        raise ValueError("datetime_to_iso needs a datetime object")
    if value.utcoffset() is None:
        raise ValueError("datetime_to_iso needs a timezone-aware datetime")
    utc_value = value.astimezone(timezone.utc)
    if utc_value.year < 1000:
        raise ValueError("datetime_to_iso only supports years 1000 to 9999")
    return utc_value.strftime(_ISO_FORMAT)


def iso_to_datetime(text: str) -> datetime:
    """
    Purpose: turn text made by datetime_to_iso back into a datetime.
    Inputs: text (str) - exactly the fixed 32-character format.
    Output: datetime - timezone-aware, in UTC.
    Steps:
        1. Check the text is a string of the expected length.
        2. Parse it with the same pattern that datetime_to_iso writes.
        3. Attach the UTC timezone.
    Example: "2025-03-14T09:15:02.000000+00:00" -> datetime(2025, 3, 14, 9, 15, 2, UTC).
    Errors: ValueError if the text is not in the fixed format.
    """
    if not isinstance(text, str) or len(text) != _ISO_TEXT_LENGTH:
        raise ValueError("iso_to_datetime needs text in the fixed 32 character format")
    parsed_value = datetime.strptime(text, _ISO_FORMAT)
    return parsed_value.replace(tzinfo=timezone.utc)


def utc_now() -> datetime:
    """
    Purpose: the current time as a timezone-aware UTC datetime.
    Inputs: none.
    Output: datetime - now, in UTC.
    Steps:
        1. Ask Python for the current time in the UTC zone.
    Example: utc_now().tzinfo is timezone.utc -> True.
    Errors: none.
    """
    return datetime.now(timezone.utc)


def _timestamp_to_text(value):
    """datetime_to_iso, but any problem becomes a ContractError."""
    try:
        return datetime_to_iso(value)
    except ValueError as error:
        raise ContractError("bad timestamp: " + str(error)) from error


# ---------------------------------------------------------------
# Small public helpers: severity order, incident ID text
# ---------------------------------------------------------------

def severity_rank(severity: str) -> int:
    """
    Purpose: give each severity a number so alerts can be sorted.
    Inputs: severity (str) - one of low, medium, high, critical.
    Output: int - low is 1, medium 2, high 3, critical 4.
    Steps:
        1. Reject unknown text.
        2. Return the position in SEVERITIES plus one.
    Example: severity_rank("high") -> 3.
    Errors: ValueError if severity is not in SEVERITIES.
    """
    if severity not in SEVERITIES:
        raise ValueError("unknown severity: " + repr(severity))
    return SEVERITIES.index(severity) + 1


def format_incident_id(incident_id: int) -> str:
    """
    Purpose: turn the database number of an incident into the text users see.
    Inputs: incident_id (int) - zero or greater.
    Output: str - INC- followed by the number padded to 4 digits.
    Steps:
        1. Check the number is a whole number that is not negative.
        2. Pad it with leading zeros.
    Example: format_incident_id(7) -> "INC-0007".
    Errors: ValueError if incident_id is not a whole number of zero or more.
    """
    if not _is_whole_number(incident_id) or incident_id < 0:
        raise ValueError("incident_id must be a whole number of zero or more")
    return "INC-" + str(incident_id).zfill(4)


# ---------------------------------------------------------------
# Canonical JSON and IDs
# ---------------------------------------------------------------

def canonical_json(data: dict) -> str:
    """
    Purpose: write a dictionary as ONE agreed piece of text, so hashing it
        always gives the same answer for the same data.
    Inputs: data (dict) - values may be text, numbers, True/False, None,
        lists and dictionaries.
    Output: str - JSON with keys sorted alphabetically, no spaces, non-English
        letters written as \\uXXXX escapes, and None written as null.
    Steps:
        1. Check data is a dictionary.
        2. Call json.dumps with sort_keys, compact separators and ASCII escaping.
        3. Turn any JSON problem into a ContractError.
    Example: {"b": None, "a": 1} -> '{"a":1,"b":null}'.
    Errors: ContractError if data is not a dict or holds something JSON cannot
        store (a datetime, a set, NaN...).
    """
    if not isinstance(data, dict):
        raise ContractError("canonical_json needs a dictionary")
    try:
        # sort_keys: the text cannot change because of insertion order.
        # separators: no spaces, so there is only one way to write it.
        # ensure_ascii: accents and emoji become \uXXXX, so the text is plain ASCII.
        # allow_nan=False: NaN has no valid JSON form, so it is refused.
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ContractError("canonical_json cannot convert this data: " + str(error)) from error


def _content_text_form(content):
    """
    Purpose: check a content dictionary has exactly the 11 keys and return a
        NEW copy in which the timestamp is written as fixed text.
    Inputs: content (dict) - the 11 EVENT_CONTENT_KEYS; timestamp is a datetime.
    Output: dict - the same 11 keys, with timestamp as fixed ISO text.
    Steps:
        1. Reject anything that is not a dictionary.
        2. Reject a missing key, then reject an unexpected key.
        3. Copy the values into a new dictionary and convert the timestamp.
    Example: {"timestamp": <09:15:02 UTC>, ...} -> {"timestamp": "2025-03-14T09:15:02.000000+00:00", ...}.
    Errors: ContractError for the problems in steps 1 and 2 or a bad timestamp.
    """
    if not isinstance(content, dict):
        raise ContractError("content must be a dictionary")
    for key in EVENT_CONTENT_KEYS:
        if key not in content:
            raise ContractError("content is missing key: " + key)
    for key in content:
        if key not in EVENT_CONTENT_KEYS:
            raise ContractError("content has an unexpected key: " + str(key))
    text_form = {}
    for key in EVENT_CONTENT_KEYS:
        text_form[key] = content[key]
    text_form["timestamp"] = _timestamp_to_text(content["timestamp"])
    return text_form


def _find_source_file_problem(source_file):
    """Return a problem sentence for a bad file name, or None if it is fine."""
    if not _is_non_empty_text(source_file):
        return "source_file must be non-empty text"
    if "/" in source_file or "\\" in source_file:
        return "source_file must be a file name only, never a folder path"
    return None


def make_event_id(content: dict, source_file: str, occurrence: int) -> str:
    """
    Purpose: build the ID of an event from what happened, which file it came
        from, and how many identical rows came before it in that file.
    Inputs:
        content (dict) - exactly the 11 keys in EVENT_CONTENT_KEYS; the
            timestamp is a timezone-aware datetime.
        source_file (str) - file name only, no folder.
        occurrence (int) - 1 for the first identical row in the file, 2 for
            the second, and so on. Restarts at 1 for every file.
    Output: str - "EVT-" plus the first 16 hex characters of a SHA-256 hash.
    Steps:
        1. Check the content keys and write the timestamp as fixed text.
        2. Check source_file and occurrence.
        3. Add source_file and occurrence to the dictionary.
        4. Convert to canonical JSON, encode as UTF-8, hash with SHA-256.
        5. Keep the first 16 hex characters and add the EVT- prefix.
    Example: the same row, same file, occurrence 1 -> always the same ID;
        occurrence 2 -> a different ID.
    Errors: ContractError for missing or extra content keys, a bad timestamp,
        a bad file name, or an occurrence that is not a whole number >= 1.
    """
    id_content = _content_text_form(content)
    file_problem = _find_source_file_problem(source_file)
    if file_problem is not None:
        raise ContractError(file_problem)
    if not _is_whole_number(occurrence) or occurrence < 1:
        raise ContractError("occurrence must be a whole number of 1 or more")
    id_content["source_file"] = source_file
    id_content["occurrence"] = occurrence
    full_hash = _hash_text(canonical_json(id_content))
    return "EVT-" + full_hash[:EVENT_ID_HEX_LENGTH]


def make_content_fingerprint(event: dict) -> str:
    """
    Purpose: a fingerprint of WHAT happened, ignoring which file it was in.
        Used only to warn when two differently named files overlap.
    Inputs: event (dict) - an event that has the 11 content keys.
    Output: str - the full SHA-256 hex text (64 characters).
    Steps:
        1. Pick the 11 content keys out of the event.
        2. Write the timestamp as fixed text.
        3. Convert to canonical JSON and hash with SHA-256.
    Example: the same row in auth_a.csv and auth_b.csv -> the same fingerprint.
    Errors: ContractError if event is not a dict, a content key is missing,
        or the timestamp is bad.
    """
    if not isinstance(event, dict):
        raise ContractError("event must be a dictionary")
    content = {}
    for key in EVENT_CONTENT_KEYS:
        if key not in event:
            raise ContractError("event is missing key: " + key)
        content[key] = event[key]
    return _hash_text(canonical_json(_content_text_form(content)))


def _find_event_id_list_problem(event_ids):
    """Return a problem sentence if the list of event IDs is unusable, or None."""
    if not isinstance(event_ids, list):
        return "event_ids must be a list"
    if len(event_ids) == 0:
        return "event_ids must not be empty"
    seen_ids = set()
    for event_id in event_ids:
        if not isinstance(event_id, str) or event_id == "":
            return "event_ids must contain only non-empty text"
        if event_id in seen_ids:
            return "event_ids contains a duplicate: " + event_id
        seen_ids.add(event_id)
    return None


def make_alert_id(rule_id: str, source_ip: str | None, time_start: datetime,
                  time_end: datetime, event_ids: list) -> str:
    """
    Purpose: build the ID of an alert from its rule, source, time range and
        evidence, so two different findings never share an ID.
    Inputs:
        rule_id (str) - for example NET_PORT_SCAN.
        source_ip (str or None) - the main source address, or None.
        time_start, time_end (datetime) - timezone-aware.
        event_ids (list of str) - the supporting event IDs, in any order.
    Output: str - "ALT-" plus the first 16 hex characters of a SHA-256 hash.
    Steps:
        1. Check the event ID list (not empty, all text, no duplicates).
        2. Make a SORTED COPY of the list. The caller's list is not changed.
        3. Build a dictionary with event_ids, rule_id, source_ip, time_end,
           time_start (timestamps written as fixed text).
        4. Canonical JSON, UTF-8, SHA-256, first 16 hex characters, ALT- prefix.
    Example: the same alert with its event IDs shuffled -> the same ID; one
        extra event ID -> a different ID.
    Errors: ContractError for an empty list, non-text or duplicate event IDs,
        a bad rule_id or source_ip, or a naive timestamp.
    """
    list_problem = _find_event_id_list_problem(event_ids)
    if list_problem is not None:
        raise ContractError(list_problem)
    if not _is_non_empty_text(rule_id):
        raise ContractError("rule_id must be non-empty text")
    if source_ip is not None and not isinstance(source_ip, str):
        raise ContractError("source_ip must be text or None")
    id_content = {
        "event_ids": sorted(event_ids),  # sorted() makes a new list
        "rule_id": rule_id,
        "source_ip": source_ip,
        "time_end": _timestamp_to_text(time_end),
        "time_start": _timestamp_to_text(time_start),
    }
    full_hash = _hash_text(canonical_json(id_content))
    return "ALT-" + full_hash[:EVENT_ID_HEX_LENGTH]


# ---------------------------------------------------------------
# Event checks
# ---------------------------------------------------------------

def _check_raw_event(raw_event, problems):
    """raw_event must be a dictionary of text to text, values at most 500 long."""
    if not isinstance(raw_event, dict):
        problems.append("raw_event must be a dictionary")
        return
    for column_name in raw_event:
        cell_value = raw_event[column_name]
        if not isinstance(column_name, str) or not isinstance(cell_value, str):
            problems.append("raw_event must map text to text")
            return
        if len(cell_value) > _MAX_RAW_VALUE_LENGTH:
            problems.append("raw_event values must be cut to 500 characters")
            return


def _check_core_event_fields(event, problems):
    """Checks for the fields every event must have."""
    if not _is_aware_utc(event["timestamp"]):
        problems.append("timestamp must be a timezone-aware UTC datetime")
    if not _is_normalised_ip(event["source_ip"]):
        problems.append("source_ip must be a valid IP address in normalised text form")
    file_problem = _find_source_file_problem(event["source_file"])
    if file_problem is not None:
        problems.append(file_problem)
    row_number = event["source_row"]
    if not _is_whole_number(row_number) or row_number < _FIRST_DATA_ROW:
        problems.append("source_row must be a whole number of 2 or more (line 1 is the header)")
    _check_raw_event(event["raw_event"], problems)


def _check_optional_text(event, key, max_length, case_rule, problems):
    """
    Purpose: check one optional text field (protocol, service or username).
    Inputs: event (dict) - holds the field; key (str) - which field;
        max_length (int); case_rule (str) - "upper", "lower" or "keep";
        problems (list) - a sentence is appended here for the first problem.
    Output: none (the problems list is added to).
    Steps:
        1. None is fine. Otherwise it must be text.
        2. Then check, in order: not empty, no spaces at the ends, not too
           long, no control characters, and the required letter case.
    Example: protocol "tcp" with case_rule "upper" -> "protocol must be uppercase".
    Errors: none (problems are collected, not raised).
    """
    value = event[key]
    if value is None:
        return
    if not isinstance(value, str):
        problems.append(key + " must be text or None")
    elif value == "":
        problems.append(key + " must not be an empty string (use None)")
    elif value != value.strip():
        problems.append(key + " must not start or end with spaces")
    elif len(value) > max_length:
        problems.append(key + " must be at most " + str(max_length) + " characters")
    elif _has_control_characters(value):
        problems.append(key + " must not contain control characters")
    elif case_rule == "upper" and value != value.upper():
        problems.append(key + " must be uppercase")
    elif case_rule == "lower" and value != value.lower():
        problems.append(key + " must be lowercase")


def _check_optional_count(event, key, problems):
    """bytes_sent and bytes_received are None or a whole number of zero or more."""
    value = event[key]
    if value is None:
        return
    if not _is_whole_number(value) or value < 0:
        problems.append(key + " must be None or a whole number of zero or more")


def _check_optional_event_fields(event, problems):
    """Checks for the fields that may be None."""
    destination_ip = event["destination_ip"]
    if destination_ip is not None and not _is_normalised_ip(destination_ip):
        problems.append("destination_ip must be None or a valid normalised IP address")
    port = event["destination_port"]
    if port is not None:
        if not _is_whole_number(port) or port < 0 or port > 65535:
            problems.append("destination_port must be None or a whole number from 0 to 65535")
    _check_optional_text(event, "protocol", _MAX_PROTOCOL_LENGTH, "upper", problems)
    _check_optional_text(event, "service", _MAX_SERVICE_LENGTH, "lower", problems)
    _check_optional_text(event, "username", _MAX_USERNAME_LENGTH, "keep", problems)
    _check_optional_count(event, "bytes_sent", problems)
    _check_optional_count(event, "bytes_received", problems)


def _check_authentication_rules(event, problems):
    """Rules that only apply to authentication events (C.1)."""
    if event["status"] not in AUTH_STATUSES:
        problems.append("status of an authentication event must be success or failure")
    if event["username"] is None:
        problems.append("username is required for authentication events")
    if event["destination_port"] is not None:
        problems.append("destination_port must be None for authentication events")


def _check_network_rules(event, problems):
    """Rules that only apply to network connection events (C.1)."""
    if event["status"] not in NETWORK_STATUSES:
        problems.append("status of a network event must be allowed or rejected")
    if event["destination_ip"] is None:
        problems.append("destination_ip is required for network events")
    if event["username"] is not None:
        problems.append("username must be None for network events")


def _find_event_field_problems(event):
    """Run every field check on a dictionary that has all the event keys
    (event_id itself is not looked at here). Returns a list of problems."""
    problems = []
    if event["event_type"] not in EVENT_TYPES:
        problems.append("event_type must be authentication or network_connection")
    _check_core_event_fields(event, problems)
    _check_optional_event_fields(event, problems)
    if event["event_type"] == "authentication":
        _check_authentication_rules(event, problems)
    elif event["event_type"] == "network_connection":
        _check_network_rules(event, problems)
    return problems


def make_event(event_type: str, timestamp: datetime, source_ip: str, status: str,
               source_file: str, source_row: int, raw_event: dict,
               occurrence: int = 1, destination_ip: str | None = None,
               destination_port: int | None = None, protocol: str | None = None,
               username: str | None = None, service: str | None = None,
               bytes_sent: int | None = None, bytes_received: int | None = None) -> dict:
    """
    Purpose: build one valid event dictionary, including its event_id.
    Inputs: the 15 values of an event (see C.1). Required: event_type,
        timestamp (aware datetime), source_ip, status, source_file,
        source_row, raw_event. Optional values default to None.
        occurrence (int, default 1) is only used for the ID.
    Output: dict - exactly the 15 keys of EVENT_KEYS, in that order. The
        timestamp is converted to UTC. raw_event is copied.
    Steps:
        1. Collect the values in one dictionary (converting aware times to UTC).
        2. Run every field check; if anything is wrong, raise one error that
           lists all the problems.
        3. Build the ID with make_event_id from the 11 content values.
        4. Return the dictionary with the keys in the standard order.
    Example: make_event("authentication", <09:15:02 UTC>, "203.0.113.50",
        "failure", "auth_sample.csv", 2, {...}, username="admin") ->
        a dictionary whose event_id starts with "EVT-".
    Errors: ContractError listing every invalid value.
    """
    # This function is longer than 30 lines only because it must list all
    # fifteen event values once; the checking work is done by helpers.
    fields = {
        "event_type": event_type,
        "timestamp": _to_utc_if_aware(timestamp),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "username": username,
        "service": service,
        "status": status,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "source_file": source_file,
        "source_row": source_row,
        "raw_event": raw_event,
    }
    problems = _find_event_field_problems(fields)
    if len(problems) > 0:
        raise ContractError("Invalid event: " + "; ".join(problems))
    content = {}
    for key in EVENT_CONTENT_KEYS:
        content[key] = fields[key]
    fields["event_id"] = make_event_id(content, source_file, occurrence)
    fields["raw_event"] = dict(raw_event)  # a copy, so later edits by the caller cannot change it
    event = {}
    for key in EVENT_KEYS:
        event[key] = fields[key]
    return event


def validate_event(event: dict) -> list:
    """
    Purpose: report every problem found in an event dictionary.
    Inputs: event (dict) - any dictionary.
    Output: list of str - one sentence per problem; an empty list means valid.
    Steps:
        1. If it is not a dictionary, report that and stop.
        2. Report every missing key (and every unexpected key).
        3. If no key is missing, run all the field checks.
        4. Check that event_id looks like EVT- plus 16 lowercase hex characters.
    Example: validate_event({}) -> 15 sentences, one "missing key: ..." each.
    Errors: none (problems are returned, never raised).
    """
    if not isinstance(event, dict):
        return ["event must be a dictionary"]
    problems = []
    for key in EVENT_KEYS:
        if key not in event:
            problems.append("missing key: " + key)
    for key in event:
        if key not in EVENT_KEYS:
            problems.append("unexpected key: " + str(key))
    for problem in problems:
        if problem.startswith("missing key"):
            return problems  # field checks need every key to be present
    problems.extend(_find_event_field_problems(event))
    if not _has_id_format(event["event_id"], "EVT-"):
        problems.append("event_id must be EVT- followed by 16 lowercase hex characters")
    return problems


# ---------------------------------------------------------------
# Alert checks
# ---------------------------------------------------------------

def _check_alert_choices(alert, problems):
    """rule_id, severity and confidence must come from the allowed lists."""
    if alert["rule_id"] not in RULE_IDS:
        problems.append("rule_id must be one of " + ", ".join(RULE_IDS))
    if alert["severity"] not in SEVERITIES:
        problems.append("severity must be one of " + ", ".join(SEVERITIES))
    if alert["confidence"] not in CONFIDENCES:
        problems.append("confidence must be one of " + ", ".join(CONFIDENCES))


def _check_alert_text(alert, problems):
    """title, description and recommended_action must be real sentences."""
    for key in ["title", "description", "recommended_action"]:
        if not _is_non_empty_text(alert[key]):
            problems.append(key + " must be non-empty text")


def _check_alert_times(alert, problems):
    """The three timestamps must be aware UTC and time_start <= time_end."""
    for key in ["detected_at", "time_start", "time_end"]:
        if not _is_aware_utc(alert[key]):
            problems.append(key + " must be a timezone-aware UTC datetime")
    if _is_aware_utc(alert["time_start"]) and _is_aware_utc(alert["time_end"]):
        if alert["time_end"] < alert["time_start"]:
            problems.append("time_end must not be earlier than time_start")


def _check_evidence_value_types(evidence, problems):
    """The four required evidence keys must hold the right kind of value."""
    for key in ["rule_parameters", "observed"]:
        if key in evidence and not isinstance(evidence[key], dict):
            problems.append("evidence " + key + " must be a dictionary")
    for key in ["explanation", "limitations"]:
        if key in evidence and not _is_list_of_text(evidence[key]):
            problems.append("evidence " + key + " must be a list of text sentences")


def _check_correlation_values(block, problems):
    """
    Purpose: check the values inside evidence['correlation'] (FS.3.4).
    Inputs: block (dict) - the correlation dictionary; problems (list) -
        sentences are appended here.
    Output: none (the problems list is added to).
    Steps:
        1. For each key that is present, check its value (link_key must be
           source_ip; at least 2 linked alert IDs; gap_seconds a whole number
           of zero or more; destination_match True/False; match_conditions
           a list of text). Missing keys are reported by the caller.
    Example: gap_seconds = -1 -> "correlation gap_seconds must be ...".
    Errors: none (problems are collected, not raised).
    """
    if "link_key" in block and block["link_key"] != "source_ip":
        problems.append("correlation link_key must be source_ip")
    if "linked_alert_ids" in block:
        linked_ids = block["linked_alert_ids"]
        if not _is_list_of_text(linked_ids) or len(linked_ids) < 2:
            problems.append("correlation linked_alert_ids must be a list of at least 2 IDs")
    if "gap_seconds" in block:
        gap = block["gap_seconds"]
        if not _is_whole_number(gap) or gap < 0:
            problems.append("correlation gap_seconds must be a whole number of zero or more")
    if "destination_match" in block and not isinstance(block["destination_match"], bool):
        problems.append("correlation destination_match must be True or False")
    if "match_conditions" in block and not _is_list_of_text(block["match_conditions"]):
        problems.append("correlation match_conditions must be a list of text sentences")


def _check_correlation_block(evidence, problems):
    """A CORR_AUTH_NET alert must carry evidence['correlation'] with six keys."""
    if "correlation" not in evidence:
        problems.append("evidence is missing key: correlation")
        return
    block = evidence["correlation"]
    if not isinstance(block, dict):
        problems.append("evidence correlation must be a dictionary")
        return
    for key in _CORRELATION_KEYS:
        if key not in block:
            problems.append("evidence correlation is missing key: " + key)
    _check_correlation_values(block, problems)


def _check_evidence(alert, problems):
    """
    Purpose: run every check on an alert's evidence dictionary.
    Inputs: alert (dict) - has rule_id and evidence; problems (list) -
        sentences are appended here.
    Output: none (the problems list is added to).
    Steps:
        1. Evidence must be a dictionary with the four required keys.
        2. Check the type of each required value.
        3. For CORR_AUTH_NET alerts also check the correlation block.
        4. Try canonical_json, because evidence is stored as JSON text later.
    Example: evidence without "limitations" -> "evidence is missing key: limitations".
    Errors: none (problems are collected, not raised).
    """
    evidence = alert["evidence"]
    if not isinstance(evidence, dict):
        problems.append("evidence must be a dictionary")
        return
    for key in _REQUIRED_EVIDENCE_KEYS:
        if key not in evidence:
            problems.append("evidence is missing key: " + key)
    _check_evidence_value_types(evidence, problems)
    if alert["rule_id"] == "CORR_AUTH_NET":
        _check_correlation_block(evidence, problems)
    try:
        canonical_json(evidence)
    except ContractError as error:
        problems.append("evidence cannot be stored as JSON text: " + str(error))


def _find_alert_field_problems(alert):
    """Run every field check on a dictionary that has all the alert keys
    (alert_id itself is not looked at here). Returns a list of problems."""
    problems = []
    _check_alert_choices(alert, problems)
    _check_alert_text(alert, problems)
    _check_alert_times(alert, problems)
    source_ip = alert["source_ip"]
    if source_ip is not None and not _is_normalised_ip(source_ip):
        problems.append("source_ip must be None or a valid normalised IP address")
    event_id_problem = _find_event_id_list_problem(alert["event_ids"])
    if event_id_problem is not None:
        problems.append(event_id_problem)
    _check_evidence(alert, problems)
    return problems


def make_alert(rule_id: str, title: str, description: str, severity: str,
               confidence: str, time_start: datetime, time_end: datetime,
               source_ip: str | None, event_ids: list, evidence: dict,
               recommended_action: str, detected_at: datetime | None = None) -> dict:
    """
    Purpose: build one valid alert dictionary, including its alert_id.
    Inputs: the 12 values listed in C.2. detected_at (datetime or None) is
        when the analysis ran; None means "now". event_ids are the supporting
        event IDs in time order (the stored order).
    Output: dict - exactly the 13 keys of ALERT_KEYS, in that order. All
        timestamps are UTC. event_ids is stored as a copy, in the order given.
    Steps:
        1. Fill in detected_at with the current time if it is None.
        2. Collect the values (converting aware times to UTC).
        3. Run every field check; raise one error listing all problems.
        4. Build the ID with make_alert_id (this never changes the caller's list).
        5. Return the dictionary with the keys in the standard order.
    Example: make_alert("NET_PORT_SCAN", "Possible port scanning activity", ...)
        -> a dictionary whose alert_id starts with "ALT-".
    Errors: ContractError listing every invalid value.
    """
    # Longer than 30 lines only because it lists every alert value once;
    # the checking work is done by helper functions.
    if detected_at is None:
        detected_at = utc_now()
    fields = {
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "detected_at": _to_utc_if_aware(detected_at),
        "time_start": _to_utc_if_aware(time_start),
        "time_end": _to_utc_if_aware(time_end),
        "source_ip": source_ip,
        "event_ids": event_ids,
        "evidence": evidence,
        "recommended_action": recommended_action,
    }
    problems = _find_alert_field_problems(fields)
    if len(problems) > 0:
        raise ContractError("Invalid alert: " + "; ".join(problems))
    fields["event_ids"] = list(event_ids)  # a copy, so the caller's list stays theirs
    fields["alert_id"] = make_alert_id(
        rule_id, source_ip, fields["time_start"], fields["time_end"], event_ids
    )
    alert = {}
    for key in ALERT_KEYS:
        alert[key] = fields[key]
    return alert


def validate_alert(alert: dict) -> list:
    """
    Purpose: report every problem found in an alert dictionary.
    Inputs: alert (dict) - any dictionary.
    Output: list of str - one sentence per problem; an empty list means valid.
    Steps:
        1. If it is not a dictionary, report that and stop.
        2. Report every missing key (and every unexpected key).
        3. If no key is missing, run all the field checks, including the four
           required evidence keys (and the correlation block for CORR_ alerts).
        4. Check that alert_id looks like ALT- plus 16 lowercase hex characters.
    Example: validate_alert({}) -> 13 sentences, one "missing key: ..." each.
    Errors: none (problems are returned, never raised).
    """
    if not isinstance(alert, dict):
        return ["alert must be a dictionary"]
    problems = []
    for key in ALERT_KEYS:
        if key not in alert:
            problems.append("missing key: " + key)
    for key in alert:
        if key not in ALERT_KEYS:
            problems.append("unexpected key: " + str(key))
    for problem in problems:
        if problem.startswith("missing key"):
            return problems  # field checks need every key to be present
    problems.extend(_find_alert_field_problems(alert))
    if not _has_id_format(alert["alert_id"], "ALT-"):
        problems.append("alert_id must be ALT- followed by 16 lowercase hex characters")
    return problems
