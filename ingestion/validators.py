# ingestion/validators.py
# Purpose: small functions that each check ONE value from a CSV cell.
# parse_timestamp: text -> timezone-aware UTC datetime (rules in D.2).
# parse_ip_address / parse_port / parse_optional_non_negative_int: one value each.
# normalise_status: maps words such as "Failed" to failure/success/allowed/rejected.
# clean_text_value: trims text and rejects control characters or long text.
# check_columns: compares a CSV header with the columns a log type needs.
# Every checker raises ValueError with a short message; csv_ingest.py turns
# that into one of the fixed rejection reasons of Section D.5.
# Uses: only the Python standard library (no other project module).

import ipaddress
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------
# Column definitions (Section D.3 and D.4). The ORDER matters: a row with
# several problems is rejected for the first problem found when the
# columns are checked in this order (D.5).
# ---------------------------------------------------------------
AUTH_COLUMNS = ["timestamp", "source_ip", "username", "status", "destination_ip", "service"]
AUTH_REQUIRED_COLUMNS = ["timestamp", "source_ip", "username", "status"]

NETWORK_COLUMNS = [
    "timestamp", "source_ip", "destination_ip", "status",
    "destination_port", "protocol", "bytes_sent", "bytes_received",
]
NETWORK_REQUIRED_COLUMNS = ["timestamp", "source_ip", "destination_ip", "status"]

COLUMNS_BY_LOG_TYPE = {
    "authentication": AUTH_COLUMNS,
    "network_connection": NETWORK_COLUMNS,
}
REQUIRED_COLUMNS_BY_LOG_TYPE = {
    "authentication": AUTH_REQUIRED_COLUMNS,
    "network_connection": NETWORK_REQUIRED_COLUMNS,
}

# Status words from Section C.1. Matching ignores case and surrounding spaces.
AUTH_STATUS_WORDS = {
    "success": "success", "successful": "success", "ok": "success", "accepted": "success",
    "failure": "failure", "failed": "failure", "fail": "failure",
    "denied": "failure", "invalid": "failure",
}
NETWORK_STATUS_WORDS = {
    "allowed": "allowed", "allow": "allowed", "accept": "allowed",
    "accepted": "allowed", "permit": "allowed",
    "rejected": "rejected", "reject": "rejected", "denied": "rejected", "deny": "rejected",
    "blocked": "rejected", "block": "rejected", "drop": "rejected", "dropped": "rejected",
    "refused": "rejected", "reset": "rejected",
}

_DIGITS = "0123456789"  # ASCII digits only: str.isdigit() would also accept other scripts
_HIGHEST_PORT = 65535
_MAX_COUNT_DIGITS = 19  # 9223372036854775807 has 19 digits
_HIGHEST_COUNT = 9223372036854775807  # the largest whole number SQLite can store later
_EARLIEST_TIME = datetime(2000, 1, 1, tzinfo=timezone.utc)  # D.2 sanity range
_LATEST_TIME = datetime(2100, 1, 1, tzinfo=timezone.utc)


def _is_all_ascii_digits(text):
    """True if text is not empty and every character is one of 0-9."""
    if text == "":
        return False
    for character in text:
        if character not in _DIGITS:
            return False
    return True


def _has_control_characters(text):
    """True if text has an invisible control character (same rule as core/contracts.py)."""
    for character in text:
        code = ord(character)
        if code < 32 or 127 <= code <= 159:
            return True
    return False


# ---------------------------------------------------------------
# Timestamps (D.2). We read the text by hand instead of trusting
# datetime.fromisoformat, because newer Python versions accept many extra
# formats and we only want the ones the specification lists.
# ---------------------------------------------------------------

def _parse_date_part(date_text):
    """Read YYYY-MM-DD and return (year, month, day) as whole numbers."""
    if len(date_text) != 10 or date_text[4] != "-" or date_text[7] != "-":
        raise ValueError("date must look like 2025-03-14")
    year_text = date_text[0:4]
    month_text = date_text[5:7]
    day_text = date_text[8:10]
    for piece in [year_text, month_text, day_text]:
        if not _is_all_ascii_digits(piece):
            raise ValueError("date must contain only digits")
    return int(year_text), int(month_text), int(day_text)


def _parse_time_part(time_text):
    """Read HH:MM:SS and return (hour, minute, second) as whole numbers."""
    if len(time_text) != 8 or time_text[2] != ":" or time_text[5] != ":":
        raise ValueError("time must look like 09:15:02")
    hour_text = time_text[0:2]
    minute_text = time_text[3:5]
    second_text = time_text[6:8]
    for piece in [hour_text, minute_text, second_text]:
        if not _is_all_ascii_digits(piece):
            raise ValueError("time must contain only digits")
    return int(hour_text), int(minute_text), int(second_text)


def _split_fraction_and_zone(tail):
    """
    Split what follows HH:MM:SS into microseconds and the zone text.
    Example: ".25Z" -> (250000, "Z"); "+01:00" -> (0, "+01:00"); "" -> (0, "").
    Raises ValueError if the fraction has no digits or more than six digits.
    """
    if not tail.startswith("."):
        return 0, tail
    position = 1
    while position < len(tail) and tail[position] in _DIGITS:
        position = position + 1
    fraction_text = tail[1:position]
    if len(fraction_text) < 1 or len(fraction_text) > 6:
        raise ValueError("fractional seconds must have 1 to 6 digits")
    microsecond = int(fraction_text.ljust(6, "0"))
    return microsecond, tail[position:]


def _parse_zone(zone_text):
    """
    Purpose: turn the zone text at the end of a timestamp into a tzinfo.
    Inputs: zone_text (str) - "", "Z", or an offset such as +05:30 or -03:00.
    Output: tzinfo or None - None when no zone was given, otherwise that zone.
    Steps:
        1. Empty text means no zone: return None. "Z" means UTC.
        2. Otherwise require the shape +HH:MM or -HH:MM with ASCII digits only.
        3. Refuse hours above 23 or minutes above 59, then build the offset.
    Example: "-03:00" -> a timezone three hours behind UTC; "+0100" -> ValueError.
    Errors: ValueError for any other shape or an out-of-range offset.
    """
    if zone_text == "":
        return None
    if zone_text == "Z":
        return timezone.utc
    if len(zone_text) != 6 or zone_text[0] not in "+-" or zone_text[3] != ":":
        raise ValueError("zone must be Z or an offset such as +01:00")
    hours_text = zone_text[1:3]
    minutes_text = zone_text[4:6]
    if not _is_all_ascii_digits(hours_text) or not _is_all_ascii_digits(minutes_text):
        raise ValueError("offset must contain only digits")
    hours = int(hours_text)
    minutes = int(minutes_text)
    if hours > 23 or minutes > 59:
        raise ValueError("offset is out of range")
    offset = timedelta(hours=hours, minutes=minutes)
    if zone_text[0] == "-":
        offset = -offset
    return timezone(offset)


def parse_timestamp(text: str, assume_utc: bool = True) -> datetime:
    """
    Purpose: turn timestamp text from a CSV cell into a UTC datetime (D.2).
    Inputs:
        text (str) - for example 2025-03-14T09:15:02, 2025-03-14 09:15:02,
            2025-03-14T09:15:02.250Z or 2025-03-14T10:15:02+01:00.
        assume_utc (bool) - if True, text with no zone is treated as UTC (D1);
            if False such text is refused.
    Output: datetime - timezone-aware, converted to UTC.
    Steps:
        1. Trim spaces and check the shape: date, T or one space, time.
        2. Read the optional fraction (1 to 6 digits) and the optional zone.
        3. Build the datetime (Python refuses impossible dates such as 31 February).
        4. Convert to UTC and check it lies between 2000-01-01 and 2100-01-01.
    Example: "2025-03-14T10:15:02+01:00" -> 2025-03-14 09:15:02 UTC.
    Errors: ValueError for any other format (14/03/2025, Unix numbers, free
        text), an impossible date or time, a missing zone when assume_utc is
        False, or a time outside the sanity range.
    """
    if not isinstance(text, str):
        raise ValueError("timestamp must be text")
    cleaned = text.strip()
    if len(cleaned) < 19:
        raise ValueError("timestamp is too short")
    if cleaned[10] != "T" and cleaned[10] != " ":
        raise ValueError("date and time must be separated by T or a space")
    year, month, day = _parse_date_part(cleaned[0:10])
    hour, minute, second = _parse_time_part(cleaned[11:19])
    microsecond, zone_text = _split_fraction_and_zone(cleaned[19:])
    zone = _parse_zone(zone_text)
    if zone is None:
        if not assume_utc:
            raise ValueError("timestamp has no timezone and assume_utc is False")
        zone = timezone.utc
    # datetime() raises ValueError for 31 February, hour 24, second 60 and so on.
    local_time = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=zone)
    try:
        utc_time = local_time.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("timestamp is out of range") from error
    if utc_time < _EARLIEST_TIME or utc_time > _LATEST_TIME:
        raise ValueError("timestamp is outside 2000-01-01 to 2100-01-01")
    return utc_time


# ---------------------------------------------------------------
# Addresses, ports, numbers
# ---------------------------------------------------------------

def parse_ip_address(text: str) -> str:
    """
    Purpose: check an IPv4 or IPv6 address and write it in normalised form.
    Inputs: text (str) - for example 203.0.113.50 or 2001:DB8:0:0:0:0:0:1.
    Output: str - the address as the ipaddress module writes it (IPv4 dotted;
        IPv6 compressed and lowercase), for example 2001:db8::1.
    Steps:
        1. Trim spaces; refuse empty text.
        2. Refuse a zone suffix (fe80::1%eth0): it is not part of the address
           and would let arbitrary text into an address field.
        3. Let ipaddress.ip_address check and normalise it.
    Example: "2001:DB8:0:0:0:0:0:1" -> "2001:db8::1".
    Errors: ValueError if the text is not a valid address.
    """
    if not isinstance(text, str):
        raise ValueError("IP address must be text")
    cleaned = text.strip()
    if cleaned == "":
        raise ValueError("IP address is empty")
    if "%" in cleaned:
        raise ValueError("IP address must not have a zone suffix")
    parsed_address = ipaddress.ip_address(cleaned)  # raises ValueError itself
    return str(parsed_address)


def parse_port(text: str) -> int:
    """
    Purpose: check a TCP/UDP port number.
    Inputs: text (str) - for example 443.
    Output: int - 0 to 65535.
    Steps:
        1. Trim spaces; require only the digits 0-9 (no sign, no decimals).
        2. Drop leading zeros and refuse anything with more than 5 digits left.
        3. Convert and refuse numbers above 65535.
    Example: "65535" -> 65535; "65536" -> ValueError.
    Errors: ValueError for empty text, non-digits, or a number above 65535.
    """
    if not isinstance(text, str):
        raise ValueError("port must be text")
    cleaned = text.strip()
    if not _is_all_ascii_digits(cleaned):
        raise ValueError("port must be a whole number")
    without_leading_zeros = cleaned.lstrip("0")
    if len(without_leading_zeros) > 5:
        raise ValueError("port is too large")
    if without_leading_zeros == "":
        return 0
    port_number = int(without_leading_zeros)
    if port_number > _HIGHEST_PORT:
        raise ValueError("port must be 0 to 65535")
    return port_number


def parse_optional_non_negative_int(text: str) -> int | None:
    """
    Purpose: read a byte count such as bytes_sent. Empty means "not given".
    Inputs: text (str) - for example 15200, or empty text.
    Output: int or None - None for empty text, otherwise a whole number of
        zero or more.
    Steps:
        1. Trim spaces. Empty text returns None.
        2. Require only the digits 0-9, so 1,200 / 12.5 / -5 / 1e3 are refused.
        3. Refuse numbers too big for SQLite to store later (above 2^63 - 1),
           so a hostile value cannot crash storage.
    Example: "1,200" -> ValueError; "" -> None; "0" -> 0.
    Errors: ValueError for anything that is not a plain whole number.
    """
    if not isinstance(text, str):
        raise ValueError("number must be text")
    cleaned = text.strip()
    if cleaned == "":
        return None
    if not _is_all_ascii_digits(cleaned):
        raise ValueError("number must be a whole number of zero or more")
    without_leading_zeros = cleaned.lstrip("0")
    if len(without_leading_zeros) > _MAX_COUNT_DIGITS:
        raise ValueError("number is too large")
    if without_leading_zeros == "":
        return 0
    number = int(without_leading_zeros)
    if number > _HIGHEST_COUNT:
        raise ValueError("number is too large")
    return number


# ---------------------------------------------------------------
# Status, text, header
# ---------------------------------------------------------------

def normalise_status(text: str, log_type: str) -> str:
    """
    Purpose: turn the many words logs use for an outcome into the four
        allowed status values (Section C.1).
    Inputs: text (str) - for example "Failed"; log_type (str) - authentication
        or network_connection.
    Output: str - success or failure (authentication); allowed or rejected
        (network).
    Steps:
        1. Trim spaces and lowercase the text.
        2. Look it up in the word list of that log type.
    Example: ("  FAILED ", "authentication") -> "failure"; ("drop", "network_connection") -> "rejected".
    Errors: ValueError for an unknown word or an unknown log_type.
    """
    if log_type == "authentication":
        word_list = AUTH_STATUS_WORDS
    elif log_type == "network_connection":
        word_list = NETWORK_STATUS_WORDS
    else:
        raise ValueError("unknown log_type: " + repr(log_type))
    if not isinstance(text, str):
        raise ValueError("status must be text")
    cleaned = text.strip().lower()
    if cleaned not in word_list:
        raise ValueError("unknown status word")
    return word_list[cleaned]


def clean_text_value(text: str, max_length: int) -> str | None:
    """
    Purpose: clean one free-text cell (username, service, protocol).
    Inputs: text (str) - the cell; max_length (int) - longest allowed length
        after trimming.
    Output: str or None - the trimmed text, or None if nothing is left.
    Steps:
        1. Trim spaces at both ends. Empty text returns None.
        2. Refuse text longer than max_length.
        3. Refuse control characters (newline, tab, null...).
    Example: ("  alice ", 100) -> "alice"; ("   ", 100) -> None.
    Errors: ValueError with the message "value_too_long" or
        "control_characters" (these words are the start of the rejection
        reasons in Section D.5).
    """
    if not isinstance(text, str):
        raise ValueError("value must be text")
    cleaned = text.strip()
    if cleaned == "":
        return None
    if len(cleaned) > max_length:
        raise ValueError("value_too_long")
    if _has_control_characters(cleaned):
        raise ValueError("control_characters")
    return cleaned


def check_columns(header: list, log_type: str) -> dict:
    """
    Purpose: compare a CSV header with the columns a log type needs.
    Inputs: header (list of str) - the header cells as read; log_type (str).
    Output: dict with three lists:
        missing_required - required columns not in the header (lowercase names);
        optional_present - optional columns that are in the header (lowercase);
        unknown - header names that are not part of this log type (trimmed,
            original capitals).
    Steps:
        1. Trim and lowercase every header name, so case and spaces are ignored.
        2. Sort the names into known columns and unknown columns.
        3. List which required columns are missing and which optional are present.
    Example: header ["Timestamp", "source_ip", "note"] for authentication ->
        missing_required ["username", "status"]; unknown ["note"].
    Errors: ValueError for an unknown log_type.
    """
    if log_type not in COLUMNS_BY_LOG_TYPE:
        raise ValueError("unknown log_type: " + repr(log_type))
    known_columns = COLUMNS_BY_LOG_TYPE[log_type]
    required_columns = REQUIRED_COLUMNS_BY_LOG_TYPE[log_type]
    names_found = []
    unknown_names = []
    for header_cell in header:
        trimmed_name = str(header_cell).strip()
        lowered_name = trimmed_name.lower()
        if lowered_name in known_columns:
            names_found.append(lowered_name)
        else:
            unknown_names.append(trimmed_name)
    missing_required = []
    for column_name in required_columns:
        if column_name not in names_found:
            missing_required.append(column_name)
    optional_present = []
    for column_name in known_columns:
        if column_name in names_found and column_name not in required_columns:
            optional_present.append(column_name)
    return {
        "missing_required": missing_required,
        "optional_present": optional_present,
        "unknown": unknown_names,
    }
