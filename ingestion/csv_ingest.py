# ingestion/csv_ingest.py
# Purpose: turn the bytes of one untrusted CSV file into validated events.
# ingest_file: checks the file, reads every row, builds events with make_event
#     and lists rejected rows with a fixed reason (Section D).
# combine_ingestion_results: merges several ingest_file results, sorts events
#     by time, drops a file added twice and warns about overlapping files.
# Everything else in this file is a small private helper (names start with _).
# Uses: core/contracts.py, core/errors.py and ingestion/validators.py.
# It never imports Streamlit, SQLite or config/settings.py: the settings it
# needs arrive in the config dictionary.

import csv

from core.contracts import (
    EVENT_CONTENT_KEYS,
    canonical_json,
    datetime_to_iso,
    make_content_fingerprint,
    make_event,
)
from core.errors import ContractError, IngestionError
from ingestion.validators import (
    COLUMNS_BY_LOG_TYPE,
    REQUIRED_COLUMNS_BY_LOG_TYPE,
    check_columns,
    clean_text_value,
    normalise_status,
    parse_ip_address,
    parse_optional_non_negative_int,
    parse_port,
    parse_timestamp,
)

# Defaults used only when the config dictionary has no value (FS.3.5).
DEFAULT_MAX_UPLOAD_MB = 10
DEFAULT_MAX_ROWS_PER_FILE = 100000
DEFAULT_ASSUME_UTC = True

BYTES_PER_MEGABYTE = 1000000  # decimal megabytes, as for volume_min_bytes (see learning pack)
MAX_RAW_VALUE_LENGTH = 500  # C.1: raw_event values are cut to 500 characters
MAX_FILE_NAME_LENGTH = 255
MAX_NAMES_IN_WARNING = 10
MAX_NAME_LENGTH_IN_WARNING = 50

# The longest allowed length of each free-text column (C.1).
TEXT_COLUMN_MAX_LENGTH = {"username": 100, "service": 30, "protocol": 10}
IP_COLUMNS = ["source_ip", "destination_ip"]
COUNT_COLUMNS = ["bytes_sent", "bytes_received"]


# ---------------------------------------------------------------
# Part 1: settings and file-level checks (these stop the WHOLE file)
# ---------------------------------------------------------------

def _fail(file_name, message):
    """Raise an IngestionError whose text starts with the file name."""
    raise IngestionError(str(file_name) + ": " + message)


def _read_whole_number_setting(config, key, default):
    """Return config[key] if it is a whole number above zero, else the default
    when the key is missing. A wrong value is an IngestionError."""
    if key not in config:
        return default
    value = config[key]
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise IngestionError("config setting " + key + " must be a whole number above zero")
    return value


def _read_settings(config):
    """Return (max_upload_bytes, max_rows_per_file, assume_utc) from config."""
    if not isinstance(config, dict):
        raise IngestionError("config must be a dictionary")
    max_upload_mb = _read_whole_number_setting(config, "max_upload_mb", DEFAULT_MAX_UPLOAD_MB)
    max_rows = _read_whole_number_setting(config, "max_rows_per_file", DEFAULT_MAX_ROWS_PER_FILE)
    assume_utc = config.get("assume_utc", DEFAULT_ASSUME_UTC)
    if not isinstance(assume_utc, bool):
        raise IngestionError("config setting assume_utc must be True or False")
    return max_upload_mb * BYTES_PER_MEGABYTE, max_rows, assume_utc


def _check_file_name(file_name):
    """Refuse a name that is empty, too long, contains a folder path or a
    control character, or does not end in .csv (case does not matter)."""
    if not isinstance(file_name, str) or file_name.strip() == "":
        raise IngestionError("the file name must be non-empty text")
    shown_name = repr(file_name[:80])
    if len(file_name) > MAX_FILE_NAME_LENGTH:
        raise IngestionError("the file name is too long: " + shown_name)
    if "/" in file_name or "\\" in file_name:
        raise IngestionError("give the file name only, not a folder path: " + shown_name)
    for character in file_name:
        code = ord(character)
        if code < 32 or 127 <= code <= 159:
            raise IngestionError("the file name has a control character: " + shown_name)
    if len(file_name) <= 4 or not file_name.lower().endswith(".csv"):
        raise IngestionError("only .csv files are accepted: " + shown_name)


def _decode_text(file_bytes, file_name):
    """Decode UTF-8 (a leading byte order mark is accepted and removed).
    A file that is not UTF-8, or contains NUL bytes, is refused."""
    # 'utf-8-sig' = UTF-8 that silently drops one leading byte order mark.
    try:
        text = file_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        _fail(file_name, "the file is not valid UTF-8 text")
    if "\x00" in text:
        _fail(file_name, "the file contains NUL bytes, so it is not a text CSV file")
    return text


def _check_file_bytes(file_bytes, file_name, max_upload_bytes):
    """Check type, emptiness and size of the raw bytes."""
    if not isinstance(file_bytes, (bytes, bytearray)):
        _fail(file_name, "file_bytes must be bytes")
    if len(file_bytes) == 0:
        _fail(file_name, "the file is empty")
    if len(file_bytes) > max_upload_bytes:
        limit_text = str(max_upload_bytes // BYTES_PER_MEGABYTE)
        _fail(file_name, "the file is larger than the limit of " + limit_text + " MB")


# ---------------------------------------------------------------
# Part 2: lines, header and cells
# ---------------------------------------------------------------

def _split_into_lines(text):
    """
    Split text into lines on \\r\\n, \\r or \\n ONLY (str.splitlines would also
    split on other invisible characters). The final empty piece after the
    last line break is not a line. Line number = list position + 1, so the
    header is line 1 as in a spreadsheet.
    """
    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")
    lines = text.split("\n")
    if len(lines) > 0 and lines[-1] == "":
        lines.pop()
    return lines


def _is_blank_line(line):
    """A fully blank line: nothing but whitespace."""
    return line.strip() == ""


def _parse_line(line):
    """
    Split ONE physical line into cells with the csv module.
    Each line is parsed on its own, so a stray quote mark can damage only its
    own row instead of swallowing the rest of the file. If a single cell is
    larger than the csv module allows, csv.Error is raised and we fall back to
    a plain split on commas; the long cell is then rejected or cut later.
    """
    try:
        parsed_rows = list(csv.reader([line]))
    except csv.Error:
        return line.split(",")
    if len(parsed_rows) == 0:
        return []
    return parsed_rows[0]


def _find_header_line_index(lines, file_name):
    """Return the position of the first non-blank line (the header).
    A file with only blank lines is an empty file."""
    for index in range(len(lines)):
        if not _is_blank_line(lines[index]):
            return index
    _fail(file_name, "the file is empty (it has no header line)")


def _find_duplicate_names(header_cells):
    """Return the header names (trimmed, lowercase) that appear more than once."""
    seen_names = []
    duplicate_names = []
    for header_cell in header_cells:
        normalised_name = header_cell.strip().lower()
        if normalised_name in seen_names and normalised_name not in duplicate_names:
            duplicate_names.append(normalised_name)
        seen_names.append(normalised_name)
    return duplicate_names


def _shorten_name(name):
    """Cut a header name for display in a warning."""
    if len(name) > MAX_NAME_LENGTH_IN_WARNING:
        return name[:MAX_NAME_LENGTH_IN_WARNING] + "..."
    return name


def _make_unknown_column_warning(unknown_names):
    """Build the warning that lists ignored columns (at most 10 names)."""
    shown_names = []
    for name in unknown_names[:MAX_NAMES_IN_WARNING]:
        shown_names.append(repr(_shorten_name(name)))
    text = "Unknown columns are ignored for detection but kept in raw_event: " + ", ".join(shown_names)
    if len(unknown_names) > MAX_NAMES_IN_WARNING:
        text = text + " and " + str(len(unknown_names) - MAX_NAMES_IN_WARNING) + " more"
    return text


def _check_header(header_cells, log_type, file_name):
    """
    Purpose: apply the file-level header rules of D.1.
    Inputs: header_cells (list of str); log_type (str); file_name (str).
    Output: list of str - warnings (an unknown-columns warning, if needed).
    Steps:
        1. Refuse duplicate column names (ignoring case and spaces).
        2. Refuse a header that lacks a required column.
        3. Return a warning if there are unknown extra columns.
    Example: header "timestamp,source_ip" for authentication -> IngestionError
        naming username and status.
    Errors: IngestionError for duplicate names or missing required columns.
    """
    duplicate_names = _find_duplicate_names(header_cells)
    if len(duplicate_names) > 0:
        _fail(file_name, "duplicate column names: " + ", ".join(duplicate_names[:5]))
    column_report = check_columns(header_cells, log_type)
    if len(column_report["missing_required"]) > 0:
        _fail(file_name, "missing required column(s): " + ", ".join(column_report["missing_required"]))
    warnings = []
    if len(column_report["unknown"]) > 0:
        warnings.append(_make_unknown_column_warning(column_report["unknown"]))
    return warnings


def _find_column_positions(header_cells, log_type):
    """Map each known column name (lowercase) to its position in the header."""
    positions = {}
    known_columns = COLUMNS_BY_LOG_TYPE[log_type]
    for index in range(len(header_cells)):
        normalised_name = header_cells[index].strip().lower()
        if normalised_name in known_columns:
            positions[normalised_name] = index
    return positions


def _make_raw_row(header_cells, cells):
    """
    Build raw_event / raw_row: every header name mapped to its cell text,
    exactly as read, each value cut to 500 characters. A short row is padded
    with empty text; cells beyond the header get the names "(extra cell N)".
    """
    raw_row = {}
    for index in range(len(cells)):
        if index < len(header_cells):
            key = header_cells[index][:MAX_RAW_VALUE_LENGTH]
        else:
            key = "(extra cell " + str(index - len(header_cells) + 1) + ")"
        raw_row[key] = cells[index][:MAX_RAW_VALUE_LENGTH]
    for index in range(len(cells), len(header_cells)):
        raw_row[header_cells[index][:MAX_RAW_VALUE_LENGTH]] = ""
    return raw_row


def _find_cells_by_column(cells, positions):
    """Return {column name: cell text}. A missing trailing cell is empty text."""
    cells_by_column = {}
    for column_name in positions:
        index = positions[column_name]
        if index < len(cells):
            cells_by_column[column_name] = cells[index]
        else:
            cells_by_column[column_name] = ""
    return cells_by_column


# ---------------------------------------------------------------
# Part 3: turning one row into values (row-level problems reject ONE row)
# ---------------------------------------------------------------

def _clean_text_column(column_name, text):
    """Clean username / service / protocol. service is stored lowercase and
    protocol uppercase (C.1). The length is checked again after changing the
    case, because a few letters change length (for example the German sharp s)."""
    max_length = TEXT_COLUMN_MAX_LENGTH[column_name]
    cleaned = clean_text_value(text, max_length)
    if column_name == "service":
        cleaned = cleaned.lower()
    elif column_name == "protocol":
        cleaned = cleaned.upper()
    if len(cleaned) > max_length:
        raise ValueError("value_too_long")
    return cleaned


def _convert_non_empty_cell(column_name, text, log_type, assume_utc):
    """Convert one cell that is known not to be empty. Raises the validator's
    ValueError unchanged; _convert_cell turns it into a rejection reason."""
    if column_name == "timestamp":
        return parse_timestamp(text, assume_utc)
    if column_name in IP_COLUMNS:
        return parse_ip_address(text)
    if column_name == "status":
        return normalise_status(text, log_type)
    if column_name == "destination_port":
        return parse_port(text)
    if column_name in COUNT_COLUMNS:
        return parse_optional_non_negative_int(text)
    return _clean_text_column(column_name, text)


def _make_rejection_reason(column_name, error):
    """Choose the fixed reason text of Section D.5 for a failed column."""
    if column_name == "timestamp":
        return "invalid_timestamp"
    if column_name in IP_COLUMNS:
        return "invalid_ip:" + column_name
    if column_name == "status":
        return "invalid_status"
    if column_name == "destination_port":
        return "invalid_port"
    if column_name in COUNT_COLUMNS:
        return "invalid_number:" + column_name
    return str(error) + ":" + column_name  # value_too_long or control_characters


def _convert_cell(column_name, text, log_type, assume_utc):
    """
    Purpose: check and convert ONE cell, or explain why the row is rejected.
    Inputs: column_name (str); text (str) - the cell; log_type (str);
        assume_utc (bool).
    Output: the converted value; None for an empty optional cell.
    Steps:
        1. Empty text: a required column gives missing_required_value, an
           optional column gives None.
        2. Otherwise run the matching validator.
        3. If the validator raises ValueError, re-raise it with the fixed
           reason text of Section D.5 as the message.
    Example: ("source_ip", "999.1.1.1", ...) -> ValueError("invalid_ip:source_ip").
    Errors: ValueError whose message is the rejection reason.
    """
    if text.strip() == "":
        if column_name in REQUIRED_COLUMNS_BY_LOG_TYPE[log_type]:
            raise ValueError("missing_required_value:" + column_name)
        return None
    try:
        return _convert_non_empty_cell(column_name, text, log_type, assume_utc)
    except ValueError as error:
        raise ValueError(_make_rejection_reason(column_name, error)) from error


def _convert_row(cells_by_column, log_type, assume_utc):
    """
    Purpose: convert every column of one row, in the order of Section D.
    Inputs: cells_by_column (dict); log_type (str); assume_utc (bool).
    Output: dict - column name -> converted value (None when empty).
    Steps:
        1. Walk the columns in the order of the D.3 / D.4 tables.
        2. Convert each; the first problem stops the walk (D.5: a row is
           rejected for the first problem found).
    Example: auth row with a bad IP and a bad status -> ValueError("invalid_ip:source_ip").
    Errors: ValueError whose message is the rejection reason.
    """
    converted_values = {}
    for column_name in COLUMNS_BY_LOG_TYPE[log_type]:
        if column_name in cells_by_column:
            cell_text = cells_by_column[column_name]
            converted_values[column_name] = _convert_cell(column_name, cell_text, log_type, assume_utc)
        else:
            converted_values[column_name] = None  # an optional column the file does not have
    return converted_values


# ---------------------------------------------------------------
# Part 4: building events, with the occurrence number (FS.3.1)
# ---------------------------------------------------------------

def _make_content_dictionary(log_type, values):
    """The 11 EVENT_CONTENT_KEYS of an event. Columns that this log type does
    not have (for example username in a network log) stay None."""
    content = {"event_type": log_type}
    for key in EVENT_CONTENT_KEYS:
        if key != "event_type":
            content[key] = values.get(key)
    return content


def _count_occurrence(content, tally):
    """
    Count how many times this exact content has been seen in THIS file.
    The tally is keyed by the canonical JSON text of the 11 content keys.
    The first identical row gets 1, the second 2, and so on (FS.3.1).
    """
    text_form = dict(content)
    text_form["timestamp"] = datetime_to_iso(content["timestamp"])
    tally_key = canonical_json(text_form)
    seen_before = tally.get(tally_key, 0)
    tally[tally_key] = seen_before + 1
    return seen_before + 1


def _build_event(log_type, values, file_name, line_number, raw_row, tally):
    """
    Purpose: build one event with core.contracts.make_event (ingestion never
        builds an event dictionary or an ID by hand).
    Inputs: log_type (str); values (dict) - converted cells; file_name (str);
        line_number (int) - becomes source_row; raw_row (dict) - becomes
        raw_event; tally (dict) - occurrence counts for this file.
    Output: dict - a valid 15-key event.
    Steps:
        1. Gather the 11 content values and count the occurrence in this file.
        2. Call make_event, which validates everything and creates the event_id.
        3. If make_event still refuses, stop the file loudly (never drop a row silently).
    Example: the second identical row in a file gets occurrence 2, so a new event_id.
    Errors: IngestionError only if make_event raises ContractError.
    """
    content = _make_content_dictionary(log_type, values)
    occurrence = _count_occurrence(content, tally)
    try:
        return make_event(
            event_type=log_type,
            timestamp=content["timestamp"],
            source_ip=content["source_ip"],
            status=content["status"],
            source_file=file_name,
            source_row=line_number,
            raw_event=raw_row,
            occurrence=occurrence,
            destination_ip=content["destination_ip"],
            destination_port=content["destination_port"],
            protocol=content["protocol"],
            username=content["username"],
            service=content["service"],
            bytes_sent=content["bytes_sent"],
            bytes_received=content["bytes_received"],
        )
    except ContractError as error:
        # Our own checks should have caught this. If not, stop loudly instead
        # of dropping the row silently.
        _fail(file_name, "internal check failed at line " + str(line_number) + ": " + str(error))


def _make_rejected_row(file_name, line_number, reason, raw_row):
    """The dictionary stored in rejected_rows (D.6)."""
    return {
        "source_file": file_name,
        "source_row": line_number,
        "reason": reason,
        "raw_row": raw_row,
    }


def _process_row(cells, line_number, file_info, tally):
    """
    Purpose: handle one non-blank data row: accept it as an event or reject it.
    Inputs:
        cells (list of str) - the parsed cells of the row.
        line_number (int) - physical line number in the file (header = 1).
        file_info (dict) - file_name, log_type, header_cells, positions, assume_utc.
        tally (dict) - occurrence counts for this file; updated for accepted rows.
    Output: tuple (event, rejected_row); exactly one of the two is None.
    Steps:
        1. Build raw_row. A row with more cells than the header is rejected
           (too_many_columns).
        2. Convert the columns; a ValueError means the row is rejected with
           that reason.
        3. Otherwise build the event with make_event.
    Example: 7 cells under a 6-column header -> (None, {... "reason": "too_many_columns"}).
    Errors: IngestionError only if make_event refuses a row our own checks accepted.
    """
    header_cells = file_info["header_cells"]
    raw_row = _make_raw_row(header_cells, cells)
    file_name = file_info["file_name"]
    if len(cells) > len(header_cells):
        return None, _make_rejected_row(file_name, line_number, "too_many_columns", raw_row)
    cells_by_column = _find_cells_by_column(cells, file_info["positions"])
    try:
        values = _convert_row(cells_by_column, file_info["log_type"], file_info["assume_utc"])
    except ValueError as error:
        return None, _make_rejected_row(file_name, line_number, str(error), raw_row)
    event = _build_event(file_info["log_type"], values, file_name, line_number, raw_row, tally)
    return event, None


# ---------------------------------------------------------------
# Part 5: the whole file
# ---------------------------------------------------------------

def _read_data_rows(lines, header_index, file_info, max_rows):
    """
    Purpose: process every line after the header.
    Inputs: lines (list of str); header_index (int); file_info (dict, see
        _process_row); max_rows (int) - the limit max_rows_per_file.
    Output: dict with events, rejected_rows, rows_read, rows_blank (blank lines
        after the header).
    Steps:
        1. Skip fully blank lines and count them.
        2. Count every other line as a data row; more than max_rows rows
           stops the whole file (D6).
        3. Process the row and collect the event or the rejected row.
    Example: header + 3 good lines + 1 blank line -> rows_read 3, rows_blank 1.
    Errors: IngestionError when there are more than max_rows data rows.
    """
    events = []
    rejected_rows = []
    tally = {}
    rows_read = 0
    rows_blank = 0
    for index in range(header_index + 1, len(lines)):
        line = lines[index]
        if _is_blank_line(line):
            rows_blank = rows_blank + 1
            continue
        rows_read = rows_read + 1
        if rows_read > max_rows:
            _fail(file_info["file_name"], "the file has more than " + str(max_rows) + " data rows")
        cells = _parse_line(line)
        event, rejected_row = _process_row(cells, index + 1, file_info, tally)
        if event is not None:
            events.append(event)
        else:
            rejected_rows.append(rejected_row)
    return {
        "events": events,
        "rejected_rows": rejected_rows,
        "rows_read": rows_read,
        "rows_blank": rows_blank,
    }


def _make_summary(rows, header_warnings, blank_lines_before_header):
    """
    Purpose: build the summary dictionary of D.6.
    Inputs: rows (dict) - events, rejected_rows, rows_read, rows_blank from
        _read_data_rows; header_warnings (list of str); blank_lines_before_header (int).
    Output: dict - rows_read, rows_blank, events_accepted, rows_rejected,
        earliest_timestamp, latest_timestamp, warnings.
    Steps:
        1. Find the earliest and latest event timestamps (None if no events).
        2. Copy the header warnings.
        3. If MORE than half of the rows were rejected, add the warning
           high_rejection_rate (D.1).
    Example: 3 rows read, 2 rejected -> warnings contain "high_rejection_rate".
    Errors: none.
    """
    events = rows["events"]
    earliest_timestamp = None
    latest_timestamp = None
    for event in events:
        if earliest_timestamp is None or event["timestamp"] < earliest_timestamp:
            earliest_timestamp = event["timestamp"]
        if latest_timestamp is None or event["timestamp"] > latest_timestamp:
            latest_timestamp = event["timestamp"]
    rows_rejected = len(rows["rejected_rows"])
    warnings = list(header_warnings)
    if rows_rejected * 2 > rows["rows_read"]:
        warnings.append("high_rejection_rate")  # the exact warning name used in D.1
    return {
        "rows_read": rows["rows_read"],
        "rows_blank": rows["rows_blank"] + blank_lines_before_header,
        "events_accepted": len(events),
        "rows_rejected": rows_rejected,
        "earliest_timestamp": earliest_timestamp,
        "latest_timestamp": latest_timestamp,
        "warnings": warnings,
    }


def ingest_file(file_bytes: bytes, file_name: str, log_type: str, config: dict) -> dict:
    """
    Purpose: validate and normalise ONE uploaded CSV file (Section D).
    Inputs:
        file_bytes (bytes) - the raw file content; it is untrusted.
        file_name (str) - the file name only, for example auth_sample.csv. It
            becomes source_file and is part of every event ID (D2).
        log_type (str) - "authentication" or "network_connection".
        config (dict) - uses max_upload_mb, max_rows_per_file and assume_utc.
    Output: dict with exactly the keys file_name, log_type, events (list of
        event dictionaries), rejected_rows (list of dicts with source_file,
        source_row, reason, raw_row) and summary (rows_read, rows_blank,
        events_accepted, rows_rejected, earliest_timestamp, latest_timestamp,
        warnings). rows_read = events_accepted + rows_rejected.
    Steps:
        1. File-level checks: log_type, file name, size, empty, UTF-8.
        2. Split into lines, find the header, check its columns.
        3. Process every data row: reject it with a fixed reason or build an
           event with make_event (which also gives it its event ID).
        4. Build the summary and return everything.
    Example: ingest_file(data, "auth_sample.csv", "authentication", config)
        -> {"events": [20 events], "rejected_rows": [], "summary": {...}, ...}.
    Errors: IngestionError for a file-level problem: wrong extension, empty
        file, too large, not UTF-8, no header, missing or duplicate columns,
        too many rows, unknown log_type or an invalid config value.
    """
    max_upload_bytes, max_rows, assume_utc = _read_settings(config)
    if log_type not in COLUMNS_BY_LOG_TYPE:
        raise IngestionError("unknown log_type: " + repr(log_type))
    _check_file_name(file_name)
    _check_file_bytes(file_bytes, file_name, max_upload_bytes)
    lines = _split_into_lines(_decode_text(file_bytes, file_name))
    header_index = _find_header_line_index(lines, file_name)
    header_cells = _parse_line(lines[header_index])
    header_warnings = _check_header(header_cells, log_type, file_name)
    file_info = {
        "file_name": file_name,
        "log_type": log_type,
        "header_cells": header_cells,
        "positions": _find_column_positions(header_cells, log_type),
        "assume_utc": assume_utc,
    }
    rows = _read_data_rows(lines, header_index, file_info, max_rows)
    summary = _make_summary(rows, header_warnings, header_index)  # lines before the header are all blank
    return {
        "file_name": file_name,
        "log_type": log_type,
        "events": rows["events"],
        "rejected_rows": rows["rejected_rows"],
        "summary": summary,
    }


# ---------------------------------------------------------------
# Part 6: combining several files (R1.1.3 to R1.1.5)
# ---------------------------------------------------------------

def _event_sort_key(event):
    """Order events by time, then file name, then row number (R1.1.5)."""
    return (event["timestamp"], event["source_file"], event["source_row"])


def _merge_events_and_drop_repeats(results):
    """
    Collect every event, keeping only the first copy of each event_id.
    The same event_id can only appear twice when the SAME file name with the
    same rows was added twice. Returns (events, duplicates_removed,
    repeat_counts) where repeat_counts maps file name -> events dropped.
    """
    events = []
    seen_ids = set()
    repeat_counts = {}
    for result in results:
        for event in result["events"]:
            if event["event_id"] in seen_ids:
                name = event["source_file"]
                repeat_counts[name] = repeat_counts.get(name, 0) + 1
            else:
                seen_ids.add(event["event_id"])
                events.append(event)
    duplicates_removed = sum(repeat_counts.values())
    return events, duplicates_removed, repeat_counts


def _collect_fingerprints_by_file(events):
    """Return {file name: set of content fingerprints}, in order of first
    appearance. Dictionaries keep insertion order in Python 3.7 and later."""
    fingerprints_by_file = {}
    for event in events:
        name = event["source_file"]
        if name not in fingerprints_by_file:
            fingerprints_by_file[name] = set()
        fingerprints_by_file[name].add(make_content_fingerprint(event))
    return fingerprints_by_file


def _find_overlap_warnings(events):
    """
    Purpose: warn when two DIFFERENTLY NAMED files hold identical events.
    Inputs: events (list) - the merged events.
    Output: list of str - one warning per pair of files that share at least
        one distinct content fingerprint (R1.1.4). Nothing is removed.
    Steps:
        1. Build, for each file name, the set of content fingerprints.
        2. Compare every pair of file names; count shared fingerprints.
        3. Write a warning for each pair with a count above zero.
    Example: auth_b.csv repeats 120 events of auth_a.csv -> "auth_b.csv shares
        120 identical events with auth_a.csv. They were kept as separate events. ..."
    Errors: none.
    """
    fingerprints_by_file = _collect_fingerprints_by_file(events)
    file_names = list(fingerprints_by_file.keys())
    warnings = []
    for later_index in range(1, len(file_names)):
        for earlier_index in range(later_index):
            later_name = file_names[later_index]
            earlier_name = file_names[earlier_index]
            shared_count = len(fingerprints_by_file[later_name] & fingerprints_by_file[earlier_name])
            if shared_count > 0:
                warnings.append(_make_overlap_text(later_name, earlier_name, shared_count))
    return warnings


def _make_overlap_text(later_name, earlier_name, shared_count):
    """The overlap warning sentence of R1.1.4."""
    noun = "events"
    if shared_count == 1:
        noun = "event"
    return (
        later_name + " shares " + str(shared_count) + " identical " + noun + " with " + earlier_name
        + ". They were kept as separate events. If these are overlapping exports,"
        " alert counts may be inflated."
    )


def combine_ingestion_results(results: list) -> dict:
    """
    Purpose: merge the results of several ingest_file calls into one data set
        for detection (Section A.3 step 2).
    Inputs: results (list of dict) - each one returned by ingest_file.
    Output: dict with exactly the keys:
        events - all events sorted by timestamp, then source_file, then source_row;
        rejected_rows - every rejected row of every file, in input order;
        summaries - each file's summary dictionary, in input order;
        duplicates_removed (int) - events dropped because the same event_id
            appeared twice (only possible when the same file was added twice);
        overlap_warnings (list of str) - a warning for each repeated file and
            for each pair of differently named files with identical events.
    Steps:
        1. Check the input shape.
        2. Merge events, keeping the first copy of every event_id and counting
           the rest; add a warning naming each repeated file.
        3. Sort the events.
        4. Add an overlap warning for every pair of differently named files
           that share events. No event is removed for overlap (D2).
    Example: auth_a.csv and a renamed copy auth_b.csv (3 rows each) -> 6 events,
        duplicates_removed 0, one warning "auth_b.csv shares 3 identical events with auth_a.csv. ...".
    Errors: none (E.5). The function raises no project exception. Passing
        something that is not a list of ingest_file results is a programming
        mistake, and Python's own TypeError or KeyError will show it.
    """
    events, duplicates_removed, repeat_counts = _merge_events_and_drop_repeats(results)
    warnings = []
    for file_name in repeat_counts:
        warnings.append(
            file_name + " was added more than once. " + str(repeat_counts[file_name])
            + " duplicate events were removed and one copy was kept."
        )
    events.sort(key=_event_sort_key)
    warnings.extend(_find_overlap_warnings(events))
    rejected_rows = []
    summaries = []
    for result in results:
        rejected_rows.extend(result["rejected_rows"])
        summaries.append(result["summary"])
    return {
        "events": events,
        "rejected_rows": rejected_rows,
        "summaries": summaries,
        "duplicates_removed": duplicates_removed,
        "overlap_warnings": warnings,
    }
