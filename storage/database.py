# storage/database.py
# ---------------------------------------------------------------
# Purpose: the SQLite layer for saved alerts and the events they reference
# (FS.5, Section F, R1.2, R1.8). SQLite is NOT a log archive.
# get_connection / initialise_database: open the file, create the 8 tables.
# save_alerts: all-or-nothing save of alerts, their events and alert links.
# get_alerts / get_alert / get_events_for_alert: read saved data back.
# get_existing_alert_ids / get_summary_counts: small questions for the dashboard.
# Every SQL value goes through a ? placeholder. Uses: core only.

import json
import os
import sqlite3

from core.contracts import (
    ALERT_KEYS,
    EVENT_KEYS,
    INCIDENT_STATUSES,
    SEVERITIES,
    canonical_json,
    datetime_to_iso,
    iso_to_datetime,
    utc_now,
    validate_alert,
    validate_event,
)
from core.errors import BrokenReferenceError, DatabaseError

# Decision D14: the database lives here, relative to the project folder.
DEFAULT_DATABASE_PATH = "data/network_sentinel.db"

_SCHEMA_VERSION = 1
_ID_CHUNK_SIZE = 500  # how many IDs one "IN (...)" query may carry

# The only alert filters get_alerts accepts. These are fixed words that WE
# wrote, so they are safe to place inside the SQL text. The values the caller
# gives still travel through ? placeholders.
_ALERT_FILTER_COLUMNS = ["severity", "confidence", "rule_id", "source_ip"]

# The schema is Section F plus the alert_links table of R1.8, word for word.
_SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS events (
        event_id         TEXT PRIMARY KEY,
        event_type       TEXT NOT NULL CHECK (event_type IN ('authentication', 'network_connection')),
        timestamp        TEXT NOT NULL,
        source_ip        TEXT NOT NULL,
        destination_ip   TEXT,
        destination_port INTEGER,
        protocol         TEXT,
        username         TEXT,
        service          TEXT,
        status           TEXT NOT NULL,
        bytes_sent       INTEGER,
        bytes_received   INTEGER,
        source_file      TEXT NOT NULL,
        source_row       INTEGER NOT NULL,
        raw_event_json   TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS alerts (
        alert_id           TEXT PRIMARY KEY,
        rule_id            TEXT NOT NULL,
        title              TEXT NOT NULL,
        description        TEXT NOT NULL,
        severity           TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
        confidence         TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
        detected_at        TEXT NOT NULL,
        time_start         TEXT NOT NULL,
        time_end           TEXT NOT NULL,
        source_ip          TEXT,
        evidence_json      TEXT NOT NULL,
        recommended_action TEXT NOT NULL,
        saved_at           TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS alert_events (
        alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
        event_id TEXT NOT NULL REFERENCES events(event_id),
        position INTEGER NOT NULL,
        PRIMARY KEY (alert_id, event_id)
    )""",
    """CREATE TABLE IF NOT EXISTS incidents (
        incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
        title       TEXT NOT NULL,
        summary     TEXT NOT NULL DEFAULT '',
        status      TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
        priority    TEXT NOT NULL CHECK (priority IN ('low', 'medium', 'high', 'critical')),
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        closed_at   TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS incident_alerts (
        incident_id INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
        alert_id    TEXT NOT NULL REFERENCES alerts(alert_id),
        added_at    TEXT NOT NULL,
        PRIMARY KEY (incident_id, alert_id)
    )""",
    """CREATE TABLE IF NOT EXISTS incident_notes (
        note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
        author      TEXT NOT NULL,
        text        TEXT NOT NULL,
        created_at  TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS incident_history (
        history_id  INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
        action      TEXT NOT NULL CHECK (action IN ('created', 'status_changed', 'note_added', 'alert_added')),
        old_value   TEXT,
        new_value   TEXT,
        changed_by  TEXT NOT NULL,
        changed_at  TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS alert_links (
        alert_id        TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
        linked_alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
        PRIMARY KEY (alert_id, linked_alert_id),
        CHECK (alert_id <> linked_alert_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip  ON alerts(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_rule_id    ON alerts(rule_id)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_time_start ON alerts(time_start)",
    "CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events(event_id)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_status  ON incidents(status)",
    "CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert ON incident_alerts(alert_id)",
    "CREATE INDEX IF NOT EXISTS idx_notes_incident    ON incident_notes(incident_id)",
    "CREATE INDEX IF NOT EXISTS idx_history_incident  ON incident_history(incident_id)",
    "CREATE INDEX IF NOT EXISTS idx_alert_links_linked ON alert_links(linked_alert_id)",
]


# ---------------------------------------------------------------
# Connection and schema
# ---------------------------------------------------------------

def get_connection(db_path: str) -> sqlite3.Connection:
    """
    Purpose: open the SQLite file with foreign keys switched on and rows
        that can be read by column name.
    Inputs: db_path (str) - path of the database file, for example
        "data/network_sentinel.db". The file is created if it is missing,
        but its folder must already exist.
    Output: sqlite3.Connection - the caller must close it.
    Steps:
        1. Refuse an empty or non-text path.
        2. Connect with isolation_level=None. That means Python does NOT
           start transactions behind our back; we write BEGIN and COMMIT
           ourselves so every transaction is visible in the code.
        3. Ask for rows readable by name (row["title"]).
        4. Switch foreign keys ON. SQLite has them OFF by default, and the
           setting only lasts for this one connection.
        5. Check that the switch really worked.
    Example: connection = get_connection("data/network_sentinel.db").
    Errors: DatabaseError if the path is bad or SQLite cannot open the file.
    """
    if not isinstance(db_path, str) or db_path.strip() == "":
        raise DatabaseError("db_path must be non-empty text")
    connection = None
    try:
        connection = sqlite3.connect(db_path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        setting_row = connection.execute("PRAGMA foreign_keys").fetchone()
        if setting_row[0] != 1:
            raise DatabaseError("SQLite did not switch foreign keys on")
    except sqlite3.Error as error:
        if connection is not None:
            connection.close()
        raise DatabaseError("Could not open the database: " + str(error)) from error
    except DatabaseError:
        connection.close()
        raise
    return connection


def initialise_database(db_path: str) -> None:
    """
    Purpose: create the eight tables and the indexes if they are missing.
    Inputs: db_path (str) - path of the database file.
    Output: None. Safe to run again and again (CREATE ... IF NOT EXISTS).
    Steps:
        1. Create the folder of the file if it does not exist yet.
        2. Open a connection and read PRAGMA user_version (0 means a new file).
        3. Refuse a file made by a newer schema version.
        4. In ONE transaction run every CREATE statement and set
           user_version to 1. If anything fails nothing is half-created.
    Example: initialise_database("data/network_sentinel.db") twice -> same tables.
    Errors: DatabaseError if the folder cannot be made, SQLite fails, or the
        file belongs to a newer schema version.
    """
    if not isinstance(db_path, str) or db_path.strip() == "":
        raise DatabaseError("db_path must be non-empty text")
    folder_path = os.path.dirname(db_path)
    try:
        if folder_path != "":
            os.makedirs(folder_path, exist_ok=True)
    except OSError as error:
        raise DatabaseError("Could not create the database folder: " + str(error)) from error
    connection = get_connection(db_path)
    try:
        version_row = connection.execute("PRAGMA user_version").fetchone()
        if version_row[0] not in (0, _SCHEMA_VERSION):
            raise DatabaseError("This database was made by a newer version of Network Sentinel")
        connection.execute("BEGIN IMMEDIATE")
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version = " + str(_SCHEMA_VERSION))
        connection.execute("COMMIT")
    except Exception as error:
        _rollback_and_reraise(connection, error, "Could not create the database tables")
    finally:
        connection.close()


# ---------------------------------------------------------------
# Small private helpers
# ---------------------------------------------------------------

def _now_text():
    """The current UTC time in the project's fixed text format."""
    return datetime_to_iso(utc_now())


def _rollback_and_reraise(connection, error, message):
    """
    Undo any open transaction, then raise the right kind of error.
    A SQLite error becomes DatabaseError; every other error (for example
    BrokenReferenceError) is raised again unchanged.
    """
    try:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
    except sqlite3.Error:
        pass  # the original error matters more than a failed rollback
    if isinstance(error, sqlite3.Error):
        raise DatabaseError(message + ": " + str(error)) from error
    raise error


def _make_placeholders(count):
    """Return '?, ?, ?' with count question marks (for an IN list)."""
    return ", ".join(["?"] * count)


def _split_into_chunks(items, chunk_size):
    """Cut a list into smaller lists, so one query never has too many ? marks."""
    chunks = []
    for start in range(0, len(items), chunk_size):
        chunks.append(items[start:start + chunk_size])
    return chunks


def _find_stored_alert_ids(connection, alert_ids):
    """Return the set of these alert IDs that exist in the alerts table."""
    found_ids = set()
    for chunk in _split_into_chunks(alert_ids, _ID_CHUNK_SIZE):
        sql = "SELECT alert_id FROM alerts WHERE alert_id IN (" + _make_placeholders(len(chunk)) + ")"
        for row in connection.execute(sql, chunk):
            found_ids.add(row["alert_id"])
    return found_ids


def _find_stored_event_ids(connection, event_ids):
    """Return the set of these event IDs that exist in the events table."""
    found_ids = set()
    for chunk in _split_into_chunks(event_ids, _ID_CHUNK_SIZE):
        sql = "SELECT event_id FROM events WHERE event_id IN (" + _make_placeholders(len(chunk)) + ")"
        for row in connection.execute(sql, chunk):
            found_ids.add(row["event_id"])
    return found_ids


def _is_correlated(alert):
    """True for a correlated alert (its rule_id starts with CORR_)."""
    return alert["rule_id"].startswith("CORR_")


# ---------------------------------------------------------------
# save_alerts and its steps (R1.2.3)
# ---------------------------------------------------------------

def _check_save_arguments(alerts, events, available_alerts):
    """Make sure save_alerts received lists of dictionaries."""
    if not isinstance(alerts, list):
        raise DatabaseError("alerts must be a list")
    if not isinstance(events, list):
        raise DatabaseError("events must be a list")
    if available_alerts is not None and not isinstance(available_alerts, list):
        raise DatabaseError("available_alerts must be a list or None")


def _check_one_alert(alert):
    """Run validate_alert and turn any problems into one DatabaseError."""
    problems = validate_alert(alert)
    if len(problems) > 0:
        if isinstance(alert, dict):
            label = str(alert.get("alert_id"))
        else:
            label = "(not a dictionary)"
        raise DatabaseError("Invalid alert " + label + ": " + "; ".join(problems))


def _collect_chosen_alerts(alerts):
    """Step 1 and 4: gather the chosen alerts by ID (validated, first copy wins)."""
    collected = {}
    for alert in alerts:
        _check_one_alert(alert)
        if alert["alert_id"] not in collected:
            collected[alert["alert_id"]] = alert
    return collected


def _index_alerts_by_id(available_alerts):
    """Make an alert_id -> alert dictionary from the session list (may be None)."""
    index = {}
    if available_alerts is None:
        return index
    for alert in available_alerts:
        if isinstance(alert, dict) and isinstance(alert.get("alert_id"), str):
            if alert["alert_id"] not in index:
                index[alert["alert_id"]] = alert
    return index


def _require_base_rule(rule_id, linked_id, correlated_id):
    """A linked alert must be a base alert (AUTH_ or NET_), never CORR_ (R1.2.3 step 3)."""
    if not (rule_id.startswith("AUTH_") or rule_id.startswith("NET_")):
        raise BrokenReferenceError(
            "Correlated alert " + correlated_id + " links to " + linked_id
            + ", which is not a base alert"
        )


def _resolve_one_link(connection, collected, available_by_id, linked_id, correlated_id):
    """
    Find one linked base alert: chosen list, then session list, then database.
    Returns True when the alert was added automatically from the session list.
    Raises BrokenReferenceError if it cannot be found anywhere.
    """
    if linked_id in collected:
        _require_base_rule(collected[linked_id]["rule_id"], linked_id, correlated_id)
        return False
    if linked_id in available_by_id:
        candidate = available_by_id[linked_id]
        _check_one_alert(candidate)
        _require_base_rule(candidate["rule_id"], linked_id, correlated_id)
        collected[linked_id] = candidate
        return True
    row = connection.execute("SELECT rule_id FROM alerts WHERE alert_id = ?", (linked_id,)).fetchone()
    if row is None:
        raise BrokenReferenceError(
            "Correlated alert " + correlated_id + " links to " + linked_id
            + ", which is not in the selection, the session or the database"
        )
    _require_base_rule(row["rule_id"], linked_id, correlated_id)
    return False


def _resolve_linked_alerts(connection, collected, available_by_id):
    """
    Step 2 and 3 of R1.2.3: for every chosen correlated alert, make sure each
    linked base alert can be found. Adds session base alerts to `collected`.
    Returns the list of alert IDs that were added automatically.
    """
    auto_added_ids = []
    chosen_ids = list(collected.keys())  # a copy, because collected grows below
    for alert_id in chosen_ids:
        alert = collected[alert_id]
        if not _is_correlated(alert):
            continue
        for linked_id in alert["evidence"]["correlation"]["linked_alert_ids"]:
            was_added = _resolve_one_link(connection, collected, available_by_id, linked_id, alert_id)
            if was_added:
                auto_added_ids.append(linked_id)
    return auto_added_ids


def _index_events_by_id(events):
    """Make an event_id -> event dictionary from the session event list."""
    index = {}
    for event in events:
        if isinstance(event, dict) and isinstance(event.get("event_id"), str):
            index[event["event_id"]] = event
    return index


def _list_needed_event_ids(collected):
    """All event IDs referenced by the collected alerts, each once, in order."""
    needed_ids = []
    seen_ids = set()
    for alert in collected.values():
        for event_id in alert["event_ids"]:
            if event_id not in seen_ids:
                seen_ids.add(event_id)
                needed_ids.append(event_id)
    return needed_ids


def _check_events_exist(connection, needed_ids, events_by_id):
    """Step 5: every referenced event must be in the session list or the database."""
    not_in_session = []
    for event_id in needed_ids:
        if event_id not in events_by_id:
            not_in_session.append(event_id)
    stored_ids = _find_stored_event_ids(connection, not_in_session)
    for event_id in not_in_session:
        if event_id not in stored_ids:
            raise BrokenReferenceError(
                "Event " + event_id + " is referenced by an alert but is neither in the "
                "session events nor in the database"
            )


def _pick_events_to_write(needed_ids, events_by_id):
    """The referenced events that the session has (validated). Others are already stored."""
    events_to_write = []
    for event_id in needed_ids:
        if event_id in events_by_id:
            problems = validate_event(events_by_id[event_id])
            if len(problems) > 0:
                raise DatabaseError("Invalid event " + event_id + ": " + "; ".join(problems))
            events_to_write.append(events_by_id[event_id])
    return events_to_write


def _insert_events(connection, events_to_write):
    """
    Insert events with INSERT OR IGNORE: an event that is already stored is
    skipped and never overwritten. Returns how many rows were really added.
    """
    sql = (
        "INSERT OR IGNORE INTO events (event_id, event_type, timestamp, source_ip, "
        "destination_ip, destination_port, protocol, username, service, status, "
        "bytes_sent, bytes_received, source_file, source_row, raw_event_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    inserted_count = 0
    for event in events_to_write:
        values = (
            event["event_id"], event["event_type"], datetime_to_iso(event["timestamp"]),
            event["source_ip"], event["destination_ip"], event["destination_port"],
            event["protocol"], event["username"], event["service"], event["status"],
            event["bytes_sent"], event["bytes_received"], event["source_file"],
            event["source_row"], canonical_json(event["raw_event"]),
        )
        cursor = connection.execute(sql, values)
        inserted_count = inserted_count + cursor.rowcount  # 1 if added, 0 if ignored
    return inserted_count


def _insert_alert_rows(connection, alert_list, saved_at_text):
    """
    Insert alerts with INSERT OR IGNORE. Returns the list of alert IDs that
    were really added (an already stored alert is skipped, never overwritten).
    """
    sql = (
        "INSERT OR IGNORE INTO alerts (alert_id, rule_id, title, description, severity, "
        "confidence, detected_at, time_start, time_end, source_ip, evidence_json, "
        "recommended_action, saved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    inserted_ids = []
    for alert in alert_list:
        values = (
            alert["alert_id"], alert["rule_id"], alert["title"], alert["description"],
            alert["severity"], alert["confidence"], datetime_to_iso(alert["detected_at"]),
            datetime_to_iso(alert["time_start"]), datetime_to_iso(alert["time_end"]),
            alert["source_ip"], canonical_json(alert["evidence"]),
            alert["recommended_action"], saved_at_text,
        )
        cursor = connection.execute(sql, values)
        if cursor.rowcount == 1:
            inserted_ids.append(alert["alert_id"])
    return inserted_ids


def _insert_alert_event_rows(connection, alert_list):
    """One alert_events row per event ID of each alert; position keeps the time order."""
    sql = "INSERT OR IGNORE INTO alert_events (alert_id, event_id, position) VALUES (?, ?, ?)"
    for alert in alert_list:
        position = 0
        for event_id in alert["event_ids"]:
            connection.execute(sql, (alert["alert_id"], event_id, position))
            position = position + 1


def _insert_alert_link_rows(connection, correlated_list):
    """One alert_links row per link from a correlated alert to a base alert (R1.8)."""
    sql = "INSERT OR IGNORE INTO alert_links (alert_id, linked_alert_id) VALUES (?, ?)"
    for alert in correlated_list:
        for linked_id in alert["evidence"]["correlation"]["linked_alert_ids"]:
            connection.execute(sql, (alert["alert_id"], linked_id))


def _split_base_and_correlated(collected):
    """Base alerts must be written before correlated ones (foreign keys)."""
    base_list = []
    correlated_list = []
    for alert in collected.values():
        if _is_correlated(alert):
            correlated_list.append(alert)
        else:
            base_list.append(alert)
    return base_list, correlated_list


def _keep_inserted(alert_list, inserted_ids):
    """Only the alerts in alert_list whose ID is in inserted_ids."""
    kept = []
    for alert in alert_list:
        if alert["alert_id"] in inserted_ids:
            kept.append(alert)
    return kept


def _save_inside_transaction(connection, alerts, events, available_alerts):
    """
    Everything save_alerts does after BEGIN. Every check comes BEFORE the
    first write, so a refused save has not written anything.
    """
    collected = _collect_chosen_alerts(alerts)
    available_by_id = _index_alerts_by_id(available_alerts)
    auto_added_ids = _resolve_linked_alerts(connection, collected, available_by_id)
    events_by_id = _index_events_by_id(events)
    needed_ids = _list_needed_event_ids(collected)
    _check_events_exist(connection, needed_ids, events_by_id)
    events_to_write = _pick_events_to_write(needed_ids, events_by_id)

    saved_at_text = _now_text()
    base_list, correlated_list = _split_base_and_correlated(collected)
    events_inserted = _insert_events(connection, events_to_write)
    inserted_ids = _insert_alert_rows(connection, base_list, saved_at_text)
    inserted_ids.extend(_insert_alert_rows(connection, correlated_list, saved_at_text))
    _insert_alert_event_rows(connection, _keep_inserted(base_list + correlated_list, inserted_ids))
    _insert_alert_link_rows(connection, _keep_inserted(correlated_list, inserted_ids))

    newly_added_base_ids = []
    for alert_id in auto_added_ids:
        if alert_id in inserted_ids:
            newly_added_base_ids.append(alert_id)
    return {
        "alerts_inserted": len(inserted_ids),
        "alerts_skipped_duplicate": len(collected) - len(inserted_ids),
        "events_inserted": events_inserted,
        "events_skipped_duplicate": len(events_to_write) - events_inserted,
        "base_alerts_added_automatically": newly_added_base_ids,
    }


def save_alerts(db_path: str, alerts: list, events: list, available_alerts: list | None = None) -> dict:
    """
    Purpose: save chosen alerts, the base alerts they depend on, and ONLY the
        events those alerts reference - all or nothing (FS.5, R1.2).
    Inputs:
        db_path (str) - the database file.
        alerts (list of dict) - the alerts the user chose to save.
        events (list of dict) - ALL events of the session; storage picks out
            only the ones the alerts reference.
        available_alerts (list of dict or None) - ALL alerts of the session,
            used only to find base alerts the user did not select.
    Output: dict with alerts_inserted (int, includes base alerts added
        automatically), alerts_skipped_duplicate (int), events_inserted (int),
        events_skipped_duplicate (int) and base_alerts_added_automatically
        (list of alert IDs that were really added to the database this time).
    Steps:
        1. Open a connection and start ONE transaction (BEGIN IMMEDIATE).
        2. Validate the chosen alerts with validate_alert.
        3. For each correlated alert find every linked base alert: chosen
           list, then session list (add it), then the database; otherwise
           raise BrokenReferenceError. A linked alert must be a base alert.
        4. Check every event ID is in the session events or the database.
        5. INSERT OR IGNORE in this order: events, base alerts, correlated
           alerts, alert_events, alert_links.
        6. COMMIT. On ANY error ROLLBACK, so nothing partial is left.
    Example: saving only a correlated alert with its two base alerts in
        available_alerts -> alerts_inserted 3, base_alerts_added_automatically
        lists the two base alert IDs. Saving it again -> alerts_inserted 0,
        alerts_skipped_duplicate 3.
    Errors: BrokenReferenceError (missing base alert, base alert that is not
        a base alert, or missing event; nothing is written); DatabaseError
        (invalid alert or event, bad arguments, or SQLite failure; rolled back).
    """
    _check_save_arguments(alerts, events, available_alerts)
    connection = get_connection(db_path)
    try:
        # A transaction groups several writes so they all happen or none do.
        # BEGIN IMMEDIATE takes the write lock now, so nobody can change the
        # data between our checks and our inserts.
        connection.execute("BEGIN IMMEDIATE")
        result = _save_inside_transaction(connection, alerts, events, available_alerts)
        connection.execute("COMMIT")
        return result
    except Exception as error:
        # Any failure, even one we did not expect, undoes every write above.
        _rollback_and_reraise(connection, error, "Could not save alerts")
    finally:
        connection.close()


# ---------------------------------------------------------------
# Reading alerts and events back (E.8)
# ---------------------------------------------------------------

def _event_from_row(row):
    """Turn one events row into an event dictionary with the 15 contract keys."""
    event = {}
    for key in EVENT_KEYS:
        if key == "timestamp":
            event[key] = iso_to_datetime(row["timestamp"])
        elif key == "raw_event":
            event[key] = json.loads(row["raw_event_json"])
        else:
            event[key] = row[key]
    return event


def _read_event_ids_of_alert(connection, alert_id):
    """The event IDs of an alert in their stored (time) order."""
    sql = "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY position"
    event_ids = []
    for row in connection.execute(sql, (alert_id,)):
        event_ids.append(row["event_id"])
    return event_ids


def _alert_from_row(connection, row):
    """Turn one alerts row into an alert dictionary with the 13 contract keys."""
    alert = {}
    for key in ALERT_KEYS:
        if key in ("detected_at", "time_start", "time_end"):
            alert[key] = iso_to_datetime(row[key])
        elif key == "evidence":
            alert[key] = json.loads(row["evidence_json"])
        elif key == "event_ids":
            alert[key] = _read_event_ids_of_alert(connection, row["alert_id"])
        else:
            alert[key] = row[key]
    return alert


def _build_alert_filter(filters):
    """
    Turn the filters dictionary into (WHERE text, list of values).
    Only column names from our own whitelist ever enter the SQL text; every
    value the caller supplied goes into the values list for ? placeholders.
    """
    if filters is None:
        return "", []
    if not isinstance(filters, dict):
        raise DatabaseError("filters must be a dictionary or None")
    allowed_keys = _ALERT_FILTER_COLUMNS + ["incident_id"]
    for key in filters:
        if key not in allowed_keys:
            raise DatabaseError("Unknown alert filter: " + str(key))
    conditions = []
    values = []
    for column in _ALERT_FILTER_COLUMNS:
        if filters.get(column) is not None:
            conditions.append(column + " = ?")
            values.append(filters[column])
    if filters.get("incident_id") is not None:
        conditions.append("alert_id IN (SELECT alert_id FROM incident_alerts WHERE incident_id = ?)")
        values.append(filters["incident_id"])
    if len(conditions) == 0:
        return "", []
    return " WHERE " + " AND ".join(conditions), values


def get_alerts(db_path: str, filters: dict | None = None) -> list:
    """
    Purpose: read saved alerts, newest time_start first.
    Inputs: db_path (str); filters (dict or None) - optional keys severity,
        confidence, rule_id, source_ip, incident_id. A key with value None is ignored.
    Output: list of alert dictionaries (the 13 contract keys; timestamps are
        datetime; evidence is a dictionary; event_ids in stored order).
    Steps:
        1. Build the WHERE text from the whitelist of filter names.
        2. Run one SELECT with ? placeholders, ORDER BY time_start DESC.
        3. Convert each row back into an alert dictionary.
    Example: get_alerts(path, {"severity": "high"}) -> only high alerts.
    Errors: DatabaseError for an unknown filter key or a SQLite failure.
    """
    where_text, values = _build_alert_filter(filters)
    sql = "SELECT * FROM alerts" + where_text + " ORDER BY time_start DESC, alert_id ASC"
    connection = get_connection(db_path)
    try:
        alerts = []
        for row in connection.execute(sql, values).fetchall():
            alerts.append(_alert_from_row(connection, row))
        return alerts
    except (sqlite3.Error, ValueError) as error:
        raise DatabaseError("Could not read alerts: " + str(error)) from error
    finally:
        connection.close()


def get_alert(db_path: str, alert_id: str) -> dict | None:
    """
    Purpose: read one saved alert.
    Inputs: db_path (str); alert_id (str) - for example "ALT-0123456789abcdef".
    Output: the alert dictionary, or None if no alert has that ID.
    Steps:
        1. SELECT the row with a ? placeholder.
        2. If there is none return None, otherwise convert it.
    Example: get_alert(path, saved_alert["alert_id"]) == saved_alert -> True.
    Errors: DatabaseError on a SQLite failure or damaged stored data.
    """
    connection = get_connection(db_path)
    try:
        row = connection.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if row is None:
            return None
        return _alert_from_row(connection, row)
    except (sqlite3.Error, ValueError) as error:
        raise DatabaseError("Could not read the alert: " + str(error)) from error
    finally:
        connection.close()


def get_events_for_alert(db_path: str, alert_id: str) -> list:
    """
    Purpose: read the stored events an alert references (all of them, no cap).
    Inputs: db_path (str); alert_id (str).
    Output: list of event dictionaries (15 contract keys, timestamp as
        datetime, raw_event as dictionary), oldest first. Empty list if the
        alert is unknown.
    Steps:
        1. JOIN alert_events to events using the alert ID (? placeholder).
        2. ORDER BY timestamp, source_file, source_row.
        3. Convert each row.
    Example: len(get_events_for_alert(path, alert["alert_id"])) == len(alert["event_ids"]).
    Errors: DatabaseError on a SQLite failure or damaged stored data.
    """
    sql = (
        "SELECT events.* FROM alert_events "
        "JOIN events ON events.event_id = alert_events.event_id "
        "WHERE alert_events.alert_id = ? "
        "ORDER BY events.timestamp, events.source_file, events.source_row"
    )
    connection = get_connection(db_path)
    try:
        events = []
        for row in connection.execute(sql, (alert_id,)).fetchall():
            events.append(_event_from_row(row))
        return events
    except (sqlite3.Error, ValueError) as error:
        raise DatabaseError("Could not read the events: " + str(error)) from error
    finally:
        connection.close()


def get_existing_alert_ids(db_path: str, alert_ids: list) -> list:
    """
    Purpose: tell the dashboard which of its session alerts are already saved.
    Inputs: db_path (str); alert_ids (list of str).
    Output: list of str - the given IDs that are stored, in the order given,
        each once.
    Steps:
        1. Ask SQLite which of the IDs exist (in chunks, with ? placeholders).
        2. Walk the caller's list and keep the ones found.
    Example: get_existing_alert_ids(path, ["ALT-aaa...", "ALT-bbb..."]) -> ["ALT-aaa..."].
    Errors: DatabaseError if alert_ids is not a list or SQLite fails.
    """
    if not isinstance(alert_ids, list):
        raise DatabaseError("alert_ids must be a list")
    connection = get_connection(db_path)
    try:
        found_ids = _find_stored_alert_ids(connection, alert_ids)
    except sqlite3.Error as error:
        raise DatabaseError("Could not look up alert IDs: " + str(error)) from error
    finally:
        connection.close()
    existing_ids = []
    for alert_id in alert_ids:
        if alert_id in found_ids and alert_id not in existing_ids:
            existing_ids.append(alert_id)
    return existing_ids


def _count_incidents_by_status(connection):
    """Incident counts per status. Every allowed status appears, 0 if none."""
    counts = {}
    for status in INCIDENT_STATUSES:
        counts[status] = 0
    for row in connection.execute("SELECT status AS name, COUNT(*) AS total FROM incidents GROUP BY status"):
        counts[row["name"]] = row["total"]
    return counts


def _count_alerts_by_severity(connection):
    """Alert counts per severity. Every allowed severity appears, 0 if none."""
    counts = {}
    for severity in SEVERITIES:
        counts[severity] = 0
    for row in connection.execute("SELECT severity AS name, COUNT(*) AS total FROM alerts GROUP BY severity"):
        counts[row["name"]] = row["total"]
    return counts


def get_summary_counts(db_path: str) -> dict:
    """
    Purpose: small totals for the Overview page ("Saved in database").
    Inputs: db_path (str).
    Output: dict with alerts_total (int), incidents_total (int),
        incidents_by_status (dict: all four statuses), alerts_by_severity
        (dict: all four severities). Missing groups are 0.
    Steps:
        1. COUNT the alerts and incidents.
        2. GROUP BY status and by severity.
    Example: empty database -> alerts_total 0, incidents_by_status {"open": 0, ...}.
    Errors: DatabaseError on a SQLite failure.
    """
    connection = get_connection(db_path)
    try:
        alerts_total = connection.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()["total"]
        incidents_total = connection.execute("SELECT COUNT(*) AS total FROM incidents").fetchone()["total"]
        by_status = _count_incidents_by_status(connection)
        by_severity = _count_alerts_by_severity(connection)
    except sqlite3.Error as error:
        raise DatabaseError("Could not count saved data: " + str(error)) from error
    finally:
        connection.close()
    return {
        "alerts_total": alerts_total,
        "incidents_total": incidents_total,
        "incidents_by_status": by_status,
        "alerts_by_severity": by_severity,
    }
