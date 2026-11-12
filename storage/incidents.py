# storage/incidents.py
# ---------------------------------------------------------------
# Purpose: incidents, notes and history in SQLite (FS.3.6, C.3, R2.5).
# create_incident / add_alerts_to_incident: group saved alerts (base alerts of
#   a correlated alert are linked automatically).
# update_incident_status / add_note: change an incident; each writes history.
# get_incident / list_incidents / get_incident_details: read incidents back.
# There are NO delete functions (decision D8). The author is "analyst" (D7).
# Uses: core and storage/database.py (get_connection, get_alert, get_events_for_alert).

import sqlite3

from core.contracts import (
    ALLOWED_STATUS_TRANSITIONS,
    INCIDENT_STATUSES,
    SEVERITIES,
    datetime_to_iso,
    iso_to_datetime,
    severity_rank,
    utc_now,
)
from core.errors import BrokenReferenceError, DatabaseError, IncidentNotFound, InvalidStatusTransition
from storage.database import get_alert, get_connection, get_events_for_alert

_MAX_TITLE_LENGTH = 120
_MAX_SUMMARY_LENGTH = 2000
_MAX_NOTE_LENGTH = 2000
_MAX_PERSON_LENGTH = 100  # author / changed_by / created_by
_CLOSED_STATUSES = ["resolved", "false_positive"]


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
    IncidentNotFound or BrokenReferenceError) is raised again unchanged.
    """
    try:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
    except sqlite3.Error:
        pass  # the original error matters more than a failed rollback
    if isinstance(error, sqlite3.Error):
        raise DatabaseError(message + ": " + str(error)) from error
    raise error


def _is_incident_id(value):
    """True for a real whole number above zero (a bool is not accepted)."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _clean_text(value, name, max_length):
    """
    Check a text argument is real text of 1 to max_length characters after
    trimming spaces. Returns the trimmed text. Raises ValueError otherwise.
    """
    if not isinstance(value, str):
        raise ValueError(name + " must be text")
    trimmed = value.strip()
    if trimmed == "":
        raise ValueError(name + " must not be empty")
    if len(trimmed) > max_length:
        raise ValueError(name + " must be at most " + str(max_length) + " characters")
    return trimmed


def _clean_alert_id_list(alert_ids):
    """Check alert_ids is a list of non-empty text; return it without duplicates."""
    if not isinstance(alert_ids, list):
        raise ValueError("alert_ids must be a list")
    unique_ids = []
    for alert_id in alert_ids:
        if not isinstance(alert_id, str) or alert_id == "":
            raise ValueError("alert_ids must contain only non-empty text")
        if alert_id not in unique_ids:
            unique_ids.append(alert_id)
    return unique_ids


def _read_alert_info(connection, alert_id):
    """Return (rule_id, severity) of a stored alert, or raise BrokenReferenceError."""
    row = connection.execute(
        "SELECT rule_id, severity FROM alerts WHERE alert_id = ?", (alert_id,)
    ).fetchone()
    if row is None:
        raise BrokenReferenceError("Alert " + alert_id + " is not saved in the database")
    return row["rule_id"], row["severity"]


def _expand_alert_ids(connection, alert_ids):
    """
    R2.5: check every given alert exists, then add the base alerts of any
    correlated alert (read from alert_links). Returns the full list of IDs,
    given alerts first, no duplicates.
    """
    full_ids = list(alert_ids)
    for alert_id in alert_ids:
        rule_id, severity = _read_alert_info(connection, alert_id)
        if rule_id.startswith("CORR_"):
            sql = "SELECT linked_alert_id FROM alert_links WHERE alert_id = ? ORDER BY linked_alert_id"
            for row in connection.execute(sql, (alert_id,)).fetchall():
                if row["linked_alert_id"] not in full_ids:
                    full_ids.append(row["linked_alert_id"])
    return full_ids


def _highest_severity(connection, alert_ids):
    """The highest severity among the stored alerts with these IDs."""
    best_severity = SEVERITIES[0]
    for alert_id in alert_ids:
        rule_id, severity = _read_alert_info(connection, alert_id)
        if severity_rank(severity) > severity_rank(best_severity):
            best_severity = severity
    return best_severity


def _insert_history(connection, incident_id, action, old_value, new_value, changed_by, changed_at_text):
    """Write one incident_history row."""
    sql = (
        "INSERT INTO incident_history (incident_id, action, old_value, new_value, changed_by, changed_at) "
        "VALUES (?, ?, ?, ?, ?, ?)"
    )
    connection.execute(sql, (incident_id, action, old_value, new_value, changed_by, changed_at_text))


def _require_incident(connection, incident_id):
    """Return the incidents row, or raise IncidentNotFound."""
    if not _is_incident_id(incident_id):
        raise IncidentNotFound("No incident with ID " + repr(incident_id))
    row = connection.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if row is None:
        raise IncidentNotFound("No incident with ID " + str(incident_id))
    return row


def _touch_incident(connection, incident_id, now_text):
    """Set updated_at (used by every change except the first creation)."""
    connection.execute("UPDATE incidents SET updated_at = ? WHERE incident_id = ?", (now_text, incident_id))


def _read_alert_ids_of_incident(connection, incident_id):
    """Alert IDs linked to an incident, in the order they were linked."""
    sql = "SELECT alert_id FROM incident_alerts WHERE incident_id = ? ORDER BY added_at, rowid"
    alert_ids = []
    for row in connection.execute(sql, (incident_id,)).fetchall():
        alert_ids.append(row["alert_id"])
    return alert_ids


def _incident_from_row(connection, row):
    """Turn an incidents row into the incident dictionary of C.3."""
    closed_at = None
    if row["closed_at"] is not None:
        closed_at = iso_to_datetime(row["closed_at"])
    return {
        "incident_id": row["incident_id"],
        "title": row["title"],
        "summary": row["summary"],
        "status": row["status"],
        "priority": row["priority"],
        "created_at": iso_to_datetime(row["created_at"]),
        "updated_at": iso_to_datetime(row["updated_at"]),
        "closed_at": closed_at,
        "alert_ids": _read_alert_ids_of_incident(connection, row["incident_id"]),
    }


# ---------------------------------------------------------------
# Creating incidents and linking alerts
# ---------------------------------------------------------------

def _check_create_arguments(title, alert_ids, summary, priority, created_by):
    """Validate create_incident's arguments. Returns (title, unique alert IDs, summary, created_by)."""
    clean_title = _clean_text(title, "title", _MAX_TITLE_LENGTH)
    if not isinstance(summary, str):
        raise ValueError("summary must be text")
    if len(summary) > _MAX_SUMMARY_LENGTH:
        raise ValueError("summary must be at most " + str(_MAX_SUMMARY_LENGTH) + " characters")
    if priority is not None and priority not in SEVERITIES:
        raise ValueError("priority must be None or one of " + ", ".join(SEVERITIES))
    unique_ids = _clean_alert_id_list(alert_ids)
    if len(unique_ids) == 0 and priority is None:
        raise ValueError("an incident with no alerts needs an explicit priority")
    clean_author = _clean_text(created_by, "created_by", _MAX_PERSON_LENGTH)
    return clean_title, unique_ids, summary, clean_author


def _link_alerts(connection, incident_id, alert_ids, added_at_text):
    """Write one incident_alerts row for each alert ID."""
    sql = "INSERT INTO incident_alerts (incident_id, alert_id, added_at) VALUES (?, ?, ?)"
    for alert_id in alert_ids:
        connection.execute(sql, (incident_id, alert_id, added_at_text))


def create_incident(db_path: str, title: str, alert_ids: list, summary: str = "",
                    priority: str | None = None, created_by: str = "analyst") -> int:
    """
    Purpose: create an incident (status open), link its alerts, write history.
    Inputs:
        db_path (str); title (str, 1 to 120 characters); alert_ids (list of
        str) - saved alerts to link; summary (str, up to 2000 characters, may
        be empty); priority (str or None) - one of low/medium/high/critical,
        None means the highest severity of all linked alerts; created_by (str).
    Output: int - the new incident_id (show it with format_incident_id).
    Steps:
        1. Validate the arguments (ValueError if bad).
        2. In ONE transaction: check every alert exists (R2.5).
        3. Add the base alerts of every correlated alert (from alert_links).
        4. Work out the priority from the full set when it was not given.
        5. Insert the incident, one incident_alerts row per alert, and ONE
           history row: action created, new_value "N alerts". No alert_added
           rows are written at creation.
    Example: create_incident(path, "Scan then login", [corr_id]) with a
        correlated alert that has two base alerts -> 3 alerts linked,
        history says "3 alerts", priority from all three.
    Errors: ValueError (bad title, summary, priority, author or alert_ids);
        BrokenReferenceError (an alert is not saved); DatabaseError (SQLite).
    """
    clean_title, unique_ids, clean_summary, clean_author = _check_create_arguments(
        title, alert_ids, summary, priority, created_by
    )
    connection = get_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")  # one transaction: all of it or none of it
        full_ids = _expand_alert_ids(connection, unique_ids)
        if priority is None:
            priority = _highest_severity(connection, full_ids)
        now_text = _now_text()
        sql = (
            "INSERT INTO incidents (title, summary, status, priority, created_at, updated_at, closed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL)"
        )
        cursor = connection.execute(sql, (clean_title, clean_summary, "open", priority, now_text, now_text))
        incident_id = cursor.lastrowid
        _link_alerts(connection, incident_id, full_ids, now_text)
        _insert_history(connection, incident_id, "created", None, str(len(full_ids)) + " alerts",
                        clean_author, now_text)
        connection.execute("COMMIT")
        return incident_id
    except Exception as error:
        _rollback_and_reraise(connection, error, "Could not create the incident")
    finally:
        connection.close()


def add_alerts_to_incident(db_path: str, incident_id: int, alert_ids: list, changed_by: str = "analyst") -> int:
    """
    Purpose: link more saved alerts to an existing incident (R2.5).
    Inputs: db_path (str); incident_id (int); alert_ids (list of str);
        changed_by (str).
    Output: int - how many alerts were newly linked, INCLUDING base alerts
        that were added automatically. Alerts already linked are skipped.
    Steps:
        1. Validate the arguments.
        2. In one transaction: find the incident, check every alert exists,
           add the base alerts of correlated alerts.
        3. For each alert not yet linked insert an incident_alerts row and an
           alert_added history row (new_value = the alert ID).
        4. If anything was added, set updated_at. The priority never changes.
    Example: adding the same alert twice -> first call returns 1, second returns 0.
    Errors: ValueError (bad alert_ids or changed_by); IncidentNotFound;
        BrokenReferenceError (an alert is not saved); DatabaseError (SQLite).
    """
    unique_ids = _clean_alert_id_list(alert_ids)
    clean_author = _clean_text(changed_by, "changed_by", _MAX_PERSON_LENGTH)
    connection = get_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_incident(connection, incident_id)
        already_linked = _read_alert_ids_of_incident(connection, incident_id)
        full_ids = _expand_alert_ids(connection, unique_ids)
        now_text = _now_text()
        added_count = 0
        for alert_id in full_ids:
            if alert_id in already_linked:
                continue
            _link_alerts(connection, incident_id, [alert_id], now_text)
            _insert_history(connection, incident_id, "alert_added", None, alert_id, clean_author, now_text)
            added_count = added_count + 1
        if added_count > 0:
            _touch_incident(connection, incident_id, now_text)
        connection.execute("COMMIT")
        return added_count
    except Exception as error:
        _rollback_and_reraise(connection, error, "Could not add alerts to the incident")
    finally:
        connection.close()


# ---------------------------------------------------------------
# Status and notes
# ---------------------------------------------------------------

def update_incident_status(db_path: str, incident_id: int, new_status: str, changed_by: str = "analyst") -> None:
    """
    Purpose: move an incident to a new status using the allowed transitions (C.3).
    Inputs: db_path (str); incident_id (int); new_status (str); changed_by (str).
    Output: None.
    Steps:
        1. In one transaction read the incident (IncidentNotFound if missing).
        2. Check new_status is in ALLOWED_STATUS_TRANSITIONS[current status].
        3. Set status and updated_at. closed_at is set when the new status is
           resolved or false_positive, and cleared when the incident is reopened.
        4. Write a status_changed history row (old and new status).
    Example: open -> investigating is allowed; resolved -> open raises
        InvalidStatusTransition; open -> open also raises it.
    Errors: IncidentNotFound; InvalidStatusTransition (including an unknown
        status); ValueError (bad changed_by); DatabaseError (SQLite).
    """
    clean_author = _clean_text(changed_by, "changed_by", _MAX_PERSON_LENGTH)
    connection = get_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = _require_incident(connection, incident_id)
        old_status = row["status"]
        if new_status not in ALLOWED_STATUS_TRANSITIONS[old_status]:
            raise InvalidStatusTransition(
                "An incident cannot change from " + old_status + " to " + str(new_status)
            )
        now_text = _now_text()
        closed_at_text = None
        if new_status in _CLOSED_STATUSES:
            closed_at_text = now_text
        sql = "UPDATE incidents SET status = ?, updated_at = ?, closed_at = ? WHERE incident_id = ?"
        connection.execute(sql, (new_status, now_text, closed_at_text, incident_id))
        _insert_history(connection, incident_id, "status_changed", old_status, new_status, clean_author, now_text)
        connection.execute("COMMIT")
    except Exception as error:
        _rollback_and_reraise(connection, error, "Could not change the incident status")
    finally:
        connection.close()


def add_note(db_path: str, incident_id: int, text: str, author: str = "analyst") -> int:
    """
    Purpose: add a note to an incident.
    Inputs: db_path (str); incident_id (int); text (str, 1 to 2000 characters
        after trimming); author (str, default analyst).
    Output: int - the new note_id.
    Steps:
        1. Validate the text and author (ValueError if bad).
        2. In one transaction read the incident (IncidentNotFound if missing).
        3. Insert the note, set updated_at, and write a note_added history
           row whose new_value is the note ID as text.
    Example: add_note(path, 1, "Checked firewall logs") -> 1 (the first note).
    Errors: ValueError; IncidentNotFound; DatabaseError (SQLite).
    """
    clean_note = _clean_text(text, "text", _MAX_NOTE_LENGTH)
    clean_author = _clean_text(author, "author", _MAX_PERSON_LENGTH)
    connection = get_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_incident(connection, incident_id)
        now_text = _now_text()
        sql = "INSERT INTO incident_notes (incident_id, author, text, created_at) VALUES (?, ?, ?, ?)"
        cursor = connection.execute(sql, (incident_id, clean_author, clean_note, now_text))
        note_id = cursor.lastrowid
        _touch_incident(connection, incident_id, now_text)
        _insert_history(connection, incident_id, "note_added", None, str(note_id), clean_author, now_text)
        connection.execute("COMMIT")
        return note_id
    except Exception as error:
        _rollback_and_reraise(connection, error, "Could not add the note")
    finally:
        connection.close()


# ---------------------------------------------------------------
# Reading incidents
# ---------------------------------------------------------------

def get_incident(db_path: str, incident_id: int) -> dict | None:
    """
    Purpose: read one incident.
    Inputs: db_path (str); incident_id (int).
    Output: the incident dictionary (incident_id, title, summary, status,
        priority, created_at, updated_at, closed_at, alert_ids) or None.
    Steps:
        1. SELECT the row with a ? placeholder (None if the ID is not a
           whole number above zero, or no row exists).
        2. Convert times to datetime and read the linked alert IDs.
    Example: get_incident(path, 1)["status"] -> "open".
    Errors: DatabaseError on a SQLite failure or damaged stored data.
    """
    if not _is_incident_id(incident_id):
        return None
    connection = get_connection(db_path)
    try:
        row = connection.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if row is None:
            return None
        return _incident_from_row(connection, row)
    except (sqlite3.Error, ValueError) as error:
        raise DatabaseError("Could not read the incident: " + str(error)) from error
    finally:
        connection.close()


def list_incidents(db_path: str, status: str | None = None) -> list:
    """
    Purpose: list incidents, most recently updated first.
    Inputs: db_path (str); status (str or None) - only incidents with this status.
    Output: list of incident dictionaries (same shape as get_incident).
    Steps:
        1. Refuse an unknown status.
        2. SELECT with ORDER BY updated_at DESC (? placeholder for the status).
        3. Convert each row.
    Example: list_incidents(path, "open") -> only open incidents.
    Errors: DatabaseError for an unknown status or a SQLite failure.
    """
    if status is not None and status not in INCIDENT_STATUSES:
        raise DatabaseError("Unknown incident status: " + str(status))
    connection = get_connection(db_path)
    try:
        if status is None:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY updated_at DESC, incident_id DESC"
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM incidents WHERE status = ? ORDER BY updated_at DESC, incident_id DESC",
                (status,),
            ).fetchall()
        incidents = []
        for row in rows:
            incidents.append(_incident_from_row(connection, row))
        return incidents
    except (sqlite3.Error, ValueError) as error:
        raise DatabaseError("Could not list incidents: " + str(error)) from error
    finally:
        connection.close()


def _read_notes(connection, incident_id):
    """Notes of an incident, oldest first, as dictionaries (C.3)."""
    sql = "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at, note_id"
    notes = []
    for row in connection.execute(sql, (incident_id,)).fetchall():
        notes.append({
            "note_id": row["note_id"],
            "incident_id": row["incident_id"],
            "author": row["author"],
            "text": row["text"],
            "created_at": iso_to_datetime(row["created_at"]),
        })
    return notes


def _read_history(connection, incident_id):
    """History rows of an incident, oldest first, as dictionaries (C.3)."""
    sql = "SELECT * FROM incident_history WHERE incident_id = ? ORDER BY changed_at, history_id"
    history = []
    for row in connection.execute(sql, (incident_id,)).fetchall():
        history.append({
            "history_id": row["history_id"],
            "incident_id": row["incident_id"],
            "action": row["action"],
            "old_value": row["old_value"],
            "new_value": row["new_value"],
            "changed_by": row["changed_by"],
            "changed_at": iso_to_datetime(row["changed_at"]),
        })
    return history


def _combine_events(db_path, alerts):
    """The events of all these alerts, each once, oldest first."""
    events_by_id = {}
    for alert in alerts:
        for event in get_events_for_alert(db_path, alert["alert_id"]):
            events_by_id[event["event_id"]] = event
    events = list(events_by_id.values())
    events.sort(key=_event_sort_key)
    return events


def _event_sort_key(event):
    """Sort order for events: time, then file name, then row number."""
    return (event["timestamp"], event["source_file"], event["source_row"])


def get_incident_details(db_path: str, incident_id: int) -> dict:
    """
    Purpose: the full bundle the dashboard and the PDF report need (C.3).
    Inputs: db_path (str); incident_id (int).
    Output: dict - the incident dictionary plus four keys: alerts (list of
        alert dictionaries, base alerts included), events (the stored events
        of those alerts, no duplicates, oldest first), notes (oldest first)
        and history (oldest first).
    Steps:
        1. Read the incident (IncidentNotFound if missing).
        2. Read each linked alert with get_alert.
        3. Combine their stored events without duplicates.
        4. Read the notes and the history.
    Example: details["alerts"][0]["alert_id"] in details["alert_ids"] -> True.
    Errors: IncidentNotFound; DatabaseError (SQLite failure, damaged data).
    """
    incident = get_incident(db_path, incident_id)
    if incident is None:
        raise IncidentNotFound("No incident with ID " + repr(incident_id))
    alerts = []
    for alert_id in incident["alert_ids"]:
        alert = get_alert(db_path, alert_id)
        if alert is not None:
            alerts.append(alert)
    connection = get_connection(db_path)
    try:
        notes = _read_notes(connection, incident_id)
        history = _read_history(connection, incident_id)
    except (sqlite3.Error, ValueError) as error:
        raise DatabaseError("Could not read the incident details: " + str(error)) from error
    finally:
        connection.close()
    details = dict(incident)
    details["alerts"] = alerts
    details["events"] = _combine_events(db_path, alerts)
    details["notes"] = notes
    details["history"] = history
    return details
