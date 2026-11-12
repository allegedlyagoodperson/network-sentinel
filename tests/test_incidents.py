# tests/test_incidents.py
# ---------------------------------------------------------------
# Purpose: tests for storage/incidents.py (Stage 1C): creating incidents, status
# transitions, notes, history, linking alerts (including base alerts of correlated
# alerts, R2.5), missing references, and persistence of every change.
# Run from the project folder with: python -m pytest tests/test_incidents.py -v
# Every test uses a temporary database (tmp_path), never data/network_sentinel.db.
# Uses: storage, core, pytest, and tests/fixtures/storage_reporting_fixtures.py.

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

import storage_reporting_fixtures as fx  # noqa: E402
from core.contracts import ALLOWED_STATUS_TRANSITIONS, INCIDENT_STATUSES  # noqa: E402
from core.errors import BrokenReferenceError, DatabaseError, IncidentNotFound, InvalidStatusTransition  # noqa: E402
from storage import database, incidents  # noqa: E402
from storage.database import get_alerts, initialise_database, save_alerts  # noqa: E402
from storage.incidents import (  # noqa: E402
    add_alerts_to_incident,
    add_note,
    create_incident,
    get_incident,
    get_incident_details,
    list_incidents,
    update_incident_status,
)


@pytest.fixture
def db_path(tmp_path):
    """A fresh, initialised temporary database."""
    path = str(tmp_path / "incidents.db")
    initialise_database(path)
    return path


@pytest.fixture
def saved(db_path):
    """A database that already holds the three scenario alerts. Returns (path, scenario)."""
    scenario = fx.make_scenario(auth_severity="medium", network_severity="critical", correlated_severity="high")
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    save_alerts(db_path, session_alerts, scenario["events"], session_alerts)
    return db_path, scenario


def query(path, sql, values=()):
    """Run a SELECT with a plain sqlite3 connection (test helper)."""
    connection = sqlite3.connect(path)
    try:
        return connection.execute(sql, values).fetchall()
    finally:
        connection.close()


def history_actions(path, incident_id):
    rows = query(path, "SELECT action FROM incident_history WHERE incident_id = ? ORDER BY history_id",
                 (incident_id,))
    return [row[0] for row in rows]


# ---------------------------------------------------------------
# Creating and reading incidents
# ---------------------------------------------------------------

def test_create_incident_returns_an_id_and_stores_the_c3_fields(saved):
    path, scenario = saved
    alert_id = scenario["auth_alert"]["alert_id"]
    incident_id = create_incident(path, "Login attempts", [alert_id], summary="First look")
    assert incident_id == 1
    incident = get_incident(path, incident_id)
    assert list(incident.keys()) == ["incident_id", "title", "summary", "status", "priority", "created_at",
                                     "updated_at", "closed_at", "alert_ids"]
    assert incident["title"] == "Login attempts"
    assert incident["summary"] == "First look"
    assert incident["status"] == "open"
    assert incident["priority"] == "medium"
    assert incident["created_at"] == incident["updated_at"]
    assert incident["created_at"].tzinfo is not None
    assert incident["closed_at"] is None
    assert incident["alert_ids"] == [alert_id]


def test_incident_ids_count_upwards(saved):
    path, scenario = saved
    alert_id = scenario["auth_alert"]["alert_id"]
    assert create_incident(path, "One", [alert_id]) == 1
    assert create_incident(path, "Two", [alert_id]) == 2


def test_priority_defaults_to_the_highest_severity_and_can_be_overridden(saved):
    path, scenario = saved
    both = [scenario["auth_alert"]["alert_id"], scenario["network_alert"]["alert_id"]]
    assert get_incident(path, create_incident(path, "Auto", both))["priority"] == "critical"
    assert get_incident(path, create_incident(path, "Manual", both, priority="low"))["priority"] == "low"


def test_creation_writes_exactly_one_history_row(saved):
    path, scenario = saved
    incident_id = create_incident(path, "Login attempts", [scenario["auth_alert"]["alert_id"]])
    assert history_actions(path, incident_id) == ["created"]
    row = query(path, "SELECT old_value, new_value, changed_by FROM incident_history")[0]
    assert row == (None, "1 alerts", "analyst")


def test_a_correlated_alert_brings_its_base_alerts_into_the_incident(saved):
    path, scenario = saved
    incident_id = create_incident(path, "Scan then login", [scenario["correlated_alert"]["alert_id"]])
    incident = get_incident(path, incident_id)
    assert sorted(incident["alert_ids"]) == sorted([
        scenario["correlated_alert"]["alert_id"], scenario["auth_alert"]["alert_id"],
        scenario["network_alert"]["alert_id"]])
    assert incident["alert_ids"][0] == scenario["correlated_alert"]["alert_id"]
    assert incident["priority"] == "critical"  # the critical base alert counts
    assert history_actions(path, incident_id) == ["created"]
    assert query(path, "SELECT new_value FROM incident_history")[0][0] == "3 alerts"


def test_duplicate_alert_ids_are_linked_once(saved):
    path, scenario = saved
    alert_id = scenario["auth_alert"]["alert_id"]
    incident = get_incident(path, create_incident(path, "Dup", [alert_id, alert_id]))
    assert incident["alert_ids"] == [alert_id]


def test_an_incident_without_alerts_needs_an_explicit_priority(db_path):
    with pytest.raises(ValueError):
        create_incident(db_path, "Empty", [])
    incident_id = create_incident(db_path, "Empty but ranked", [], priority="low")
    assert get_incident(db_path, incident_id)["alert_ids"] == []


def test_one_alert_can_belong_to_several_incidents(saved):
    path, scenario = saved
    alert_id = scenario["auth_alert"]["alert_id"]
    create_incident(path, "One", [alert_id])
    create_incident(path, "Two", [alert_id])
    assert len(get_alerts(path, {"incident_id": 1})) == 1
    assert len(get_alerts(path, {"incident_id": 2})) == 1
    assert get_alerts(path, {"incident_id": 99}) == []


def test_missing_alert_is_rejected_and_nothing_is_created(saved):
    path, scenario = saved
    with pytest.raises(BrokenReferenceError):
        create_incident(path, "Broken", [scenario["auth_alert"]["alert_id"], "ALT-0000000000000000"])
    assert query(path, "SELECT COUNT(*) FROM incidents")[0][0] == 0
    assert query(path, "SELECT COUNT(*) FROM incident_alerts")[0][0] == 0
    assert query(path, "SELECT COUNT(*) FROM incident_history")[0][0] == 0


def test_an_unsaved_session_alert_cannot_be_put_in_an_incident(db_path):
    scenario = fx.make_scenario()  # never saved
    with pytest.raises(BrokenReferenceError):
        create_incident(db_path, "Unsaved", [scenario["auth_alert"]["alert_id"]])


@pytest.mark.parametrize("title", ["", "   ", None, 5, "x" * 121])
def test_bad_titles_raise_value_error(saved, title):
    path, scenario = saved
    with pytest.raises(ValueError):
        create_incident(path, title, [scenario["auth_alert"]["alert_id"]])


def test_title_of_exactly_120_characters_is_accepted(saved):
    path, scenario = saved
    incident_id = create_incident(path, "x" * 120, [scenario["auth_alert"]["alert_id"]])
    assert len(get_incident(path, incident_id)["title"]) == 120


@pytest.mark.parametrize("keyword, value", [
    ("summary", "s" * 2001), ("summary", 5), ("priority", "urgent"), ("priority", 3),
    ("created_by", ""), ("created_by", None),
])
def test_other_bad_arguments_raise_value_error(saved, keyword, value):
    path, scenario = saved
    arguments = {keyword: value}
    with pytest.raises(ValueError):
        create_incident(path, "Title", [scenario["auth_alert"]["alert_id"]], **arguments)


@pytest.mark.parametrize("bad_ids", ["ALT-1", [5], [""], None])
def test_bad_alert_id_lists_raise_value_error(saved, bad_ids):
    path, scenario = saved
    with pytest.raises(ValueError):
        create_incident(path, "Title", bad_ids)


def test_get_incident_returns_none_for_unknown_or_malformed_ids(saved):
    path, scenario = saved
    create_incident(path, "One", [scenario["auth_alert"]["alert_id"]])
    for bad_id in [999, 0, -1, "1", None, True, 1.0]:
        assert get_incident(path, bad_id) is None


def test_list_incidents_filters_by_status_and_shows_recently_updated_first(saved):
    path, scenario = saved
    alert_id = scenario["auth_alert"]["alert_id"]
    first = create_incident(path, "First", [alert_id])
    second = create_incident(path, "Second", [alert_id])
    add_note(path, first, "Touched later")  # first is now the most recently updated
    assert [i["incident_id"] for i in list_incidents(path)] == [first, second]
    update_incident_status(path, second, "investigating")
    assert [i["incident_id"] for i in list_incidents(path, "investigating")] == [second]
    assert [i["incident_id"] for i in list_incidents(path, "open")] == [first]
    assert list_incidents(path, "resolved") == []


def test_list_incidents_rejects_an_unknown_status(db_path):
    with pytest.raises(DatabaseError):
        list_incidents(db_path, "banana")


# ---------------------------------------------------------------
# Status changes
# ---------------------------------------------------------------

def put_in_status(path, incident_id, target_status):
    """Move a new (open) incident into target_status using only legal moves."""
    if target_status != "open":
        update_incident_status(path, incident_id, target_status)


ALLOWED_PAIRS = []
FORBIDDEN_PAIRS = []
for _old_status in INCIDENT_STATUSES:
    for _new_status in INCIDENT_STATUSES:
        if _new_status in ALLOWED_STATUS_TRANSITIONS[_old_status]:
            ALLOWED_PAIRS.append((_old_status, _new_status))
        else:
            FORBIDDEN_PAIRS.append((_old_status, _new_status))


@pytest.mark.parametrize("old_status, new_status", ALLOWED_PAIRS)
def test_every_allowed_transition_works_and_is_recorded(saved, old_status, new_status):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    put_in_status(path, incident_id, old_status)
    before = get_incident(path, incident_id)
    update_incident_status(path, incident_id, new_status, changed_by="alice")
    after = get_incident(path, incident_id)
    assert after["status"] == new_status
    assert after["updated_at"] >= before["updated_at"]
    last_history = query(path, "SELECT action, old_value, new_value, changed_by FROM incident_history "
                               "ORDER BY history_id DESC LIMIT 1")[0]
    assert last_history == ("status_changed", old_status, new_status, "alice")


@pytest.mark.parametrize("old_status, new_status", FORBIDDEN_PAIRS)
def test_every_forbidden_transition_is_refused_and_changes_nothing(saved, old_status, new_status):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    put_in_status(path, incident_id, old_status)
    before = get_incident(path, incident_id)
    history_before = history_actions(path, incident_id)
    with pytest.raises(InvalidStatusTransition):
        update_incident_status(path, incident_id, new_status)
    assert get_incident(path, incident_id) == before
    assert history_actions(path, incident_id) == history_before


def test_the_allowed_transition_table_is_the_frozen_one():
    assert ALLOWED_STATUS_TRANSITIONS == {
        "open": ["investigating", "resolved", "false_positive"],
        "investigating": ["open", "resolved", "false_positive"],
        "resolved": ["investigating"],
        "false_positive": ["investigating"],
    }


def test_an_unknown_status_is_an_invalid_transition(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    for bad_status in ["banana", "", None, 5]:
        with pytest.raises(InvalidStatusTransition):
            update_incident_status(path, incident_id, bad_status)


@pytest.mark.parametrize("closing_status", ["resolved", "false_positive"])
def test_closed_at_is_set_when_closing_and_cleared_when_reopened(saved, closing_status):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    assert get_incident(path, incident_id)["closed_at"] is None
    update_incident_status(path, incident_id, closing_status)
    closed = get_incident(path, incident_id)
    assert closed["closed_at"] is not None
    assert closed["closed_at"] == closed["updated_at"]
    update_incident_status(path, incident_id, "investigating")
    assert get_incident(path, incident_id)["closed_at"] is None


def test_status_change_on_a_missing_incident_raises_incident_not_found(db_path):
    for bad_id in [1, 999, 0, "1", None, True]:
        with pytest.raises(IncidentNotFound):
            update_incident_status(db_path, bad_id, "investigating")


def test_bad_changed_by_raises_value_error_and_changes_nothing(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    with pytest.raises(ValueError):
        update_incident_status(path, incident_id, "investigating", changed_by="")
    assert get_incident(path, incident_id)["status"] == "open"


def test_a_failure_while_writing_history_rolls_back_the_status_change(saved, monkeypatch):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])

    def failing_history(*arguments):
        raise sqlite3.OperationalError("injected failure")

    monkeypatch.setattr(incidents, "_insert_history", failing_history)
    with pytest.raises(DatabaseError):
        update_incident_status(path, incident_id, "resolved")
    monkeypatch.undo()
    incident = get_incident(path, incident_id)
    assert incident["status"] == "open"
    assert incident["closed_at"] is None


# ---------------------------------------------------------------
# Notes
# ---------------------------------------------------------------

def test_add_note_stores_the_note_updates_the_incident_and_writes_history(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    before = get_incident(path, incident_id)
    note_id = add_note(path, incident_id, "  Checked the firewall logs  ")
    assert note_id == 1
    details = get_incident_details(path, incident_id)
    assert details["notes"][0]["note_id"] == 1
    assert details["notes"][0]["incident_id"] == incident_id
    assert details["notes"][0]["text"] == "Checked the firewall logs"
    assert details["notes"][0]["author"] == "analyst"
    assert details["notes"][0]["created_at"].tzinfo is not None
    assert details["updated_at"] >= before["updated_at"]
    assert history_actions(path, incident_id) == ["created", "note_added"]
    assert details["history"][1]["new_value"] == "1"


def test_note_length_limits(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    assert add_note(path, incident_id, "n" * 2000) == 1
    for bad_text in ["", "   \n ", None, 7, "n" * 2001]:
        with pytest.raises(ValueError):
            add_note(path, incident_id, bad_text)
    with pytest.raises(ValueError):
        add_note(path, incident_id, "ok", author="")
    assert query(path, "SELECT COUNT(*) FROM incident_notes")[0][0] == 1


def test_add_note_to_a_missing_incident_raises_incident_not_found(db_path):
    with pytest.raises(IncidentNotFound):
        add_note(db_path, 5, "text")
    with pytest.raises(IncidentNotFound):
        add_note(db_path, "1", "text")


def test_notes_come_back_oldest_first(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    for text in ["first", "second", "third"]:
        add_note(path, incident_id, text)
    notes = get_incident_details(path, incident_id)["notes"]
    assert [note["text"] for note in notes] == ["first", "second", "third"]


def test_injection_text_in_incident_fields_is_stored_as_plain_text(saved):
    path, scenario = saved
    evil = "x'); DROP TABLE incidents;--"
    incident_id = create_incident(path, evil, [scenario["auth_alert"]["alert_id"]], summary=evil, created_by=evil)
    add_note(path, incident_id, evil, author=evil)
    update_incident_status(path, incident_id, "investigating", changed_by=evil)
    details = get_incident_details(path, incident_id)
    assert details["title"] == evil
    assert details["summary"] == evil
    assert details["notes"][0]["text"] == evil
    assert details["notes"][0]["author"] == evil
    assert details["history"][-1]["changed_by"] == evil
    assert query(path, "SELECT COUNT(*) FROM incidents")[0][0] == 1


# ---------------------------------------------------------------
# Linking more alerts (R2.5)
# ---------------------------------------------------------------

def test_add_alerts_links_new_alerts_writes_history_and_keeps_priority(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    before = get_incident(path, incident_id)
    added = add_alerts_to_incident(path, incident_id, [scenario["network_alert"]["alert_id"]], changed_by="bob")
    assert added == 1
    after = get_incident(path, incident_id)
    assert after["alert_ids"] == [scenario["auth_alert"]["alert_id"], scenario["network_alert"]["alert_id"]]
    assert after["priority"] == before["priority"] == "medium"  # priority is never recomputed
    assert after["updated_at"] >= before["updated_at"]
    row = query(path, "SELECT action, old_value, new_value, changed_by FROM incident_history "
                      "ORDER BY history_id DESC LIMIT 1")[0]
    assert row == ("alert_added", None, scenario["network_alert"]["alert_id"], "bob")


def test_adding_an_already_linked_alert_changes_nothing(saved):
    path, scenario = saved
    alert_id = scenario["auth_alert"]["alert_id"]
    incident_id = create_incident(path, "T", [alert_id])
    before = get_incident(path, incident_id)
    assert add_alerts_to_incident(path, incident_id, [alert_id]) == 0
    assert get_incident(path, incident_id) == before
    assert history_actions(path, incident_id) == ["created"]


def test_adding_a_correlated_alert_also_adds_missing_base_alerts(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    added = add_alerts_to_incident(path, incident_id, [scenario["correlated_alert"]["alert_id"]])
    assert added == 2  # the correlated alert and the network base alert; the auth alert was linked already
    assert len(get_incident(path, incident_id)["alert_ids"]) == 3
    assert history_actions(path, incident_id) == ["created", "alert_added", "alert_added"]


def test_add_alerts_with_one_missing_alert_adds_none_of_them(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    with pytest.raises(BrokenReferenceError):
        add_alerts_to_incident(path, incident_id, [scenario["network_alert"]["alert_id"], "ALT-0000000000000000"])
    assert get_incident(path, incident_id)["alert_ids"] == [scenario["auth_alert"]["alert_id"]]
    assert history_actions(path, incident_id) == ["created"]


def test_add_alerts_to_a_missing_incident_raises_incident_not_found(saved):
    path, scenario = saved
    with pytest.raises(IncidentNotFound):
        add_alerts_to_incident(path, 42, [scenario["auth_alert"]["alert_id"]])


def test_add_alerts_with_an_empty_list_returns_zero(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    assert add_alerts_to_incident(path, incident_id, []) == 0


def test_database_refuses_an_incident_link_to_a_missing_alert(saved):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    connection = database.get_connection(path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO incident_alerts (incident_id, alert_id, added_at) VALUES (?, ?, ?)",
                               (incident_id, "ALT-0000000000000000", "2025-01-01T00:00:00.000000+00:00"))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO incident_notes (incident_id, author, text, created_at) "
                               "VALUES (?, ?, ?, ?)", (999, "a", "b", "2025-01-01T00:00:00.000000+00:00"))
    finally:
        connection.close()


# ---------------------------------------------------------------
# Details bundle
# ---------------------------------------------------------------

def test_incident_details_has_the_c3_shape(saved):
    path, scenario = saved
    incident_id = create_incident(path, "Scan then login", [scenario["correlated_alert"]["alert_id"]])
    add_note(path, incident_id, "A note")
    update_incident_status(path, incident_id, "investigating")
    details = get_incident_details(path, incident_id)
    assert list(details.keys()) == ["incident_id", "title", "summary", "status", "priority", "created_at",
                                    "updated_at", "closed_at", "alert_ids", "alerts", "events", "notes",
                                    "history"]
    assert [alert["alert_id"] for alert in details["alerts"]] == details["alert_ids"]
    assert len(details["alerts"]) == 3  # base alerts are included
    assert details["alerts"][0] == scenario["correlated_alert"]
    assert [h["action"] for h in details["history"]] == ["created", "note_added", "status_changed"]
    assert list(details["history"][0].keys()) == ["history_id", "incident_id", "action", "old_value",
                                                  "new_value", "changed_by", "changed_at"]
    assert list(details["notes"][0].keys()) == ["note_id", "incident_id", "author", "text", "created_at"]


def test_incident_details_events_have_no_duplicates_and_are_oldest_first(saved):
    path, scenario = saved
    # The correlated alert references all 12 events, which the base alerts also reference.
    incident_id = create_incident(path, "T", [scenario["correlated_alert"]["alert_id"]])
    events = get_incident_details(path, incident_id)["events"]
    assert len(events) == 12
    assert len(set(event["event_id"] for event in events)) == 12
    assert [event["timestamp"] for event in events] == sorted(event["timestamp"] for event in events)
    assert events == scenario["events"]


def test_incident_details_for_a_missing_incident_raises(db_path):
    with pytest.raises(IncidentNotFound):
        get_incident_details(db_path, 1)
    with pytest.raises(IncidentNotFound):
        get_incident_details(db_path, "1")


# ---------------------------------------------------------------
# Persistence and the "no deletion" rule
# ---------------------------------------------------------------

def test_every_incident_change_survives_closing_and_reopening(tmp_path):
    path = str(tmp_path / "restart.db")
    initialise_database(path)
    scenario = fx.make_scenario()
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    save_alerts(path, session_alerts, scenario["events"], session_alerts)
    incident_id = create_incident(path, "Persistent", [scenario["auth_alert"]["alert_id"]], summary="S")
    add_alerts_to_incident(path, incident_id, [scenario["network_alert"]["alert_id"]])
    add_note(path, incident_id, "Note one")
    update_incident_status(path, incident_id, "resolved")
    # "Restart": nothing is kept except the file path.
    del scenario, session_alerts
    details = get_incident_details(path, incident_id)
    assert details["title"] == "Persistent"
    assert details["status"] == "resolved"
    assert details["closed_at"] is not None
    assert len(details["alerts"]) == 2
    assert [note["text"] for note in details["notes"]] == ["Note one"]
    assert [h["action"] for h in details["history"]] == ["created", "alert_added", "note_added", "status_changed"]
    assert query(path, "SELECT COUNT(*) FROM incident_history")[0][0] == 4


def test_version_1_has_no_delete_or_remove_functions():
    for module in [database, incidents]:
        for name in dir(module):
            if name.startswith("_"):
                continue
            lowered = name.lower()
            assert not lowered.startswith("delete"), name
            assert not lowered.startswith("remove"), name
            assert not lowered.startswith("clear"), name
    source = Path(incidents.__file__).read_text(encoding="utf-8").upper()
    assert "DELETE FROM" not in source
    assert "DROP TABLE" not in source


# ---------------------------------------------------------------
# Rollback of every incident write (added by the final compliance audit)
# ---------------------------------------------------------------

def make_failing_history(fail_on_call_number):
    """A stand-in for incidents._insert_history that raises on one chosen call."""
    call_counter = []

    def failing_history(*arguments):
        call_counter.append(1)
        if len(call_counter) == fail_on_call_number:
            raise sqlite3.OperationalError("injected failure")
        return incidents_real_insert_history(*arguments)

    return failing_history


incidents_real_insert_history = incidents._insert_history


def test_failure_while_creating_an_incident_leaves_no_incident_links_or_history(saved, monkeypatch):
    path, scenario = saved
    monkeypatch.setattr(incidents, "_insert_history", make_failing_history(1))
    with pytest.raises(DatabaseError):
        create_incident(path, "Will fail", [scenario["correlated_alert"]["alert_id"]])
    monkeypatch.undo()
    assert query(path, "SELECT COUNT(*) FROM incidents")[0][0] == 0
    assert query(path, "SELECT COUNT(*) FROM incident_alerts")[0][0] == 0
    assert query(path, "SELECT COUNT(*) FROM incident_history")[0][0] == 0


def test_failure_while_adding_a_note_leaves_no_note_and_no_update(saved, monkeypatch):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    before = get_incident(path, incident_id)
    monkeypatch.setattr(incidents, "_insert_history", make_failing_history(1))
    with pytest.raises(DatabaseError):
        add_note(path, incident_id, "Will fail")
    monkeypatch.undo()
    assert query(path, "SELECT COUNT(*) FROM incident_notes")[0][0] == 0
    assert get_incident(path, incident_id) == before
    assert history_actions(path, incident_id) == ["created"]


def test_failure_halfway_through_adding_alerts_links_none_of_them(saved, monkeypatch):
    path, scenario = saved
    incident_id = create_incident(path, "T", [scenario["auth_alert"]["alert_id"]])
    before = get_incident(path, incident_id)
    monkeypatch.setattr(incidents, "_insert_history", make_failing_history(2))  # second new alert fails
    with pytest.raises(DatabaseError):
        add_alerts_to_incident(path, incident_id, [scenario["correlated_alert"]["alert_id"]])
    monkeypatch.undo()
    assert get_incident(path, incident_id) == before  # the first link was rolled back too
    assert history_actions(path, incident_id) == ["created"]
