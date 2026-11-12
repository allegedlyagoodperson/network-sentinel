# tests/test_storage.py
# ---------------------------------------------------------------
# Purpose: tests for storage/database.py (Stage 1C): schema, saving, reading,
# duplicates, broken references, transactions, SQL injection strings and
# persistence after closing and reopening the file (FS.5, R1.2, R1.8, R1.9, R2.7).
# Run from the project folder with: python -m pytest tests/test_storage.py -v
# Every test uses a temporary database (tmp_path), never data/network_sentinel.db.
# Uses: storage, core, pytest, and tests/fixtures/storage_reporting_fixtures.py.

import re
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

import storage_reporting_fixtures as fx  # noqa: E402
from core.contracts import CONTRACT_VERSION, make_alert, validate_alert, validate_event  # noqa: E402
from core.errors import BrokenReferenceError, DatabaseError  # noqa: E402
from storage import database  # noqa: E402
from storage.database import (  # noqa: E402
    DEFAULT_DATABASE_PATH,
    get_alert,
    get_alerts,
    get_connection,
    get_events_for_alert,
    get_existing_alert_ids,
    get_summary_counts,
    initialise_database,
    save_alerts,
)

PROJECT_FOLDER = Path(__file__).resolve().parent.parent
ALL_TABLES = [
    "events", "alerts", "alert_events", "alert_links",
    "incidents", "incident_alerts", "incident_notes", "incident_history",
]


@pytest.fixture
def db_path(tmp_path):
    """A fresh, initialised temporary database."""
    path = str(tmp_path / "test.db")
    initialise_database(path)
    return path


def count_rows(path, table_name):
    """Count the rows of one table using a plain sqlite3 connection (test helper)."""
    connection = sqlite3.connect(path)
    try:
        return connection.execute("SELECT COUNT(*) FROM " + table_name).fetchone()[0]
    finally:
        connection.close()


def assert_all_tables_empty(path):
    for table_name in ALL_TABLES:
        assert count_rows(path, table_name) == 0, table_name + " should be empty"


# ---------------------------------------------------------------
# Contract, path and schema
# ---------------------------------------------------------------

def test_contract_version_is_1_0():
    assert CONTRACT_VERSION == 1.0


def test_database_path_is_the_specified_one():
    assert DEFAULT_DATABASE_PATH == "data/network_sentinel.db"
    gitignore_lines = (PROJECT_FOLDER / ".gitignore").read_text().splitlines()
    assert "data/network_sentinel.db" in gitignore_lines


def test_tests_do_not_touch_the_real_database(db_path):
    real_database = PROJECT_FOLDER / DEFAULT_DATABASE_PATH
    existed_before = real_database.exists()
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    assert real_database.exists() == existed_before
    assert db_path != str(real_database)


def test_initialise_creates_all_eight_tables(db_path):
    connection = sqlite3.connect(db_path)
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    connection.close()
    table_names = [row[0] for row in rows if not row[0].startswith("sqlite_")]
    assert sorted(table_names) == sorted(ALL_TABLES)


def test_initialise_creates_the_indexes_and_schema_version(db_path):
    connection = sqlite3.connect(db_path)
    index_rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    connection.close()
    index_names = [row[0] for row in index_rows]
    for expected_name in ["idx_alerts_source_ip", "idx_alerts_severity", "idx_alerts_rule_id",
                          "idx_alerts_time_start", "idx_alert_events_event", "idx_incidents_status",
                          "idx_incident_alerts_alert", "idx_notes_incident", "idx_history_incident",
                          "idx_alert_links_linked"]:
        assert expected_name in index_names
    assert version == 1


def test_initialise_twice_is_safe_and_keeps_data(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    initialise_database(db_path)
    initialise_database(db_path)
    assert count_rows(db_path, "alerts") == 1


def test_initialise_creates_a_missing_folder(tmp_path):
    path = str(tmp_path / "data" / "nested" / "sentinel.db")
    initialise_database(path)
    assert Path(path).exists()


@pytest.mark.parametrize("table_name, expected_columns", [
    ("events", ["event_id", "event_type", "timestamp", "source_ip", "destination_ip", "destination_port",
                "protocol", "username", "service", "status", "bytes_sent", "bytes_received",
                "source_file", "source_row", "raw_event_json"]),
    ("alerts", ["alert_id", "rule_id", "title", "description", "severity", "confidence", "detected_at",
                "time_start", "time_end", "source_ip", "evidence_json", "recommended_action", "saved_at"]),
    ("alert_events", ["alert_id", "event_id", "position"]),
    ("alert_links", ["alert_id", "linked_alert_id"]),
    ("incidents", ["incident_id", "title", "summary", "status", "priority", "created_at", "updated_at",
                   "closed_at"]),
    ("incident_alerts", ["incident_id", "alert_id", "added_at"]),
    ("incident_notes", ["note_id", "incident_id", "author", "text", "created_at"]),
    ("incident_history", ["history_id", "incident_id", "action", "old_value", "new_value", "changed_by",
                          "changed_at"]),
])
def test_table_columns_match_the_specification(db_path, table_name, expected_columns):
    connection = sqlite3.connect(db_path)
    rows = connection.execute("PRAGMA table_info(" + table_name + ")").fetchall()
    connection.close()
    assert [row[1] for row in rows] == expected_columns


def test_get_connection_switches_foreign_keys_on_and_reads_by_name(db_path):
    connection = get_connection(db_path)
    try:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        row = connection.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()
        assert row["total"] == 0
    finally:
        connection.close()


@pytest.mark.parametrize("bad_path", ["", "   ", None, 42])
def test_get_connection_rejects_bad_paths(bad_path):
    with pytest.raises(DatabaseError):
        get_connection(bad_path)


def test_get_connection_reports_an_unopenable_file(tmp_path):
    with pytest.raises(DatabaseError):
        get_connection(str(tmp_path / "no_such_folder" / "x.db"))


def test_functions_on_an_uninitialised_database_raise_database_error(tmp_path):
    empty_path = str(tmp_path / "empty.db")
    scenario = fx.make_scenario()
    with pytest.raises(DatabaseError):
        get_alerts(empty_path)
    with pytest.raises(DatabaseError):
        get_summary_counts(empty_path)
    with pytest.raises(DatabaseError):
        save_alerts(empty_path, [scenario["auth_alert"]], scenario["events"])


def test_only_the_storage_folder_imports_sqlite3_and_storage_never_imports_streamlit():
    for folder_name in ["core", "config", "reporting", "dashboard", "ingestion", "detection", "correlation"]:
        folder = PROJECT_FOLDER / folder_name
        if not folder.exists():
            continue
        for python_file in folder.glob("*.py"):
            assert "import sqlite3" not in python_file.read_text(encoding="utf-8"), str(python_file)
    for python_file in (PROJECT_FOLDER / "storage").glob("*.py"):
        text = python_file.read_text(encoding="utf-8")
        assert "streamlit" not in text.replace("Streamlit", "")
        assert "import reportlab" not in text


# ---------------------------------------------------------------
# Saving and reading back (round trip)
# ---------------------------------------------------------------

def test_round_trip_alert_is_exactly_what_was_saved(db_path):
    scenario = fx.make_scenario()
    result = save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    assert result["alerts_inserted"] == 1
    saved_alert = get_alert(db_path, scenario["auth_alert"]["alert_id"])
    assert saved_alert == scenario["auth_alert"]
    assert validate_alert(saved_alert) == []
    assert saved_alert["time_start"].tzinfo is not None
    assert isinstance(saved_alert["evidence"], dict)
    assert saved_alert["event_ids"] == scenario["auth_alert"]["event_ids"]


def test_round_trip_events_are_exactly_what_was_saved(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    stored_events = get_events_for_alert(db_path, scenario["auth_alert"]["alert_id"])
    assert stored_events == scenario["events"][:6]
    for event in stored_events:
        assert validate_event(event) == []
        assert isinstance(event["raw_event"], dict)


def test_get_alerts_returns_saved_alerts_newest_time_start_first(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"], scenario["network_alert"]], scenario["events"])
    alerts = get_alerts(db_path)
    assert [alert["rule_id"] for alert in alerts] == ["NET_PORT_SCAN", "AUTH_BRUTE_FORCE"]
    assert alerts[1] == scenario["auth_alert"]


def test_only_events_referenced_by_saved_alerts_are_stored(db_path):
    # R1.9: analyse many events, save one alert that references 6 of them.
    scenario = fx.make_scenario()
    many_events = list(scenario["events"])
    for index in range(100, 1100):
        many_events.append(fx.make_auth_event(index, username="other", source_ip="198.51.100.7"))
    result = save_alerts(db_path, [scenario["auth_alert"]], many_events)
    assert result["events_inserted"] == 6
    assert count_rows(db_path, "events") == 6
    assert count_rows(db_path, "alert_events") == 6


def test_missing_values_come_back_as_none(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["network_alert"]], scenario["events"])
    login = get_events_for_alert(db_path, scenario["auth_alert"]["alert_id"])
    assert login == []  # not saved, so nothing is returned
    network_event = get_events_for_alert(db_path, scenario["network_alert"]["alert_id"])[0]
    assert network_event["username"] is None
    assert network_event["service"] is None
    assert network_event["destination_port"] == 20


def test_unicode_and_nested_evidence_survive(db_path):
    event = fx.make_auth_event(0, username="Zoë 你好 😀")
    evidence = fx.make_evidence({"nested": {"list": [1, 2.5, None, True], "text": "naïve café"}})
    alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [event], evidence=evidence)
    save_alerts(db_path, [alert], [event])
    assert get_alert(db_path, alert["alert_id"]) == alert
    assert get_events_for_alert(db_path, alert["alert_id"]) == [event]


def test_event_ids_keep_the_order_they_were_given(db_path):
    scenario = fx.make_scenario()
    alert = scenario["correlated_alert"]
    save_alerts(db_path, [alert], scenario["events"], [scenario["auth_alert"], scenario["network_alert"]])
    assert get_alert(db_path, alert["alert_id"])["event_ids"] == alert["event_ids"]


def test_get_events_for_alert_is_oldest_first_and_unknown_alert_gives_empty_list(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"],
                [scenario["auth_alert"], scenario["network_alert"]])
    events = get_events_for_alert(db_path, scenario["correlated_alert"]["alert_id"])
    timestamps = [event["timestamp"] for event in events]
    assert timestamps == sorted(timestamps)
    assert len(events) == 12
    assert get_events_for_alert(db_path, "ALT-0000000000000000") == []


def test_get_alert_returns_none_for_an_unknown_id(db_path):
    assert get_alert(db_path, "ALT-0000000000000000") is None


def test_fifteen_linked_successes_are_all_stored(db_path):
    # R2.7: 21 event_ids, success_events limited to 10, but storage never trims.
    alert, events = fx.make_success_alert()
    assert len(alert["event_ids"]) == 21
    result = save_alerts(db_path, [alert], events)
    assert result["events_inserted"] == 21
    assert count_rows(db_path, "alert_events") == 21
    assert count_rows(db_path, "events") == 21
    assert len(get_events_for_alert(db_path, alert["alert_id"])) == 21
    saved_alert = get_alert(db_path, alert["alert_id"])
    assert saved_alert == alert
    assert len(saved_alert["evidence"]["success_events"]) == 10


def test_an_event_shared_by_two_alerts_is_stored_once(db_path):
    shared_event = fx.make_auth_event(0)
    other_event = fx.make_auth_event(1)
    first_alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [shared_event])
    second_alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [shared_event, other_event])
    result = save_alerts(db_path, [first_alert, second_alert], [shared_event, other_event])
    assert result["alerts_inserted"] == 2
    assert result["events_inserted"] == 2
    assert count_rows(db_path, "events") == 2
    assert count_rows(db_path, "alert_events") == 3


# ---------------------------------------------------------------
# Duplicates
# ---------------------------------------------------------------

def test_saving_the_same_alert_twice_stores_one_copy_and_reports_skips(db_path):
    scenario = fx.make_scenario()
    first = save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    second = save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    assert first == {"alerts_inserted": 1, "alerts_skipped_duplicate": 0, "events_inserted": 6,
                     "events_skipped_duplicate": 0, "base_alerts_added_automatically": []}
    assert second == {"alerts_inserted": 0, "alerts_skipped_duplicate": 1, "events_inserted": 0,
                      "events_skipped_duplicate": 6, "base_alerts_added_automatically": []}
    assert count_rows(db_path, "alerts") == 1
    assert count_rows(db_path, "events") == 6
    assert count_rows(db_path, "alert_events") == 6


def test_the_same_alert_given_twice_in_one_call_is_saved_once(db_path):
    scenario = fx.make_scenario()
    result = save_alerts(db_path, [scenario["auth_alert"], scenario["auth_alert"]], scenario["events"])
    assert result["alerts_inserted"] == 1
    assert count_rows(db_path, "alerts") == 1


def test_a_saved_alert_is_never_overwritten(db_path):
    scenario = fx.make_scenario()
    original = scenario["auth_alert"]
    save_alerts(db_path, [original], scenario["events"])
    changed = dict(original)
    changed["title"] = "A different title"
    changed["recommended_action"] = "Different advice"
    result = save_alerts(db_path, [changed], scenario["events"])
    assert result["alerts_skipped_duplicate"] == 1
    assert get_alert(db_path, original["alert_id"])["title"] == original["title"]


def test_an_empty_save_does_nothing(db_path):
    result = save_alerts(db_path, [], [])
    assert result == {"alerts_inserted": 0, "alerts_skipped_duplicate": 0, "events_inserted": 0,
                      "events_skipped_duplicate": 0, "base_alerts_added_automatically": []}


# ---------------------------------------------------------------
# Correlated alerts and broken references (R1.2, R1.8, R1.9)
# ---------------------------------------------------------------

def test_saving_only_a_correlated_alert_adds_the_base_alerts_from_the_session(db_path):
    scenario = fx.make_scenario()
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    result = save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"], session_alerts)
    assert result["alerts_inserted"] == 3
    assert sorted(result["base_alerts_added_automatically"]) == sorted(
        [scenario["auth_alert"]["alert_id"], scenario["network_alert"]["alert_id"]])
    assert count_rows(db_path, "alerts") == 3
    assert count_rows(db_path, "alert_links") == 2
    assert count_rows(db_path, "events") == 12


def test_evidence_link_list_and_alert_links_table_agree(db_path):
    scenario = fx.make_scenario()
    correlated = scenario["correlated_alert"]
    save_alerts(db_path, [correlated], scenario["events"], [scenario["auth_alert"], scenario["network_alert"]])
    connection = sqlite3.connect(db_path)
    rows = connection.execute("SELECT linked_alert_id FROM alert_links WHERE alert_id = ?",
                              (correlated["alert_id"],)).fetchall()
    connection.close()
    stored_alert = get_alert(db_path, correlated["alert_id"])
    assert set(row[0] for row in rows) == set(stored_alert["evidence"]["correlation"]["linked_alert_ids"])


def test_base_alerts_saved_earlier_are_not_added_again(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"], scenario["network_alert"]], scenario["events"])
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    result = save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"], session_alerts)
    assert result["alerts_inserted"] == 1
    assert result["base_alerts_added_automatically"] == []
    assert count_rows(db_path, "alert_links") == 2


def test_base_alerts_that_exist_only_in_the_database_are_enough(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"], scenario["network_alert"]], scenario["events"])
    result = save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"])
    assert result["alerts_inserted"] == 1
    assert count_rows(db_path, "alert_links") == 2


def test_repeating_a_correlated_save_reports_only_skips(db_path):
    scenario = fx.make_scenario()
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"], session_alerts)
    result = save_alerts(db_path, session_alerts, scenario["events"], session_alerts)
    assert result["alerts_inserted"] == 0
    assert result["alerts_skipped_duplicate"] == 3
    assert result["base_alerts_added_automatically"] == []
    assert count_rows(db_path, "alerts") == 3
    assert count_rows(db_path, "alert_links") == 2


def test_missing_base_alert_raises_broken_reference_and_writes_nothing(db_path):
    scenario = fx.make_scenario()
    with pytest.raises(BrokenReferenceError):
        save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"], [scenario["auth_alert"]])
    assert_all_tables_empty(db_path)


def test_missing_base_alert_without_a_session_list_raises_broken_reference(db_path):
    scenario = fx.make_scenario()
    with pytest.raises(BrokenReferenceError):
        save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"])
    assert_all_tables_empty(db_path)


def test_missing_supporting_event_raises_broken_reference_and_writes_nothing(db_path):
    scenario = fx.make_scenario()
    events_without_one = scenario["events"][1:]  # the first failed login is missing
    with pytest.raises(BrokenReferenceError):
        save_alerts(db_path, [scenario["auth_alert"]], events_without_one)
    assert_all_tables_empty(db_path)


def test_an_event_that_is_already_stored_does_not_have_to_be_in_the_session(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    other_alert = fx.make_base_alert("AUTH_BRUTE_FORCE", scenario["events"][:3], title="Smaller range")
    result = save_alerts(db_path, [other_alert], [])  # no session events at all
    assert result["alerts_inserted"] == 1
    assert result["events_inserted"] == 0


def test_a_linked_alert_that_is_itself_correlated_is_refused(db_path):
    scenario = fx.make_scenario()
    first = scenario["correlated_alert"]
    second_evidence = fx.make_evidence({"correlation": {
        "link_key": "source_ip", "link_value": fx.ATTACKER_IP,
        "linked_alert_ids": [first["alert_id"], scenario["auth_alert"]["alert_id"]],
        "gap_seconds": 0, "destination_match": False, "match_conditions": ["x"]}})
    second = make_alert("CORR_AUTH_NET", "Second", "Possible.", "high", "medium",
                        scenario["events"][0]["timestamp"], scenario["events"][5]["timestamp"], fx.ATTACKER_IP,
                        [event["event_id"] for event in scenario["events"][:6]], second_evidence, "Act")
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], first, second]
    with pytest.raises(BrokenReferenceError):
        save_alerts(db_path, [second], scenario["events"], session_alerts)
    assert_all_tables_empty(db_path)


def test_database_refuses_a_link_to_a_missing_alert(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    connection = get_connection(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO alert_links (alert_id, linked_alert_id) VALUES (?, ?)",
                               (scenario["auth_alert"]["alert_id"], "ALT-0000000000000000"))
        with pytest.raises(sqlite3.IntegrityError):  # an alert cannot link to itself
            connection.execute("INSERT INTO alert_links (alert_id, linked_alert_id) VALUES (?, ?)",
                               (scenario["auth_alert"]["alert_id"], scenario["auth_alert"]["alert_id"]))
    finally:
        connection.close()


def test_database_refuses_an_alert_event_row_for_a_missing_event(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    connection = get_connection(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO alert_events (alert_id, event_id, position) VALUES (?, ?, ?)",
                               (scenario["auth_alert"]["alert_id"], "EVT-0000000000000000", 99))
    finally:
        connection.close()


# ---------------------------------------------------------------
# Validation and bad arguments
# ---------------------------------------------------------------

def test_an_invalid_alert_is_refused_and_nothing_is_written(db_path):
    scenario = fx.make_scenario()
    broken = dict(scenario["auth_alert"])
    broken["severity"] = "catastrophic"
    with pytest.raises(DatabaseError):
        save_alerts(db_path, [scenario["network_alert"], broken], scenario["events"])
    assert_all_tables_empty(db_path)


def test_an_alert_with_a_missing_key_is_refused(db_path):
    scenario = fx.make_scenario()
    broken = dict(scenario["auth_alert"])
    del broken["evidence"]
    with pytest.raises(DatabaseError):
        save_alerts(db_path, [broken], scenario["events"])
    assert_all_tables_empty(db_path)


def test_an_invalid_event_is_refused_and_nothing_is_written(db_path):
    scenario = fx.make_scenario()
    broken_events = []
    for event in scenario["events"]:
        broken_events.append(dict(event))
    broken_events[0]["event_type"] = "something_else"
    with pytest.raises(DatabaseError):
        save_alerts(db_path, [scenario["auth_alert"]], broken_events)
    assert_all_tables_empty(db_path)


def test_bad_argument_types_raise_database_error(db_path):
    with pytest.raises(DatabaseError):
        save_alerts(db_path, "not a list", [])
    with pytest.raises(DatabaseError):
        save_alerts(db_path, [], "not a list")
    with pytest.raises(DatabaseError):
        save_alerts(db_path, [], [], "not a list")
    with pytest.raises(DatabaseError):
        save_alerts(db_path, ["not a dictionary"], [])


# ---------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------

def test_failure_after_events_and_base_alerts_rolls_everything_back(db_path, monkeypatch):
    # Inject a failure AFTER events and alerts were written but before the
    # alert_events rows. The rollback must leave every table empty.
    def failing_writer(connection, alert_list):
        raise sqlite3.OperationalError("injected failure")

    monkeypatch.setattr(database, "_insert_alert_event_rows", failing_writer)
    scenario = fx.make_scenario()
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    with pytest.raises(DatabaseError):
        save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"], session_alerts)
    assert_all_tables_empty(db_path)


def test_an_unexpected_python_error_also_rolls_back_and_is_not_hidden(db_path, monkeypatch):
    def failing_writer(connection, correlated_list):
        raise RuntimeError("injected bug")

    monkeypatch.setattr(database, "_insert_alert_link_rows", failing_writer)
    scenario = fx.make_scenario()
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    with pytest.raises(RuntimeError):
        save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"], session_alerts)
    assert_all_tables_empty(db_path)


def test_the_database_works_normally_after_a_rolled_back_save(db_path, monkeypatch):
    scenario = fx.make_scenario()
    with monkeypatch.context() as patch:
        patch.setattr(database, "_insert_alert_event_rows", lambda connection, alert_list: 1 / 0)
        with pytest.raises(ZeroDivisionError):
            save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    result = save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    assert result["alerts_inserted"] == 1


# ---------------------------------------------------------------
# SQL injection strings and parameterised queries
# ---------------------------------------------------------------

INJECTION_TEXT = "x'); DROP TABLE alerts;--"


def test_injection_strings_are_stored_as_plain_text_and_tables_survive(db_path):
    event = fx.make_auth_event(0, username=INJECTION_TEXT)
    alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [event], title=INJECTION_TEXT,
                               evidence=fx.make_evidence({"note": "' OR '1'='1"}))
    save_alerts(db_path, [alert], [event])
    saved_alert = get_alert(db_path, alert["alert_id"])
    assert saved_alert["title"] == INJECTION_TEXT
    assert saved_alert["evidence"]["note"] == "' OR '1'='1"
    assert get_events_for_alert(db_path, alert["alert_id"])[0]["username"] == INJECTION_TEXT
    assert count_rows(db_path, "alerts") == 1  # the table still exists and holds the row


def test_injection_strings_in_filters_are_only_data(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"], scenario["network_alert"]], scenario["events"])
    assert get_alerts(db_path, {"source_ip": "' OR '1'='1"}) == []
    assert get_alerts(db_path, {"severity": "medium' OR 1=1 --"}) == []
    assert get_alerts(db_path, {"rule_id": "x'; DROP TABLE alerts;--"}) == []
    assert count_rows(db_path, "alerts") == 2
    assert get_alert(db_path, "ALT-x' OR '1'='1") is None
    assert get_existing_alert_ids(db_path, ["' OR '1'='1"]) == []


def test_unknown_filter_names_are_refused_so_column_names_cannot_be_injected(db_path):
    with pytest.raises(DatabaseError):
        get_alerts(db_path, {"severity = 'low' OR 1": "x"})
    with pytest.raises(DatabaseError):
        get_alerts(db_path, {"title": "x"})
    with pytest.raises(DatabaseError):
        get_alerts(db_path, "severity")


def test_the_sql_in_the_storage_files_uses_placeholders_not_string_formatting():
    for file_name in ["database.py", "incidents.py"]:
        text = (PROJECT_FOLDER / "storage" / file_name).read_text(encoding="utf-8")
        assert re.search(r"(?<![A-Za-z0-9_])f[\"']", text) is None, file_name + " must not use f-strings"
        assert ".format(" not in text, file_name + " must not use str.format"
        assert "DELETE FROM" not in text.upper(), "version 1 has no delete functions (D8)"


# ---------------------------------------------------------------
# Filters, counts and lookups
# ---------------------------------------------------------------

def test_filters_by_severity_confidence_rule_and_source(db_path):
    scenario = fx.make_scenario(auth_severity="low", network_severity="medium")
    other_event = fx.make_auth_event(50, source_ip="198.51.100.9", seconds_offset=400)
    other_alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [other_event], "critical", "high",
                                     source_ip="198.51.100.9")
    save_alerts(db_path, [scenario["auth_alert"], scenario["network_alert"], other_alert],
                scenario["events"] + [other_event])
    assert len(get_alerts(db_path)) == 3
    assert [a["rule_id"] for a in get_alerts(db_path, {"severity": "low"})] == ["AUTH_BRUTE_FORCE"]
    assert len(get_alerts(db_path, {"confidence": "high"})) == 1
    assert len(get_alerts(db_path, {"rule_id": "AUTH_BRUTE_FORCE"})) == 2
    assert len(get_alerts(db_path, {"source_ip": "198.51.100.9"})) == 1
    both = get_alerts(db_path, {"rule_id": "AUTH_BRUTE_FORCE", "source_ip": fx.ATTACKER_IP})
    assert len(both) == 1
    assert len(get_alerts(db_path, {"severity": None})) == 3  # None means "no filter"
    assert get_alerts(db_path, {}) == get_alerts(db_path)


def test_get_existing_alert_ids_returns_the_saved_subset_in_order(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    saved_id = scenario["auth_alert"]["alert_id"]
    other_id = scenario["network_alert"]["alert_id"]
    assert get_existing_alert_ids(db_path, [other_id, saved_id, saved_id]) == [saved_id]
    assert get_existing_alert_ids(db_path, []) == []


def test_get_existing_alert_ids_handles_more_ids_than_one_query_can_carry(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["auth_alert"]], scenario["events"])
    many_ids = []
    for number in range(1500):
        many_ids.append("ALT-" + str(number).zfill(16))
    many_ids.append(scenario["auth_alert"]["alert_id"])
    assert get_existing_alert_ids(db_path, many_ids) == [scenario["auth_alert"]["alert_id"]]


def test_get_existing_alert_ids_rejects_a_non_list(db_path):
    with pytest.raises(DatabaseError):
        get_existing_alert_ids(db_path, "ALT-123")


def test_summary_counts_on_an_empty_database(db_path):
    counts = get_summary_counts(db_path)
    assert counts == {
        "alerts_total": 0,
        "incidents_total": 0,
        "incidents_by_status": {"open": 0, "investigating": 0, "resolved": 0, "false_positive": 0},
        "alerts_by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    }


def test_summary_counts_after_saving(db_path):
    scenario = fx.make_scenario()
    save_alerts(db_path, [scenario["correlated_alert"]], scenario["events"],
                [scenario["auth_alert"], scenario["network_alert"]])
    counts = get_summary_counts(db_path)
    assert counts["alerts_total"] == 3
    assert counts["alerts_by_severity"]["medium"] == 2
    assert counts["alerts_by_severity"]["high"] == 1
    assert counts["incidents_total"] == 0


# ---------------------------------------------------------------
# Persistence after closing and reopening (simulated restart, R1.9)
# ---------------------------------------------------------------

def test_data_survives_closing_and_reopening_the_file(tmp_path):
    path = str(tmp_path / "restart.db")
    initialise_database(path)
    scenario = fx.make_scenario()
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    save_alerts(path, [scenario["correlated_alert"]], scenario["events"], session_alerts)
    # "Restart": forget every Python object; only the file path is kept.
    del scenario, session_alerts
    reopened = sqlite3.connect(path)
    assert reopened.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 3
    assert reopened.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 12
    reopened.close()
    alerts = get_alerts(path)
    assert len(alerts) == 3
    assert len(get_events_for_alert(path, alerts[0]["alert_id"])) > 0
    assert get_events_for_alert(path, alerts[0]["alert_id"])[0]["raw_event"] != {}


def test_after_a_restart_unsaved_alerts_are_absent_and_the_same_analysis_shows_saved(tmp_path):
    path = str(tmp_path / "restart2.db")
    initialise_database(path)
    first_run = fx.make_scenario()
    save_alerts(path, [first_run["auth_alert"]], first_run["events"])
    # The same files analysed again produce the same IDs (deterministic IDs).
    second_run = fx.make_scenario()
    ids = [second_run["auth_alert"]["alert_id"], second_run["network_alert"]["alert_id"]]
    assert get_existing_alert_ids(path, ids) == [second_run["auth_alert"]["alert_id"]]
    saved_ids = []
    for alert in get_alerts(path):
        saved_ids.append(alert["alert_id"])
    assert second_run["network_alert"]["alert_id"] not in saved_ids
    again = save_alerts(path, [second_run["auth_alert"]], second_run["events"])
    assert again["alerts_inserted"] == 0
    assert again["alerts_skipped_duplicate"] == 1
