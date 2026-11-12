# tests/test_contracts.py
# ---------------------------------------------------------------
# Purpose: the Stage 0 tests (FS.6). They check core/contracts.py,
# core/errors.py, config/settings.py, the two sample CSV files and the
# fixed golden values stored in tests/fixtures/expected_results.json.
# Run from the project folder with: python -m pytest tests/test_contracts.py -v
# Golden values are typed-in fixed text, so a later change to the code
# cannot silently change an ID and still pass.
# Uses: core, config, the standard library, and pytest.

import csv
import hashlib
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from config.settings import DEFAULT_CONFIG, get_default_config, validate_config
from core.contracts import (
    ALERT_KEYS,
    ALLOWED_STATUS_TRANSITIONS,
    AUTH_STATUSES,
    CONFIDENCES,
    CONTRACT_VERSION,
    EVENT_CONTENT_KEYS,
    EVENT_ID_HEX_LENGTH,
    EVENT_KEYS,
    EVENT_TYPES,
    INCIDENT_STATUSES,
    MAX_DETAILED_SUCCESS_EVENTS,
    NETWORK_STATUSES,
    RULE_IDS,
    SEVERITIES,
    canonical_json,
    datetime_to_iso,
    format_incident_id,
    iso_to_datetime,
    make_alert,
    make_alert_id,
    make_content_fingerprint,
    make_event,
    make_event_id,
    severity_rank,
    utc_now,
    validate_alert,
    validate_event,
)
from core.errors import (
    BrokenReferenceError,
    ConfigError,
    ContractError,
    DatabaseError,
    IncidentNotFound,
    IngestionError,
    InvalidStatusTransition,
    NetworkSentinelError,
    ReportError,
)

PROJECT_FOLDER = Path(__file__).resolve().parent.parent
EXPECTED_RESULTS_PATH = PROJECT_FOLDER / "tests" / "fixtures" / "expected_results.json"
SAMPLE_FOLDER = PROJECT_FOLDER / "data" / "sample"


# ---------------------------------------------------------------
# Helpers that build valid example data. Tests copy these and then
# break ONE thing at a time, so a failure points at that one thing.
# ---------------------------------------------------------------

def utc_time(hour, minute, second):
    """A UTC datetime on 14 March 2025."""
    return datetime(2025, 3, 14, hour, minute, second, tzinfo=timezone.utc)


def load_expected_results():
    with open(EXPECTED_RESULTS_PATH, encoding="utf-8") as file_handle:
        return json.load(file_handle)


def valid_auth_arguments():
    return {
        "event_type": "authentication",
        "timestamp": utc_time(9, 15, 2),
        "source_ip": "203.0.113.50",
        "status": "failure",
        "source_file": "auth_sample.csv",
        "source_row": 2,
        "raw_event": {"timestamp": "2025-03-14T09:15:02", "username": "admin"},
        "username": "admin",
        "destination_ip": "10.0.0.5",
        "service": "ssh",
    }


def valid_network_arguments():
    return {
        "event_type": "network_connection",
        "timestamp": utc_time(9, 16, 0),
        "source_ip": "203.0.113.50",
        "status": "rejected",
        "source_file": "network_sample.csv",
        "source_row": 2,
        "raw_event": {"timestamp": "2025-03-14T09:16:00", "destination_port": "22"},
        "destination_ip": "10.0.0.5",
        "destination_port": 22,
        "protocol": "TCP",
        "bytes_sent": 60,
        "bytes_received": 0,
    }


def valid_evidence():
    return {
        "rule_parameters": {"portscan_distinct_ports_threshold": 15},
        "observed": {"distinct_port_count": 18},
        "explanation": ["18 ports were tried in 17 seconds."],
        "limitations": ["An authorised scanner looks the same."],
    }


def valid_correlation_block():
    return {
        "link_key": "source_ip",
        "link_value": "203.0.113.50",
        "linked_alert_ids": ["ALT-1111111111111111", "ALT-2222222222222222"],
        "gap_seconds": 0,
        "destination_match": True,
        "match_conditions": ["Same source address."],
    }


def valid_alert_arguments():
    return {
        "rule_id": "NET_PORT_SCAN",
        "title": "Possible port scanning activity",
        "description": "A possible port scan was recorded.",
        "severity": "medium",
        "confidence": "high",
        "time_start": utc_time(9, 16, 0),
        "time_end": utc_time(9, 16, 17),
        "source_ip": "203.0.113.50",
        "event_ids": ["EVT-aaaaaaaaaaaaaaaa", "EVT-bbbbbbbbbbbbbbbb"],
        "evidence": valid_evidence(),
        "recommended_action": "Check whether the source is an authorised scanner.",
        "detected_at": utc_time(10, 0, 0),
    }


def valid_content():
    """The 11 content keys, with the timestamp still a datetime."""
    content = {}
    event = make_event(**valid_auth_arguments())
    for key in EVENT_CONTENT_KEYS:
        content[key] = event[key]
    return content


def event_arguments_from_json(inputs):
    """Turn the JSON inputs of a golden case into make_event arguments."""
    arguments = dict(inputs)
    # datetime.fromisoformat is Python's own parser, so this does not use our code.
    arguments["timestamp"] = datetime.fromisoformat(inputs["timestamp"])
    return arguments


def check_every_bad_value_is_rejected(make_function, good_arguments, bad_cases):
    """Try each (field, bad value) pair. Every one must raise ContractError."""
    for field_name, bad_value in bad_cases:
        arguments = dict(good_arguments)
        arguments[field_name] = bad_value
        try:
            # The two stars unpack the dictionary into keyword arguments.
            make_function(**arguments)
        except ContractError:
            continue
        pytest.fail(field_name + "=" + repr(bad_value) + " should have been rejected")


# ---------------------------------------------------------------
# Constants and version
# ---------------------------------------------------------------

def test_contract_version_is_one_point_zero():
    assert CONTRACT_VERSION == 1.0


def test_allowed_value_lists_match_the_specification():
    assert EVENT_TYPES == ["authentication", "network_connection"]
    assert AUTH_STATUSES == ["success", "failure"]
    assert NETWORK_STATUSES == ["allowed", "rejected"]
    assert SEVERITIES == ["low", "medium", "high", "critical"]
    assert CONFIDENCES == ["low", "medium", "high"]
    assert INCIDENT_STATUSES == ["open", "investigating", "resolved", "false_positive"]
    assert RULE_IDS == ["AUTH_BRUTE_FORCE", "NET_PORT_SCAN", "NET_REPEATED_REJECTS",
                        "NET_HIGH_VOLUME", "CORR_AUTH_NET"]


def test_event_and_alert_key_lists_match_the_specification():
    assert len(EVENT_KEYS) == 15
    assert EVENT_KEYS[0] == "event_id"
    assert EVENT_KEYS[-1] == "raw_event"
    assert len(ALERT_KEYS) == 13
    assert ALERT_KEYS[0] == "alert_id"
    assert ALERT_KEYS[-1] == "recommended_action"
    assert len(EVENT_CONTENT_KEYS) == 11
    for key in ["event_id", "source_file", "source_row", "raw_event"]:
        assert key not in EVENT_CONTENT_KEYS


def test_numeric_constants():
    assert EVENT_ID_HEX_LENGTH == 16
    assert MAX_DETAILED_SUCCESS_EVENTS == 10


def test_status_transition_table_matches_section_c3():
    assert ALLOWED_STATUS_TRANSITIONS == {
        "open": ["investigating", "resolved", "false_positive"],
        "investigating": ["open", "resolved", "false_positive"],
        "resolved": ["investigating"],
        "false_positive": ["investigating"],
    }


# ---------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------

def test_exception_hierarchy_matches_fs4():
    for error_class in [ContractError, ConfigError, IngestionError, ReportError, DatabaseError]:
        assert issubclass(error_class, NetworkSentinelError)
    for error_class in [BrokenReferenceError, IncidentNotFound, InvalidStatusTransition]:
        assert issubclass(error_class, DatabaseError)
    assert issubclass(NetworkSentinelError, Exception)
    assert not issubclass(ContractError, DatabaseError)


# ---------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------

def test_datetime_to_iso_uses_the_fixed_format():
    assert datetime_to_iso(utc_time(9, 15, 2)) == "2025-03-14T09:15:02.000000+00:00"


def test_datetime_to_iso_keeps_microseconds_and_a_fixed_width():
    half_second = utc_time(9, 15, 2) + timedelta(microseconds=500000)
    assert datetime_to_iso(half_second) == "2025-03-14T09:15:02.500000+00:00"
    assert len(datetime_to_iso(half_second)) == len(datetime_to_iso(utc_time(1, 2, 3))) == 32


def test_datetime_to_iso_converts_other_zones_to_utc():
    five_hours_ahead = timezone(timedelta(hours=5))
    local_time = datetime(2025, 3, 14, 14, 15, 2, tzinfo=five_hours_ahead)
    assert datetime_to_iso(local_time) == "2025-03-14T09:15:02.000000+00:00"


def test_datetime_to_iso_rejects_naive_and_non_datetimes():
    with pytest.raises(ValueError):
        datetime_to_iso(datetime(2025, 3, 14, 9, 15, 2))
    with pytest.raises(ValueError):
        datetime_to_iso("2025-03-14T09:15:02")
    with pytest.raises(ValueError):
        datetime_to_iso(datetime(5, 1, 1, tzinfo=timezone.utc))


def test_iso_to_datetime_round_trip_and_utc():
    original = utc_time(9, 15, 2) + timedelta(microseconds=123456)
    restored = iso_to_datetime(datetime_to_iso(original))
    assert restored == original
    assert restored.utcoffset() == timedelta(0)


def test_iso_to_datetime_rejects_other_formats():
    bad_texts = ["", "2025-03-14", "2025-03-14T09:15:02+00:00", "2025-03-14T09:15:02.0+00:00",
                 "2025-03-14T09:15:02.000000Z", "14/03/2025 09:15:02", "2025-02-31T09:15:02.000000+00:00", 5, None]
    for bad_text in bad_texts:
        with pytest.raises(ValueError):
            iso_to_datetime(bad_text)


def test_utc_now_is_aware_utc_and_current():
    before = datetime.now(timezone.utc)
    now = utc_now()
    after = datetime.now(timezone.utc)
    assert now.utcoffset() == timedelta(0)
    assert before <= now <= after


# ---------------------------------------------------------------
# severity_rank and format_incident_id
# ---------------------------------------------------------------

def test_severity_rank_order():
    assert [severity_rank(name) for name in SEVERITIES] == [1, 2, 3, 4]


def test_severity_rank_rejects_unknown_values():
    for bad_value in ["urgent", "", "HIGH", None]:
        with pytest.raises(ValueError):
            severity_rank(bad_value)


def test_format_incident_id():
    assert format_incident_id(7) == "INC-0007"
    assert format_incident_id(0) == "INC-0000"
    assert format_incident_id(1234) == "INC-1234"
    assert format_incident_id(12345) == "INC-12345"  # more than 4 digits still works


def test_format_incident_id_rejects_bad_numbers():
    for bad_value in [-1, "7", 7.0, None, True]:
        with pytest.raises(ValueError):
            format_incident_id(bad_value)


# ---------------------------------------------------------------
# canonical_json
# ---------------------------------------------------------------

def test_canonical_json_sorts_keys_and_has_no_spaces():
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_canonical_json_same_text_whatever_the_insertion_order():
    first = {"x": 1, "y": None, "z": "text"}
    second = {"z": "text", "y": None, "x": 1}
    assert canonical_json(first) == canonical_json(second)


def test_canonical_json_none_is_null_and_differs_from_text():
    assert canonical_json({"v": None}) == '{"v":null}'
    assert canonical_json({"v": ""}) == '{"v":""}'
    assert canonical_json({"v": "None"}) == '{"v":"None"}'


def test_canonical_json_escapes_non_ascii_letters():
    assert canonical_json({"name": "Zoë"}) == '{"name":"Zo\\u00eb"}'


def test_canonical_json_keeps_numbers_and_booleans_apart_from_text():
    assert canonical_json({"n": 5, "t": True, "s": "5"}) == '{"n":5,"s":"5","t":true}'


def test_canonical_json_does_not_modify_the_input():
    data = {"b": [3, 1, 2], "a": {"y": 1, "x": 2}}
    canonical_json(data)
    assert data == {"b": [3, 1, 2], "a": {"y": 1, "x": 2}}
    assert list(data.keys()) == ["b", "a"]


def test_canonical_json_rejects_bad_input():
    bad_inputs = ["text", [1, 2], None, {"when": utc_time(9, 0, 0)}, {"s": {1, 2}},
                  {"n": float("nan")}, {"n": float("inf")}]
    for bad_input in bad_inputs:
        with pytest.raises(ContractError):
            canonical_json(bad_input)


# ---------------------------------------------------------------
# make_event: fields, defaults, rejection
# ---------------------------------------------------------------

def test_auth_event_has_exactly_the_fifteen_keys_in_order():
    event = make_event(**valid_auth_arguments())
    assert list(event.keys()) == EVENT_KEYS


def test_auth_event_every_field():
    arguments = valid_auth_arguments()
    event = make_event(**arguments)
    assert event["event_id"].startswith("EVT-")
    assert len(event["event_id"]) == 4 + EVENT_ID_HEX_LENGTH
    assert event["event_type"] == "authentication"
    assert event["timestamp"] == utc_time(9, 15, 2)
    assert event["source_ip"] == "203.0.113.50"
    assert event["destination_ip"] == "10.0.0.5"
    assert event["destination_port"] is None
    assert event["protocol"] is None
    assert event["username"] == "admin"
    assert event["service"] == "ssh"
    assert event["status"] == "failure"
    assert event["bytes_sent"] is None
    assert event["bytes_received"] is None
    assert event["source_file"] == "auth_sample.csv"
    assert event["source_row"] == 2
    assert event["raw_event"] == arguments["raw_event"]


def test_network_event_every_field():
    event = make_event(**valid_network_arguments())
    assert list(event.keys()) == EVENT_KEYS
    assert event["event_type"] == "network_connection"
    assert event["destination_ip"] == "10.0.0.5"
    assert event["destination_port"] == 22
    assert event["protocol"] == "TCP"
    assert event["status"] == "rejected"
    assert event["bytes_sent"] == 60
    assert event["bytes_received"] == 0
    assert event["username"] is None
    assert event["service"] is None


def test_missing_optional_values_are_none_never_empty_or_zero():
    minimal = make_event("authentication", utc_time(9, 0, 0), "10.0.0.21", "success",
                         "auth_sample.csv", 2, {}, username="alice")
    for key in ["destination_ip", "destination_port", "protocol", "service", "bytes_sent", "bytes_received"]:
        assert minimal[key] is None
    network_minimal = make_event("network_connection", utc_time(9, 0, 0), "10.0.0.12", "allowed",
                                 "network_sample.csv", 2, {}, destination_ip="192.0.2.44")
    for key in ["destination_port", "protocol", "username", "service", "bytes_sent", "bytes_received"]:
        assert network_minimal[key] is None


def test_zero_bytes_stays_zero_and_is_not_confused_with_none():
    arguments = valid_network_arguments()
    arguments["bytes_sent"] = 0
    event = make_event(**arguments)
    assert event["bytes_sent"] == 0
    assert event["bytes_sent"] is not None


def test_event_raw_event_is_copied():
    arguments = valid_auth_arguments()
    event = make_event(**arguments)
    arguments["raw_event"]["username"] = "changed later"
    assert event["raw_event"]["username"] == "admin"


def test_event_boundary_values_are_accepted():
    arguments = valid_network_arguments()
    for port in [0, 65535]:
        arguments["destination_port"] = port
        assert make_event(**arguments)["destination_port"] == port
    auth_arguments = valid_auth_arguments()
    auth_arguments["username"] = "a" * 100
    auth_arguments["raw_event"] = {"cell": "x" * 500}
    auth_arguments["service"] = "s" * 30
    auth_arguments["source_ip"] = "2001:db8::1"
    assert make_event(**auth_arguments)["source_ip"] == "2001:db8::1"


def test_event_rejects_bad_authentication_values():
    bad_cases = [
        ("event_type", "firewall"), ("event_type", None),
        ("timestamp", datetime(2025, 3, 14, 9, 15, 2)),
        ("timestamp", "2025-03-14T09:15:02"), ("timestamp", None),
        ("source_ip", "999.1.1.1"), ("source_ip", "abc"), ("source_ip", ""),
        ("source_ip", " 203.0.113.50"), ("source_ip", "2001:DB8::1"), ("source_ip", None),
        ("status", "ok"), ("status", "allowed"), ("status", "FAILURE"), ("status", None),
        ("source_file", ""), ("source_file", None),
        ("source_file", "logs/auth.csv"), ("source_file", "C:\\logs\\auth.csv"),
        ("source_row", 1), ("source_row", 0), ("source_row", "2"), ("source_row", 2.0), ("source_row", True),
        ("raw_event", "text"), ("raw_event", None), ("raw_event", {"a": 5}),
        ("raw_event", {"a": "x" * 501}), ("raw_event", {5: "a"}),
        ("username", None), ("username", ""), ("username", " admin"), ("username", "a" * 101),
        ("username", "ad\x00min"), ("username", "ad\nmin"), ("username", 5),
        ("destination_ip", "not-an-ip"), ("destination_ip", ""),
        ("destination_port", 80),
        ("service", "SSH"), ("service", "x" * 31), ("service", ""), ("service", " ssh"),
        ("protocol", "tcp"), ("protocol", "TOOLONGPROTOCOL"),
        ("bytes_sent", -1), ("bytes_sent", 1.5), ("bytes_sent", "10"), ("bytes_sent", True),
        ("bytes_received", -5),
    ]
    check_every_bad_value_is_rejected(make_event, valid_auth_arguments(), bad_cases)


def test_event_rejects_bad_network_values():
    bad_cases = [
        ("status", "success"), ("status", "blocked"),
        ("destination_ip", None), ("destination_ip", "10.0.0"),
        ("destination_port", 65536), ("destination_port", -1),
        ("destination_port", "22"), ("destination_port", 22.0),
        ("username", "admin"),
        ("protocol", "tcp"), ("protocol", "TOOLONGPROTOCOL"),
        ("bytes_sent", -1), ("bytes_received", -5), ("bytes_received", 12.5),
    ]
    check_every_bad_value_is_rejected(make_event, valid_network_arguments(), bad_cases)


def test_event_error_message_lists_every_problem():
    arguments = valid_auth_arguments()
    arguments["source_ip"] = "999.1.1.1"
    arguments["status"] = "ok"
    with pytest.raises(ContractError) as error_info:
        make_event(**arguments)
    message = str(error_info.value)
    assert "source_ip" in message
    assert "status" in message


def test_event_timestamp_naive_is_rejected_and_aware_is_converted_to_utc():
    arguments = valid_auth_arguments()
    arguments["timestamp"] = datetime(2025, 3, 14, 9, 15, 2)
    with pytest.raises(ContractError):
        make_event(**arguments)
    five_hours_ahead = timezone(timedelta(hours=5))
    arguments["timestamp"] = datetime(2025, 3, 14, 14, 15, 2, tzinfo=five_hours_ahead)
    event = make_event(**arguments)
    assert event["timestamp"] == utc_time(9, 15, 2)
    assert event["timestamp"].utcoffset() == timedelta(0)


# ---------------------------------------------------------------
# validate_event
# ---------------------------------------------------------------

def test_validate_event_accepts_a_good_event():
    assert validate_event(make_event(**valid_auth_arguments())) == []
    assert validate_event(make_event(**valid_network_arguments())) == []


def test_validate_event_reports_every_missing_key():
    assert len(validate_event({})) == 15
    good_event = make_event(**valid_auth_arguments())
    for key in EVENT_KEYS:
        damaged = dict(good_event)
        del damaged[key]
        problems = validate_event(damaged)
        assert len(problems) == 1
        assert key in problems[0]


def test_validate_event_reports_several_missing_keys_at_once():
    damaged = make_event(**valid_auth_arguments())
    del damaged["username"]
    del damaged["status"]
    del damaged["raw_event"]
    assert len(validate_event(damaged)) == 3


def test_validate_event_rejects_non_dictionaries():
    for bad_value in [None, [], "event", 5]:
        assert len(validate_event(bad_value)) == 1


def test_validate_event_reports_unexpected_keys_and_bad_values():
    damaged = make_event(**valid_auth_arguments())
    damaged["extra_key"] = 1
    damaged["timestamp"] = datetime(2025, 3, 14, 9, 15, 2)
    damaged["status"] = "ok"
    problems = validate_event(damaged)
    assert len(problems) >= 3
    joined = " ".join(problems)
    assert "extra_key" in joined and "timestamp" in joined and "status" in joined


def test_validate_event_checks_the_event_id_format():
    good_event = make_event(**valid_auth_arguments())
    for bad_id in ["EVT-123", "ABC-0123456789abcdef", "EVT-0123456789ABCDEF", "", None]:
        damaged = dict(good_event)
        damaged["event_id"] = bad_id
        assert len(validate_event(damaged)) == 1


def test_validate_event_notices_a_missing_value_written_as_an_empty_string():
    damaged = make_event(**valid_auth_arguments())
    damaged["service"] = ""
    assert len(validate_event(damaged)) == 1


# ---------------------------------------------------------------
# Event IDs: golden values, determinism, occurrence, file name
# ---------------------------------------------------------------

def test_golden_event_ids_from_the_fixture():
    for case in load_expected_results()["golden_event_ids"]:
        event = make_event(**event_arguments_from_json(case["inputs"]))
        assert event["event_id"] == case["expected_event_id"], case["name"]


def test_golden_canonical_text_hashes_to_the_stored_event_id():
    # This test never calls make_event: it checks the stored values agree with each other.
    for case in load_expected_results()["golden_event_ids"]:
        full_hash = hashlib.sha256(case["canonical_text"].encode("utf-8")).hexdigest()
        assert "EVT-" + full_hash[:16] == case["expected_event_id"], case["name"]


def test_canonical_json_reproduces_the_golden_texts_exactly():
    results = load_expected_results()
    all_cases = results["golden_event_ids"] + results["golden_alert_ids"]
    all_cases.append(results["golden_content_fingerprint"])
    for case in all_cases:
        parsed_data = json.loads(case["canonical_text"])
        assert canonical_json(parsed_data) == case["canonical_text"], case["name"]


def test_spec_sample_row_canonical_text_is_the_text_in_the_specification():
    first_case = load_expected_results()["golden_event_ids"][0]
    expected_text = (
        '{"bytes_received":null,"bytes_sent":null,"destination_ip":"10.0.0.5","destination_port":null,'
        '"event_type":"authentication","occurrence":1,"protocol":null,"service":"ssh",'
        '"source_file":"auth_sample.csv","source_ip":"203.0.113.50","status":"failure",'
        '"timestamp":"2025-03-14T09:15:02.000000+00:00","username":"admin"}'
    )
    assert first_case["canonical_text"] == expected_text


def test_event_id_is_deterministic():
    first = make_event(**valid_auth_arguments())["event_id"]
    second = make_event(**valid_auth_arguments())["event_id"]
    assert first == second


def test_same_file_re_uploaded_gives_identical_id_lists():
    def ids_for_one_upload():
        ids = []
        for occurrence_number in [1, 1, 2, 3]:
            arguments = valid_auth_arguments()
            arguments["occurrence"] = occurrence_number
            ids.append(make_event(**arguments)["event_id"])
        return ids
    assert ids_for_one_upload() == ids_for_one_upload()


def test_repeated_identical_rows_get_different_ids():
    ids = []
    for occurrence_number in [1, 2, 3]:
        arguments = valid_auth_arguments()
        arguments["occurrence"] = occurrence_number
        ids.append(make_event(**arguments)["event_id"])
    assert len(set(ids)) == 3


def test_different_file_names_give_different_ids():
    first_arguments = valid_auth_arguments()
    second_arguments = valid_auth_arguments()
    second_arguments["source_file"] = "auth_copy.csv"
    assert make_event(**first_arguments)["event_id"] != make_event(**second_arguments)["event_id"]


def test_source_row_and_raw_event_are_not_part_of_the_id():
    first_arguments = valid_auth_arguments()
    second_arguments = valid_auth_arguments()
    second_arguments["source_row"] = 99
    second_arguments["raw_event"] = {"completely": "different"}
    assert make_event(**first_arguments)["event_id"] == make_event(**second_arguments)["event_id"]


def test_every_network_content_field_changes_the_id():
    base_id = make_event(**valid_network_arguments())["event_id"]
    changes = [
        ("timestamp", utc_time(9, 16, 1)), ("source_ip", "203.0.113.51"),
        ("destination_ip", "10.0.0.6"), ("destination_port", 23), ("protocol", "UDP"),
        ("status", "allowed"), ("bytes_sent", 61), ("bytes_received", 1), ("service", "ssh"),
    ]
    for field_name, new_value in changes:
        arguments = valid_network_arguments()
        arguments[field_name] = new_value
        assert make_event(**arguments)["event_id"] != base_id, field_name


def test_every_authentication_content_field_changes_the_id():
    base_id = make_event(**valid_auth_arguments())["event_id"]
    changes = [
        ("username", "Admin"), ("service", "rdp"), ("status", "success"),
        ("destination_ip", "10.0.0.6"), ("source_ip", "203.0.113.51"),
        ("timestamp", utc_time(9, 15, 3)), ("protocol", "TCP"), ("bytes_sent", 1),
    ]
    for field_name, new_value in changes:
        arguments = valid_auth_arguments()
        arguments[field_name] = new_value
        assert make_event(**arguments)["event_id"] != base_id, field_name


def test_same_instant_written_in_different_zones_gives_the_same_id():
    utc_arguments = valid_auth_arguments()
    zone_arguments = valid_auth_arguments()
    zone_arguments["timestamp"] = datetime(2025, 3, 14, 14, 15, 2, tzinfo=timezone(timedelta(hours=5)))
    assert make_event(**utc_arguments)["event_id"] == make_event(**zone_arguments)["event_id"]


def test_half_a_second_makes_a_different_id():
    whole_arguments = valid_auth_arguments()
    half_arguments = valid_auth_arguments()
    half_arguments["timestamp"] = utc_time(9, 15, 2) + timedelta(milliseconds=500)
    assert make_event(**whole_arguments)["event_id"] != make_event(**half_arguments)["event_id"]


def test_none_empty_text_and_the_word_none_give_three_different_ids():
    ids = []
    for username_value in [None, "", "None"]:
        content = valid_content()
        content["username"] = username_value
        ids.append(make_event_id(content, "auth_sample.csv", 1))
    assert len(set(ids)) == 3


def test_a_pipe_character_cannot_make_two_events_collide():
    first_content = valid_content()
    first_content["username"] = "a|b"
    first_content["service"] = "c"
    second_content = valid_content()
    second_content["username"] = "a"
    second_content["service"] = "b|c"
    assert make_event_id(first_content, "f.csv", 1) != make_event_id(second_content, "f.csv", 1)


def test_non_english_usernames_and_quotes_are_handled():
    for username in ["Zoë", "名前", 'say "hi"', "back\\slash", "emoji😀"]:
        arguments = valid_auth_arguments()
        arguments["username"] = username
        event = make_event(**arguments)
        assert validate_event(event) == []


def test_make_event_id_rejects_bad_occurrence():
    for bad_occurrence in [0, -1, "1", 1.0, True, None]:
        with pytest.raises(ContractError):
            make_event_id(valid_content(), "auth_sample.csv", bad_occurrence)


def test_make_event_id_rejects_bad_file_names():
    for bad_name in ["", None, "a/b.csv", "a\\b.csv", 5, "   "]:
        with pytest.raises(ContractError):
            make_event_id(valid_content(), bad_name, 1)


def test_make_event_id_rejects_bad_content():
    missing_key = valid_content()
    del missing_key["status"]
    extra_key = valid_content()
    extra_key["source_row"] = 2
    naive_time = valid_content()
    naive_time["timestamp"] = datetime(2025, 3, 14, 9, 15, 2)
    text_time = valid_content()
    text_time["timestamp"] = "2025-03-14T09:15:02"
    for bad_content in [missing_key, extra_key, naive_time, text_time, "text", None]:
        with pytest.raises(ContractError):
            make_event_id(bad_content, "auth_sample.csv", 1)


def test_make_event_id_does_not_modify_the_content_dictionary():
    content = valid_content()
    copy_before = dict(content)
    make_event_id(content, "auth_sample.csv", 1)
    assert content == copy_before


# ---------------------------------------------------------------
# Content fingerprint
# ---------------------------------------------------------------

def test_golden_content_fingerprint():
    case = load_expected_results()["golden_content_fingerprint"]
    event = make_event(**event_arguments_from_json(case["inputs"]))
    assert make_content_fingerprint(event) == case["expected_fingerprint"]
    independent_hash = hashlib.sha256(case["canonical_text"].encode("utf-8")).hexdigest()
    assert independent_hash == case["expected_fingerprint"]


def test_fingerprint_is_full_length_hex():
    fingerprint = make_content_fingerprint(make_event(**valid_auth_arguments()))
    assert len(fingerprint) == 64
    for character in fingerprint:
        assert character in "0123456789abcdef"


def test_fingerprint_ignores_file_name_occurrence_row_and_raw_event():
    first = make_event(**valid_auth_arguments())
    other_arguments = valid_auth_arguments()
    other_arguments["source_file"] = "auth_copy.csv"
    other_arguments["occurrence"] = 5
    other_arguments["source_row"] = 40
    other_arguments["raw_event"] = {"different": "row"}
    second = make_event(**other_arguments)
    assert first["event_id"] != second["event_id"]
    assert make_content_fingerprint(first) == make_content_fingerprint(second)


def test_fingerprint_changes_when_content_changes():
    first = make_event(**valid_auth_arguments())
    other_arguments = valid_auth_arguments()
    other_arguments["username"] = "root"
    assert make_content_fingerprint(first) != make_content_fingerprint(make_event(**other_arguments))


def test_fingerprint_rejects_bad_events():
    incomplete = make_event(**valid_auth_arguments())
    del incomplete["status"]
    for bad_event in [incomplete, "text", None, {}]:
        with pytest.raises(ContractError):
            make_content_fingerprint(bad_event)


# ---------------------------------------------------------------
# Alert IDs
# ---------------------------------------------------------------

def alert_id_from_inputs(inputs):
    return make_alert_id(
        inputs["rule_id"], inputs["source_ip"],
        datetime.fromisoformat(inputs["time_start"]), datetime.fromisoformat(inputs["time_end"]),
        inputs["event_ids"],
    )


def test_golden_alert_ids_from_the_fixture():
    for case in load_expected_results()["golden_alert_ids"]:
        assert alert_id_from_inputs(case["inputs"]) == case["expected_alert_id"], case["name"]


def test_golden_alert_canonical_text_hashes_to_the_stored_alert_id():
    for case in load_expected_results()["golden_alert_ids"]:
        full_hash = hashlib.sha256(case["canonical_text"].encode("utf-8")).hexdigest()
        assert "ALT-" + full_hash[:16] == case["expected_alert_id"], case["name"]


def test_alert_id_shape():
    alert_id = make_alert_id("NET_PORT_SCAN", "203.0.113.50", utc_time(9, 16, 0), utc_time(9, 16, 30),
                             ["EVT-aaaaaaaaaaaaaaaa"])
    assert alert_id.startswith("ALT-")
    assert len(alert_id) == 4 + EVENT_ID_HEX_LENGTH


def test_alert_id_is_deterministic():
    first = alert_id_from_inputs(load_expected_results()["golden_alert_ids"][0]["inputs"])
    second = alert_id_from_inputs(load_expected_results()["golden_alert_ids"][0]["inputs"])
    assert first == second


def test_shuffled_event_ids_give_the_same_alert_id_and_the_list_is_not_changed():
    ordered = ["EVT-aaaaaaaaaaaaaaaa", "EVT-bbbbbbbbbbbbbbbb", "EVT-cccccccccccccccc"]
    shuffled = ["EVT-cccccccccccccccc", "EVT-aaaaaaaaaaaaaaaa", "EVT-bbbbbbbbbbbbbbbb"]
    shuffled_before = list(shuffled)
    first = make_alert_id("NET_PORT_SCAN", "203.0.113.50", utc_time(9, 16, 0), utc_time(9, 16, 30), ordered)
    second = make_alert_id("NET_PORT_SCAN", "203.0.113.50", utc_time(9, 16, 0), utc_time(9, 16, 30), shuffled)
    assert first == second
    assert shuffled == shuffled_before


def test_different_evidence_gives_a_different_alert_id():
    start, end = utc_time(9, 16, 0), utc_time(9, 16, 30)
    first = make_alert_id("NET_PORT_SCAN", "203.0.113.50", start, end, ["EVT-aaaaaaaaaaaaaaaa"])
    replaced = make_alert_id("NET_PORT_SCAN", "203.0.113.50", start, end, ["EVT-bbbbbbbbbbbbbbbb"])
    extra = make_alert_id("NET_PORT_SCAN", "203.0.113.50", start, end,
                          ["EVT-aaaaaaaaaaaaaaaa", "EVT-bbbbbbbbbbbbbbbb"])
    assert len({first, replaced, extra}) == 3


def test_every_other_alert_id_input_changes_the_id():
    event_ids = ["EVT-aaaaaaaaaaaaaaaa"]
    start, end = utc_time(9, 16, 0), utc_time(9, 16, 30)
    base_id = make_alert_id("NET_PORT_SCAN", "203.0.113.50", start, end, event_ids)
    changed_ids = [
        make_alert_id("NET_REPEATED_REJECTS", "203.0.113.50", start, end, event_ids),
        make_alert_id("NET_PORT_SCAN", "203.0.113.51", start, end, event_ids),
        make_alert_id("NET_PORT_SCAN", "203.0.113.50", utc_time(9, 16, 1), end, event_ids),
        make_alert_id("NET_PORT_SCAN", "203.0.113.50", start, utc_time(9, 16, 31), event_ids),
        make_alert_id("NET_PORT_SCAN", None, start, end, event_ids),
    ]
    for changed_id in changed_ids:
        assert changed_id != base_id
    assert len(set(changed_ids)) == len(changed_ids)


def test_none_and_empty_text_source_ip_give_different_alert_ids():
    start, end = utc_time(9, 16, 0), utc_time(9, 16, 30)
    with_none = make_alert_id("NET_PORT_SCAN", None, start, end, ["EVT-aaaaaaaaaaaaaaaa"])
    with_empty = make_alert_id("NET_PORT_SCAN", "", start, end, ["EVT-aaaaaaaaaaaaaaaa"])
    assert with_none != with_empty


def test_alert_id_rejects_bad_event_id_lists():
    start, end = utc_time(9, 16, 0), utc_time(9, 16, 30)
    bad_lists = [[], "EVT-aaaaaaaaaaaaaaaa", None, [1, 2], ["EVT-aaaaaaaaaaaaaaaa", 5], [""],
                 ["EVT-aaaaaaaaaaaaaaaa", "EVT-aaaaaaaaaaaaaaaa"], ("EVT-aaaaaaaaaaaaaaaa",)]
    for bad_list in bad_lists:
        with pytest.raises(ContractError):
            make_alert_id("NET_PORT_SCAN", "203.0.113.50", start, end, bad_list)


def test_alert_id_rejects_bad_other_inputs():
    good_ids = ["EVT-aaaaaaaaaaaaaaaa"]
    start, end = utc_time(9, 16, 0), utc_time(9, 16, 30)
    naive_time = datetime(2025, 3, 14, 9, 16, 0)
    with pytest.raises(ContractError):
        make_alert_id("", "203.0.113.50", start, end, good_ids)
    with pytest.raises(ContractError):
        make_alert_id("NET_PORT_SCAN", 5, start, end, good_ids)
    with pytest.raises(ContractError):
        make_alert_id("NET_PORT_SCAN", "203.0.113.50", naive_time, end, good_ids)
    with pytest.raises(ContractError):
        make_alert_id("NET_PORT_SCAN", "203.0.113.50", start, "2025-03-14T09:16:30", good_ids)


# ---------------------------------------------------------------
# make_alert
# ---------------------------------------------------------------

def test_alert_has_exactly_the_thirteen_keys_in_order():
    alert = make_alert(**valid_alert_arguments())
    assert list(alert.keys()) == ALERT_KEYS


def test_alert_every_field():
    arguments = valid_alert_arguments()
    alert = make_alert(**arguments)
    assert alert["alert_id"].startswith("ALT-")
    assert alert["rule_id"] == "NET_PORT_SCAN"
    assert alert["title"] == "Possible port scanning activity"
    assert alert["description"] == "A possible port scan was recorded."
    assert alert["severity"] == "medium"
    assert alert["confidence"] == "high"
    assert alert["detected_at"] == utc_time(10, 0, 0)
    assert alert["time_start"] == utc_time(9, 16, 0)
    assert alert["time_end"] == utc_time(9, 16, 17)
    assert alert["source_ip"] == "203.0.113.50"
    assert alert["event_ids"] == ["EVT-aaaaaaaaaaaaaaaa", "EVT-bbbbbbbbbbbbbbbb"]
    assert alert["evidence"] == arguments["evidence"]
    assert alert["recommended_action"] == "Check whether the source is an authorised scanner."


def test_alert_detected_at_defaults_to_now():
    arguments = valid_alert_arguments()
    del arguments["detected_at"]
    before = utc_now()
    alert = make_alert(**arguments)
    after = utc_now()
    assert before <= alert["detected_at"] <= after
    assert alert["detected_at"].utcoffset() == timedelta(0)


def test_alert_keeps_event_ids_in_the_given_order_and_copies_the_list():
    arguments = valid_alert_arguments()
    arguments["event_ids"] = ["EVT-bbbbbbbbbbbbbbbb", "EVT-aaaaaaaaaaaaaaaa"]
    original_list = arguments["event_ids"]
    alert = make_alert(**arguments)
    assert alert["event_ids"] == ["EVT-bbbbbbbbbbbbbbbb", "EVT-aaaaaaaaaaaaaaaa"]
    assert alert["event_ids"] is not original_list
    original_list.append("EVT-cccccccccccccccc")
    assert len(alert["event_ids"]) == 2


def test_alert_id_from_make_alert_matches_make_alert_id():
    arguments = valid_alert_arguments()
    alert = make_alert(**arguments)
    expected_id = make_alert_id(arguments["rule_id"], arguments["source_ip"], arguments["time_start"],
                                arguments["time_end"], arguments["event_ids"])
    assert alert["alert_id"] == expected_id


def test_alert_id_ignores_severity_confidence_and_wording():
    first = make_alert(**valid_alert_arguments())
    other_arguments = valid_alert_arguments()
    other_arguments["severity"] = "high"
    other_arguments["confidence"] = "low"
    other_arguments["description"] = "Different words."
    other_arguments["evidence"]["observed"] = {"distinct_port_count": 99}
    assert make_alert(**other_arguments)["alert_id"] == first["alert_id"]


def test_alert_none_source_ip_and_equal_start_and_end_are_allowed():
    arguments = valid_alert_arguments()
    arguments["source_ip"] = None
    arguments["time_end"] = arguments["time_start"]
    alert = make_alert(**arguments)
    assert alert["source_ip"] is None
    assert validate_alert(alert) == []


def test_alert_aware_times_are_converted_to_utc():
    arguments = valid_alert_arguments()
    five_hours_ahead = timezone(timedelta(hours=5))
    arguments["time_start"] = datetime(2025, 3, 14, 14, 16, 0, tzinfo=five_hours_ahead)
    alert = make_alert(**arguments)
    assert alert["time_start"] == utc_time(9, 16, 0)
    assert alert["time_start"].utcoffset() == timedelta(0)


def test_correlated_alert_with_a_correlation_block_is_valid():
    arguments = valid_alert_arguments()
    arguments["rule_id"] = "CORR_AUTH_NET"
    arguments["evidence"]["correlation"] = valid_correlation_block()
    alert = make_alert(**arguments)
    assert validate_alert(alert) == []


def test_alert_rejects_bad_values():
    bad_cases = [
        ("rule_id", "BAD_RULE"), ("rule_id", None),
        ("title", ""), ("title", None), ("description", "   "), ("recommended_action", ""),
        ("severity", "urgent"), ("severity", "HIGH"), ("confidence", "certain"), ("confidence", None),
        ("time_start", datetime(2025, 3, 14, 9, 16, 0)), ("time_end", "2025-03-14T09:16:17"),
        ("time_end", utc_time(9, 15, 59)),
        ("detected_at", datetime(2025, 3, 14, 10, 0, 0)),
        ("source_ip", "bad"), ("source_ip", ""), ("source_ip", 5),
        ("event_ids", []), ("event_ids", "EVT-aaaaaaaaaaaaaaaa"), ("event_ids", [1]),
        ("event_ids", ["EVT-a", "EVT-a"]), ("event_ids", None),
        ("evidence", None), ("evidence", []), ("evidence", {}),
    ]
    check_every_bad_value_is_rejected(make_alert, valid_alert_arguments(), bad_cases)


def test_alert_rejects_missing_or_wrong_evidence_parts():
    for missing_key in ["rule_parameters", "observed", "explanation", "limitations"]:
        arguments = valid_alert_arguments()
        del arguments["evidence"][missing_key]
        with pytest.raises(ContractError):
            make_alert(**arguments)
    wrong_types = [("rule_parameters", []), ("observed", "text"), ("explanation", "one sentence"),
                   ("limitations", ["fine", 5]), ("explanation", None)]
    for key, bad_value in wrong_types:
        arguments = valid_alert_arguments()
        arguments["evidence"][key] = bad_value
        with pytest.raises(ContractError):
            make_alert(**arguments)


def test_alert_rejects_evidence_that_cannot_become_json():
    for bad_value in [utc_time(9, 0, 0), {1, 2}, float("nan")]:
        arguments = valid_alert_arguments()
        arguments["evidence"]["observed"] = {"bad": bad_value}
        with pytest.raises(ContractError):
            make_alert(**arguments)


def test_correlated_alert_rejects_a_missing_or_broken_correlation_block():
    arguments = valid_alert_arguments()
    arguments["rule_id"] = "CORR_AUTH_NET"
    with pytest.raises(ContractError):
        make_alert(**arguments)
    for missing_key in ["link_key", "link_value", "linked_alert_ids", "gap_seconds",
                        "destination_match", "match_conditions"]:
        broken_arguments = valid_alert_arguments()
        broken_arguments["rule_id"] = "CORR_AUTH_NET"
        block = valid_correlation_block()
        del block[missing_key]
        broken_arguments["evidence"]["correlation"] = block
        with pytest.raises(ContractError):
            make_alert(**broken_arguments)
    wrong_values = [("link_key", "username"), ("linked_alert_ids", ["ALT-1111111111111111"]),
                    ("gap_seconds", -1), ("destination_match", "yes")]
    for key, bad_value in wrong_values:
        broken_arguments = valid_alert_arguments()
        broken_arguments["rule_id"] = "CORR_AUTH_NET"
        block = valid_correlation_block()
        block[key] = bad_value
        broken_arguments["evidence"]["correlation"] = block
        with pytest.raises(ContractError):
            make_alert(**broken_arguments)


def test_alert_error_message_lists_every_problem():
    arguments = valid_alert_arguments()
    arguments["severity"] = "urgent"
    arguments["event_ids"] = []
    with pytest.raises(ContractError) as error_info:
        make_alert(**arguments)
    message = str(error_info.value)
    assert "severity" in message
    assert "event_ids" in message


# ---------------------------------------------------------------
# validate_alert
# ---------------------------------------------------------------

def test_validate_alert_accepts_a_good_alert():
    assert validate_alert(make_alert(**valid_alert_arguments())) == []


def test_validate_alert_reports_every_missing_key():
    assert len(validate_alert({})) == 13
    good_alert = make_alert(**valid_alert_arguments())
    for key in ALERT_KEYS:
        damaged = dict(good_alert)
        del damaged[key]
        problems = validate_alert(damaged)
        assert len(problems) == 1
        assert key in problems[0]


def test_validate_alert_rejects_non_dictionaries():
    for bad_value in [None, [], "alert", 5]:
        assert len(validate_alert(bad_value)) == 1


def test_validate_alert_checks_the_four_required_evidence_keys():
    good_alert = make_alert(**valid_alert_arguments())
    for key in ["rule_parameters", "observed", "explanation", "limitations"]:
        damaged = dict(good_alert)
        damaged["evidence"] = dict(good_alert["evidence"])
        del damaged["evidence"][key]
        problems = validate_alert(damaged)
        assert len(problems) == 1
        assert key in problems[0]


def test_validate_alert_reports_a_missing_correlation_block():
    arguments = valid_alert_arguments()
    arguments["rule_id"] = "CORR_AUTH_NET"
    arguments["evidence"]["correlation"] = valid_correlation_block()
    good_alert = make_alert(**arguments)
    damaged = dict(good_alert)
    damaged["evidence"] = dict(good_alert["evidence"])
    del damaged["evidence"]["correlation"]
    problems = validate_alert(damaged)
    assert len(problems) == 1
    assert "correlation" in problems[0]


def test_validate_alert_reports_unexpected_keys_bad_values_and_bad_id():
    damaged = make_alert(**valid_alert_arguments())
    damaged["extra_key"] = 1
    damaged["severity"] = "urgent"
    damaged["time_end"] = datetime(2025, 3, 14, 9, 16, 17)
    damaged["alert_id"] = "ALT-short"
    joined = " ".join(validate_alert(damaged))
    for word in ["extra_key", "severity", "time_end", "alert_id"]:
        assert word in joined


# ---------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------

EXPECTED_DEFAULTS = {
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
    "volume_min_bytes": 10000000,
    "volume_multiplier": 5.0,
    "volume_min_windows": 6,
    "volume_min_coverage": 0.5,
    "correlation_window_seconds": 900,
}


def test_default_config_has_every_key_and_value_from_fs35():
    config = get_default_config()
    assert config == EXPECTED_DEFAULTS
    assert len(config) == 17


def test_default_config_returns_a_fresh_copy_each_time():
    first = get_default_config()
    first["trusted_ips"].append("10.0.0.1")
    first["auth_failed_threshold"] = 99
    second = get_default_config()
    assert second["trusted_ips"] == []
    assert second["auth_failed_threshold"] == 5
    assert DEFAULT_CONFIG["trusted_ips"] == []


def test_volume_minimum_is_exactly_ten_million_decimal_bytes():
    config = get_default_config()
    assert config["volume_min_bytes"] == 10000000
    assert config["volume_min_bytes"] == 10 * 1000 * 1000
    assert config["volume_min_bytes"] != 10 * 1024 * 1024  # 10,485,760 is wrong
    assert load_expected_results()["config_golden"]["volume_min_bytes"] == 10000000


def test_validate_config_of_empty_dictionary_gives_the_defaults():
    assert validate_config({}) == EXPECTED_DEFAULTS


def test_validate_config_fills_missing_keys_and_keeps_given_values():
    checked = validate_config({"auth_failed_threshold": 3, "assume_utc": False})
    assert checked["auth_failed_threshold"] == 3
    assert checked["assume_utc"] is False
    assert checked["reject_threshold"] == 20


def test_validate_config_returns_a_copy_and_leaves_the_input_alone():
    given = {"trusted_ips": ["10.0.0.1"]}
    checked = validate_config(given)
    assert checked is not given
    assert given == {"trusted_ips": ["10.0.0.1"]}
    checked["trusted_ips"].append("10.0.0.2")
    assert given["trusted_ips"] == ["10.0.0.1"]


def test_validate_config_accepts_a_whole_number_multiplier_and_stores_a_float():
    checked = validate_config({"volume_multiplier": 4})
    assert checked["volume_multiplier"] == 4.0
    assert isinstance(checked["volume_multiplier"], float)


def test_validate_config_accepts_coverage_of_exactly_one():
    assert validate_config({"volume_min_coverage": 1})["volume_min_coverage"] == 1.0


def test_validate_config_normalises_trusted_addresses():
    checked = validate_config({"trusted_ips": [" 203.0.113.50 ", "2001:DB8::1"]})
    assert checked["trusted_ips"] == ["203.0.113.50", "2001:db8::1"]


def test_validate_config_rejects_bad_whole_numbers():
    whole_number_keys = [
        "max_upload_mb", "max_rows_per_file", "auth_failed_threshold", "auth_window_seconds",
        "auth_success_after_failure_seconds", "portscan_distinct_ports_threshold",
        "portscan_window_seconds", "reject_threshold", "reject_window_seconds",
        "volume_window_seconds", "volume_min_bytes", "volume_min_windows", "correlation_window_seconds",
    ]
    assert len(whole_number_keys) == 13
    for key in whole_number_keys:
        for bad_value in [0, -1, "5", 5.5, True, None, [5]]:
            with pytest.raises(ConfigError):
                validate_config({key: bad_value})


def test_validate_config_rejects_bad_decimal_settings():
    for key in ["volume_multiplier", "volume_min_coverage"]:
        for bad_value in [0, -1.0, "5", True, None, float("nan"), float("inf")]:
            with pytest.raises(ConfigError):
                validate_config({key: bad_value})
    for too_big in [1.5, 2]:
        with pytest.raises(ConfigError):
            validate_config({"volume_min_coverage": too_big})


def test_validate_config_rejects_bad_assume_utc():
    for bad_value in ["yes", 1, 0, None]:
        with pytest.raises(ConfigError):
            validate_config({"assume_utc": bad_value})


def test_validate_config_rejects_bad_trusted_ips():
    for bad_value in ["10.0.0.1", [5], ["not-an-ip"], ["10.0.0.1", ""], ("10.0.0.1",), None, ["10.0.0.256"]]:
        with pytest.raises(ConfigError):
            validate_config({"trusted_ips": bad_value})


def test_validate_config_rejects_non_dictionaries_and_unknown_keys():
    for bad_value in [None, [], "config", 5]:
        with pytest.raises(ConfigError):
            validate_config(bad_value)
    with pytest.raises(ConfigError):
        validate_config({"auth_failed_treshold": 3})  # a typo must not be ignored silently


# ---------------------------------------------------------------
# Sample files and the expected-results fixture
# ---------------------------------------------------------------

AUTH_HEADER = ["timestamp", "source_ip", "username", "status", "destination_ip", "service"]
NETWORK_HEADER = ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol",
                  "status", "bytes_sent", "bytes_received"]


def read_sample_rows(file_name):
    with open(SAMPLE_FOLDER / file_name, encoding="utf-8", newline="") as file_handle:
        return list(csv.reader(file_handle))


def test_sample_headers_match_section_d():
    assert read_sample_rows("auth_sample.csv")[0] == AUTH_HEADER
    assert read_sample_rows("network_sample.csv")[0] == NETWORK_HEADER


def test_sample_row_counts_match_the_fixture():
    sample_info = load_expected_results()["sample_files"]
    assert len(read_sample_rows("auth_sample.csv")) - 1 == sample_info["auth_sample.csv"]["data_rows"]
    assert len(read_sample_rows("network_sample.csv")) - 1 == sample_info["network_sample.csv"]["data_rows"]


def test_authentication_sample_rows_follow_section_d3():
    rows = read_sample_rows("auth_sample.csv")
    for row in rows[1:]:
        assert len(row) == len(AUTH_HEADER)
        datetime.fromisoformat(row[0])
        ipaddress.ip_address(row[1])
        assert row[2] != "" and len(row[2]) <= 100
        assert row[3] in AUTH_STATUSES
        if row[4] != "":
            ipaddress.ip_address(row[4])
        assert row[5] == row[5].lower()


def test_network_sample_rows_follow_section_d4():
    rows = read_sample_rows("network_sample.csv")
    for row in rows[1:]:
        assert len(row) == len(NETWORK_HEADER)
        datetime.fromisoformat(row[0])
        ipaddress.ip_address(row[1])
        ipaddress.ip_address(row[2])
        if row[3] != "":
            assert 0 <= int(row[3]) <= 65535
        assert row[4] == row[4].upper()
        assert row[5] in NETWORK_STATUSES
        for byte_text in [row[6], row[7]]:
            assert byte_text == "" or byte_text.isdigit()


def test_sample_files_use_only_documentation_or_private_addresses():
    allowed_networks = []
    for network_text in ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24", "10.0.0.0/8"]:
        allowed_networks.append(ipaddress.ip_network(network_text))
    for file_name, address_columns in [("auth_sample.csv", [1, 4]), ("network_sample.csv", [1, 2])]:
        for row in read_sample_rows(file_name)[1:]:
            for column_number in address_columns:
                if row[column_number] == "":
                    continue
                address = ipaddress.ip_address(row[column_number])
                assert any(address in network for network in allowed_networks), row[column_number]


def test_sample_data_contains_the_planned_suspicious_patterns():
    auth_rows = read_sample_rows("auth_sample.csv")[1:]
    network_rows = read_sample_rows("network_sample.csv")[1:]
    brute_force_failures = [r for r in auth_rows if r[1] == "203.0.113.50" and r[3] == "failure"]
    assert len(brute_force_failures) == 8
    scan_rows = [r for r in network_rows if r[1] == "203.0.113.50"]
    assert len({r[3] for r in scan_rows}) == 18
    reject_rows = [r for r in network_rows if r[1] == "10.0.0.31" and r[5] == "rejected"]
    assert len(reject_rows) == 20
    volume_rows = [r for r in network_rows if r[1] == "10.0.0.40"]
    assert max(int(r[6]) for r in volume_rows) == 12000000


def test_expected_alerts_use_allowed_values():
    results = load_expected_results()
    assert len(results["expected_alerts"]) == results["expected_base_alert_count"] + results["expected_correlated_alert_count"]
    for expected_alert in results["expected_alerts"]:
        assert expected_alert["rule_id"] in RULE_IDS
        assert expected_alert["severity"] in SEVERITIES
        assert expected_alert["confidence"] in CONFIDENCES
        ipaddress.ip_address(expected_alert["source_ip"])
        assert datetime.fromisoformat(expected_alert["time_start"]) <= datetime.fromisoformat(expected_alert["time_end"])
