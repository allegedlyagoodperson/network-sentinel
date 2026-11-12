# tests/test_ingestion.py
# ---------------------------------------------------------------
# Purpose: tests for the ingestion module (Stage 1A): validators.py and csv_ingest.py.
# Expected values come from the frozen specification (Section D, C.1, FS.3.1, R1.9),
# the Stage 0 golden values in expected_results.json, or an independent hash
# worked out here with hashlib and json (not with project code).
# Style: plain functions with assert. No decorators (Section 0.1), so cases
# that used to be "parametrised" are simple loops with a message.
# Uses: ingestion/, core/contracts.py, core/errors.py, config/settings.py and
# the files in tests/fixtures/ (ingestion_*.csv and expected_results.json).

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from config.settings import get_default_config
from core.contracts import CONTRACT_VERSION, EVENT_KEYS, validate_event
from core.errors import IngestionError, NetworkSentinelError
from ingestion.csv_ingest import combine_ingestion_results, ingest_file
from ingestion.validators import (
    check_columns,
    clean_text_value,
    normalise_status,
    parse_ip_address,
    parse_optional_non_negative_int,
    parse_port,
    parse_timestamp,
)

TESTS_FOLDER = Path(__file__).parent
FIXTURE_FOLDER = TESTS_FOLDER / "fixtures"
SAMPLE_FOLDER = TESTS_FOLDER.parent / "data" / "sample"
AUTH = "authentication"
NETWORK = "network_connection"
AUTH_HEADER = "timestamp,source_ip,username,status,destination_ip,service"
NETWORK_HEADER = "timestamp,source_ip,destination_ip,destination_port,protocol,status,bytes_sent,bytes_received"
GOOD_AUTH_ROW = "2025-03-14T09:15:02,203.0.113.50,admin,failure,10.0.0.5,ssh"


# ---------------------------------------------------------------
# Small helpers used by many tests
# ---------------------------------------------------------------

def make_config():
    return get_default_config()


def read_fixture(name):
    return (FIXTURE_FOLDER / name).read_bytes()


def ingest_fixture(name, log_type, file_name=None):
    if file_name is None:
        file_name = name
    return ingest_file(read_fixture(name), file_name, log_type, make_config())


def ingest_text(text, log_type=AUTH, file_name="test.csv", config=None):
    if config is None:
        config = make_config()
    return ingest_file(text.encode("utf-8"), file_name, log_type, config)


def auth_file_text(rows):
    return AUTH_HEADER + "\n" + "\n".join(rows) + "\n"


def event_ids(result):
    ids = []
    for event in result["events"]:
        ids.append(event["event_id"])
    return ids


def expect_ingestion_error(file_bytes, file_name, log_type, config=None):
    if config is None:
        config = make_config()
    with pytest.raises(IngestionError) as error_info:
        ingest_file(file_bytes, file_name, log_type, config)
    return str(error_info.value)


def expect_value_error(function, first_argument):
    with pytest.raises(ValueError):
        function(first_argument)


def expect_value_error_two(function, first_argument, second_argument):
    with pytest.raises(ValueError):
        function(first_argument, second_argument)


# ---------------------------------------------------------------
# Common acceptance criterion 5
# ---------------------------------------------------------------

def test_contract_version_is_one_point_zero():
    assert CONTRACT_VERSION == 1.0


# ---------------------------------------------------------------
# validators.py: timestamps (D.2)
# ---------------------------------------------------------------

def test_timestamp_accepted_forms_all_give_utc():
    expected = datetime(2025, 3, 14, 9, 15, 2, tzinfo=timezone.utc)
    accepted_texts = [
        "2025-03-14T09:15:02",
        "2025-03-14 09:15:02",
        "2025-03-14T09:15:02Z",
        "2025-03-14T09:15:02+00:00",
        "2025-03-14T14:15:02+05:00",
        "2025-03-14T05:45:02-03:30",
        "  2025-03-14T09:15:02  ",
    ]
    for text in accepted_texts:
        result = parse_timestamp(text)
        assert result == expected, text
        assert result.utcoffset().total_seconds() == 0, text


def test_timestamp_fractional_seconds():
    assert parse_timestamp("2025-03-14T09:15:02.5").microsecond == 500000
    assert parse_timestamp("2025-03-14T09:15:02.123456Z").microsecond == 123456
    assert parse_timestamp("2025-03-14T09:15:02.25+01:00").hour == 8


def test_timestamp_rejected_forms():
    rejected_texts = [
        "14/03/2025 09:15:02",      # day-first is ambiguous (D.2)
        "03/14/2025 09:15:02",      # month-first
        "1741943702",               # Unix number
        "yesterday",                # free text
        "",                         # empty
        "2025-03-14",               # no time
        "2025-02-31T09:15:02",      # impossible date
        "2025-13-01T09:15:02",      # impossible month
        "2025-03-14T24:00:00",      # impossible hour
        "2025-03-14T09:15:60",      # impossible second
        "2025-03-14T09:15:02+0100", # offset needs a colon
        "2025-03-14T09:15:02+24:00",
        "2025-03-14T09:15:02.1234567",  # more than 6 fractional digits
        "2025-03-14T09:15:02.",
        "2025-03-14T09:15:02 UTC",
        "2025-03-14t09:15:02",
        "2025-03-14T09:15:02z",
        "２０２５-03-14T09:15:02",  # full-width digits are not 0-9
    ]
    for text in rejected_texts:
        expect_value_error(parse_timestamp, text)


def test_timestamp_sanity_range_is_2000_to_2100():
    assert parse_timestamp("2000-01-01T00:00:00Z").year == 2000
    assert parse_timestamp("2099-12-31T23:59:59Z").year == 2099
    expect_value_error(parse_timestamp, "1999-12-31T23:59:59Z")
    expect_value_error(parse_timestamp, "2100-01-01T00:00:01Z")
    # The range applies to the UTC time: this is 1999-12-31 23:30 UTC.
    expect_value_error(parse_timestamp, "2000-01-01T00:30:00+01:00")


def test_timestamp_assume_utc_false_refuses_text_without_a_zone():
    expect_value_error_two(parse_timestamp, "2025-03-14T09:15:02", False)
    assert parse_timestamp("2025-03-14T09:15:02Z", False).hour == 9
    assert parse_timestamp("2025-03-14T09:15:02+00:00", False).hour == 9


# ---------------------------------------------------------------
# validators.py: addresses, ports, numbers, status, text, columns
# ---------------------------------------------------------------

def test_ip_address_normalisation():
    assert parse_ip_address("203.0.113.50") == "203.0.113.50"
    assert parse_ip_address("  10.0.0.5 ") == "10.0.0.5"
    assert parse_ip_address("2001:DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert parse_ip_address("::1") == "::1"


def test_ip_address_rejections():
    for text in ["999.1.1.1", "abc", "", "   ", "10.0.0", "10.0.0.5.1", "10.0.0.256",
                 "010.0.0.1", "10.0.0.1/24", "fe80::1%eth0", "203.0.113.4 5", "<script>"]:
        expect_value_error(parse_ip_address, text)
    # A trailing newline is only surrounding whitespace, so it is trimmed.
    assert parse_ip_address("10.0.0.1\n") == "10.0.0.1"


def test_port_boundaries():
    assert parse_port("0") == 0
    assert parse_port("65535") == 65535
    assert parse_port(" 443 ") == 443
    assert parse_port("0080") == 80
    for text in ["65536", "-1", "+80", "80.0", "http", "", "1e3", "８０", "9" * 5000]:
        expect_value_error(parse_port, text)


def test_optional_non_negative_int():
    assert parse_optional_non_negative_int("") is None
    assert parse_optional_non_negative_int("   ") is None
    assert parse_optional_non_negative_int("0") == 0
    assert parse_optional_non_negative_int("15200") == 15200
    for text in ["-1", "-0", "1,200", "12.5", "1e3", "abc", "0x10", "+5", "9" * 40]:
        expect_value_error(parse_optional_non_negative_int, text)


def test_status_words_authentication():
    for word in ["success", "successful", "ok", "accepted", " SUCCESS ", "Ok"]:
        assert normalise_status(word, AUTH) == "success", word
    for word in ["failure", "failed", "fail", "denied", "invalid", "FAILED", " Fail "]:
        assert normalise_status(word, AUTH) == "failure", word
    for word in ["allowed", "rejected", "maybe", ""]:
        expect_value_error_two(normalise_status, word, AUTH)


def test_status_words_network():
    for word in ["allowed", "allow", "accept", "accepted", "permit", "ALLOW", " Permit "]:
        assert normalise_status(word, NETWORK) == "allowed", word
    rejected_words = ["rejected", "reject", "denied", "deny", "blocked", "block",
                      "drop", "dropped", "refused", "reset", "RESET"]
    for word in rejected_words:
        assert normalise_status(word, NETWORK) == "rejected", word
    for word in ["success", "failure", "maybe", ""]:
        expect_value_error_two(normalise_status, word, NETWORK)


def test_status_unknown_log_type_is_a_value_error():
    expect_value_error_two(normalise_status, "success", "other")


def test_clean_text_value():
    assert clean_text_value("  alice ", 100) == "alice"
    assert clean_text_value("   ", 100) is None
    assert clean_text_value("", 100) is None
    assert clean_text_value("a" * 100, 100) == "a" * 100
    with pytest.raises(ValueError) as too_long:
        clean_text_value("a" * 101, 100)
    assert str(too_long.value) == "value_too_long"
    for bad_text in ["ad\tmin", "ad\x00min", "ad\x07min", "ad\x7fmin", "ad\x85min"]:
        with pytest.raises(ValueError) as control:
            clean_text_value(bad_text, 100)
        assert str(control.value) == "control_characters", repr(bad_text)


def test_check_columns_ignores_case_and_spaces():
    header = [" Timestamp", "SOURCE_IP ", "username", "status", "Notes"]
    report = check_columns(header, AUTH)
    assert report["missing_required"] == []
    assert report["optional_present"] == []
    assert report["unknown"] == ["Notes"]


def test_check_columns_reports_missing_and_optional():
    report = check_columns(["timestamp", "source_ip", "service"], AUTH)
    assert report["missing_required"] == ["username", "status"]
    assert report["optional_present"] == ["service"]
    network_report = check_columns(["timestamp", "source_ip", "protocol"], NETWORK)
    assert network_report["missing_required"] == ["destination_ip", "status"]
    assert network_report["optional_present"] == ["protocol"]
    expect_value_error_two(check_columns, ["timestamp"], "other")


def test_check_columns_has_no_aliases():
    report = check_columns(["time", "ip", "user", "result"], AUTH)
    assert len(report["missing_required"]) == 4


# ---------------------------------------------------------------
# Valid files and the sample files
# ---------------------------------------------------------------

def test_sample_files_give_zero_rejected_rows():
    expected_file = json.loads((FIXTURE_FOLDER / "expected_results.json").read_text(encoding="utf-8"))
    for file_name, log_type in [("auth_sample.csv", AUTH), ("network_sample.csv", NETWORK)]:
        data = (SAMPLE_FOLDER / file_name).read_bytes()
        result = ingest_file(data, file_name, log_type, make_config())
        expected = expected_file["sample_files"][file_name]
        assert result["rejected_rows"] == [], file_name
        assert result["summary"]["rows_rejected"] == expected["expected_rejected_rows"]
        assert result["summary"]["rows_read"] == expected["data_rows"]
        assert result["summary"]["events_accepted"] == expected["data_rows"]
        assert result["summary"]["warnings"] == []


def test_every_event_passes_stage_zero_validate_event():
    for file_name, log_type in [("auth_sample.csv", AUTH), ("network_sample.csv", NETWORK)]:
        data = (SAMPLE_FOLDER / file_name).read_bytes()
        result = ingest_file(data, file_name, log_type, make_config())
        for event in result["events"]:
            assert validate_event(event) == [], (file_name, event["source_row"])
            assert list(event.keys()) == EVENT_KEYS


def test_stage_zero_golden_event_id_is_reproduced_from_the_sample_file():
    golden = json.loads((FIXTURE_FOLDER / "expected_results.json").read_text(encoding="utf-8"))
    first_golden = golden["golden_event_ids"][0]
    assert first_golden["inputs"]["source_file"] == "auth_sample.csv"
    data = (SAMPLE_FOLDER / "auth_sample.csv").read_bytes()
    result = ingest_file(data, "auth_sample.csv", AUTH, make_config())
    assert first_golden["expected_event_id"] in event_ids(result)
    row_six = result["events"][4]  # the 09:15:02 admin failure is line 6 (header is line 1)
    assert row_six["event_id"] == first_golden["expected_event_id"]
    assert row_six["source_row"] == 6


def test_result_dictionary_has_exactly_the_d6_keys():
    result = ingest_fixture("ingestion_auth_valid.csv", AUTH)
    assert sorted(result.keys()) == ["events", "file_name", "log_type", "rejected_rows", "summary"]
    assert result["file_name"] == "ingestion_auth_valid.csv"
    assert result["log_type"] == AUTH
    summary_keys = ["earliest_timestamp", "events_accepted", "latest_timestamp",
                    "rows_blank", "rows_read", "rows_rejected", "warnings"]
    assert sorted(result["summary"].keys()) == summary_keys


def test_valid_authentication_file_is_normalised():
    result = ingest_fixture("ingestion_auth_valid.csv", AUTH)
    assert result["rejected_rows"] == []
    events = result["events"]
    assert len(events) == 4
    first, second, third, fourth = events
    assert first["event_type"] == AUTH
    assert first["username"] == "admin" and first["status"] == "failure"
    assert second["username"] == "smith, john"      # a quoted comma stays inside the cell
    assert second["status"] == "failure"            # FAILED -> failure
    assert second["service"] == "ssh"               # SSH -> ssh (lowercase)
    assert third["status"] == "success"             # Accepted -> success
    assert third["destination_ip"] is None          # empty -> None
    assert fourth["source_ip"] == "2001:db8::1"     # IPv6 compressed and lowercase
    assert fourth["service"] is None                # empty service -> None
    assert fourth["status"] == "success"            # ok -> success
    for event in events:
        assert event["destination_port"] is None
        assert event["protocol"] is None
        assert event["bytes_sent"] is None
        assert event["bytes_received"] is None
        assert event["source_file"] == "ingestion_auth_valid.csv"


def test_valid_network_file_is_normalised():
    result = ingest_fixture("ingestion_network_valid.csv", NETWORK)
    assert result["rejected_rows"] == []
    events = result["events"]
    assert len(events) == 5
    assert events[0]["status"] == "rejected" and events[0]["destination_port"] == 22
    assert events[0]["protocol"] == "TCP" and events[0]["bytes_sent"] == 60
    assert events[1]["protocol"] == "TCP"            # tcp -> TCP (uppercase)
    assert events[1]["status"] == "allowed"          # " ALLOW " -> allowed
    assert events[1]["bytes_received"] == 1840
    assert events[2]["destination_port"] is None     # ICMP: empty port -> None
    assert events[2]["bytes_sent"] is None and events[2]["bytes_received"] is None
    assert events[2]["protocol"] == "ICMP"
    assert events[3]["destination_port"] == 0 and events[3]["bytes_sent"] == 0  # zero is not missing
    assert events[3]["status"] == "rejected"         # Dropped -> rejected
    assert events[4]["destination_port"] == 65535
    for event in events:
        assert event["username"] is None
        assert event["service"] is None
        assert event["event_type"] == NETWORK
        assert event["timestamp"].utcoffset().total_seconds() == 0


def test_timestamps_in_a_file_are_converted_to_utc():
    text = auth_file_text(
        ["2025-03-14T09:15:02Z,10.0.0.1,a,failure,,",
        "2025-03-14T14:15:02+05:00,10.0.0.1,a,failure,,",
        "2025-03-14 09:15:02,10.0.0.1,a,failure,,",
        "2025-03-14T09:15:02.5,10.0.0.1,a,failure,,"],
    )
    result = ingest_text(text)
    assert result["rejected_rows"] == []
    base = datetime(2025, 3, 14, 9, 15, 2, tzinfo=timezone.utc)
    assert result["events"][0]["timestamp"] == base
    assert result["events"][1]["timestamp"] == base
    assert result["events"][2]["timestamp"] == base
    assert result["events"][3]["timestamp"].microsecond == 500000


def test_assume_utc_false_rejects_rows_without_a_zone():
    config = make_config()
    config["assume_utc"] = False
    text = auth_file_text(
        ["2025-03-14T09:15:02,10.0.0.1,a,failure,,",
        "2025-03-14T09:15:02Z,10.0.0.1,a,failure,,"],
    )
    result = ingest_text(text, config=config)
    assert len(result["events"]) == 1
    assert result["rejected_rows"][0]["reason"] == "invalid_timestamp"
    assert result["rejected_rows"][0]["source_row"] == 2


def test_source_row_is_the_spreadsheet_line_number():
    result = ingest_fixture("ingestion_auth_valid.csv", AUTH)
    row_numbers = []
    for event in result["events"]:
        row_numbers.append(event["source_row"])
    assert row_numbers == [2, 3, 4, 5]  # the header is line 1


def test_raw_event_is_the_original_row_as_text():
    result = ingest_fixture("ingestion_auth_valid.csv", AUTH)
    second = result["events"][1]
    assert second["raw_event"] == {
        "timestamp": "2025-03-14T09:15:20",
        "source_ip": "203.0.113.50",
        "username": "smith, john",
        "status": "FAILED",
        "destination_ip": "10.0.0.5",
        "service": "SSH",
    }
    network = ingest_fixture("ingestion_network_valid.csv", NETWORK)
    assert network["events"][1]["raw_event"]["status"] == " ALLOW "  # not trimmed: exactly as read
    assert network["events"][2]["raw_event"]["destination_port"] == ""


def test_raw_event_values_are_cut_to_500_characters():
    long_note = "n" * 800
    text = AUTH_HEADER + ",note\n" + GOOD_AUTH_ROW + "," + long_note + "\n"
    result = ingest_text(text)
    assert len(result["events"]) == 1
    assert len(result["events"][0]["raw_event"]["note"]) == 500


def test_header_only_file_is_valid_and_has_no_events():
    result = ingest_fixture("ingestion_header_only.csv", AUTH)
    assert result["events"] == []
    assert result["summary"]["rows_read"] == 0
    assert result["summary"]["events_accepted"] == 0
    assert result["summary"]["earliest_timestamp"] is None
    assert result["summary"]["latest_timestamp"] is None


def test_summary_time_range_and_counts_add_up():
    result = ingest_fixture("ingestion_auth_bad_ip_999.csv", AUTH)
    summary = result["summary"]
    assert summary["rows_read"] == summary["events_accepted"] + summary["rows_rejected"]
    assert summary["rows_read"] == 3 and summary["events_accepted"] == 2
    assert summary["earliest_timestamp"] == datetime(2025, 3, 14, 9, 15, 2, tzinfo=timezone.utc)
    assert summary["latest_timestamp"] == datetime(2025, 3, 14, 9, 15, 9, tzinfo=timezone.utc)


# ---------------------------------------------------------------
# File-level problems: the whole file is refused (D.1)
# ---------------------------------------------------------------

def test_wrong_extension_is_refused():
    data = read_fixture("ingestion_wrong_extension.txt")
    expect_ingestion_error(data, "ingestion_wrong_extension.txt", AUTH)
    for bad_name in ["logs.xlsx", "logs.csv.exe", "logs", "logs.csv ", "csv", ".csv"]:
        expect_ingestion_error(data, bad_name, AUTH)


def test_extension_check_ignores_case():
    for name in ["LOGS.CSV", "logs.Csv", "logs.csv"]:
        result = ingest_file(read_fixture("ingestion_auth_valid.csv"), name, AUTH, make_config())
        assert len(result["events"]) == 4


def test_empty_file_is_refused():
    expect_ingestion_error(b"", "empty.csv", AUTH)
    expect_ingestion_error(read_fixture("ingestion_empty.csv"), "empty.csv", AUTH)
    expect_ingestion_error(read_fixture("ingestion_only_blank_lines.csv"), "blank.csv", AUTH)
    expect_ingestion_error(b"\xef\xbb\xbf", "bom_only.csv", AUTH)


def test_binary_garbage_and_non_utf8_are_refused():
    expect_ingestion_error(read_fixture("ingestion_binary_garbage.csv"), "garbage.csv", AUTH)
    message = expect_ingestion_error(read_fixture("ingestion_not_utf8.csv"), "latin1.csv", AUTH)
    assert "UTF-8" in message
    expect_ingestion_error(b"\xff\xfe\x00\x01", "x.csv", NETWORK)
    expect_ingestion_error(AUTH_HEADER.encode() + b"\n\x00\n", "nul.csv", AUTH)


def test_missing_required_column_is_refused_and_named():
    message = expect_ingestion_error(read_fixture("ingestion_missing_column.csv"), "m.csv", AUTH)
    assert "username" in message
    network_header_only = (NETWORK_HEADER.replace("status,", "") + "\n").encode()
    assert "status" in expect_ingestion_error(network_header_only, "n.csv", NETWORK)


def test_every_required_column_missing_is_refused():
    required_auth = ["timestamp", "source_ip", "username", "status"]
    for missing_column in required_auth:
        kept = []
        for column in AUTH_HEADER.split(","):
            if column != missing_column:
                kept.append(column)
        data = (",".join(kept) + "\n").encode()
        message = expect_ingestion_error(data, "x.csv", AUTH)
        assert missing_column in message, missing_column


def test_incorrect_header_names_are_refused_because_there_are_no_aliases():
    data = b"time,ip,user,result\n2025-03-14T09:15:02,203.0.113.4,a,failure\n"
    expect_ingestion_error(data, "aliases.csv", AUTH)
    # A network header given to an authentication file lacks username, so it is refused.
    expect_ingestion_error((NETWORK_HEADER + "\n").encode(), "wrong_type.csv", AUTH)


def test_an_authentication_header_satisfies_the_network_required_columns():
    # D.4 requires timestamp, source_ip, destination_ip and status. An authentication
    # header has all four, so it is NOT a file-level error: username and service are
    # simply unknown columns for a network file, and the user is warned.
    result = ingest_text(AUTH_HEADER + "\n", NETWORK)
    assert result["events"] == []
    assert "username" in result["summary"]["warnings"][0]


def test_duplicate_column_names_are_refused_ignoring_case_and_spaces():
    message = expect_ingestion_error(read_fixture("ingestion_duplicate_columns.csv"), "d.csv", AUTH)
    assert "duplicate" in message.lower()
    expect_ingestion_error(b"timestamp,timestamp,source_ip,username,status\n", "d.csv", AUTH)
    expect_ingestion_error(b"note,note,timestamp,source_ip,username,status\n", "d.csv", AUTH)


def test_unknown_log_type_is_refused():
    data = read_fixture("ingestion_auth_valid.csv")
    for bad_type in ["", "auth", "AUTHENTICATION", "network", None]:
        expect_ingestion_error(data, "a.csv", bad_type)


def test_file_name_must_be_a_name_not_a_path():
    data = read_fixture("ingestion_auth_valid.csv")
    for bad_name in ["folder/a.csv", "folder\\a.csv", "../a.csv", "", "   ", "a\n.csv", None, 5]:
        expect_ingestion_error(data, bad_name, AUTH)
    expect_ingestion_error(data, "a" * 300 + ".csv", AUTH)


def test_file_bytes_must_be_bytes():
    expect_ingestion_error("timestamp,source_ip", "a.csv", AUTH)
    expect_ingestion_error(None, "a.csv", AUTH)


def test_bad_config_values_are_refused():
    data = read_fixture("ingestion_auth_valid.csv")
    for bad_config in [[], "text", {"max_upload_mb": 0}, {"max_upload_mb": "10"},
                       {"max_rows_per_file": True}, {"max_rows_per_file": -5}, {"assume_utc": "yes"}]:
        expect_ingestion_error(data, "a.csv", AUTH, bad_config)
    with pytest.raises(IngestionError):
        ingest_file(data, "a.csv", AUTH, None)


def test_config_may_be_partial_and_is_never_changed():
    data = read_fixture("ingestion_auth_valid.csv")
    result = ingest_file(data, "a.csv", AUTH, {})
    assert len(result["events"]) == 4
    config = make_config()
    config["trusted_ips"] = ["10.0.0.1"]
    before = copy.deepcopy(config)
    ingest_file(data, "a.csv", AUTH, config)
    assert config == before


def make_file_of_exact_size(total_bytes):
    """Valid rows plus a final blank line of spaces, so the file has exactly total_bytes bytes."""
    header_line = AUTH_HEADER + "\n"
    row_line = GOOD_AUTH_ROW + "\n"
    text = header_line
    while len(text) + len(row_line) <= total_bytes:
        text = text + row_line
    padding_needed = total_bytes - len(text)
    return (text + " " * padding_needed).encode("ascii")


def test_upload_size_limit_boundary():
    config = make_config()
    config["max_upload_mb"] = 1   # 1 MB = 1,000,000 bytes (decimal, like the 10 MB of volume_min_bytes)
    exactly_at_limit = make_file_of_exact_size(1000000)
    assert len(exactly_at_limit) == 1000000
    result = ingest_file(exactly_at_limit, "big.csv", AUTH, config)
    assert result["summary"]["events_accepted"] > 1000
    one_byte_over = make_file_of_exact_size(1000001)
    assert len(one_byte_over) == 1000001
    message = expect_ingestion_error(one_byte_over, "big.csv", AUTH, config)
    assert "1 MB" in message


def test_default_upload_limit_is_ten_megabytes():
    ten_megabytes_and_one = b"x" * 10000001
    message = expect_ingestion_error(ten_megabytes_and_one, "big.csv", AUTH)
    assert "10 MB" in message


def test_row_limit_boundary_with_a_small_limit():
    config = make_config()
    config["max_rows_per_file"] = 3
    three_rows = auth_file_text([GOOD_AUTH_ROW, GOOD_AUTH_ROW, GOOD_AUTH_ROW])
    assert ingest_text(three_rows, config=config)["summary"]["rows_read"] == 3
    four_rows = auth_file_text([GOOD_AUTH_ROW, GOOD_AUTH_ROW, GOOD_AUTH_ROW, GOOD_AUTH_ROW])
    message = expect_ingestion_error(four_rows.encode(), "r.csv", AUTH, config)
    assert "3" in message


def test_blank_lines_do_not_count_towards_the_row_limit():
    config = make_config()
    config["max_rows_per_file"] = 2
    text = AUTH_HEADER + "\n\n" + GOOD_AUTH_ROW + "\n\n\n" + GOOD_AUTH_ROW + "\n\n"
    assert ingest_text(text, config=config)["summary"]["rows_read"] == 2


def test_file_of_100000_rows_is_accepted_and_100001_is_rejected():
    row = GOOD_AUTH_ROW + "\n"
    exactly_limit = (AUTH_HEADER + "\n" + row * 100000).encode()
    result = ingest_file(exactly_limit, "limit.csv", AUTH, make_config())
    assert result["summary"]["events_accepted"] == 100000
    one_too_many = (AUTH_HEADER + "\n" + row * 100001).encode()
    message = expect_ingestion_error(one_too_many, "limit.csv", AUTH)
    assert "100000" in message


def test_file_level_errors_are_ingestion_errors_of_the_project_family():
    with pytest.raises(NetworkSentinelError):
        ingest_file(b"", "a.csv", AUTH, make_config())


def test_a_refused_file_returns_nothing_accepted():
    # An exception is raised, so there is no result at all (D.1: "accepts nothing").
    with pytest.raises(IngestionError):
        ingest_file(read_fixture("ingestion_missing_column.csv"), "m.csv", AUTH, make_config())


# ---------------------------------------------------------------
# Row-level problems: only the bad row is rejected, with the exact D.5 reason
# ---------------------------------------------------------------

AUTH_ROW_CASES = [
    ("ingestion_auth_bad_missing_timestamp.csv", "missing_required_value:timestamp"),
    ("ingestion_auth_bad_missing_source_ip.csv", "missing_required_value:source_ip"),
    ("ingestion_auth_bad_missing_username.csv", "missing_required_value:username"),
    ("ingestion_auth_bad_missing_status.csv", "missing_required_value:status"),
    ("ingestion_auth_bad_timestamp_dayfirst.csv", "invalid_timestamp"),
    ("ingestion_auth_bad_timestamp_feb31.csv", "invalid_timestamp"),
    ("ingestion_auth_bad_timestamp_year1999.csv", "invalid_timestamp"),
    ("ingestion_auth_bad_timestamp_unix.csv", "invalid_timestamp"),
    ("ingestion_auth_bad_ip_999.csv", "invalid_ip:source_ip"),
    ("ingestion_auth_bad_ip_text.csv", "invalid_ip:source_ip"),
    ("ingestion_auth_bad_destination_ip.csv", "invalid_ip:destination_ip"),
    ("ingestion_auth_bad_status.csv", "invalid_status"),
    ("ingestion_auth_bad_long_username.csv", "value_too_long:username"),
    ("ingestion_auth_bad_long_service.csv", "value_too_long:service"),
    ("ingestion_auth_bad_control_characters.csv", "control_characters:username"),
    ("ingestion_auth_bad_too_many_columns.csv", "too_many_columns"),
    ("ingestion_auth_bad_too_few_cells.csv", "missing_required_value:status"),
]

NETWORK_ROW_CASES = [
    ("ingestion_network_bad_port_65536.csv", "invalid_port"),
    ("ingestion_network_bad_port_text.csv", "invalid_port"),
    ("ingestion_network_bad_bytes_sent_comma.csv", "invalid_number:bytes_sent"),
    ("ingestion_network_bad_bytes_sent_decimal.csv", "invalid_number:bytes_sent"),
    ("ingestion_network_bad_bytes_received_negative.csv", "invalid_number:bytes_received"),
    ("ingestion_network_bad_long_protocol.csv", "value_too_long:protocol"),
    ("ingestion_network_bad_missing_destination_ip.csv", "missing_required_value:destination_ip"),
    ("ingestion_network_bad_status.csv", "invalid_status"),
    ("ingestion_network_bad_source_ip.csv", "invalid_ip:source_ip"),
]


def check_only_the_middle_row_is_rejected(file_name, log_type, expected_reason):
    # Each fixture has a good line 2, a bad line 3 and a good line 4.
    result = ingest_fixture(file_name, log_type)
    assert len(result["rejected_rows"]) == 1, file_name
    rejected = result["rejected_rows"][0]
    assert rejected["reason"] == expected_reason, file_name
    assert rejected["source_row"] == 3, file_name
    assert rejected["source_file"] == file_name
    assert sorted(rejected.keys()) == ["raw_row", "reason", "source_file", "source_row"]
    for key in rejected["raw_row"]:
        assert isinstance(key, str) and isinstance(rejected["raw_row"][key], str)
    accepted_rows = []
    for event in result["events"]:
        accepted_rows.append(event["source_row"])
    assert accepted_rows == [2, 4], file_name
    summary = result["summary"]
    assert summary["rows_read"] == 3
    assert summary["rows_read"] == summary["events_accepted"] + summary["rows_rejected"]
    assert summary["rows_rejected"] == 1


def test_each_authentication_row_problem_gets_its_exact_reason():
    for file_name, expected_reason in AUTH_ROW_CASES:
        check_only_the_middle_row_is_rejected(file_name, AUTH, expected_reason)


def test_each_network_row_problem_gets_its_exact_reason():
    for file_name, expected_reason in NETWORK_ROW_CASES:
        check_only_the_middle_row_is_rejected(file_name, NETWORK, expected_reason)


def test_every_reason_is_one_of_the_allowed_d5_texts():
    allowed_plain = ["invalid_timestamp", "invalid_port", "invalid_status", "too_many_columns"]
    allowed_prefixes = ["missing_required_value:", "invalid_ip:", "invalid_number:",
                        "value_too_long:", "control_characters:"]
    column_names = ["timestamp", "source_ip", "destination_ip", "username", "status", "service",
                    "protocol", "bytes_sent", "bytes_received"]
    for file_name, expected_reason in AUTH_ROW_CASES + NETWORK_ROW_CASES:
        log_type = AUTH if "_auth_" in file_name else NETWORK
        reason = ingest_fixture(file_name, log_type)["rejected_rows"][0]["reason"]
        is_allowed = reason in allowed_plain
        for prefix in allowed_prefixes:
            if reason.startswith(prefix) and reason[len(prefix):] in column_names:
                is_allowed = True
        assert is_allowed, reason


def test_a_row_with_several_problems_is_rejected_for_the_first_in_table_order():
    # Authentication order (D.3): timestamp, source_ip, username, status, destination_ip, service.
    cases = [
        ("bad-time,999.1.1.1,admin,maybe,10.0.0.999,ssh", "invalid_timestamp"),
        ("2025-03-14T09:15:02,999.1.1.1,,maybe,10.0.0.999,ssh", "invalid_ip:source_ip"),
        ("2025-03-14T09:15:02,203.0.113.4,,maybe,10.0.0.999,ssh", "missing_required_value:username"),
        ("2025-03-14T09:15:02,203.0.113.4,admin,maybe,10.0.0.999," + "s" * 40, "invalid_status"),
        ("2025-03-14T09:15:02,203.0.113.4,admin,failure,10.0.0.999," + "s" * 40, "invalid_ip:destination_ip"),
    ]
    for row, expected_reason in cases:
        result = ingest_text(auth_file_text([row]))
        assert result["rejected_rows"][0]["reason"] == expected_reason, row
    # Network order (D.4): ..., destination_ip, status, destination_port, protocol, bytes_sent, bytes_received.
    network_cases = [
        ("2025-03-14T09:15:02,203.0.113.4,10.0.0.5,70000,TCP,maybe,x,y", "invalid_status"),
        ("2025-03-14T09:15:02,203.0.113.4,10.0.0.5,70000,TCP,allowed,x,y", "invalid_port"),
        ("2025-03-14T09:15:02,203.0.113.4,10.0.0.5,80," + "P" * 11 + ",allowed,x,y", "value_too_long:protocol"),
        ("2025-03-14T09:15:02,203.0.113.4,10.0.0.5,80,TCP,allowed,x,y", "invalid_number:bytes_sent"),
        ("2025-03-14T09:15:02,203.0.113.4,10.0.0.5,80,TCP,allowed,5,y", "invalid_number:bytes_received"),
    ]
    for row, expected_reason in network_cases:
        result = ingest_text(NETWORK_HEADER + "\n" + row + "\n", NETWORK)
        assert result["rejected_rows"][0]["reason"] == expected_reason, row


def test_too_many_columns_is_checked_before_any_value():
    row = "bad-time,999.1.1.1,admin,maybe,10.0.0.999,ssh,extra"
    result = ingest_text(auth_file_text([row]))
    rejected = result["rejected_rows"][0]
    assert rejected["reason"] == "too_many_columns"
    assert rejected["raw_row"]["(extra cell 1)"] == "extra"


def test_too_few_cells_are_read_as_empty_trailing_values():
    # destination_ip and service are optional, so a short row is fine.
    result = ingest_text(auth_file_text(["2025-03-14T09:15:02,203.0.113.4,admin,failure"]))
    assert result["rejected_rows"] == []
    event = result["events"][0]
    assert event["destination_ip"] is None and event["service"] is None
    assert event["raw_event"]["service"] == ""


def test_optional_columns_may_be_missing_from_the_header():
    text = "timestamp,source_ip,username,status\n2025-03-14T09:15:02,203.0.113.4,admin,failure\n"
    result = ingest_text(text)
    assert len(result["events"]) == 1
    network_text = "timestamp,source_ip,destination_ip,status\n2025-03-14T09:15:02,203.0.113.4,10.0.0.5,allowed\n"
    network_result = ingest_text(network_text, NETWORK)
    assert network_result["events"][0]["destination_port"] is None
    assert network_result["events"][0]["bytes_sent"] is None


def test_whitespace_only_required_values_count_as_missing():
    result = ingest_text(auth_file_text(["2025-03-14T09:15:02,203.0.113.4,   ,failure,,"]))
    assert result["rejected_rows"][0]["reason"] == "missing_required_value:username"


def test_field_boundaries_are_accepted():
    username_100 = "u" * 100
    service_30 = "s" * 30
    text = auth_file_text(["2025-03-14T09:15:02,203.0.113.4," + username_100 + ",failure,,"+ service_30])
    result = ingest_text(text)
    assert result["rejected_rows"] == []
    assert result["events"][0]["username"] == username_100
    assert result["events"][0]["service"] == service_30
    network_text = NETWORK_HEADER + "\n2025-03-14T09:15:02,203.0.113.4,10.0.0.5,0,ABCDEFGHIJ,allowed,0,0\n"
    network_result = ingest_text(network_text, NETWORK)
    assert network_result["rejected_rows"] == []
    assert network_result["events"][0]["protocol"] == "ABCDEFGHIJ"


def test_invalid_protocol_and_service_values():
    long_protocol = ingest_text(NETWORK_HEADER + "\n2025-03-14T09:15:02,203.0.113.4,10.0.0.5,80,ABCDEFGHIJK,allowed,1,1\n", NETWORK)
    assert long_protocol["rejected_rows"][0]["reason"] == "value_too_long:protocol"
    control_service = ingest_text(auth_file_text(["2025-03-14T09:15:02,203.0.113.4,admin,failure,,ss\x07h"]))
    assert control_service["rejected_rows"][0]["reason"] == "control_characters:service"
    control_protocol = ingest_text(NETWORK_HEADER + "\n2025-03-14T09:15:02,203.0.113.4,10.0.0.5,80,T\x01P,allowed,1,1\n", NETWORK)
    assert control_protocol["rejected_rows"][0]["reason"] == "control_characters:protocol"


def test_letters_that_grow_when_changed_to_uppercase_cannot_break_the_length_limit():
    # In Python 'ß'.upper() is 'SS'. Six of them are 6 characters but 12 once uppercase.
    row = "2025-03-14T09:15:02,203.0.113.4,10.0.0.5,80," + "ß" * 6 + ",allowed,1,1"
    result = ingest_text(NETWORK_HEADER + "\n" + row + "\n", NETWORK)
    assert result["events"] == []
    assert result["rejected_rows"][0]["reason"] == "value_too_long:protocol"


def test_all_rejected_file_is_not_an_error_but_has_a_warning():
    text = auth_file_text(["bad,x,y,z", "bad,x,y,z"])
    result = ingest_text(text)
    assert result["events"] == []
    assert result["summary"]["rows_rejected"] == 2
    assert "high_rejection_rate" in result["summary"]["warnings"]


def test_high_rejection_rate_needs_more_than_half_rejected():
    good = "2025-03-14T09:15:02,203.0.113.4,a,failure,,"
    bad = "bad,x,y,z"
    exactly_half = ingest_text(auth_file_text([good, bad]))
    assert exactly_half["summary"]["warnings"] == []
    more_than_half = ingest_text(auth_file_text([good, bad, bad]))
    # D.1: "the summary gets the warning high_rejection_rate" - exactly that name.
    assert more_than_half["summary"]["warnings"] == ["high_rejection_rate"]


def test_a_stray_quote_damages_only_its_own_row():
    text = auth_file_text(
        [GOOD_AUTH_ROW,
        '2025-03-14T09:15:03,203.0.113.4,"unterminated,failure,,',
        "2025-03-14T09:15:04,203.0.113.4,carol,failure,,"],
    )
    result = ingest_text(text)
    usernames = []
    for event in result["events"]:
        usernames.append(event["username"])
    assert usernames == ["admin", "carol"]      # the rest of the file is NOT swallowed
    assert len(result["rejected_rows"]) == 1
    assert result["rejected_rows"][0]["source_row"] == 3


def test_a_huge_cell_is_rejected_without_crashing():
    huge = "x" * 300000
    text = auth_file_text(
        [GOOD_AUTH_ROW,
        "2025-03-14T09:15:03,203.0.113.4," + huge + ",failure,,",
        "2025-03-14T09:15:04,203.0.113.4,carol,failure,,"],
    )
    result = ingest_text(text)
    assert len(result["events"]) == 2
    assert result["rejected_rows"][0]["reason"] == "value_too_long:username"
    assert len(result["rejected_rows"][0]["raw_row"]["username"]) == 500


# ---------------------------------------------------------------
# Hostile content (I.2): plain text only, nothing evaluated
# ---------------------------------------------------------------

def test_hostile_usernames_are_kept_as_plain_text():
    result = ingest_fixture("ingestion_auth_hostile.csv", AUTH)
    assert result["rejected_rows"] == []
    usernames = []
    for event in result["events"]:
        usernames.append(event["username"])
    assert usernames == [
        "=1+1",
        "+1234",
        "-5",
        "@SUM(A1)",
        "<script>alert(1)</script>",
        "'; DROP TABLE alerts;--",
        "José 用户 \U0001F600",
    ]
    assert result["events"][0]["raw_event"]["username"] == "=1+1"
    for event in result["events"]:
        assert validate_event(event) == []


def test_unusual_unicode_in_the_username_gives_a_valid_event_id():
    result = ingest_fixture("ingestion_auth_hostile.csv", AUTH)
    last_event = result["events"][-1]
    assert last_event["event_id"].startswith("EVT-")
    assert len(last_event["event_id"]) == 20


def test_control_characters_in_free_text_are_rejected():
    for bad_character in ["\t", "\x00", "\x1b", "\x7f", "\x85"]:
        if bad_character == "\x00":
            continue  # a NUL byte stops the whole file instead (tested above)
        row = "2025-03-14T09:15:02,203.0.113.4,ad" + bad_character + "min,failure,,"
        result = ingest_text(auth_file_text([row]))
        assert result["rejected_rows"][0]["reason"] == "control_characters:username", repr(bad_character)


def test_ip_columns_do_not_accept_free_text_or_zone_suffixes():
    for bad_ip in ["fe80::1%eth0", "<script>", "10.0.0.1; DROP TABLE x", "203.0.113.4 extra"]:
        row = "2025-03-14T09:15:02," + bad_ip + ",admin,failure,,"
        result = ingest_text(auth_file_text([row]))
        assert result["rejected_rows"][0]["reason"] == "invalid_ip:source_ip", bad_ip


# ---------------------------------------------------------------
# Header handling, line endings, blank lines, byte order mark
# ---------------------------------------------------------------

def test_header_names_ignore_case_and_surrounding_spaces_and_any_order():
    text = " Status , USERNAME,Timestamp,source_IP \nfailure,admin,2025-03-14T09:15:02,203.0.113.4\n"
    result = ingest_text(text)
    assert result["rejected_rows"] == []
    event = result["events"][0]
    assert event["username"] == "admin" and event["status"] == "failure"
    assert event["source_ip"] == "203.0.113.4"
    assert event["raw_event"][" Status "] == "failure"  # raw_event keeps the header as read


def test_unknown_columns_are_ignored_but_kept_in_raw_event_with_a_warning():
    result = ingest_fixture("ingestion_unknown_column.csv", AUTH)
    assert result["rejected_rows"] == []
    event = result["events"][0]
    assert event["raw_event"]["Notes"] == "first note"
    assert event["raw_event"]["extra_flag"] == "yes"
    assert sorted(event.keys()) == sorted(EVENT_KEYS)
    warnings = result["summary"]["warnings"]
    assert len(warnings) == 1
    assert "Notes" in warnings[0] and "extra_flag" in warnings[0]


def test_many_unknown_columns_give_a_short_warning():
    names = []
    for number in range(30):
        names.append("extra" + str(number))
    text = AUTH_HEADER + "," + ",".join(names) + "\n" + GOOD_AUTH_ROW + "\n"
    warning = ingest_text(text)["summary"]["warnings"][0]
    assert "and 20 more" in warning
    assert "extra29" not in warning


def test_byte_order_mark_is_accepted():
    result = ingest_fixture("ingestion_with_bom.csv", AUTH)
    assert len(result["events"]) == 1
    assert result["events"][0]["raw_event"]["timestamp"] == "2025-03-14T09:15:02"


def test_windows_line_endings_give_the_same_events_as_unix_ones():
    windows = ingest_fixture("ingestion_crlf.csv", AUTH, "same.csv")
    unix_text = AUTH_HEADER + "\n" + GOOD_AUTH_ROW + "\n" + "2025-03-14T09:15:09,203.0.113.50,backup,failure,10.0.0.5,ssh\n"
    unix = ingest_text(unix_text, AUTH, "same.csv")
    assert len(windows["events"]) == 2
    assert event_ids(windows) == event_ids(unix)
    assert windows["events"][0]["raw_event"]["service"] == "ssh"   # no stray carriage return


def test_file_without_a_final_newline_is_read():
    text = AUTH_HEADER + "\n" + GOOD_AUTH_ROW
    assert len(ingest_text(text)["events"]) == 1


def test_blank_lines_are_skipped_counted_and_keep_line_numbers():
    result = ingest_fixture("ingestion_auth_blank_lines.csv", AUTH)
    assert result["rejected_rows"] == []
    row_numbers = []
    for event in result["events"]:
        row_numbers.append(event["source_row"])
    assert row_numbers == [2, 5]   # lines 3 and 4 are blank
    summary = result["summary"]
    assert summary["rows_read"] == 2
    assert summary["rows_blank"] == 3  # lines 3, 4 and the final blank line 6
    assert summary["rows_read"] == summary["events_accepted"] + summary["rows_rejected"]


def test_blank_lines_before_the_header_are_skipped():
    plain = ingest_text(AUTH_HEADER + "\n" + GOOD_AUTH_ROW + "\n", AUTH, "x.csv")
    shifted = ingest_text("\n\n" + AUTH_HEADER + "\n" + GOOD_AUTH_ROW + "\n", AUTH, "x.csv")
    assert shifted["events"][0]["source_row"] == 4
    assert plain["events"][0]["source_row"] == 2
    assert event_ids(plain) == event_ids(shifted)   # R1.9: same IDs when row numbers change
    assert shifted["summary"]["rows_blank"] == 2


def test_cells_that_start_with_equals_plus_minus_at_are_ordinary_text_in_unknown_columns():
    text = AUTH_HEADER + ",note\n" + GOOD_AUTH_ROW + ",=1+1\n"
    result = ingest_text(text)
    assert result["events"][0]["raw_event"]["note"] == "=1+1"


# ---------------------------------------------------------------
# Event IDs, occurrence, file name (FS.3.1, R1.1, R1.9)
# ---------------------------------------------------------------

def hand_made_event_id(content_pairs, source_file, occurrence):
    """The ID recipe of FS.3.1 written out with json and hashlib only."""
    data = dict(content_pairs)
    data["source_file"] = source_file
    data["occurrence"] = occurrence
    text = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "EVT-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def test_event_id_matches_an_independent_hand_calculation():
    row = "2025-03-14T14:15:02+05:00,203.0.113.50,Admin,FAILED,10.0.0.5,SSH"
    result = ingest_text(auth_file_text([row]), AUTH, "auth_sample.csv")
    expected = hand_made_event_id(
        {
            "bytes_received": None, "bytes_sent": None, "destination_ip": "10.0.0.5",
            "destination_port": None, "event_type": "authentication", "protocol": None,
            "service": "ssh", "source_ip": "203.0.113.50", "status": "failure",
            "timestamp": "2025-03-14T09:15:02.000000+00:00", "username": "Admin",
        },
        "auth_sample.csv",
        1,
    )
    assert result["events"][0]["event_id"] == expected


def test_network_event_id_matches_an_independent_hand_calculation():
    row = "2025-03-14T09:16:00,203.0.113.50,10.0.0.5,22,tcp,reject,60,0"
    result = ingest_text(NETWORK_HEADER + "\n" + row + "\n", NETWORK, "net.csv")
    expected = hand_made_event_id(
        {
            "bytes_received": 0, "bytes_sent": 60, "destination_ip": "10.0.0.5",
            "destination_port": 22, "event_type": "network_connection", "protocol": "TCP",
            "service": None, "source_ip": "203.0.113.50", "status": "rejected",
            "timestamp": "2025-03-14T09:16:00.000000+00:00", "username": None,
        },
        "net.csv",
        1,
    )
    assert result["events"][0]["event_id"] == expected


def test_three_identical_rows_get_occurrences_1_2_3_and_three_different_ids():
    result = ingest_fixture("ingestion_auth_repeated_rows.csv", AUTH, "rep.csv")
    assert len(result["events"]) == 4 and result["rejected_rows"] == []
    ids = event_ids(result)
    assert len(set(ids)) == 4
    content = {
        "bytes_received": None, "bytes_sent": None, "destination_ip": "10.0.0.5",
        "destination_port": None, "event_type": "authentication", "protocol": None,
        "service": "ssh", "source_ip": "203.0.113.50", "status": "failure",
        "timestamp": "2025-03-14T09:15:02.000000+00:00", "username": "admin",
    }
    assert ids[0] == hand_made_event_id(content, "rep.csv", 1)
    assert ids[1] == hand_made_event_id(content, "rep.csv", 2)
    assert ids[2] == hand_made_event_id(content, "rep.csv", 3)
    other_content = dict(content)
    other_content["username"] = "backup"
    other_content["timestamp"] = "2025-03-14T09:15:09.000000+00:00"
    assert ids[3] == hand_made_event_id(other_content, "rep.csv", 1)   # a different row starts at 1


def test_identical_rows_that_differ_only_in_spelling_share_one_occurrence_count():
    # "FAILED" and "failure" normalise to the same content, so they are identical events.
    text = auth_file_text(
        ["2025-03-14T09:15:02,203.0.113.4,a,FAILED,,SSH",
        "2025-03-14T09:15:02,203.0.113.4,a,failure,,ssh"],
    )
    result = ingest_text(text, AUTH, "x.csv")
    first, second = result["events"]
    assert first["event_id"] != second["event_id"]
    assert first["event_id"] == hand_made_event_id(
        {"bytes_received": None, "bytes_sent": None, "destination_ip": None, "destination_port": None,
         "event_type": "authentication", "protocol": None, "service": "ssh", "source_ip": "203.0.113.4",
         "status": "failure", "timestamp": "2025-03-14T09:15:02.000000+00:00", "username": "a"},
        "x.csv", 1)


def test_occurrence_restarts_at_one_for_every_file():
    one = ingest_text(auth_file_text([GOOD_AUTH_ROW, GOOD_AUTH_ROW]), AUTH, "same_name.csv")
    two = ingest_text(auth_file_text([GOOD_AUTH_ROW, GOOD_AUTH_ROW]), AUTH, "same_name.csv")
    assert event_ids(one) == event_ids(two)


def test_same_file_ingested_twice_gives_identical_id_lists():
    data = (SAMPLE_FOLDER / "auth_sample.csv").read_bytes()
    first = ingest_file(data, "auth_sample.csv", AUTH, make_config())
    second = ingest_file(data, "auth_sample.csv", AUTH, make_config())
    assert event_ids(first) == event_ids(second)
    network = (SAMPLE_FOLDER / "network_sample.csv").read_bytes()
    assert event_ids(ingest_file(network, "n.csv", NETWORK, make_config())) == \
        event_ids(ingest_file(network, "n.csv", NETWORK, make_config()))


def test_same_rows_under_a_different_file_name_get_different_ids():
    data = (SAMPLE_FOLDER / "auth_sample.csv").read_bytes()
    first = ingest_file(data, "auth_a.csv", AUTH, make_config())
    second = ingest_file(data, "auth_b.csv", AUTH, make_config())
    for first_id in event_ids(first):
        assert first_id not in event_ids(second)
    assert len(first["events"]) == len(second["events"]) == 20
    assert first["events"][0]["source_file"] == "auth_a.csv"


def test_event_ids_depend_on_protocol():
    row_tcp = "2025-03-14T09:16:00,203.0.113.4,10.0.0.5,22,TCP,allowed,60,0"
    row_udp = "2025-03-14T09:16:00,203.0.113.4,10.0.0.5,22,UDP,allowed,60,0"
    one = ingest_text(NETWORK_HEADER + "\n" + row_tcp + "\n", NETWORK, "n.csv")
    two = ingest_text(NETWORK_HEADER + "\n" + row_udp + "\n", NETWORK, "n.csv")
    assert event_ids(one) != event_ids(two)


def test_none_empty_text_and_zero_are_different_in_the_id():
    with_none = ingest_text(NETWORK_HEADER + "\n2025-03-14T09:16:00,203.0.113.4,10.0.0.5,22,TCP,allowed,,\n", NETWORK, "n.csv")
    with_zero = ingest_text(NETWORK_HEADER + "\n2025-03-14T09:16:00,203.0.113.4,10.0.0.5,22,TCP,allowed,0,0\n", NETWORK, "n.csv")
    assert event_ids(with_none) != event_ids(with_zero)


def test_ids_do_not_depend_on_row_number_or_extra_columns_or_spacing():
    plain = ingest_text(AUTH_HEADER + "\n" + GOOD_AUTH_ROW + "\n", AUTH, "x.csv")
    padded = ingest_text(
        AUTH_HEADER + ",note\n\n\n" + "  2025-03-14T09:15:02 ,203.0.113.50, admin ,failure,10.0.0.5,ssh,hello\n",
        AUTH, "x.csv")
    assert event_ids(plain) == event_ids(padded)
    assert plain["events"][0]["source_row"] != padded["events"][0]["source_row"]


def test_same_instant_written_in_different_zones_gives_the_same_id():
    texts = ["2025-03-14T09:15:02Z", "2025-03-14T14:15:02+05:00", "2025-03-14 09:15:02"]
    ids = []
    for timestamp_text in texts:
        row = timestamp_text + ",203.0.113.4,a,failure,,"
        ids.append(event_ids(ingest_text(auth_file_text([row]), AUTH, "x.csv"))[0])
    assert ids[0] == ids[1] == ids[2]


def test_missing_service_and_the_word_none_give_different_ids():
    # R1.9: None, an empty string and the word "None" are three different things.
    # An empty cell becomes None; the text "None" becomes the lowercase text "none".
    empty_cell = ingest_text(auth_file_text(["2025-03-14T09:15:02,203.0.113.4,a,failure,,"]), AUTH, "x.csv")
    word_none = ingest_text(auth_file_text(["2025-03-14T09:15:02,203.0.113.4,a,failure,,None"]), AUTH, "x.csv")
    assert empty_cell["events"][0]["service"] is None
    assert word_none["events"][0]["service"] == "none"
    assert event_ids(empty_cell) != event_ids(word_none)
    username_none = ingest_text(auth_file_text(["2025-03-14T09:15:02,203.0.113.4,None,failure,,"]), AUTH, "x.csv")
    username_a = ingest_text(auth_file_text(["2025-03-14T09:15:02,203.0.113.4,a,failure,,"]), AUTH, "x.csv")
    assert username_none["events"][0]["username"] == "None"   # case is preserved for usernames
    assert event_ids(username_none) != event_ids(username_a)


def test_usernames_with_pipe_quotes_backslash_or_non_english_letters_get_distinct_ids():
    # R1.9: the old "join with |" method could confuse these; canonical JSON cannot.
    names = ["a|b", "a", "b", 'say "hi"', "back\\slash", "it's", "caf\u00e9", "\u7528\u6237"]
    rows = []
    for name in names:
        quoted_name = '"' + name.replace('"', '""') + '"'
        rows.append("2025-03-14T09:15:02,203.0.113.4," + quoted_name + ",failure,,")
    result = ingest_text(auth_file_text(rows), AUTH, "x.csv")
    assert result["rejected_rows"] == []
    stored_names = []
    for event in result["events"]:
        stored_names.append(event["username"])
        assert validate_event(event) == []
    assert stored_names == names
    assert len(set(event_ids(result))) == len(names)


def test_half_a_second_changes_the_id():
    one = ingest_text(auth_file_text(["2025-03-14T09:15:02,203.0.113.4,a,failure,,"]), AUTH, "x.csv")
    two = ingest_text(auth_file_text(["2025-03-14T09:15:02.5,203.0.113.4,a,failure,,"]), AUTH, "x.csv")
    assert event_ids(one) != event_ids(two)


def test_rows_appended_to_a_file_keep_the_old_ids():
    original = auth_file_text([GOOD_AUTH_ROW, GOOD_AUTH_ROW])
    extended = original + "2025-03-14T10:00:00,203.0.113.4,zed,failure,,\n"
    first = ingest_text(original, AUTH, "grow.csv")
    second = ingest_text(extended, AUTH, "grow.csv")
    assert event_ids(second)[:2] == event_ids(first)
    assert len(second["events"]) == 3
    assert event_ids(second)[2] not in event_ids(first)


def test_a_rejected_row_does_not_use_up_an_occurrence_number():
    with_bad_row = auth_file_text([GOOD_AUTH_ROW, "bad,row", GOOD_AUTH_ROW])
    without_bad_row = auth_file_text([GOOD_AUTH_ROW, GOOD_AUTH_ROW])
    assert event_ids(ingest_text(with_bad_row, AUTH, "x.csv")) == event_ids(ingest_text(without_bad_row, AUTH, "x.csv"))


# ---------------------------------------------------------------
# combine_ingestion_results (R1.1.3 to R1.1.5)
# ---------------------------------------------------------------

def test_combine_returns_exactly_the_documented_keys():
    result = ingest_fixture("ingestion_auth_valid.csv", AUTH)
    combined = combine_ingestion_results([result])
    assert sorted(combined.keys()) == ["duplicates_removed", "events", "overlap_warnings",
                                       "rejected_rows", "summaries"]
    assert combined["duplicates_removed"] == 0
    assert combined["overlap_warnings"] == []
    assert combined["summaries"] == [result["summary"]]


def test_combine_of_nothing_is_empty():
    combined = combine_ingestion_results([])
    assert combined["events"] == [] and combined["rejected_rows"] == []
    assert combined["summaries"] == [] and combined["duplicates_removed"] == 0
    assert combined["overlap_warnings"] == []


def test_combine_sorts_by_timestamp_then_file_then_row():
    late_file = ingest_text(auth_file_text(
        ["2025-03-14T10:00:00,203.0.113.4,a,failure,,",
        "2025-03-14T08:00:00,203.0.113.4,b,failure,,",
        "2025-03-14T09:00:00,203.0.113.4,c1,failure,,",
        "2025-03-14T09:00:00,203.0.113.4,c2,failure,,"],
    ), AUTH, "zzz.csv")
    early_file = ingest_text(auth_file_text(
        ["2025-03-14T09:00:00,203.0.113.5,d,failure,,"],
    ), AUTH, "aaa.csv")
    combined = combine_ingestion_results([late_file, early_file])
    order = []
    for event in combined["events"]:
        order.append(event["username"])
    # 08:00 b; then the three 09:00 events: aaa.csv first, then zzz.csv rows 4 and 5; then 10:00 a.
    assert order == ["b", "d", "c1", "c2", "a"]


def test_combine_merges_authentication_and_network_files():
    auth = ingest_file((SAMPLE_FOLDER / "auth_sample.csv").read_bytes(), "auth_sample.csv", AUTH, make_config())
    network = ingest_file((SAMPLE_FOLDER / "network_sample.csv").read_bytes(), "network_sample.csv", NETWORK, make_config())
    combined = combine_ingestion_results([auth, network])
    assert len(combined["events"]) == 72
    assert combined["overlap_warnings"] == []
    assert len(combined["summaries"]) == 2
    timestamps = []
    for event in combined["events"]:
        timestamps.append(event["timestamp"])
    assert timestamps == sorted(timestamps)
    for event in combined["events"]:
        assert validate_event(event) == []


def test_combine_collects_rejected_rows_from_every_file():
    first = ingest_fixture("ingestion_auth_bad_ip_999.csv", AUTH)
    second = ingest_fixture("ingestion_network_bad_port_65536.csv", NETWORK)
    combined = combine_ingestion_results([first, second])
    reasons = []
    for rejected in combined["rejected_rows"]:
        reasons.append(rejected["reason"])
    assert reasons == ["invalid_ip:source_ip", "invalid_port"]
    assert len(combined["events"]) == 4


def test_same_file_added_twice_keeps_one_copy_and_warns():
    one = ingest_fixture("ingestion_auth_valid.csv", AUTH)
    two = ingest_fixture("ingestion_auth_valid.csv", AUTH)
    combined = combine_ingestion_results([one, two])
    assert len(combined["events"]) == 4
    assert combined["duplicates_removed"] == 4
    assert len(combined["overlap_warnings"]) == 1
    assert "ingestion_auth_valid.csv" in combined["overlap_warnings"][0]
    assert len(combined["summaries"]) == 2     # both uploads are still reported


def test_same_file_added_twice_with_repeated_rows_keeps_every_distinct_event():
    one = ingest_fixture("ingestion_auth_repeated_rows.csv", AUTH)
    two = ingest_fixture("ingestion_auth_repeated_rows.csv", AUTH)
    combined = combine_ingestion_results([one, two])
    assert len(combined["events"]) == 4         # the three repeated rows are all kept once
    assert combined["duplicates_removed"] == 4


def test_renamed_copy_is_kept_and_an_overlap_warning_gives_the_shared_count():
    data = read_fixture("ingestion_auth_valid.csv")
    first = ingest_file(data, "auth_a.csv", AUTH, make_config())
    second = ingest_file(data, "auth_b.csv", AUTH, make_config())
    combined = combine_ingestion_results([first, second])
    assert len(combined["events"]) == 8          # nothing is removed or merged
    assert combined["duplicates_removed"] == 0
    assert len(combined["overlap_warnings"]) == 1
    warning = combined["overlap_warnings"][0]
    assert warning.startswith("auth_b.csv shares 4 identical events with auth_a.csv.")
    assert "kept as separate events" in warning


def test_overlap_counts_distinct_fingerprints_not_rows():
    # Three identical rows in both files are ONE shared fingerprint (R1.1.4).
    data = read_fixture("ingestion_auth_repeated_rows.csv")
    first = ingest_file(data, "one.csv", AUTH, make_config())
    second = ingest_file(data, "two.csv", AUTH, make_config())
    combined = combine_ingestion_results([first, second])
    assert len(combined["events"]) == 8
    assert "shares 2 identical events" in combined["overlap_warnings"][0]


def test_partial_overlap_and_no_overlap():
    first = ingest_text(auth_file_text(
        ["2025-03-14T09:00:00,203.0.113.4,a,failure,,", "2025-03-14T09:00:01,203.0.113.4,b,failure,,"]), AUTH, "f1.csv")
    second = ingest_text(auth_file_text(
        ["2025-03-14T09:00:01,203.0.113.4,b,failure,,", "2025-03-14T09:00:02,203.0.113.4,c,failure,,"]), AUTH, "f2.csv")
    third = ingest_text(auth_file_text(
        ["2025-03-14T11:00:00,203.0.113.4,z,failure,,"]), AUTH, "f3.csv")
    combined = combine_ingestion_results([first, second, third])
    assert len(combined["events"]) == 5
    assert len(combined["overlap_warnings"]) == 1
    assert combined["overlap_warnings"][0].startswith("f2.csv shares 1 identical event with f1.csv.")


def test_combine_does_not_change_its_input():
    one = ingest_fixture("ingestion_auth_valid.csv", AUTH)
    two = ingest_fixture("ingestion_auth_valid.csv", AUTH)
    results = [one, two]
    before_lengths = [len(one["events"]), len(two["events"])]
    combine_ingestion_results(results)
    assert [len(one["events"]), len(two["events"])] == before_lengths
    assert len(results) == 2


def test_combine_raises_no_project_exception_for_valid_input():
    # E.5 lists no errors for combine_ingestion_results. Valid input (including
    # results with no events, or with a rejected-only file) must never raise.
    all_rejected = ingest_text(auth_file_text(["bad,x,y,z"]))
    empty_file = ingest_fixture("ingestion_header_only.csv", AUTH)
    combined = combine_ingestion_results([all_rejected, empty_file])
    assert combined["events"] == [] and len(combined["rejected_rows"]) == 1


def test_combine_does_not_turn_programming_mistakes_into_project_errors():
    # Input that is not a list of ingest_file results is a programming mistake.
    # E.5 says "raises none", so we must NOT raise IngestionError (or any other
    # NetworkSentinelError); Python's own TypeError / KeyError is what appears.
    for bad_input in ["text", None, [1], [{}], [{"file_name": "a.csv"}]]:
        try:
            combine_ingestion_results(bad_input)
        except NetworkSentinelError:
            assert False, "combine raised a project exception for " + repr(bad_input)
        except (TypeError, KeyError):
            pass


# ---------------------------------------------------------------
# Integration hand-over: what detection will receive
# ---------------------------------------------------------------

def test_integration_path_csv_to_detection_input():
    config = make_config()
    results = []
    for file_name, log_type in [("auth_sample.csv", AUTH), ("network_sample.csv", NETWORK)]:
        data = (SAMPLE_FOLDER / file_name).read_bytes()
        results.append(ingest_file(data, file_name, log_type, config))
    combined = combine_ingestion_results(results)
    events = combined["events"]          # this list is what run_analysis(events, config) receives
    assert isinstance(events, list) and len(events) == 72
    failures_from_attacker = 0
    for event in events:
        assert validate_event(event) == []
        if event["event_type"] == AUTH and event["source_ip"] == "203.0.113.50" and event["status"] == "failure":
            failures_from_attacker = failures_from_attacker + 1
    assert failures_from_attacker == 8   # the brute-force burst of expected_results.json


def test_a_corrupt_file_next_to_a_good_one_is_reported_and_the_good_one_is_used():
    # The dashboard calls ingest_file once per file and catches IngestionError per file (G.3).
    results = []
    error_messages = []
    uploads = [("good.csv", read_fixture("ingestion_auth_valid.csv")),
               ("corrupt.csv", read_fixture("ingestion_binary_garbage.csv"))]
    for file_name, data in uploads:
        try:
            results.append(ingest_file(data, file_name, AUTH, make_config()))
        except IngestionError as error:
            error_messages.append(str(error))
    combined = combine_ingestion_results(results)
    assert len(combined["events"]) == 4
    assert len(error_messages) == 1 and error_messages[0].startswith("corrupt.csv:")


# ---------------------------------------------------------------
# Project rules for this module (Section 0 and 0.1)
# ---------------------------------------------------------------

def read_module_text(name):
    return (TESTS_FOLDER.parent / "ingestion" / name).read_text(encoding="utf-8")


def test_ingestion_does_not_import_forbidden_modules():
    for name in ["validators.py", "csv_ingest.py", "__init__.py"]:
        text = read_module_text(name)
        for forbidden in ["import streamlit", "from streamlit", "import sqlite3", "config.settings",
                          "from storage", "from detection", "from correlation", "from reporting",
                          "from dashboard", "import pandas"]:
            assert forbidden not in text, (name, forbidden)


def test_every_ingestion_file_has_a_header_comment():
    for name in ["validators.py", "csv_ingest.py", "__init__.py"]:
        first_lines = read_module_text(name).split("\n")[:10]
        comment_lines = 0
        for line in first_lines:
            if line.startswith("#"):
                comment_lines = comment_lines + 1
        assert comment_lines >= 5, name


def test_public_functions_have_the_six_docstring_headings():
    public_functions = [
        parse_timestamp, parse_ip_address, parse_port, parse_optional_non_negative_int,
        normalise_status, clean_text_value, check_columns, ingest_file, combine_ingestion_results,
    ]
    for function in public_functions:
        docstring = function.__doc__
        positions = []
        for heading in ["Purpose:", "Inputs:", "Output:", "Steps:", "Example", "Errors:"]:
            assert heading in docstring, (function.__name__, heading)
            positions.append(docstring.index(heading))
        assert positions == sorted(positions), function.__name__


def test_public_signatures_match_the_specification():
    import inspect
    expected = {
        ingest_file: ["file_bytes", "file_name", "log_type", "config"],
        combine_ingestion_results: ["results"],
        parse_timestamp: ["text", "assume_utc"],
        parse_ip_address: ["text"],
        parse_port: ["text"],
        parse_optional_non_negative_int: ["text"],
        normalise_status: ["text", "log_type"],
        clean_text_value: ["text", "max_length"],
        check_columns: ["header", "log_type"],
    }
    for function in expected:
        names = list(inspect.signature(function).parameters.keys())
        assert names == expected[function], function.__name__
