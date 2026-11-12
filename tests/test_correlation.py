# tests/test_correlation.py
# ---------------------------------------------------------------
# Purpose: tests for correlation and analysis engine: correlate_alerts, run_analysis, and
# the Stage 0 golden cases from tests/fixtures/expected_results.json.
# Correlation tests cover the positive link, every negative case (different
# address, one log source only, gap too large, trusted address), the inclusive
# gap boundary, destination_match, the union of event IDs and distinct IDs.
# Run from the project folder with: python -m pytest tests/test_correlation.py -v
# Uses: core, config, detection, correlation, the standard library, and pytest.

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))

from detection_builders import (  # noqa: E402
    PROJECT_FOLDER,
    all_alert_text,
    check_alert_invariants,
    default_config,
    load_sample_events,
    make_auth_event,
    make_failure_burst,
    make_network_event,
    make_reject_events,
    make_scan_events,
    make_volume_events,
)

from core.contracts import CONTRACT_VERSION, iso_to_datetime, make_alert_id, validate_alert  # noqa: E402
from core.errors import ConfigError  # noqa: E402
from correlation.correlator import correlate_alerts  # noqa: E402
from detection.auth_rules import detect_failed_logins  # noqa: E402
from detection.engine import run_analysis  # noqa: E402
from detection.network_rules import detect_port_scans  # noqa: E402

IP_ONE = "203.0.113.50"
IP_TWO = "198.51.100.77"
EXPECTED_PATH = PROJECT_FOLDER / "tests" / "fixtures" / "expected_results.json"


def test_contract_version_is_still_one_point_zero():
    assert CONTRACT_VERSION == 1.0


def burst_alerts(events, **changes):
    return detect_failed_logins(events, default_config(**changes))[0]


def scan_alerts(events, **changes):
    return detect_port_scans(events, default_config(**changes))[0]


def pair_dataset(scan_start=60, scan_destination="10.0.0.5", source_ip=IP_ONE):
    """A login burst (0-20 s, destination 10.0.0.5) and a port scan starting at scan_start."""
    auth_events = make_failure_burst(source_ip, 0, 6, 4)
    scan_events = make_scan_events(source_ip, scan_destination, scan_start, 20)
    return auth_events + scan_events


def correlate(events, **changes):
    config = default_config(**changes)
    base = detect_failed_logins(events, config)[0] + detect_port_scans(events, config)[0]
    return correlate_alerts(base, events, config), base


# ===============================================================
# correlate_alerts
# ===============================================================

def test_correlation_positive_case_links_one_pair():
    events = pair_dataset()
    correlated, base = correlate(events)
    assert len(base) == 2
    assert len(correlated) == 1
    alert = correlated[0]
    check_alert_invariants(alert, events)
    assert alert["rule_id"] == "CORR_AUTH_NET"
    assert alert["source_ip"] == IP_ONE
    block = alert["evidence"]["correlation"]
    assert block["link_key"] == "source_ip"
    assert block["link_value"] == IP_ONE
    assert sorted(block["linked_alert_ids"]) == sorted(alert["alert_id"] for alert in base)
    assert block["gap_seconds"] == 40           # burst ends at 20 s, the scan starts at 60 s


def test_correlation_overlapping_alerts_have_gap_zero():
    events = make_failure_burst(IP_ONE, 0, 6, 4) + make_scan_events(IP_ONE, "10.0.0.5", 10, 20)
    assert correlate(events)[0][0]["evidence"]["correlation"]["gap_seconds"] == 0
    assert "overlap" in " ".join(correlate(events)[0][0]["evidence"]["correlation"]["match_conditions"])


def test_correlation_destination_match_raises_confidence_to_high():
    events = pair_dataset(scan_destination="10.0.0.5")      # logins also target 10.0.0.5
    alert = correlate(events)[0][0]
    assert alert["evidence"]["correlation"]["destination_match"] is True
    assert alert["confidence"] == "high"
    assert "10.0.0.5" in " ".join(alert["evidence"]["correlation"]["match_conditions"])


def test_correlation_without_destination_match_is_medium_confidence_but_still_linked():
    events = pair_dataset(scan_destination="10.0.0.77")
    alert = correlate(events)[0][0]
    assert alert["evidence"]["correlation"]["destination_match"] is False
    assert alert["confidence"] == "medium"


def test_correlation_severity_is_high_or_critical_if_the_login_alert_has_a_success():
    plain = correlate(pair_dataset())[0][0]
    with_success = pair_dataset() + [make_auth_event(40, IP_ONE, "admin", "success")]
    critical = correlate(with_success)[0][0]
    assert plain["severity"] == "high"
    assert critical["severity"] == "critical"
    assert critical["evidence"]["correlation"]["destination_match"] is True


def test_correlation_different_source_addresses_are_not_linked():
    events = make_failure_burst(IP_ONE, 0, 6, 4) + make_scan_events(IP_TWO, "10.0.0.5", 60, 20)
    correlated, base = correlate(events)
    assert len(base) == 2
    assert correlated == []


def test_correlation_needs_both_an_authentication_and_a_network_alert():
    two_auth = make_failure_burst(IP_ONE, 0, 6, 4) + make_failure_burst(IP_ONE, 9000, 6, 4)
    two_net = make_scan_events(IP_ONE, "10.0.0.5", 0, 20) + make_reject_events(IP_ONE, 30, 25, 1)
    assert correlate(two_auth)[0] == []
    config = default_config()
    network_base = detect_port_scans(two_net, config)[0]
    assert correlate_alerts(network_base, two_net, config) == []


def test_correlation_gap_larger_than_the_window_is_not_linked():
    events = pair_dataset(scan_start=2 * 3600)
    assert correlate(events)[0] == []


def test_correlation_gap_boundary_is_inclusive():
    # The login burst ends at 20 s. A scan starting at 920 s is exactly 900 s later.
    assert len(correlate(pair_dataset(scan_start=920))[0]) == 1
    assert correlate(pair_dataset(scan_start=921))[0] == []
    inside = correlate(pair_dataset(scan_start=920))[0][0]
    assert inside["evidence"]["correlation"]["gap_seconds"] == 900


def test_correlation_close_timestamps_alone_never_link_alerts():
    events = make_failure_burst(IP_ONE, 0, 6, 4) + make_scan_events(IP_TWO, "10.0.0.5", 1, 20)
    assert correlate(events)[0] == []


def test_correlation_trusted_address_is_never_linked():
    base_events = pair_dataset()
    config = default_config()
    base = detect_failed_logins(base_events, config)[0] + detect_port_scans(base_events, config)[0]
    trusted_config = default_config(trusted_ips=[IP_ONE])
    assert correlate_alerts(base, base_events, trusted_config) == []


def test_correlation_event_ids_are_the_union_without_duplicates_in_time_order():
    events = pair_dataset()
    correlated, base = correlate(events)
    alert = correlated[0]
    union = set()
    for base_alert in base:
        union.update(base_alert["event_ids"])
    assert len(alert["event_ids"]) == len(union) == len(set(alert["event_ids"]))
    assert set(alert["event_ids"]) == union
    check_alert_invariants(alert, events)


def test_correlation_removes_an_event_shared_by_both_alerts():
    events = pair_dataset()
    config = default_config()
    base = detect_failed_logins(events, config)[0] + detect_port_scans(events, config)[0]
    auth_alert = base[0] if base[0]["rule_id"].startswith("AUTH_") else base[1]
    net_alert = base[1] if auth_alert is base[0] else base[0]
    shared_id = auth_alert["event_ids"][0]
    net_alert["event_ids"] = [shared_id] + net_alert["event_ids"]      # pretend both alerts use one event
    alert = correlate_alerts(base, events, config)[0]
    assert alert["event_ids"].count(shared_id) == 1


def test_correlation_time_range_spans_both_alerts():
    events = pair_dataset()
    correlated, base = correlate(events)
    assert correlated[0]["time_start"] == min(alert["time_start"] for alert in base)
    assert correlated[0]["time_end"] == max(alert["time_end"] for alert in base)


def test_correlation_two_scans_make_two_correlated_alerts_with_different_ids():
    events = (make_failure_burst(IP_ONE, 0, 6, 4)
              + make_scan_events(IP_ONE, "10.0.0.5", 30, 20) + make_scan_events(IP_ONE, "10.0.0.6", 30, 20))
    correlated, base = correlate(events)
    assert len(base) == 3
    assert len(correlated) == 2
    assert correlated[0]["alert_id"] != correlated[1]["alert_id"]
    for alert in correlated:
        check_alert_invariants(alert, events)


def test_correlation_ignores_existing_correlated_alerts_and_junk():
    events = pair_dataset()
    correlated, base = correlate(events)
    config = default_config()
    again = correlate_alerts(base + correlated + ["junk", None, {"rule_id": "AUTH_X"}], events, config)
    assert len(again) == 1
    assert again[0]["alert_id"] == correlated[0]["alert_id"]


def test_correlation_with_missing_events_still_links_and_never_crashes():
    events = pair_dataset()
    config = default_config()
    base = detect_failed_logins(events, config)[0] + detect_port_scans(events, config)[0]
    alert = correlate_alerts(base, [], config)[0]          # no events to compare destinations
    assert alert["evidence"]["correlation"]["destination_match"] is False
    assert validate_alert(alert) == []


def test_correlation_alert_id_comes_from_the_stage_0_factory():
    alert = correlate(pair_dataset())[0][0]
    expected = make_alert_id(alert["rule_id"], alert["source_ip"], alert["time_start"], alert["time_end"], alert["event_ids"])
    assert alert["alert_id"] == expected


def test_correlation_does_not_change_its_inputs_and_is_repeatable():
    events = pair_dataset()
    config = default_config()
    base = detect_failed_logins(events, config)[0] + detect_port_scans(events, config)[0]
    snapshot = [dict(alert) for alert in base]
    first = correlate_alerts(base, events, config)
    second = correlate_alerts(list(reversed(base)), events, config)
    assert base == snapshot
    assert [alert["alert_id"] for alert in first] == [alert["alert_id"] for alert in second]


def test_correlation_wording_has_no_forbidden_words_and_says_possible():
    with_success = pair_dataset() + [make_auth_event(40, IP_ONE, "admin", "success")]
    for events in [pair_dataset(), with_success]:
        alert = correlate(events)[0][0]
        text = all_alert_text(alert)
        assert "possible" in text
        for word in ["compromised", "breached", "attacker", "confirmed"]:
            assert word not in text


def test_correlation_missing_window_setting_raises_config_error():
    config = default_config()
    del config["correlation_window_seconds"]
    with pytest.raises(ConfigError):
        correlate_alerts([], [], config)


# ===============================================================
# run_analysis
# ===============================================================

def test_run_analysis_returns_exactly_the_documented_keys():
    result = run_analysis(pair_dataset(), default_config())
    assert sorted(result) == sorted(["alerts", "base_alert_count", "correlated_alert_count", "notes",
                                     "events_analysed", "events_ignored_trusted", "analysed_at"])
    # The 20-port scan is also 20 rejected connections, so the rejection rule fires too.
    assert result["base_alert_count"] == 3
    assert result["correlated_alert_count"] == 1      # both network alerts share the same events: one alert, see next test
    assert len(result["alerts"]) == 4
    assert isinstance(result["analysed_at"], datetime)
    assert result["analysed_at"].utcoffset() == timedelta(0)


def test_two_network_alerts_with_the_same_events_make_one_correlated_alert_listing_both():
    result = run_analysis(pair_dataset(), default_config())
    correlated = [alert for alert in result["alerts"] if alert["rule_id"] == "CORR_AUTH_NET"]
    base_ids = [alert["alert_id"] for alert in result["alerts"] if alert["rule_id"] != "CORR_AUTH_NET"]
    assert len(correlated) == 1
    assert sorted(correlated[0]["evidence"]["correlation"]["linked_alert_ids"]) == sorted(base_ids)
    assert correlated[0]["evidence"]["observed"]["linked_alert_count"] == 3
    conditions = " ".join(correlated[0]["evidence"]["correlation"]["match_conditions"])
    assert "also meets all three linking conditions" in conditions
    assert validate_alert(correlated[0]) == []


def test_run_analysis_sorts_alerts_by_time_start_then_rule_id():
    result = run_analysis(pair_dataset(), default_config())
    keys = [(alert["time_start"], alert["rule_id"]) for alert in result["alerts"]]
    assert keys == sorted(keys)


def test_run_analysis_gives_every_alert_the_same_detected_at():
    result = run_analysis(pair_dataset(), default_config())
    for alert in result["alerts"]:
        assert alert["detected_at"] == result["analysed_at"]
        assert validate_alert(alert) == []


def test_run_analysis_counts_trusted_events_and_ignores_them():
    events = pair_dataset() + make_failure_burst("10.0.0.99", 0, 8, 2)
    result = run_analysis(events, default_config(trusted_ips=["10.0.0.99"]))
    assert result["events_ignored_trusted"] == 8
    assert result["events_analysed"] == len(events) - 8
    for alert in result["alerts"]:
        assert alert["source_ip"] != "10.0.0.99"


def test_run_analysis_empty_input():
    result = run_analysis([], default_config())
    assert result["alerts"] == []
    assert result["base_alert_count"] == 0 and result["correlated_alert_count"] == 0
    assert result["events_analysed"] == 0 and result["notes"] == []


def test_run_analysis_notes_include_skipped_rule_notes_and_skipped_input():
    events = pair_dataset()
    events.append("not an event")
    events.append(events[0])                                  # a repeated event_id
    network_without_bytes = [make_network_event(500 + index, IP_TWO, "10.0.0.5", 443, "allowed") for index in range(4)]
    result = run_analysis(events + network_without_bytes, default_config())
    joined = " ".join(result["notes"])
    assert "1 items in the event list were not event dictionaries" in joined
    assert "1 events repeated an event_id" in joined
    assert "NET_HIGH_VOLUME" in joined


def test_run_analysis_rejects_a_bad_configuration():
    bad_values = [("auth_failed_threshold", 0), ("auth_window_seconds", "300"), ("volume_multiplier", -1),
                  ("volume_min_coverage", 1.5), ("reject_threshold", True), ("trusted_ips", ["not an address"])]
    for key, value in bad_values:
        with pytest.raises(ConfigError):
            run_analysis([], default_config(**{key: value}))
    missing = default_config()
    del missing["portscan_window_seconds"]
    with pytest.raises(ConfigError):
        run_analysis([], missing)
    with pytest.raises(ConfigError):
        run_analysis([], "not a dict")


def test_run_analysis_is_deterministic_and_order_independent():
    events = pair_dataset() + make_volume_events("10.0.0.40", [1000000] * 8 + [12000000])
    first = run_analysis(events, default_config())
    second = run_analysis(list(reversed(events)), default_config())
    assert [alert["alert_id"] for alert in first["alerts"]] == [alert["alert_id"] for alert in second["alerts"]]
    ids = [alert["alert_id"] for alert in first["alerts"]]
    assert len(ids) == len(set(ids))


def test_run_analysis_does_not_change_the_event_list():
    events = pair_dataset()
    snapshot = [dict(event) for event in events]
    run_analysis(events, default_config())
    assert events == snapshot


def test_alerts_are_ready_for_storage_save_alerts_checks():
    # save_alerts (the storage module) needs: valid alerts, every event_id present in the
    # events list, and every base alert of a correlated alert present in the alert list.
    events = pair_dataset() + [make_auth_event(40, IP_ONE, "admin", "success")]
    result = run_analysis(events, default_config())
    event_ids = {event["event_id"] for event in events}
    alert_ids = {alert["alert_id"] for alert in result["alerts"]}
    for alert in result["alerts"]:
        assert validate_alert(alert) == []
        assert set(alert["event_ids"]) <= event_ids
        if alert["rule_id"] == "CORR_AUTH_NET":
            for linked_id in alert["evidence"]["correlation"]["linked_alert_ids"]:
                assert linked_id in alert_ids
                linked = [candidate for candidate in result["alerts"] if candidate["alert_id"] == linked_id][0]
                assert linked["rule_id"].startswith(("AUTH_", "NET_"))
        json.dumps(alert["evidence"])          # evidence is stored as JSON text, so it must be JSON-safe


# ===============================================================
# Stage 0 golden cases: the two sample files and expected_results.json
# ===============================================================

def load_expected():
    with open(EXPECTED_PATH, encoding="utf-8") as expected_file:
        return json.load(expected_file)


def find_alert(alerts, rule_id, source_ip):
    matches = [alert for alert in alerts if alert["rule_id"] == rule_id and alert["source_ip"] == source_ip]
    assert len(matches) == 1, "expected exactly one " + rule_id + " alert for " + source_ip
    return matches[0]


def test_sample_files_produce_exactly_the_expected_alerts():
    expected = load_expected()
    events = load_sample_events()
    assert len(events) == 72
    result = run_analysis(events, default_config())
    assert result["base_alert_count"] == expected["expected_base_alert_count"]
    assert result["correlated_alert_count"] == expected["expected_correlated_alert_count"]
    assert len(result["alerts"]) == len(expected["expected_alerts"])
    for wanted in expected["expected_alerts"]:
        alert = find_alert(result["alerts"], wanted["rule_id"], wanted["source_ip"])
        check_alert_invariants(alert, events)
        assert alert["severity"] == wanted["severity"]
        assert alert["confidence"] == wanted["confidence"]
        assert alert["time_start"] == datetime.fromisoformat(wanted["time_start"])
        assert alert["time_end"] == datetime.fromisoformat(wanted["time_end"])
        assert len(alert["event_ids"]) == wanted["supporting_event_count"]


def test_sample_files_match_the_evidence_expectations():
    expected = load_expected()
    result = run_analysis(load_sample_events(), default_config())
    for wanted in expected["expected_alerts"]:
        alert = find_alert(result["alerts"], wanted["rule_id"], wanted["source_ip"])
        for key, value in wanted["evidence_expectations"].items():
            if key == "why":
                continue
            if key == "bucket_start":
                # the fixture writes the short ISO form; the alert uses the fixed 32-character form
                assert iso_to_datetime(alert["evidence"][key]) == datetime.fromisoformat(value)
            elif key in alert["evidence"]:
                assert alert["evidence"][key] == value, key
            else:
                assert alert["evidence"]["correlation"][key] == value, key


def test_sample_files_skipped_volume_sources_note_lists_the_expected_addresses():
    result = run_analysis(load_sample_events(), default_config())
    volume_notes = [note for note in result["notes"] if note.startswith("NET_HIGH_VOLUME")]
    assert len(volume_notes) == 1
    for address in ["198.51.100.23", "203.0.113.50", "10.0.0.31"]:
        assert address in volume_notes[0]


def test_sample_files_benign_sources_produce_no_alert():
    expected = load_expected()
    result = run_analysis(load_sample_events(), default_config())
    for benign in expected["benign_sources_no_alert_expected"]:
        for alert in result["alerts"]:
            assert alert["source_ip"] != benign["source_ip"], benign["source_ip"]


def test_sample_correlated_alert_is_critical_because_the_login_burst_has_a_success():
    result = run_analysis(load_sample_events(), default_config())
    alert = find_alert(result["alerts"], "CORR_AUTH_NET", IP_ONE)
    assert alert["severity"] == "critical"
    assert alert["confidence"] == "high"
    assert alert["evidence"]["correlation"]["destination_match"] is True
    assert alert["evidence"]["correlation"]["gap_seconds"] == 0


def test_sample_run_twice_gives_identical_alert_ids():
    first = run_analysis(load_sample_events(), default_config())
    second = run_analysis(load_sample_events(), default_config())
    assert [alert["alert_id"] for alert in first["alerts"]] == [alert["alert_id"] for alert in second["alerts"]]


def test_stage_0_golden_alert_id_is_reproduced_through_the_factory():
    # The same inputs as golden_alert_ids[0] in expected_results.json, event IDs shuffled.
    expected = load_expected()["golden_alert_ids"][0]
    inputs = expected["inputs"]
    alert_id = make_alert_id(inputs["rule_id"], inputs["source_ip"], datetime.fromisoformat(inputs["time_start"]),
                             datetime.fromisoformat(inputs["time_end"]), list(inputs["event_ids"]))
    assert alert_id == expected["expected_alert_id"]
