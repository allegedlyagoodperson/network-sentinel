# tests/test_detection.py
# ---------------------------------------------------------------
# Purpose: tests for detection rules: find_bursts and the four detection
# rules (AUTH_BRUTE_FORCE, NET_PORT_SCAN, NET_REPEATED_REJECTS, NET_HIGH_VOLUME).
# Every rule gets the three boundary cases (one below, exactly at, well above
# the threshold), trusted-address, empty-input and determinism tests.
# Run from the project folder with: python -m pytest tests/test_detection.py -v
# Events are built with make_event (see tests/fixtures/detection_builders.py);
# no CSV files and no ingestion code are needed.
# Uses: core, config, detection, the standard library, and pytest.

import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))

from detection_builders import (  # noqa: E402
    all_alert_text,
    check_alert_invariants,
    default_config,
    make_auth_event,
    make_failure_burst,
    make_network_event,
    make_reject_events,
    make_scan_events,
    make_volume_events,
    time_at,
)

from core.contracts import CONTRACT_VERSION, make_alert_id, datetime_to_iso  # noqa: E402
from core.errors import ConfigError  # noqa: E402
from detection.auth_rules import detect_failed_logins  # noqa: E402
from detection.engine import run_analysis  # noqa: E402
from detection.network_rules import (  # noqa: E402
    detect_port_scans,
    detect_repeated_rejections,
    detect_unusual_traffic_volume,
)
from detection.windowing import find_bursts  # noqa: E402

ATTACKER_IP = "203.0.113.50"
OTHER_IP = "198.51.100.77"
HOST_A = "10.0.0.50"
HOST_B = "10.0.0.51"


def test_contract_version_is_still_one_point_zero():
    assert CONTRACT_VERSION == 1.0


# ===============================================================
# find_bursts
# ===============================================================

def seconds_list(*offsets):
    """Timestamps from offsets in seconds (a tiny helper for the burst tests)."""
    return [time_at(offset) for offset in offsets]


def test_find_bursts_empty_input_gives_no_bursts():
    assert find_bursts([], None, 5, 300) == []


def test_find_bursts_one_below_exactly_at_and_well_above_the_threshold():
    assert find_bursts(seconds_list(0, 10, 20, 30), None, 5, 300) == []
    assert find_bursts(seconds_list(0, 10, 20, 30, 40), None, 5, 300) == [(0, 4)]
    assert find_bursts(seconds_list(*range(0, 200, 10)), None, 5, 300) == [(0, 19)]


def test_find_bursts_window_is_inclusive():
    exactly_window = seconds_list(0, 75, 150, 225, 300)
    one_second_too_wide = seconds_list(0, 75, 150, 225, 301)
    assert find_bursts(exactly_window, None, 5, 300) == [(0, 4)]
    assert find_bursts(one_second_too_wide, None, 5, 300) == []


def test_find_bursts_window_uses_exact_fractions_of_a_second():
    just_inside = seconds_list(0, 1, 2, 3, 300.0)
    just_outside = seconds_list(0, 1, 2, 3, 300.000001)
    assert find_bursts(just_inside, None, 5, 300) == [(0, 4)]
    assert find_bursts(just_outside, None, 5, 300) == []


def test_find_bursts_one_long_attack_is_one_burst():
    long_attack = seconds_list(*range(0, 3000, 10))  # 300 events over 50 minutes
    assert find_bursts(long_attack, None, 5, 300) == [(0, 299)]


def test_find_bursts_two_separated_bursts_are_two_bursts():
    two_bursts = seconds_list(0, 1, 2, 3, 4, 7200, 7201, 7202, 7203, 7204)
    assert find_bursts(two_bursts, None, 5, 300) == [(0, 4), (5, 9)]


def test_find_bursts_ignores_a_lone_event_before_the_burst():
    timestamps = seconds_list(0, 5000, 5001, 5002, 5003, 5004)
    assert find_bursts(timestamps, None, 5, 300) == [(1, 5)]


def test_find_bursts_counts_distinct_values_when_values_are_given():
    timestamps = seconds_list(0, 1, 2, 3, 4, 5)
    assert find_bursts(timestamps, [80, 80, 80, 443, 443, 22], 3, 60) == [(0, 5)]
    assert find_bursts(timestamps, [80, 80, 80, 443, 443, 443], 3, 60) == []


def test_find_bursts_distinct_values_leave_the_window_correctly():
    # Port 80 appears twice, far apart. The first copy must not be counted in the second window.
    timestamps = seconds_list(0, 1, 2, 1000, 1001, 1002)
    values = [80, 81, 82, 80, 83, 84]
    assert find_bursts(timestamps, values, 3, 60) == [(0, 2), (3, 5)]


def test_find_bursts_equal_timestamps_all_count():
    assert find_bursts(seconds_list(0, 0, 0, 0, 0), None, 5, 60) == [(0, 4)]


def test_find_bursts_rejects_bad_arguments():
    with pytest.raises(ValueError):
        find_bursts(seconds_list(0, 1), [1], 2, 60)
    with pytest.raises(ValueError):
        find_bursts(seconds_list(0, 1), None, 0, 60)
    with pytest.raises(ValueError):
        find_bursts(seconds_list(0, 1), None, 2, -1)


def test_find_bursts_does_not_change_its_inputs():
    timestamps = seconds_list(0, 1, 2, 3, 4)
    values = [1, 2, 3, 4, 5]
    find_bursts(timestamps, values, 3, 60)
    assert timestamps == seconds_list(0, 1, 2, 3, 4)
    assert values == [1, 2, 3, 4, 5]


# ===============================================================
# AUTH_BRUTE_FORCE: thresholds, severity, confidence
# ===============================================================

def run_auth(events, **changes):
    """Run the rule with default settings (plus any changes) and check every alert."""
    alerts, notes = detect_failed_logins(events, default_config(**changes))
    assert notes == []
    for alert in alerts:
        check_alert_invariants(alert, events)
    return alerts


def test_auth_below_threshold_gives_no_alert():
    assert run_auth(make_failure_burst(ATTACKER_IP, 0, 4, 15)) == []


def test_auth_at_threshold_gives_one_medium_severity_low_confidence_alert():
    events = make_failure_burst(ATTACKER_IP, 0, 5, 15)
    alerts = run_auth(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_id"] == "AUTH_BRUTE_FORCE"
    assert alert["severity"] == "medium"
    assert alert["confidence"] == "low"
    assert alert["source_ip"] == ATTACKER_IP
    assert alert["evidence"]["failure_count"] == 5
    assert alert["evidence"]["followed_by_success"] is False
    assert len(alert["event_ids"]) == 5


def test_auth_well_above_threshold_is_still_one_alert():
    assert len(run_auth(make_failure_burst(ATTACKER_IP, 0, 40, 5))) == 1


def test_auth_window_boundary_is_inclusive():
    exactly_300 = make_failure_burst(ATTACKER_IP, 0, 5, 75)       # last failure at exactly 300 s
    just_over = make_failure_burst(ATTACKER_IP, 0, 4, 75) + [make_auth_event(301, ATTACKER_IP, "admin", "failure")]
    assert len(run_auth(exactly_300)) == 1
    assert run_auth(just_over) == []


def test_auth_password_spray_has_high_confidence():
    events = make_failure_burst(ATTACKER_IP, 0, 12, 5, ["admin", "root", "backup", "test"])
    alert = run_auth(events)[0]
    assert alert["confidence"] == "high"
    assert alert["evidence"]["distinct_usernames"] == 4
    assert alert["evidence"]["usernames_sample"] == ["admin", "backup", "root", "test"]


def test_auth_confidence_rubric_for_one_username():
    # threshold 5: fewer than 10 failures -> low; 10 to 14 -> medium; 15 or more -> high
    assert run_auth(make_failure_burst(ATTACKER_IP, 0, 9, 5))[0]["confidence"] == "low"
    assert run_auth(make_failure_burst(ATTACKER_IP, 0, 10, 5))[0]["confidence"] == "medium"
    assert run_auth(make_failure_burst(ATTACKER_IP, 0, 14, 5))[0]["confidence"] == "medium"
    assert run_auth(make_failure_burst(ATTACKER_IP, 0, 15, 5))[0]["confidence"] == "high"


def test_auth_confidence_rubric_for_several_usernames():
    two_names = make_failure_burst(ATTACKER_IP, 0, 5, 5, ["admin", "root"])
    three_names = make_failure_burst(ATTACKER_IP, 0, 5, 5, ["admin", "root", "backup"])
    assert run_auth(two_names)[0]["confidence"] == "medium"
    assert run_auth(three_names)[0]["confidence"] == "high"


def test_auth_two_bursts_two_hours_apart_give_two_alerts():
    events = make_failure_burst(ATTACKER_IP, 0, 5, 10) + make_failure_burst(ATTACKER_IP, 7200, 5, 10)
    alerts = run_auth(events)
    assert len(alerts) == 2
    assert alerts[0]["alert_id"] != alerts[1]["alert_id"]


def test_auth_slow_attack_is_a_documented_false_negative():
    assert run_auth(make_failure_burst(ATTACKER_IP, 0, 5, 300)) == []


def test_auth_forgetful_user_gives_no_alert():
    events = [make_auth_event(0, "10.0.0.23", "carol", "failure"), make_auth_event(20, "10.0.0.23", "carol", "failure"),
              make_auth_event(40, "10.0.0.23", "carol", "success")]
    assert run_auth(events) == []


def test_auth_failures_from_different_addresses_are_never_added_together():
    events = make_failure_burst(ATTACKER_IP, 0, 3, 5) + make_failure_burst(OTHER_IP, 1, 3, 5)
    assert run_auth(events) == []


def test_auth_successes_never_count_towards_the_threshold():
    events = make_failure_burst(ATTACKER_IP, 0, 4, 5) + [make_auth_event(30, ATTACKER_IP, "admin", "success")]
    assert run_auth(events) == []


def test_auth_trusted_address_is_ignored_completely():
    events = make_failure_burst(ATTACKER_IP, 0, 8, 5) + [make_auth_event(60, ATTACKER_IP, "admin", "success")]
    assert run_auth(events, trusted_ips=[ATTACKER_IP]) == []


def test_auth_empty_and_irrelevant_input_gives_empty_result():
    assert detect_failed_logins([], default_config()) == ([], [])
    network_only = make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 30)
    assert detect_failed_logins(network_only, default_config()) == ([], [])


# ===============================================================
# AUTH_BRUTE_FORCE: successes after failures (R2.2, R2.3)
# ===============================================================
# Six failures for admin at 0..5 s, so T (the last failure) is at 5 s.

LAST_FAILURE = 5


def six_admin_failures():
    return make_failure_burst(ATTACKER_IP, 0, 6, 1, ["admin"])


def test_auth_success_after_failures_raises_severity_but_not_confidence():
    without_success = run_auth(six_admin_failures())[0]
    events = six_admin_failures() + [make_auth_event(LAST_FAILURE + 30, ATTACKER_IP, "admin", "success")]
    alert = run_auth(events)[0]
    assert len(alert["event_ids"]) == 7
    assert alert["time_end"] == time_at(LAST_FAILURE + 30)
    assert alert["severity"] == "high"
    assert without_success["severity"] == "medium"
    assert alert["confidence"] == without_success["confidence"] == "low"
    assert alert["evidence"]["followed_by_success"] is True
    assert alert["evidence"]["success_event_count"] == 1
    assert alert["evidence"]["successful_usernames"] == ["admin"]
    assert alert["evidence"]["successful_usernames_also_failed"] == ["admin"]
    assert alert["event_ids"][-1] == alert["evidence"]["success_events"][0]["event_id"]


def test_auth_success_wording_uses_the_real_timing_and_the_match_template():
    events = six_admin_failures() + [make_auth_event(LAST_FAILURE + 30, ATTACKER_IP, "admin", "success")]
    alert = run_auth(events)[0]
    sentences = alert["evidence"]["explanation"]
    assert ("A successful login for admin was recorded from the same address 30 seconds after the last failed attempt."
            in sentences)
    assert "That username also had failed attempts in this burst." in sentences
    assert "30 seconds after the last failed attempt" in alert["description"]


def test_auth_success_for_a_different_username_uses_the_no_match_template():
    events = six_admin_failures() + [make_auth_event(LAST_FAILURE + 30, ATTACKER_IP, "carol", "success")]
    alert = run_auth(events)[0]
    assert alert["severity"] == "high"
    assert alert["evidence"]["successful_usernames_also_failed"] == []
    assert alert["evidence"]["success_events"][0]["username_also_failed"] is False
    assert "That username did not appear among the failed attempts." in alert["evidence"]["explanation"]


def test_auth_username_match_ignores_capital_letters():
    events = six_admin_failures() + [make_auth_event(LAST_FAILURE + 30, ATTACKER_IP, "ADMIN", "success")]
    alert = run_auth(events)[0]
    assert alert["evidence"]["successful_usernames_also_failed"] == ["ADMIN"]


def test_auth_several_successful_usernames_use_the_several_template():
    failures = make_failure_burst(ATTACKER_IP, 0, 6, 1, ["alice"])
    successes = [make_auth_event(LAST_FAILURE + 30, ATTACKER_IP, "alice", "success"),
                 make_auth_event(LAST_FAILURE + 60, ATTACKER_IP, "bob", "success")]
    alert = run_auth(failures + successes)[0]
    sentences = alert["evidence"]["explanation"]
    assert ("Successful logins for 2 usernames (alice, bob) were recorded from the same address "
            "after the last failed attempt.") in sentences
    assert "The first was recorded 30 seconds after it." in sentences
    assert "1 of them (alice) also had failed attempts." in sentences
    assert alert["evidence"]["successful_usernames"] == ["alice", "bob"]


def test_auth_success_at_the_same_timestamp_as_the_last_failure_is_not_linked():
    events = six_admin_failures() + [make_auth_event(LAST_FAILURE, ATTACKER_IP, "admin", "success")]
    alert = run_auth(events)[0]
    assert alert["severity"] == "medium"
    assert len(alert["event_ids"]) == 6
    assert alert["evidence"]["followed_by_success"] is False


def test_auth_success_one_second_after_says_one_second_singular():
    events = six_admin_failures() + [make_auth_event(LAST_FAILURE + 1, ATTACKER_IP, "admin", "success")]
    alert = run_auth(events)[0]
    assert alert["severity"] == "high"
    assert "1 second after the last failed attempt" in alert["description"]
    assert "1 seconds" not in all_alert_text(alert)


def test_auth_success_under_one_second_says_within_one_second():
    events = six_admin_failures() + [make_auth_event(LAST_FAILURE + 0.5, ATTACKER_IP, "admin", "success")]
    alert = run_auth(events)[0]
    assert "within 1 second after the last failed attempt" in alert["description"]


def test_auth_success_window_upper_bound_is_inclusive_and_fractions_count():
    inside = six_admin_failures() + [make_auth_event(LAST_FAILURE + 300, ATTACKER_IP, "admin", "success")]
    half_second_over = six_admin_failures() + [make_auth_event(LAST_FAILURE + 300.5, ATTACKER_IP, "admin", "success")]
    one_second_over = six_admin_failures() + [make_auth_event(LAST_FAILURE + 301, ATTACKER_IP, "admin", "success")]
    assert run_auth(inside)[0]["severity"] == "high"
    assert run_auth(half_second_over)[0]["severity"] == "medium"
    assert run_auth(one_second_over)[0]["severity"] == "medium"


def test_auth_success_window_follows_the_configuration():
    events = six_admin_failures() + [make_auth_event(LAST_FAILURE + 100, ATTACKER_IP, "admin", "success")]
    assert run_auth(events, auth_success_after_failure_seconds=100)[0]["severity"] == "high"
    assert run_auth(events, auth_success_after_failure_seconds=99)[0]["severity"] == "medium"


def test_auth_success_during_the_burst_is_not_linked():
    failures = make_failure_burst(ATTACKER_IP, 0, 6, 10)            # failures at 0, 10, ... 50
    during = make_auth_event(25, ATTACKER_IP, "admin", "success")
    alert = run_auth(failures + [during])[0]
    assert during["event_id"] not in alert["event_ids"]
    assert alert["time_end"] == time_at(50)
    assert alert["severity"] == "medium"


def test_auth_success_before_the_burst_is_not_linked():
    before = make_auth_event(0, ATTACKER_IP, "admin", "success")
    failures = make_failure_burst(ATTACKER_IP, 10, 6, 1)
    alert = run_auth([before] + failures)[0]
    assert before["event_id"] not in alert["event_ids"]
    assert alert["severity"] == "medium"


def test_auth_success_from_a_different_address_is_not_linked():
    events = six_admin_failures() + [make_auth_event(LAST_FAILURE + 30, OTHER_IP, "admin", "success")]
    alert = run_auth(events)[0]
    assert alert["severity"] == "medium"
    assert len(alert["event_ids"]) == 6


def test_auth_one_success_can_link_to_two_bursts():
    # The burst window stays 300 s but the success window is widened to 900 s,
    # so a success at 400 s falls inside the window of both bursts.
    first_burst = make_failure_burst(ATTACKER_IP, 0, 5, 1)           # last failure at 4 s
    second_burst = make_failure_burst(ATTACKER_IP, 304, 5, 1)        # last failure at 308 s
    success = make_auth_event(400, ATTACKER_IP, "admin", "success")
    alerts = run_auth(first_burst + second_burst + [success], auth_success_after_failure_seconds=900)
    assert len(alerts) == 2
    for alert in alerts:
        assert success["event_id"] in alert["event_ids"]
        assert alert["severity"] == "high"


def fifteen_success_dataset():
    """R2.7 dataset auth_success_cap: 6 failures, 15 linked successes, 1 too late."""
    failures = []
    for index in range(6):
        username = "admin" if index < 3 else "user12"
        failures.append(make_auth_event(index, ATTACKER_IP, username, "failure"))
    successes = []
    for index in range(15):
        username = "user" + str(index + 1).zfill(2)
        successes.append(make_auth_event(15 + index * 10, ATTACKER_IP, username, "success"))
    too_late = make_auth_event(306, ATTACKER_IP, "user16", "success")   # 301 s after the last failure
    return failures + successes + [too_late]


def test_auth_fifteen_successes_are_all_linked_but_only_ten_are_detailed():
    events = fifteen_success_dataset()
    alert = run_auth(events)[0]
    evidence = alert["evidence"]
    assert len(alert["event_ids"]) == 21
    assert evidence["success_event_count"] == 15
    assert len(evidence["success_events"]) == 10
    assert evidence["success_events"][0]["username"] == "user01"
    assert evidence["success_events"][9]["username"] == "user10"
    assert evidence["success_events_not_detailed"] == 5
    assert evidence["successful_usernames"] == ["user" + str(number).zfill(2) for number in range(1, 16)]
    assert evidence["successful_usernames_also_failed"] == ["user12"]   # user12 is not in the detail list
    assert alert["time_end"] == time_at(155)                            # the 15th success, not the 16th
    assert "many successful logins from one address suggests a shared address such as an office router" in all_alert_text(alert)


def test_auth_success_counts_always_add_up():
    for success_count in [0, 1, 10, 11, 25]:
        successes = [make_auth_event(10 + index, ATTACKER_IP, "user" + str(index), "success") for index in range(success_count)]
        alert = run_auth(six_admin_failures() + successes)[0]
        evidence = alert["evidence"]
        assert evidence["success_event_count"] == success_count
        assert len(alert["event_ids"]) == 6 + success_count
        assert len(evidence["success_events"]) + evidence["success_events_not_detailed"] == success_count
        assert len(evidence["success_events"]) <= 10
        assert evidence["followed_by_success"] is (success_count > 0)


def test_auth_wording_never_uses_forbidden_words_and_says_possible_or_recorded():
    datasets = [six_admin_failures(), fifteen_success_dataset(),
                six_admin_failures() + [make_auth_event(35, ATTACKER_IP, "carol", "success")],
                make_failure_burst(ATTACKER_IP, 0, 12, 5, ["a", "b", "c", "d"])]
    for events in datasets:
        for alert in run_auth(events):
            text = all_alert_text(alert)
            for word in ["compromised", "breached", "attacker", "confirmed"]:
                assert word not in text
            assert "possible" in text or "recorded" in text


def test_auth_success_alert_states_the_required_limitations():
    events = six_admin_failures() + [make_auth_event(35, ATTACKER_IP, "admin", "success")]
    text = " ".join(run_auth(events)[0]["evidence"]["limitations"]).lower()
    assert "mistyped a password and then succeeded" in text
    assert "sharing one address" in text
    assert "does not show whether the successful login was authorised" in text


# ===============================================================
# AUTH_BRUTE_FORCE: input handling and determinism
# ===============================================================

def test_auth_event_without_a_username_is_skipped_not_fatal():
    events = make_failure_burst(ATTACKER_IP, 0, 5, 5)
    events[2] = dict(events[2])
    events[2]["username"] = None
    assert run_auth(events) == []          # only 4 usable failures remain


def test_auth_junk_in_the_event_list_is_skipped():
    events = make_failure_burst(ATTACKER_IP, 0, 5, 5) + ["not an event", 42, None, {"event_id": "EVT-x"}]
    assert len(run_auth(events)) == 1


def test_auth_duplicate_event_dictionaries_are_counted_once():
    events = make_failure_burst(ATTACKER_IP, 0, 5, 5)
    once = run_auth(events)
    twice = run_auth(events + events)
    assert twice[0]["alert_id"] == once[0]["alert_id"]
    assert len(twice[0]["event_ids"]) == 5


def test_auth_input_order_does_not_change_the_alert_ids():
    events = six_admin_failures() + [make_auth_event(35, ATTACKER_IP, "admin", "success")]
    forward = run_auth(events)
    backward = run_auth(list(reversed(events)))
    assert [alert["alert_id"] for alert in forward] == [alert["alert_id"] for alert in backward]
    assert forward[0]["event_ids"] == backward[0]["event_ids"]


def test_auth_the_input_list_is_not_changed():
    events = make_failure_burst(ATTACKER_IP, 0, 6, 5)
    snapshot = list(reversed(events))
    run_auth(snapshot)
    assert snapshot == list(reversed(events))


def test_auth_same_data_twice_gives_identical_ids():
    events = fifteen_success_dataset()
    assert [alert["alert_id"] for alert in run_auth(events)] == [alert["alert_id"] for alert in run_auth(events)]


def test_auth_alert_id_comes_from_the_stage_0_factory():
    alert = run_auth(six_admin_failures())[0]
    expected = make_alert_id(alert["rule_id"], alert["source_ip"], alert["time_start"], alert["time_end"], alert["event_ids"])
    assert alert["alert_id"] == expected


def test_auth_evidence_event_ids_are_in_time_order_and_never_trimmed():
    alert = run_auth(fifteen_success_dataset())[0]
    assert len(alert["event_ids"]) == len(set(alert["event_ids"])) == 21


def test_auth_missing_setting_raises_config_error():
    config = default_config()
    del config["auth_window_seconds"]
    with pytest.raises(ConfigError):
        detect_failed_logins(make_failure_burst(ATTACKER_IP, 0, 5, 5), config)


def test_auth_rule_parameters_record_the_thresholds_used():
    alert = run_auth(make_failure_burst(ATTACKER_IP, 0, 3, 5), auth_failed_threshold=3)[0]
    assert alert["evidence"]["rule_parameters"]["auth_failed_threshold"] == 3
    assert alert["evidence"]["rule_parameters"]["auth_window_seconds"] == 300


# ===============================================================
# NET_PORT_SCAN
# ===============================================================

def run_scan(events, **changes):
    alerts, notes = detect_port_scans(events, default_config(**changes))
    assert notes == []
    for alert in alerts:
        check_alert_invariants(alert, events)
    return alerts


def test_scan_one_below_exactly_at_and_well_above_the_threshold():
    assert run_scan(make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 14)) == []
    assert len(run_scan(make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 15))) == 1
    assert len(run_scan(make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 40))) == 1


def test_scan_forty_rejected_ports_is_medium_severity_high_confidence():
    alert = run_scan(make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 40))[0]
    assert alert["rule_id"] == "NET_PORT_SCAN"
    assert alert["severity"] == "medium"
    assert alert["confidence"] == "high"
    assert alert["evidence"]["distinct_port_count"] == 40
    assert alert["evidence"]["destination_ip"] == "10.0.0.5"
    assert alert["evidence"]["rejected_ratio"] == 1.0


def test_scan_severity_becomes_high_at_three_times_the_threshold():
    assert run_scan(make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 44))[0]["severity"] == "medium"
    assert run_scan(make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 45))[0]["severity"] == "high"


def test_scan_confidence_rubric_uses_the_seventy_percent_boundaries():
    def mixed(rejected_count, allowed_count):
        rejected = make_scan_events(ATTACKER_IP, "10.0.0.5", 0, rejected_count, "rejected", first_port=1000)
        allowed = make_scan_events(ATTACKER_IP, "10.0.0.5", rejected_count, allowed_count, "allowed", first_port=5000)
        return rejected + allowed
    assert run_scan(mixed(14, 6))[0]["confidence"] == "high"      # exactly 70 percent rejected
    assert run_scan(mixed(13, 7))[0]["confidence"] == "medium"    # 65 percent rejected, 35 allowed
    assert run_scan(mixed(10, 10))[0]["confidence"] == "medium"
    assert run_scan(mixed(6, 14))[0]["confidence"] == "low"       # exactly 70 percent allowed
    assert run_scan(make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 20, "allowed"))[0]["confidence"] == "low"


def test_scan_window_boundary_is_inclusive():
    # 14 ports in the first 13 seconds, then a 15th port exactly 60 s after the first event (integer seconds).
    first_fourteen = make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 14)
    exactly_60 = first_fourteen + [make_network_event(60, ATTACKER_IP, "10.0.0.5", 9000, "rejected", bytes_sent=60)]
    at_61 = first_fourteen + [make_network_event(61, ATTACKER_IP, "10.0.0.5", 9000, "rejected", bytes_sent=60)]
    assert len(run_scan(exactly_60)) == 1
    assert run_scan(at_61) == []


def test_scan_repeating_the_same_few_ports_is_not_a_scan():
    events = []
    for index in range(100):
        events.append(make_network_event(index * 0.5, ATTACKER_IP, "10.0.0.5", 80 + index % 5, "allowed", bytes_sent=100))
    assert run_scan(events) == []


def test_scan_busy_web_client_is_not_a_scan():
    events = []
    for index in range(500):
        events.append(make_network_event(index * 0.1, "198.51.100.23", "10.0.0.8", 443, "allowed", bytes_sent=100 + index))
    assert run_scan(events) == []


def test_scan_two_targets_in_the_same_time_range_give_two_alerts_with_different_ids():
    events = (make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 20, first_port=1000)
              + make_scan_events(ATTACKER_IP, "10.0.0.6", 0, 20, first_port=1000))
    # Both scans cover exactly the same seconds, so the time range is identical.
    alerts = run_scan(events)
    assert len(alerts) == 2
    assert alerts[0]["time_start"] == alerts[1]["time_start"]
    assert alerts[0]["time_end"] == alerts[1]["time_end"]
    assert alerts[0]["source_ip"] == alerts[1]["source_ip"]
    assert alerts[0]["alert_id"] != alerts[1]["alert_id"]


def test_scan_events_without_a_port_are_skipped():
    icmp_events = []
    for index in range(30):
        icmp_events.append(make_network_event(index, ATTACKER_IP, "10.0.0.5", None, "allowed", bytes_sent=64))
    assert run_scan(icmp_events) == []


def test_scan_ports_sample_is_sorted_and_limited_to_twenty():
    alert = run_scan(make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 30, first_port=2000))[0]
    sample = alert["evidence"]["ports_sample"]
    assert len(sample) == 20
    assert sample == sorted(sample)
    assert alert["evidence"]["distinct_port_count"] == 30


def test_scan_trusted_address_is_ignored():
    events = make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 40)
    assert run_scan(events, trusted_ips=[ATTACKER_IP]) == []


def test_scan_empty_input_and_wording():
    assert detect_port_scans([], default_config()) == ([], [])
    alert = run_scan(make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 20))[0]
    text = all_alert_text(alert)
    assert "possible" in text
    assert "not proof" in text


def test_scan_same_data_twice_gives_identical_ids_in_any_order():
    events = make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 20)
    first = run_scan(events)
    second = run_scan(list(reversed(events)))
    assert [alert["alert_id"] for alert in first] == [alert["alert_id"] for alert in second]


# ===============================================================
# NET_REPEATED_REJECTS
# ===============================================================

def run_rejects(events, **changes):
    alerts, notes = detect_repeated_rejections(events, default_config(**changes))
    assert notes == []
    for alert in alerts:
        check_alert_invariants(alert, events)
    return alerts


def test_rejects_one_below_exactly_at_and_well_above_the_threshold():
    assert run_rejects(make_reject_events("10.0.0.31", 0, 19, 5)) == []
    assert len(run_rejects(make_reject_events("10.0.0.31", 0, 20, 5))) == 1
    assert len(run_rejects(make_reject_events("10.0.0.31", 0, 100, 1))) == 1


def test_rejects_single_target_is_low_severity_low_confidence():
    alert = run_rejects(make_reject_events("10.0.0.31", 0, 25, 2))[0]
    assert alert["rule_id"] == "NET_REPEATED_REJECTS"
    assert alert["severity"] == "low"
    assert alert["confidence"] == "low"
    assert alert["evidence"]["rejected_count"] == 25
    assert alert["evidence"]["distinct_destinations"] == 1
    assert alert["evidence"]["distinct_ports"] == 1
    assert alert["evidence"]["top_destination_port"] == 514


def test_rejects_varied_destinations_give_medium_confidence():
    alert = run_rejects(make_reject_events("10.0.0.31", 0, 25, 2, vary_destinations=True))[0]
    assert alert["confidence"] == "medium"
    assert alert["evidence"]["distinct_destinations"] == 25


def test_rejects_same_address_but_different_ports_is_not_a_single_target():
    events = []
    for index in range(25):
        events.append(make_network_event(index, "10.0.0.31", "10.0.0.9", 500 + index % 3, "rejected", bytes_sent=60))
    alert = run_rejects(events)[0]
    assert alert["confidence"] == "medium"
    assert alert["evidence"]["top_destination_port"] == 500
    assert alert["evidence"]["distinct_ports"] == 3


def test_rejects_severity_is_medium_at_three_times_the_threshold():
    assert run_rejects(make_reject_events("10.0.0.31", 0, 59, 1))[0]["severity"] == "low"
    assert run_rejects(make_reject_events("10.0.0.31", 0, 60, 1))[0]["severity"] == "medium"


def test_rejects_window_boundary_is_inclusive():
    # 19 rejections in the first 18 seconds, then a 20th exactly 120 s after the first (integer seconds).
    first_nineteen = make_reject_events("10.0.0.31", 0, 19, 1)
    exactly_120 = first_nineteen + [make_network_event(120, "10.0.0.31", "10.0.0.9", 514, "rejected", bytes_sent=60)]
    at_121 = first_nineteen + [make_network_event(121, "10.0.0.31", "10.0.0.9", 514, "rejected", bytes_sent=60)]
    assert len(run_rejects(exactly_120)) == 1
    assert run_rejects(at_121) == []


def test_rejects_allowed_connections_do_not_count():
    rejected = make_reject_events("10.0.0.31", 0, 15, 1)
    allowed = []
    for index in range(30):
        allowed.append(make_network_event(20 + index, "10.0.0.31", "10.0.0.9", 514, "allowed", bytes_sent=60))
    assert run_rejects(rejected + allowed) == []


def test_rejects_trusted_address_and_empty_input():
    assert run_rejects(make_reject_events("10.0.0.31", 0, 30, 1), trusted_ips=["10.0.0.31"]) == []
    assert detect_repeated_rejections([], default_config()) == ([], [])


def test_rejects_two_separated_bursts_give_two_alerts():
    events = make_reject_events("10.0.0.31", 0, 20, 1) + make_reject_events("10.0.0.31", 5000, 20, 1)
    assert len(run_rejects(events)) == 2


def test_rejects_two_sources_are_judged_separately():
    events = make_reject_events("10.0.0.31", 0, 12, 1) + make_reject_events("10.0.0.32", 0, 12, 1)
    assert run_rejects(events) == []


# ===============================================================
# NET_HIGH_VOLUME (R1.3, R1.9, FS.8)
# ===============================================================

def run_volume(events, **changes):
    alerts, notes = detect_unusual_traffic_volume(events, default_config(**changes))
    for alert in alerts:
        check_alert_invariants(alert, events)
    return alerts, notes


def test_volume_positive_dataset_flags_the_spike_against_its_own_baseline():
    events = make_volume_events(HOST_A, [1000000] * 8 + [12000000])
    alerts, notes = run_volume(events)
    assert notes == []
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_id"] == "NET_HIGH_VOLUME"
    assert alert["severity"] == "medium"
    assert alert["confidence"] == "low"
    evidence = alert["evidence"]
    assert evidence["baseline_bytes"] == 1000000
    assert evidence["eligible_bucket_count"] == 9
    assert evidence["baseline_scope"] == "this_source_ip_only"
    assert evidence["bucket_bytes_sent"] == 12000000
    assert evidence["bucket_start"] == datetime_to_iso(time_at(8 * 300))
    assert evidence["bucket_end"] == datetime_to_iso(time_at(9 * 300))
    assert alert["time_start"] == alert["time_end"] == time_at(8 * 300 + 30)


def test_volume_two_hosts_each_judged_against_itself_gives_no_alert():
    events = make_volume_events(HOST_A, [1000000] * 8) + make_volume_events(HOST_B, [40000000] * 8)
    alerts, notes = run_volume(events)
    assert alerts == []
    assert notes == []


def test_volume_a_busy_neighbour_does_not_hide_a_spike():
    events = make_volume_events(HOST_A, [1000000] * 8 + [12000000]) + make_volume_events(HOST_B, [40000000] * 8)
    alerts, notes = run_volume(events)
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == HOST_A


def test_volume_source_with_five_active_buckets_is_skipped_with_a_note():
    events = make_volume_events(HOST_A, [1000000] * 4 + [12000000])
    alerts, notes = run_volume(events)
    assert alerts == []
    assert notes == ["NET_HIGH_VOLUME: 1 source address skipped (fewer than 6 active buckets): " + HOST_A + "."]


def test_volume_minimum_bytes_boundary_is_inclusive():
    exactly = make_volume_events(HOST_A, [1000000] * 5 + [10000000])
    one_less = make_volume_events(HOST_A, [1000000] * 5 + [9999999])
    assert len(run_volume(exactly)[0]) == 1
    assert run_volume(one_less)[0] == []        # far above 5 x the median, but below the 10 MB minimum


def test_volume_default_minimum_is_ten_million_decimal_bytes():
    assert default_config()["volume_min_bytes"] == 10000000


def test_volume_multiplier_boundary_is_inclusive():
    exactly = make_volume_events(HOST_A, [4000000] * 5 + [20000000])
    one_less = make_volume_events(HOST_A, [4000000] * 5 + [19999999])
    assert len(run_volume(exactly)[0]) == 1
    assert run_volume(one_less)[0] == []        # above the 10 MB minimum but below 5 x the 4 MB median


def test_volume_zero_byte_buckets_are_not_eligible():
    spike_dataset = make_volume_events(HOST_A, [1000000] * 5 + [10000000])
    zero_events = []
    for index in range(3):
        zero_events.append(make_network_event((20 + index) * 300 + 10, HOST_A, "192.0.2.80", 443, "allowed", bytes_sent=0))
    alerts, notes = run_volume(spike_dataset + zero_events)
    assert len(alerts) == 1
    assert alerts[0]["evidence"]["eligible_bucket_count"] == 6
    assert alerts[0]["evidence"]["baseline_bytes"] == 1000000


def test_volume_zero_byte_buckets_do_not_help_a_source_reach_the_minimum():
    five_real = make_volume_events(HOST_A, [1000000] * 4 + [12000000])
    zero_events = []
    for index in range(3):
        zero_events.append(make_network_event((20 + index) * 300 + 10, HOST_A, "192.0.2.80", 443, "allowed", bytes_sent=0))
    alerts, notes = run_volume(five_real + zero_events)
    assert alerts == []
    assert len(notes) == 1


def test_volume_even_count_median_is_the_average_of_the_two_middle_values():
    events = make_volume_events(HOST_A, [1000000, 2000000, 2000000, 4000000, 6000000, 20000000])
    alerts, notes = run_volume(events)
    assert len(alerts) == 1                    # 20,000,000 is at least 15,000,000; 6,000,000 is not
    assert alerts[0]["evidence"]["baseline_bytes"] == 3000000
    assert alerts[0]["evidence"]["bucket_bytes_sent"] == 20000000


def test_volume_median_can_be_a_half_number():
    events = make_volume_events(HOST_A, [1000000, 2000000, 3000000, 3000001, 6000000, 20000000])
    alert = run_volume(events)[0][0]
    assert alert["evidence"]["baseline_bytes"] == 3000000.5


def test_volume_buckets_line_up_with_the_clock_not_with_the_first_event():
    events = make_volume_events(HOST_A, [1000000] * 4, first_bucket_index=-4)   # buckets before 09:00
    events.append(make_network_event(-60 + 1, HOST_A, "192.0.2.80", 443, "allowed", bytes_sent=1000000))  # 08:59:01, bucket 08:55
    events.append(make_network_event(14 * 60 + 59, HOST_A, "192.0.2.80", 443, "allowed", bytes_sent=1000000))   # 09:14:59
    events.append(make_network_event(15 * 60, HOST_A, "192.0.2.80", 443, "allowed", bytes_sent=6000000))        # 09:15:00
    events.append(make_network_event(19 * 60 + 59, HOST_A, "192.0.2.80", 443, "allowed", bytes_sent=6000000))   # 09:19:59
    alerts, notes = run_volume(events)
    assert len(alerts) == 1
    assert alerts[0]["evidence"]["bucket_start"] == datetime_to_iso(time_at(15 * 60))
    assert len(alerts[0]["event_ids"]) == 2           # 09:15:00 and 09:19:59, but not 09:14:59
    assert alerts[0]["time_start"] == time_at(15 * 60)
    assert alerts[0]["time_end"] == time_at(19 * 60 + 59)


def test_volume_without_bytes_is_skipped_with_a_note():
    events = []
    for index in range(20):
        events.append(make_network_event(index * 60, HOST_A, "192.0.2.80", 443, "allowed", bytes_sent=None))
    alerts, notes = run_volume(events)
    assert alerts == []
    assert notes == ["NET_HIGH_VOLUME skipped: fewer than 50 percent of network events contain bytes_sent."]


def test_volume_coverage_boundary_is_inclusive():
    with_bytes = make_volume_events(HOST_A, [1000000] * 8 + [12000000])         # 9 events with bytes
    without_nine = [make_network_event(7000 + index, HOST_B, "192.0.2.80", 443, "allowed") for index in range(9)]
    without_ten = [make_network_event(7000 + index, HOST_B, "192.0.2.80", 443, "allowed") for index in range(10)]
    exactly_half = run_volume(with_bytes + without_nine)
    below_half = run_volume(with_bytes + without_ten)
    assert len(exactly_half[0]) == 1 and exactly_half[1] == []
    assert below_half[0] == [] and len(below_half[1]) == 1


def test_volume_invalid_byte_values_count_as_missing():
    events = make_volume_events(HOST_A, [1000000] * 8 + [12000000])
    broken = []
    for bad_value in [-5, "abc", True, 1.5]:
        event = dict(make_network_event(9000 + len(broken), HOST_B, "192.0.2.80", 443, "allowed"))
        event["bytes_sent"] = bad_value
        broken.append(event)
    alerts, notes = run_volume(events + broken)
    assert len(alerts) == 1                    # coverage is 9 of 13, the bad values do not crash anything
    assert alerts[0]["source_ip"] == HOST_A


def test_volume_nightly_backup_is_a_known_false_positive():
    events = make_volume_events("10.0.0.60", [200000] * 10 + [50000000])
    alerts, notes = run_volume(events)
    assert len(alerts) == 1
    assert "nightly backup" in " ".join(alerts[0]["evidence"]["limitations"]).lower()


def test_volume_a_source_that_is_always_busy_never_triggers():
    alerts, notes = run_volume(make_volume_events(HOST_B, [50000000] * 10))
    assert alerts == []


def test_volume_trusted_address_is_ignored():
    events = make_volume_events(HOST_A, [1000000] * 8 + [12000000])
    alerts, notes = run_volume(events, trusted_ips=[HOST_A])
    assert alerts == [] and notes == []


def test_volume_empty_input_and_non_network_events():
    assert detect_unusual_traffic_volume([], default_config()) == ([], [])
    auth_only = make_failure_burst(ATTACKER_IP, 0, 6, 5)
    assert detect_unusual_traffic_volume(auth_only, default_config()) == ([], [])


def test_volume_skipped_note_lists_at_most_ten_addresses_then_and_n_more():
    events = []
    for index in range(12):
        events.append(make_network_event(index * 10, "10.1.0." + str(index + 1), "192.0.2.80", 443, "allowed", bytes_sent=1000))
    alerts, notes = run_volume(events)
    assert alerts == []
    assert len(notes) == 1
    assert "12 source addresses skipped" in notes[0]
    assert notes[0].endswith(", and 2 more.")
    assert notes[0].count("10.1.0.") == 10


def test_volume_window_setting_changes_the_buckets():
    # With 600-second buckets two neighbouring 300-second events share one bucket.
    events = make_volume_events(HOST_A, [1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 7000000, 7000000])
    alerts, notes = run_volume(events, volume_window_seconds=600)
    assert len(alerts) == 1
    assert alerts[0]["evidence"]["bucket_bytes_sent"] == 14000000
    assert len(alerts[0]["event_ids"]) == 2


def test_volume_same_data_twice_gives_identical_ids():
    events = make_volume_events(HOST_A, [1000000] * 8 + [12000000])
    first = run_volume(events)[0]
    second = run_volume(list(reversed(events)))[0]
    assert [alert["alert_id"] for alert in first] == [alert["alert_id"] for alert in second]


def test_volume_each_triggering_bucket_gives_its_own_alert():
    events = make_volume_events(HOST_A, [1000000] * 8 + [12000000, 1000000, 13000000])
    alerts, notes = run_volume(events)
    assert len(alerts) == 2
    assert alerts[0]["alert_id"] != alerts[1]["alert_id"]


# ===============================================================
# Time-range invariant over every rule dataset (R2.7)
# ===============================================================

def test_every_alert_from_every_dataset_obeys_the_invariants():
    datasets = [
        (detect_failed_logins, fifteen_success_dataset()),
        (detect_failed_logins, make_failure_burst(ATTACKER_IP, 0, 12, 5, ["a", "b", "c", "d"])),
        (detect_port_scans, make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 40)),
        (detect_repeated_rejections, make_reject_events("10.0.0.31", 0, 25, 2)),
        (detect_unusual_traffic_volume, make_volume_events(HOST_A, [1000000] * 8 + [12000000])),
    ]
    for rule_function, events in datasets:
        alerts, notes = rule_function(events, default_config())
        assert len(alerts) >= 1
        for alert in alerts:
            check_alert_invariants(alert, events)
            assert alert["evidence"]["rule_parameters"] != {}
            assert alert["detected_at"].utcoffset() == timedelta(0)


# ===============================================================
# Alert ID behaviour (R2.1, R2.7)
# ===============================================================

def test_ids_scan_two_targets_through_run_analysis_gives_two_alerts_with_different_ids():
    # R2.7 dataset net_scan_two_targets. Allowed connections are used so that the
    # repeated-rejection rule does not also fire and the result is easy to read.
    events = (make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 20, status="allowed")
              + make_scan_events(ATTACKER_IP, "10.0.0.6", 0, 20, status="allowed"))
    result = run_analysis(events, default_config())
    scans = [alert for alert in result["alerts"] if alert["rule_id"] == "NET_PORT_SCAN"]
    assert len(scans) == 2
    assert scans[0]["time_start"] == scans[1]["time_start"] and scans[0]["time_end"] == scans[1]["time_end"]
    assert scans[0]["source_ip"] == scans[1]["source_ip"]
    assert scans[0]["alert_id"] != scans[1]["alert_id"]


def test_ids_more_failures_inside_the_same_range_make_a_new_alert_id():
    original = [make_auth_event(offset, ATTACKER_IP, "admin", "failure") for offset in [0, 75, 150, 225, 300]]
    extra = make_auth_event(100, ATTACKER_IP, "admin", "failure")
    before = run_auth(original)[0]
    after = run_auth(original + [extra])[0]
    assert before["time_start"] == after["time_start"] and before["time_end"] == after["time_end"]
    assert len(after["event_ids"]) == 6
    assert before["alert_id"] != after["alert_id"]


def test_ids_changing_thresholds_but_not_the_evidence_keeps_the_same_id():
    events = make_failure_burst(ATTACKER_IP, 0, 5, 1)
    strict = run_auth(events, auth_failed_threshold=5)[0]
    loose = run_auth(events, auth_failed_threshold=4)[0]
    assert strict["alert_id"] == loose["alert_id"]
    assert strict["evidence"]["rule_parameters"]["auth_failed_threshold"] == 5
    assert loose["evidence"]["rule_parameters"]["auth_failed_threshold"] == 4


# ===============================================================
# I.4 labelled datasets: true positives, false positives, false negatives
# ===============================================================
# Each dataset says which rules it is about and which alerts a person would
# EXPECT (the label). We count, per rule: TP (expected and produced), FP
# (produced but not expected) and FN (expected but not produced). The datasets
# were written by us for rules we wrote, so the scores show the code does what
# we meant; they say nothing about performance on real networks (I.4).

def labelled_datasets():
    """List of (name, rules_under_test, events, expected list of (rule_id, source_ip))."""
    auth_rule = ["AUTH_BRUTE_FORCE"]
    scan_rule = ["NET_PORT_SCAN"]
    reject_rule = ["NET_REPEATED_REJECTS"]
    volume_rule = ["NET_HIGH_VOLUME"]
    corr_rule = ["CORR_AUTH_NET"]
    attacker_login = ("AUTH_BRUTE_FORCE", ATTACKER_IP)
    forgetful = [make_auth_event(0, "10.0.0.23", "carol", "failure"), make_auth_event(20, "10.0.0.23", "carol", "failure"),
                 make_auth_event(40, "10.0.0.23", "carol", "success")]
    busy_client = [make_network_event(index, "198.51.100.23", "10.0.0.8", 443, "allowed", bytes_sent=500 + index) for index in range(500)]
    login_burst = make_failure_burst(ATTACKER_IP, 0, 6, 4)
    return [
        ("auth_below_threshold", auth_rule, make_failure_burst(ATTACKER_IP, 0, 4, 15), []),
        ("auth_at_threshold", auth_rule, make_failure_burst(ATTACKER_IP, 0, 5, 15), [attacker_login]),
        ("auth_password_spray", auth_rule, make_failure_burst(ATTACKER_IP, 0, 12, 5, ["admin", "root", "backup", "test"]), [attacker_login]),
        ("auth_success_after_failures", auth_rule, six_admin_failures() + [make_auth_event(35, ATTACKER_IP, "admin", "success")], [attacker_login]),
        ("auth_two_bursts", auth_rule, make_failure_burst(ATTACKER_IP, 0, 5, 10) + make_failure_burst(ATTACKER_IP, 7200, 5, 10), [attacker_login, attacker_login]),
        ("auth_slow_attack", auth_rule, make_failure_burst(ATTACKER_IP, 0, 5, 300), [attacker_login]),
        ("auth_forgetful_user", auth_rule, forgetful, []),
        ("net_scan_positive", scan_rule, make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 40), [("NET_PORT_SCAN", ATTACKER_IP)]),
        ("net_scan_below", scan_rule, make_scan_events(ATTACKER_IP, "10.0.0.5", 0, 14), []),
        ("net_busy_web_client", scan_rule, busy_client, []),
        ("net_rejects_positive", reject_rule, make_reject_events("10.0.0.31", 0, 25, 2, vary_destinations=True), [("NET_REPEATED_REJECTS", "10.0.0.31")]),
        ("net_rejects_single_target", reject_rule, make_reject_events("10.0.0.31", 0, 25, 2), [("NET_REPEATED_REJECTS", "10.0.0.31")]),
        ("net_volume_positive", volume_rule, make_volume_events(HOST_A, [1000000] * 8 + [12000000]), [("NET_HIGH_VOLUME", HOST_A)]),
        ("net_volume_no_bytes", volume_rule, [make_network_event(index * 60, HOST_A, "192.0.2.80", 443, "allowed") for index in range(12)], []),
        ("net_nightly_backup", volume_rule, make_volume_events("10.0.0.60", [200000] * 10 + [50000000]), []),
        ("corr_positive", corr_rule, login_burst + make_scan_events(ATTACKER_IP, "10.0.0.77", 300, 20), [("CORR_AUTH_NET", ATTACKER_IP)]),
        ("corr_destination_match", corr_rule, login_burst + make_scan_events(ATTACKER_IP, "10.0.0.5", 300, 20), [("CORR_AUTH_NET", ATTACKER_IP)]),
        ("corr_different_ip", corr_rule, login_burst + make_scan_events(OTHER_IP, "10.0.0.5", 300, 20), []),
        ("corr_far_apart", corr_rule, login_burst + make_scan_events(ATTACKER_IP, "10.0.0.5", 7200, 20), []),
    ]


def count_outcomes(produced_pairs, expected_pairs):
    """TP, FP, FN for one dataset. A pair is (rule_id, source_ip); repeats count."""
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    for pair in set(produced_pairs) | set(expected_pairs):
        produced = produced_pairs.count(pair)
        expected = expected_pairs.count(pair)
        true_positives = true_positives + min(produced, expected)
        false_positives = false_positives + max(produced - expected, 0)
        false_negatives = false_negatives + max(expected - produced, 0)
    return true_positives, false_positives, false_negatives


def test_labelled_datasets_table_of_tp_fp_fn_per_rule():
    totals = {}
    for name, rules_under_test, events, expected_pairs in labelled_datasets():
        result = run_analysis(events, default_config())
        produced_pairs = []
        for alert in result["alerts"]:
            if alert["rule_id"] in rules_under_test:
                produced_pairs.append((alert["rule_id"], alert["source_ip"]))
        true_positives, false_positives, false_negatives = count_outcomes(produced_pairs, expected_pairs)
        for rule_id in rules_under_test:
            tally = totals.setdefault(rule_id, [0, 0, 0])
            tally[0] = tally[0] + true_positives
            tally[1] = tally[1] + false_positives
            tally[2] = tally[2] + false_negatives
    print("")
    print("rule                  TP  FP  FN  precision  recall")
    for rule_id in sorted(totals):
        tp, fp, fn = totals[rule_id]
        precision = "n/a" if tp + fp == 0 else format(tp / (tp + fp), ".2f")
        recall = "n/a" if tp + fn == 0 else format(tp / (tp + fn), ".2f")
        print(rule_id.ljust(20), str(tp).rjust(3), str(fp).rjust(3), str(fn).rjust(3), precision.rjust(10), recall.rjust(7))
    # The known, explained errors (I.4): the slow attack is missed (false negative of
    # a 300 s window) and the nightly backup is flagged (false positive of volume alone).
    assert totals["AUTH_BRUTE_FORCE"] == [5, 0, 1]
    assert totals["NET_PORT_SCAN"] == [1, 0, 0]
    assert totals["NET_REPEATED_REJECTS"] == [2, 0, 0]
    assert totals["NET_HIGH_VOLUME"] == [1, 1, 0]
    assert totals["CORR_AUTH_NET"] == [2, 0, 0]
