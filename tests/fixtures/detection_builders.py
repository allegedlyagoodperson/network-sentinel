# tests/fixtures/detection_builders.py
# ---------------------------------------------------------------
# Purpose: synthetic-event builders and alert checks for the detection tests.
# make_auth_event / make_network_event: one valid event, built with make_event.
# make_failure_burst / make_scan_events / make_reject_events / make_volume_events:
#     whole datasets with a known outcome.
# check_alert_invariants / all_alert_text: rules every alert must obey.
# load_sample_events: reads the Stage 0 sample CSVs (a tiny stand-in for ingestion,
#     which belongs to the ingestion module). All addresses are documentation/private ranges.

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config.settings import get_default_config
from core.contracts import make_event, validate_alert

PROJECT_FOLDER = Path(__file__).resolve().parents[2]

# 09:00:00 UTC is a multiple of 300 seconds, so volume buckets line up with these times.
BASE_TIME = datetime(2025, 3, 14, 9, 0, 0, tzinfo=timezone.utc)

FORBIDDEN_WORDS = ["compromised", "breached", "attacker", "confirmed"]


def time_at(seconds):
    """A UTC time this many seconds after 09:00:00 on 2025-03-14 (may be fractional)."""
    return BASE_TIME + timedelta(seconds=seconds)


def default_config(**changes):
    """A fresh default configuration with some settings changed for one test."""
    config = get_default_config()
    for key in changes:
        config[key] = changes[key]
    return config


# ---------------------------------------------------------------
# Single events
# ---------------------------------------------------------------

def make_auth_event(seconds, source_ip, username, status, destination_ip="10.0.0.5", occurrence=1):
    """One authentication event, `seconds` after 09:00:00."""
    return make_event(
        event_type="authentication", timestamp=time_at(seconds), source_ip=source_ip, status=status,
        source_file="auth_test.csv", source_row=2, raw_event={"test": "auth"}, occurrence=occurrence,
        destination_ip=destination_ip, username=username, service="ssh",
    )


def make_network_event(seconds, source_ip, destination_ip, destination_port, status,
                       bytes_sent=None, occurrence=1):
    """One network connection event, `seconds` after 09:00:00."""
    return make_event(
        event_type="network_connection", timestamp=time_at(seconds), source_ip=source_ip, status=status,
        source_file="network_test.csv", source_row=2, raw_event={"test": "network"}, occurrence=occurrence,
        destination_ip=destination_ip, destination_port=destination_port, protocol="TCP",
        bytes_sent=bytes_sent, bytes_received=0 if bytes_sent is not None else None,
    )


# ---------------------------------------------------------------
# Whole datasets
# ---------------------------------------------------------------

def make_failure_burst(source_ip, start_seconds, count, spacing_seconds, usernames=None):
    """`count` failed logins, `spacing_seconds` apart, usernames used in turn."""
    if usernames is None:
        usernames = ["admin"]
    events = []
    for index in range(count):
        username = usernames[index % len(usernames)]
        events.append(make_auth_event(start_seconds + index * spacing_seconds, source_ip, username, "failure"))
    return events


def make_scan_events(source_ip, destination_ip, start_seconds, port_count, status="rejected",
                     spacing_seconds=1, first_port=1000):
    """One connection to each of `port_count` different ports."""
    events = []
    for index in range(port_count):
        events.append(make_network_event(start_seconds + index * spacing_seconds, source_ip, destination_ip,
                                         first_port + index, status, bytes_sent=60))
    return events


def make_reject_events(source_ip, start_seconds, count, spacing_seconds, destination_ip="10.0.0.9",
                       destination_port=514, vary_destinations=False):
    """`count` rejected connections. They hit one address and port, or many addresses."""
    events = []
    for index in range(count):
        target_ip = destination_ip
        if vary_destinations:
            target_ip = "10.0.1." + str(index % 200 + 1)
        events.append(make_network_event(start_seconds + index * spacing_seconds, source_ip, target_ip,
                                         destination_port, "rejected", bytes_sent=60))
    return events


def make_volume_events(source_ip, bucket_totals, first_bucket_index=0):
    """One event per bucket (bucket k starts k x 300 s after 09:00:00). The event
    sits 30 s into its bucket and carries the whole bucket total as bytes_sent."""
    events = []
    for position in range(len(bucket_totals)):
        bucket_start = (first_bucket_index + position) * 300
        events.append(make_network_event(bucket_start + 30, source_ip, "192.0.2.80", 443, "allowed",
                                         bytes_sent=bucket_totals[position]))
    return events


# ---------------------------------------------------------------
# Checks every alert must pass
# ---------------------------------------------------------------

def all_alert_text(alert):
    """Every piece of human-readable text of an alert, joined in lower case."""
    pieces = [alert["title"], alert["description"], alert["recommended_action"]]
    pieces.extend(alert["evidence"]["explanation"])
    pieces.extend(alert["evidence"]["limitations"])
    if "correlation" in alert["evidence"]:
        pieces.extend(alert["evidence"]["correlation"]["match_conditions"])
    return " ".join(pieces).lower()


def check_alert_invariants(alert, events):
    """
    Assert the rules every alert must obey (FS.3.2 and R2.7): it passes
    validate_alert; every event_id exists in the input; every referenced event
    lies between time_start and time_end inclusive; time_start and time_end each
    equal some referenced timestamp; event_ids are in time order; the forbidden
    words never appear.
    """
    assert validate_alert(alert) == []
    events_by_id = {}
    for event in events:
        if isinstance(event, dict) and "event_id" in event:   # junk items are skipped by the rules too
            events_by_id[event["event_id"]] = event
    timestamps = []
    for event_id in alert["event_ids"]:
        assert event_id in events_by_id, "event_id not in the input: " + event_id
        timestamps.append(events_by_id[event_id]["timestamp"])
    for timestamp in timestamps:
        assert alert["time_start"] <= timestamp <= alert["time_end"]
    assert alert["time_start"] in timestamps
    assert alert["time_end"] in timestamps
    assert timestamps == sorted(timestamps)
    text = all_alert_text(alert)
    for word in FORBIDDEN_WORDS:
        assert word not in text, "forbidden word in alert text: " + word


# ---------------------------------------------------------------
# The Stage 0 sample files (a stand-in for ingestion, tests only)
# ---------------------------------------------------------------

def _text_or_none(value):
    """Empty CSV cell -> None."""
    if value is None or value == "":
        return None
    return value


def _number_or_none(value):
    """Empty CSV cell -> None, otherwise a whole number."""
    if value is None or value == "":
        return None
    return int(value)


def _read_sample_file(file_name, log_type):
    """Read one Stage 0 sample CSV into event dictionaries with make_event."""
    path = PROJECT_FOLDER / "data" / "sample" / file_name
    events = []
    seen_counts = {}
    with open(path, newline="", encoding="utf-8") as sample_file:
        for line_number, row in enumerate(csv.DictReader(sample_file), start=2):
            timestamp = datetime.fromisoformat(row["timestamp"]).replace(tzinfo=timezone.utc)
            details = {"destination_ip": _text_or_none(row.get("destination_ip"))}
            if log_type == "authentication":
                event_type = "authentication"
                details["username"] = row["username"]
                details["service"] = _text_or_none(row.get("service"))
            else:
                event_type = "network_connection"
                details["destination_port"] = _number_or_none(row["destination_port"])
                details["protocol"] = _text_or_none(row["protocol"])
                details["bytes_sent"] = _number_or_none(row["bytes_sent"])
                details["bytes_received"] = _number_or_none(row["bytes_received"])
            tally_key = json.dumps([row["timestamp"], row["source_ip"], row["status"], details], sort_keys=True)
            seen_counts[tally_key] = seen_counts.get(tally_key, 0) + 1
            events.append(make_event(event_type, timestamp, row["source_ip"], row["status"], file_name,
                                     line_number, dict(row), occurrence=seen_counts[tally_key], **details))
    return events


def load_sample_events():
    """The authentication and network sample events together (72 events)."""
    return _read_sample_file("auth_sample.csv", "authentication") + _read_sample_file("network_sample.csv", "network_connection")
