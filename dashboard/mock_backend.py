# dashboard/mock_backend.py
# ---------------------------------------------------------------
# Development and test backend for controlled demonstrations.
# It supplies deterministic sample responses when mock mode is explicitly enabled.
# The normal application configuration uses the real backend modules.
# Purpose: provide deterministic stand-ins for ingestion, detection, storage and
# reporting so dashboard pages can be tested without changing production data.
# Every mock function takes
# and returns exactly the shapes of FS.4 / Section C / Section D.
# The mock NEVER reads the contents of uploaded files: it returns a fixed
# scenario that matches data/sample/*.csv and expected_results.json.
# The mock "database" lives in st.session_state["mock_database"] (lost on refresh).
# Only dashboard/backend_calls.py imports this file.
# Uses: core (contracts and errors), config.settings, streamlit.

from datetime import datetime, timedelta, timezone

import streamlit as st

from config.settings import validate_config
from core.contracts import (
    ALLOWED_STATUS_TRANSITIONS,
    EVENT_TYPES,
    INCIDENT_STATUSES,
    MAX_DETAILED_SUCCESS_EVENTS,
    SEVERITIES,
    datetime_to_iso,
    make_alert,
    make_event,
    severity_rank,
    utc_now,
    validate_alert,
)
from core.errors import (
    BrokenReferenceError,
    ContractError,
    IncidentNotFound,
    IngestionError,
    InvalidStatusTransition,
)

MOCK_NOTICE = "MOCK: the file contents were not read; a fixed sample scenario was returned."

# ---------------------------------------------------------------
# Fixed sample rows (the same scenario as data/sample/*.csv)
# ---------------------------------------------------------------

_AUTH_ROWS = [
    ("2025-03-14T08:58:10", "10.0.0.21", "alice", "success", "10.0.0.5", "ssh"),
    ("2025-03-14T09:02:45", "10.0.0.22", "bob", "success", "10.0.0.5", "rdp"),
    ("2025-03-14T09:05:12", "10.0.0.23", "carol", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T09:05:30", "10.0.0.23", "carol", "success", "10.0.0.5", "ssh"),
    ("2025-03-14T09:15:02", "203.0.113.50", "admin", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T09:15:09", "203.0.113.50", "admin", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T09:15:14", "203.0.113.50", "backup", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T09:15:20", "203.0.113.50", "root", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T09:15:31", "203.0.113.50", "admin", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T09:15:44", "203.0.113.50", "test", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T09:15:51", "203.0.113.50", "backup", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T09:15:58", "203.0.113.50", "admin", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T09:16:40", "203.0.113.50", "backup", "success", "10.0.0.5", "ssh"),
    ("2025-03-14T09:20:41", "198.51.100.23", "alice", "success", "10.0.0.5", "ssh"),
    ("2025-03-14T09:21:03", "198.51.100.23", "alice", "success", None, "web"),
    ("2025-03-14T10:02:10", "198.51.100.77", "admin", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T10:02:25", "198.51.100.77", "admin", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T10:02:41", "198.51.100.77", "admin", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T10:02:58", "198.51.100.77", "admin", "failure", "10.0.0.5", "ssh"),
    ("2025-03-14T10:30:00", "10.0.0.21", "alice", "success", "10.0.0.5", "ssh"),
]

_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5900, 8080]
_VOLUME_NORMAL_BYTES = [1000000, 1200000, 900000, 1100000, 1000000, 1300000, 950000, 1050000]
_VOLUME_NORMAL_TIMES = ["11:02:30", "11:07:30", "11:12:30", "11:17:30", "11:22:30", "11:27:30", "11:32:30", "11:37:30"]


def _network_rows():
    """
    Purpose: build the 52 fixed network rows of the mock scenario (the same rows as data/sample/network_sample.csv).
    Inputs: none.
    Output: list of tuples (time, source, destination, port, protocol, status, bytes_sent, bytes_received).
    Steps:
        1. Add the 18 port scan rows (one per second).
        2. Add the web client and ICMP rows.
        3. Add 20 rejections 5 seconds apart.
        4. Add the 8 normal traffic rows and the 12,000,000 byte row.
    Example: len(_network_rows()) -> 52.
    Errors: none.
    """
    rows = []
    for second_number in range(len(_SCAN_PORTS)):
        port = _SCAN_PORTS[second_number]
        status = "allowed" if port == 80 else "rejected"
        bytes_sent = 520 if port == 80 else 60
        rows.append(("2025-03-14T09:16:" + str(second_number).zfill(2), "203.0.113.50", "10.0.0.5", port, "TCP", status, bytes_sent, 0))
    rows.append(("2025-03-14T09:17:30", "198.51.100.23", "10.0.0.8", 443, "TCP", "allowed", 15200, 88400))
    rows.append(("2025-03-14T09:17:45", "198.51.100.23", "10.0.0.8", 443, "TCP", "allowed", 9800, 64100))
    rows.append(("2025-03-14T09:18:00", "10.0.0.12", "192.0.2.44", None, "ICMP", "allowed", None, None))
    rows.append(("2025-03-14T09:18:20", "198.51.100.23", "10.0.0.8", 443, "TCP", "allowed", 12300, 70250))
    rows.append(("2025-03-14T09:19:05", "198.51.100.23", "10.0.0.8", 443, "TCP", "allowed", 7400, 51900))
    for reject_number in range(20):
        seconds = reject_number * 5
        time_text = "2025-03-14T09:" + str(40 + seconds // 60) + ":" + str(seconds % 60).zfill(2)
        rows.append((time_text, "10.0.0.31", "10.0.0.9", 514, "UDP", "rejected", 60, 0))
    for index in range(len(_VOLUME_NORMAL_BYTES)):
        time_text = "2025-03-14T" + _VOLUME_NORMAL_TIMES[index]
        rows.append((time_text, "10.0.0.40", "192.0.2.80", 443, "TCP", "allowed", _VOLUME_NORMAL_BYTES[index], 52000))
    rows.append(("2025-03-14T11:42:30", "10.0.0.40", "192.0.2.80", 443, "TCP", "allowed", 12000000, 48000))
    return rows


def _parse_time(time_text):
    """Sample times have no timezone, so they are read as UTC (decision D1)."""
    return datetime.fromisoformat(time_text).replace(tzinfo=timezone.utc)


def _text_or_empty(value):
    """CSV cells are always text; a missing value is an empty cell."""
    if value is None:
        return ""
    return str(value)


def _build_auth_events(file_name):
    """Events for the fixed authentication scenario, built with make_event."""
    events = []
    row_number = 2  # line 1 of a CSV file is the header
    for time_text, source_ip, username, status, destination_ip, service in _AUTH_ROWS:
        raw_event = {
            "timestamp": time_text, "source_ip": source_ip, "username": username,
            "status": status, "destination_ip": _text_or_empty(destination_ip), "service": service,
        }
        events.append(make_event(
            "authentication", _parse_time(time_text), source_ip, status, file_name, row_number,
            raw_event, destination_ip=destination_ip, username=username, service=service,
        ))
        row_number += 1
    return events


def _build_network_events(file_name):
    """
    Purpose: turn the fixed network rows into real event dictionaries with make_event.
    Inputs: file_name (str) - becomes source_file of every event.
    Output: list of 52 event dictionaries.
    Steps:
        1. Walk through the rows; the first data row is CSV line 2.
        2. Build the raw_event text row.
        3. Call make_event for each row.
    Example: _build_network_events('net.csv')[0]['source_file'] -> 'net.csv'.
    Errors: ContractError if a row were invalid (it is not).
    """
    events = []
    row_number = 2
    for row in _network_rows():
        time_text, source_ip, destination_ip, port, protocol, status, bytes_sent, bytes_received = row
        raw_event = {
            "timestamp": time_text, "source_ip": source_ip, "destination_ip": destination_ip,
            "destination_port": _text_or_empty(port), "protocol": protocol, "status": status,
            "bytes_sent": _text_or_empty(bytes_sent), "bytes_received": _text_or_empty(bytes_received),
        }
        events.append(make_event(
            "network_connection", _parse_time(time_text), source_ip, status, file_name, row_number,
            raw_event, destination_ip=destination_ip, destination_port=port, protocol=protocol,
            bytes_sent=bytes_sent, bytes_received=bytes_received,
        ))
        row_number += 1
    return events


# ---------------------------------------------------------------
# Mock ingestion (stands in for ingestion/csv_ingest.py, the ingestion module)
# ---------------------------------------------------------------

def mock_ingest_file(file_bytes, file_name, log_type, config):
    """
    Purpose: MOCK of ingest_file. Returns the fixed scenario in the D.6 shape.
    Inputs: file_bytes (bytes), file_name (str), log_type (str), config (dict).
    Output: dict - file_name, log_type, events, rejected_rows, summary (D.6).
    Steps:
        1. Do two tiny file-level checks so the error display can be shown
           (unknown log type, wrong extension, empty file).
        2. Build the fixed events for that log type, named after the file.
        3. Return them with a summary that carries a MOCK warning.
    Example: mock_ingest_file(b"x", "auth.csv", "authentication", {}) -> 20 events.
    Errors: IngestionError for the checks in step 1.
    """
    if log_type not in EVENT_TYPES:
        raise IngestionError("Unknown log type: " + str(log_type))
    if not file_name.lower().endswith(".csv"):
        raise IngestionError(file_name + ": the file must have the extension .csv")
    if len(file_bytes) == 0:
        raise IngestionError(file_name + ": the file is empty")
    if log_type == "authentication":
        events = _build_auth_events(file_name)
    else:
        events = _build_network_events(file_name)
    summary = {
        "rows_read": len(events),
        "rows_blank": 0,
        "events_accepted": len(events),
        "rows_rejected": 0,
        "earliest_timestamp": events[0]["timestamp"],
        "latest_timestamp": events[-1]["timestamp"],
        "warnings": [MOCK_NOTICE],
    }
    return {"file_name": file_name, "log_type": log_type, "events": events,
            "rejected_rows": [], "summary": summary}


def _event_sort_key(event):
    """Sort order used by combine_ingestion_results: time, then file, then row."""
    return (event["timestamp"], event["source_file"], event["source_row"])


def mock_combine_ingestion_results(results):
    """
    Purpose: MOCK of combine_ingestion_results (R1.1.5 keys).
    Inputs: results (list of D.6 dictionaries).
    Output: dict - events, rejected_rows, summaries, duplicates_removed,
        overlap_warnings (always empty in the mock).
    Steps:
        1. Collect events, dropping an event whose ID was already seen.
        2. Sort the events by time, file name and row.
        3. Collect rejected rows and summaries.
    Example: the same file added twice -> duplicates_removed equals its event count.
    Errors: none.
    """
    seen_ids = set()
    events = []
    rejected_rows = []
    summaries = []
    duplicates_removed = 0
    for result in results:
        for event in result["events"]:
            if event["event_id"] in seen_ids:
                duplicates_removed += 1
            else:
                seen_ids.add(event["event_id"])
                events.append(event)
        rejected_rows.extend(result["rejected_rows"])
        summaries.append(result["summary"])
    events = sorted(events, key=_event_sort_key)
    return {"events": events, "rejected_rows": rejected_rows, "summaries": summaries,
            "duplicates_removed": duplicates_removed, "overlap_warnings": []}


# ---------------------------------------------------------------
# Mock analysis (stands in for detection/engine.py, the detection and correlation modules)
# The mock only looks at the fixed scenario's addresses and mostly ignores
# thresholds; it copies them into rule_parameters so the panels look real.
# ---------------------------------------------------------------

def _select_events(events, source_ip, event_type, status=None):
    """Events from one address of one type (and optionally one status), in the order given."""
    selected = []
    for event in events:
        if event["source_ip"] != source_ip or event["event_type"] != event_type:
            continue
        if status is not None and event["status"] != status:
            continue
        selected.append(event)
    return selected


def _ids_in_time_order(events):
    """The event IDs of the given events, in time order (the stored order)."""
    id_list = []
    for event in sorted(events, key=_event_sort_key):
        id_list.append(event["event_id"])
    return id_list


def _link_successes(failures, successes, window_seconds):
    """Successes strictly after the last failure and at most window_seconds later (R2.2)."""
    linked = []
    last_failure_time = failures[-1]["timestamp"]
    for success in successes:
        seconds_after = (success["timestamp"] - last_failure_time).total_seconds()
        if 0 < seconds_after <= window_seconds:
            linked.append(success)
    return linked


def _auth_confidence(distinct_count, failure_count, threshold):
    """Confidence rubric of FS.3.3. A success never raises it."""
    if distinct_count >= 3 or failure_count >= 3 * threshold:
        return "high"
    if distinct_count == 1 and failure_count < 2 * threshold:
        return "low"
    return "medium"


def _success_detail_list(linked, failed_usernames):
    """The detail list of linked successes (at most MAX_DETAILED_SUCCESS_EVENTS)."""
    details = []
    for success in linked[:MAX_DETAILED_SUCCESS_EVENTS]:
        details.append({
            "event_id": success["event_id"],
            "timestamp": datetime_to_iso(success["timestamp"]),
            "username": success["username"],
            "username_also_failed": success["username"].lower() in failed_usernames,
        })
    return details


def _auth_evidence(failures, linked, config):
    """
    Purpose: build the evidence dictionary of the mock AUTH_BRUTE_FORCE alert with the FS.3.3 and R2.3 keys.
    Inputs: failures (list of events), linked (list of linked success events), config (dict).
    Output: dict - evidence with the four required keys plus the rule's extra keys.
    Steps:
        1. Work out usernames, the burst length and the linked success names.
        2. Write the explanation sentences (the timing sentence only if a success is linked).
        3. Fill in the detail list of at most 10 successes.
    Example: 8 failures and 1 linked success -> followed_by_success True, success_event_count 1.
    Errors: none.
    """
    threshold = config["auth_failed_threshold"]
    usernames = sorted({event["username"] for event in failures})
    failed_lowercase = {name.lower() for name in usernames}
    successful_names = sorted({event["username"] for event in linked})
    span = int((failures[-1]["timestamp"] - failures[0]["timestamp"]).total_seconds())
    explanation = [str(len(failures)) + " failed logins were recorded from 203.0.113.50 within " + str(span) + " seconds. "
                   "The threshold is " + str(threshold) + " in " + str(config["auth_window_seconds"]) + " seconds."]
    if len(linked) > 0:
        seconds_after = int((linked[0]["timestamp"] - failures[-1]["timestamp"]).total_seconds())
        explanation.append("A successful login for " + ", ".join(successful_names) + " was recorded from the same address "
                           + str(seconds_after) + " seconds after the last failed attempt.")
    return {
        "rule_parameters": {"auth_failed_threshold": threshold, "auth_window_seconds": config["auth_window_seconds"],
                            "auth_success_after_failure_seconds": config["auth_success_after_failure_seconds"]},
        "observed": {"failure_count": len(failures), "distinct_usernames": len(usernames)},
        "explanation": explanation,
        "limitations": [
            "A real user who mistyped a password and then succeeded looks the same.",
            "Several people sharing one address (for example an office router) can look the same.",
            "This alert does not show whether the login was authorised.",
        ],
        "failure_count": len(failures), "distinct_usernames": len(usernames), "usernames_sample": usernames[:10],
        "followed_by_success": len(linked) > 0, "success_event_count": len(linked),
        "success_events": _success_detail_list(linked, failed_lowercase),
        "success_events_not_detailed": max(0, len(linked) - MAX_DETAILED_SUCCESS_EVENTS),
        "successful_usernames": successful_names,
        "successful_usernames_also_failed": sorted([name for name in successful_names if name.lower() in failed_lowercase]),
    }


def _build_mock_auth_alert(events, config, detected_at):
    """
    Purpose: MOCK of AUTH_BRUTE_FORCE for the address 203.0.113.50 only.
    Inputs: events (list), config (dict), detected_at (datetime).
    Output: alert dictionary, or None if there are too few failures.
    Steps:
        1. Pick the failures and successes of the address.
        2. Return None below the failure threshold.
        3. Link successes after the last failure, build the evidence and the alert with make_alert.
    Example: sample events -> severity high, confidence high, 9 event IDs.
    Errors: none.
    """
    failures = _select_events(events, "203.0.113.50", "authentication", "failure")
    successes = _select_events(events, "203.0.113.50", "authentication", "success")
    threshold = config["auth_failed_threshold"]
    if len(failures) < threshold:
        return None
    linked = _link_successes(failures, successes, config["auth_success_after_failure_seconds"])
    evidence = _auth_evidence(failures, linked, config)
    ordered = sorted(failures + linked, key=_event_sort_key)
    confidence = _auth_confidence(evidence["distinct_usernames"], len(failures), threshold)
    return make_alert(
        "AUTH_BRUTE_FORCE", "Repeated failed logins from one source",
        "Possible repeated failed logins were recorded from 203.0.113.50 and a successful login from the same address followed.",
        "high" if linked else "medium", confidence, ordered[0]["timestamp"], ordered[-1]["timestamp"], "203.0.113.50",
        _ids_in_time_order(ordered), evidence,
        "Review the targeted accounts, consider temporarily blocking the address, enable multi-factor authentication, "
        "and check whether the later login was expected.", detected_at,
    )


def _build_mock_scan_alert(events, config, detected_at):
    """
    Purpose: MOCK of NET_PORT_SCAN for 203.0.113.50 scanning 10.0.0.5.
    Inputs: events (list), config (dict), detected_at (datetime).
    Output: alert dictionary, or None if too few distinct ports.
    Steps:
        1. Pick the address's connections to 10.0.0.5 that have a port.
        2. Return None below the distinct port threshold.
        3. Work out the rejected share, severity and confidence.
        4. Build the alert with make_alert.
    Example: sample events -> 18 ports, severity medium, confidence high.
    Errors: none.
    """
    scan_events = []
    for event in _select_events(events, "203.0.113.50", "network_connection"):
        if event["destination_ip"] == "10.0.0.5" and event["destination_port"] is not None:
            scan_events.append(event)
    ports = sorted({event["destination_port"] for event in scan_events})
    threshold = config["portscan_distinct_ports_threshold"]
    if len(ports) < threshold:
        return None
    rejected_count = len(_select_events(scan_events, "203.0.113.50", "network_connection", "rejected"))
    rejected_ratio = rejected_count / len(scan_events)
    confidence = "high" if rejected_ratio >= 0.7 else "medium"
    severity = "high" if len(ports) >= 3 * threshold else "medium"
    evidence = {
        "rule_parameters": {"portscan_distinct_ports_threshold": threshold, "portscan_window_seconds": config["portscan_window_seconds"]},
        "observed": {"distinct_port_count": len(ports), "rejected_ratio": round(rejected_ratio, 2)},
        "explanation": [str(len(ports)) + " distinct ports on 10.0.0.5 were tried by 203.0.113.50; the threshold is " + str(threshold) + "."],
        "limitations": ["An authorised vulnerability scanner produces the same pattern.",
                        "A legitimate application that probes several services can look similar."],
        "distinct_port_count": len(ports), "ports_sample": ports[:20], "destination_ip": "10.0.0.5",
        "rejected_ratio": round(rejected_ratio, 2),
    }
    ordered = sorted(scan_events, key=_event_sort_key)
    return make_alert(
        "NET_PORT_SCAN", "Possible port scanning activity",
        "A possible port scan of 10.0.0.5 was recorded from 203.0.113.50.", severity, confidence,
        ordered[0]["timestamp"], ordered[-1]["timestamp"], "203.0.113.50", _ids_in_time_order(scan_events), evidence,
        "Confirm whether the source is an authorised scanner, check the targeted host for exposed services, and consider blocking the source.",
        detected_at,
    )


def _build_mock_reject_alert(events, config, detected_at):
    """
    Purpose: MOCK of NET_REPEATED_REJECTS for 10.0.0.31.
    Inputs: events (list), config (dict), detected_at (datetime).
    Output: alert dictionary, or None below the rejection threshold.
    Steps:
        1. Pick the address's rejected connections.
        2. Return None below the threshold.
        3. Low confidence when every rejection hits one address and port.
        4. Build the alert with make_alert.
    Example: sample events -> 20 rejections, severity low, confidence low.
    Errors: none.
    """
    rejected = _select_events(events, "10.0.0.31", "network_connection", "rejected")
    threshold = config["reject_threshold"]
    if len(rejected) < threshold:
        return None
    targets = {(event["destination_ip"], event["destination_port"]) for event in rejected}
    severity = "medium" if len(rejected) >= 3 * threshold else "low"
    evidence = {
        "rule_parameters": {"reject_threshold": threshold, "reject_window_seconds": config["reject_window_seconds"]},
        "observed": {"rejected_count": len(rejected)},
        "explanation": [str(len(rejected)) + " rejected connections were recorded from 10.0.0.31; the threshold is " + str(threshold) + "."],
        "limitations": ["A misconfigured client that keeps retrying looks the same.",
                        "Every rejection targeted one address and port, which is typical of a faulty client."],
        "rejected_count": len(rejected), "distinct_destinations": 1, "distinct_ports": 1, "top_destination_port": 514,
    }
    confidence = "low" if len(targets) == 1 else "medium"
    ordered = sorted(rejected, key=_event_sort_key)
    return make_alert(
        "NET_REPEATED_REJECTS", "Repeated rejected network connections",
        "Possible repeated rejected connections were recorded from 10.0.0.31.", severity, confidence,
        ordered[0]["timestamp"], ordered[-1]["timestamp"], "10.0.0.31", _ids_in_time_order(rejected), evidence,
        "Check firewall rules and whether a legitimate client is misconfigured; monitor for escalation.", detected_at,
    )


def _median_of(numbers):
    """The median of a list of numbers (middle value, or average of the two middle values)."""
    ordered = sorted(numbers)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _volume_evidence(biggest, baseline, host_event_count, config):
    """
    Purpose: build the evidence dictionary of the mock NET_HIGH_VOLUME alert (FS.3.3 keys).
    Inputs: biggest (the event with the most bytes), baseline (number), host_event_count (int), config (dict).
    Output: dict - evidence including bucket_start, bucket_end and baseline_scope.
    Steps:
        1. Work out the clock-aligned bucket the event falls in.
        2. Fill in the required evidence keys and the rule's extra keys.
    Example: 12,000,000 bytes at 11:42:30 -> bucket_start 11:40:00.
    Errors: none.
    """
    window = config["volume_window_seconds"]
    bucket_start_seconds = int(biggest["timestamp"].timestamp()) // window * window
    bucket_start = datetime.fromtimestamp(bucket_start_seconds, timezone.utc)
    return {
        "rule_parameters": {"volume_min_bytes": config["volume_min_bytes"], "volume_multiplier": config["volume_multiplier"],
                            "volume_window_seconds": window, "volume_min_windows": config["volume_min_windows"]},
        "observed": {"bucket_bytes_sent": biggest["bytes_sent"], "baseline_bytes": baseline},
        "explanation": ["10.0.0.40 sent " + str(biggest["bytes_sent"]) + " bytes in one bucket; its own typical bucket is " + str(int(baseline)) + " bytes."],
        "limitations": ["A nightly backup or software update looks like this.",
                        "A source that is always very busy never triggers, because its own normal is already high."],
        "bucket_start": datetime_to_iso(bucket_start),
        "bucket_end": datetime_to_iso(bucket_start + timedelta(seconds=window)),
        "bucket_bytes_sent": biggest["bytes_sent"], "baseline_bytes": baseline,
        "multiplier_observed": round(biggest["bytes_sent"] / baseline, 2),
        "eligible_bucket_count": host_event_count, "baseline_scope": "this_source_ip_only",
    }


def _build_mock_volume_alert(events, config, detected_at):
    """
    Purpose: MOCK of NET_HIGH_VOLUME for host 10.0.0.40 (each event counts as one bucket).
    Inputs: events (list), config (dict), detected_at (datetime).
    Output: alert dictionary, or None if the host has too little data or no big enough bucket.
    Steps:
        1. Collect the host's events that have bytes_sent.
        2. Return None with too few buckets.
        3. Find the median and the biggest event.
        4. Return None unless it passes the minimum and the multiplier test.
        5. Build the evidence and the alert.
    Example: sample events -> one alert for the 12,000,000 byte event.
    Errors: none.
    """
    host_events = []
    for event in _select_events(events, "10.0.0.40", "network_connection"):
        if event["bytes_sent"] is not None:
            host_events.append(event)
    if len(host_events) < config["volume_min_windows"]:
        return None
    baseline = _median_of([event["bytes_sent"] for event in host_events])
    biggest = host_events[0]
    for event in host_events:
        if event["bytes_sent"] > biggest["bytes_sent"]:
            biggest = event
    if biggest["bytes_sent"] < config["volume_min_bytes"] or biggest["bytes_sent"] < config["volume_multiplier"] * baseline:
        return None
    evidence = _volume_evidence(biggest, baseline, len(host_events), config)
    return make_alert(
        "NET_HIGH_VOLUME", "Unusually high outbound traffic volume",
        "A recorded burst of outbound traffic from 10.0.0.40 was much larger than that host's own typical traffic.",
        "medium", "low", biggest["timestamp"], biggest["timestamp"], "10.0.0.40", [biggest["event_id"]], evidence,
        "Identify what the host was sending and to where, and compare with normal backups or updates.", detected_at,
    )


def _gap_in_seconds(first_alert, second_alert):
    """Seconds between two alert time ranges (0 if they overlap)."""
    if first_alert["time_end"] < second_alert["time_start"]:
        return int((second_alert["time_start"] - first_alert["time_end"]).total_seconds())
    if second_alert["time_end"] < first_alert["time_start"]:
        return int((first_alert["time_start"] - second_alert["time_end"]).total_seconds())
    return 0


def _destinations_of(alert, events_by_id):
    """The set of non-None destination addresses among an alert's events."""
    addresses = set()
    for event_id in alert["event_ids"]:
        address = events_by_id[event_id]["destination_ip"]
        if address is not None:
            addresses.add(address)
    return addresses


def _correlation_conditions(auth_alert, shared_destinations, config):
    """Plain-English statements for each linking condition that was met."""
    conditions = ["Both alerts have the same source address (" + auth_alert["source_ip"] + ").",
                  "The two time ranges overlap or are within " + str(config["correlation_window_seconds"]) + " seconds."]
    if len(shared_destinations) > 0:
        conditions.append("Both alerts involve the destination address " + sorted(shared_destinations)[0] + ".")
    return conditions


def _build_mock_correlated_alert(auth_alert, net_alert, events, config, detected_at):
    """
    Purpose: MOCK of CORR_AUTH_NET built from one authentication alert and one network alert.
    Inputs: auth_alert, net_alert (dicts), events (list), config (dict), detected_at (datetime).
    Output: alert dictionary whose event_ids are the union of the two alerts' event IDs.
    Steps:
        1. Compare the destination addresses of the two alerts.
        2. Join the event ID lists without duplicates.
        3. Write the correlation block.
        4. Severity critical if the login burst had a success; confidence high if destinations match.
    Example: sample alerts -> critical, high, 27 event IDs.
    Errors: none.
    """
    events_by_id = {event["event_id"]: event for event in events}
    shared = _destinations_of(auth_alert, events_by_id).intersection(_destinations_of(net_alert, events_by_id))
    destination_match = len(shared) > 0
    union_ids = list(auth_alert["event_ids"])
    for event_id in net_alert["event_ids"]:
        if event_id not in union_ids:
            union_ids.append(event_id)
    union_events = [events_by_id[event_id] for event_id in union_ids]
    evidence = {
        "rule_parameters": {"correlation_window_seconds": config["correlation_window_seconds"]},
        "observed": {"linked_alert_count": 2},
        "explanation": ["Failed logins and a port scan were recorded from the same address at overlapping times."],
        "limitations": ["Several people behind one shared address can create a false link.",
                        "Close timing alone never links alerts; the source address must match."],
        "correlation": {"link_key": "source_ip", "link_value": auth_alert["source_ip"],
                        "linked_alert_ids": [auth_alert["alert_id"], net_alert["alert_id"]],
                        "gap_seconds": _gap_in_seconds(auth_alert, net_alert), "destination_match": destination_match,
                        "match_conditions": _correlation_conditions(auth_alert, shared, config)},
    }
    ordered = sorted(union_events, key=_event_sort_key)
    severity = "critical" if auth_alert["evidence"]["followed_by_success"] else "high"
    return make_alert(
        "CORR_AUTH_NET", "Related authentication and network activity from the same source",
        "Possible related login and network activity was recorded from the same source address.",
        severity, "high" if destination_match else "medium",
        ordered[0]["timestamp"], ordered[-1]["timestamp"], auth_alert["source_ip"], _ids_in_time_order(union_events),
        evidence, "Treat the source as a priority for investigation, review the login and network evidence together, "
        "and consider creating an incident.", detected_at,
    )


def _skipped_sources_note(events):
    """A fixed note about sources with too few active buckets (the mock does not compute this)."""
    skipped = []
    for address in ["10.0.0.31", "198.51.100.23", "203.0.113.50"]:
        if len(_select_events(events, address, "network_connection")) > 0:
            skipped.append(address)
    if len(skipped) == 0:
        return None
    return ("NET_HIGH_VOLUME: " + str(len(skipped)) + " source addresses skipped (fewer than "
            + "6 active buckets): " + ", ".join(skipped))


def mock_run_analysis(events, config):
    """
    Purpose: MOCK of run_analysis. Builds canned alerts for the fixed scenario.
    Inputs: events (list of event dicts), config (dict).
    Output: dict - alerts, base_alert_count, correlated_alert_count, notes,
        events_analysed, events_ignored_trusted, analysed_at (FS.4).
    Steps:
        1. Check the configuration (ConfigError if invalid).
        2. Set aside events from trusted addresses and count them.
        3. Build each canned alert if its events are present.
        4. Build the correlated alert if both an authentication and a port scan alert exist.
        5. Sort alerts by time_start then rule_id and add the notes.
    Example: both sample files loaded -> 5 alerts (4 base, 1 correlated).
    Errors: ConfigError from validate_config.
    """
    config = validate_config(config)
    detected_at = utc_now()
    analysed = []
    for event in events:
        if event["source_ip"] not in config["trusted_ips"]:
            analysed.append(event)
    base_alerts = []
    builders = [_build_mock_auth_alert, _build_mock_scan_alert, _build_mock_reject_alert, _build_mock_volume_alert]
    for builder in builders:
        alert = builder(analysed, config, detected_at)
        if alert is not None:
            base_alerts.append(alert)
    correlated = []
    auth_alert = _first_alert_with_rule(base_alerts, "AUTH_BRUTE_FORCE")
    scan_alert = _first_alert_with_rule(base_alerts, "NET_PORT_SCAN")
    if auth_alert is not None and scan_alert is not None:
        correlated.append(_build_mock_correlated_alert(auth_alert, scan_alert, analysed, config, detected_at))
    all_alerts = sorted(base_alerts + correlated, key=_alert_time_rule_key)
    notes = ["MOCK ANALYSIS: these alerts are a fixed sample scenario, not real detection results."]
    skipped_note = _skipped_sources_note(analysed)
    if skipped_note is not None:
        notes.append(skipped_note)
    return {"alerts": all_alerts, "base_alert_count": len(base_alerts), "correlated_alert_count": len(correlated),
            "notes": notes, "events_analysed": len(analysed), "events_ignored_trusted": len(events) - len(analysed),
            "analysed_at": detected_at}


def _first_alert_with_rule(alerts, rule_id):
    """The first alert with this rule ID, or None."""
    for alert in alerts:
        if alert["rule_id"] == rule_id:
            return alert
    return None


def _alert_time_rule_key(alert):
    """Sort order of run_analysis: time_start, then rule_id."""
    return (alert["time_start"], alert["rule_id"])


# ---------------------------------------------------------------
# Mock storage (stands in for storage/database.py and storage/incidents.py, the storage and reporting modules)
# Everything is kept in st.session_state["mock_database"]; there is no SQL here.
# ---------------------------------------------------------------

def _get_store():
    """The mock database dictionary, created the first time it is needed."""
    if "mock_database" not in st.session_state:
        st.session_state["mock_database"] = {
            "alerts": {}, "events": {}, "alert_links": {}, "incidents": {},
            "notes": [], "history": [], "next_incident_id": 1, "next_note_id": 1, "next_history_id": 1,
        }
    return st.session_state["mock_database"]


def mock_initialise_database(db_path):
    """MOCK of initialise_database: just makes sure the mock store exists."""
    _get_store()


def _find_alert_in_list(alert_list, alert_id):
    """The alert with this ID in a list of alerts, or None."""
    if alert_list is None:
        return None
    for alert in alert_list:
        if alert["alert_id"] == alert_id:
            return alert
    return None


def _add_linked_base_alerts(chosen, available_alerts, store):
    """
    Purpose: R1.2.3 steps 2 and 3. Make sure every base alert that a chosen
        correlated alert depends on is chosen, available, or already stored.
    Inputs: chosen (dict of alert_id -> alert, extended in place),
        available_alerts (list or None), store (the mock database).
    Output: list of alert IDs that were added automatically.
    Steps:
        1. For each chosen correlated alert, read its linked alert IDs.
        2. If a linked ID is neither chosen nor stored, look in available_alerts.
        3. If it is nowhere, raise BrokenReferenceError.
        4. A linked alert must be a base alert, never a correlated one.
    Example: saving only CORR_AUTH_NET adds its two base alerts from the session list.
    Errors: BrokenReferenceError.
    """
    automatic_ids = []
    for alert in list(chosen.values()):
        if not alert["rule_id"].startswith("CORR_"):
            continue
        for linked_id in alert["evidence"]["correlation"]["linked_alert_ids"]:
            linked_alert = chosen.get(linked_id)
            if linked_alert is None:
                linked_alert = _find_alert_in_list(available_alerts, linked_id)
                if linked_alert is not None:
                    chosen[linked_id] = linked_alert
                    automatic_ids.append(linked_id)
                else:
                    linked_alert = store["alerts"].get(linked_id)
            if linked_alert is None:
                raise BrokenReferenceError("A linked base alert is missing: " + linked_id)
            if linked_alert["rule_id"].startswith("CORR_"):
                raise BrokenReferenceError("A linked alert must be a base alert: " + linked_id)
    return automatic_ids


def _write_alerts_and_events(chosen, events_by_id, needed_event_ids, automatic_ids, store):
    """
    Purpose: the write step of mock_save_alerts: events, then base alerts, then correlated alerts and their links.
    Inputs: chosen (dict of alerts), events_by_id (dict), needed_event_ids (list), automatic_ids (list), store (the mock database).
    Output: dict - the five save_alerts result keys.
    Steps:
        1. Store each needed event unless it is already stored (count it either way).
        2. Store base alerts before correlated alerts; skip ones already stored.
        3. Record the links of each correlated alert.
    Example: saving the same alerts twice -> the second result has only skipped duplicates.
    Errors: none (checks were done before this step).
    """
    result = {"alerts_inserted": 0, "alerts_skipped_duplicate": 0, "events_inserted": 0,
              "events_skipped_duplicate": 0, "base_alerts_added_automatically": automatic_ids}
    for event_id in needed_event_ids:
        if event_id in store["events"]:
            result["events_skipped_duplicate"] += 1
        else:
            store["events"][event_id] = events_by_id[event_id]
            result["events_inserted"] += 1
    base_first = sorted(chosen.values(), key=_base_alerts_first_key)
    for alert in base_first:
        if alert["alert_id"] in store["alerts"]:
            result["alerts_skipped_duplicate"] += 1
            continue
        store["alerts"][alert["alert_id"]] = alert
        result["alerts_inserted"] += 1
        if alert["rule_id"].startswith("CORR_"):
            store["alert_links"][alert["alert_id"]] = list(alert["evidence"]["correlation"]["linked_alert_ids"])
    return result


def mock_save_alerts(db_path, alerts, events, available_alerts=None):
    """
    Purpose: MOCK of save_alerts (R1.2): all-or-nothing, adds missing base alerts.
    Inputs: db_path (str, unused), alerts (list), events (list), available_alerts (list or None).
    Output: dict - alerts_inserted, alerts_skipped_duplicate, events_inserted,
        events_skipped_duplicate, base_alerts_added_automatically.
    Steps:
        1. Collect the chosen alerts and add linked base alerts.
        2. Validate every alert and check every event ID can be found.
        3. Only then write; anything already stored is skipped and counted.
    Example: saving twice -> the second call reports only skipped duplicates.
    Errors: BrokenReferenceError, ContractError.
    """
    store = _get_store()
    chosen = {}
    for alert in alerts:
        chosen[alert["alert_id"]] = alert
    automatic_ids = _add_linked_base_alerts(chosen, available_alerts, store)
    events_by_id = {}
    for event in events:
        events_by_id[event["event_id"]] = event
    needed_event_ids = []
    for alert in chosen.values():
        problems = validate_alert(alert)
        if len(problems) > 0:
            raise ContractError("Invalid alert " + alert["alert_id"] + ": " + "; ".join(problems))
        for event_id in alert["event_ids"]:
            if event_id not in events_by_id and event_id not in store["events"]:
                raise BrokenReferenceError("A supporting event is missing: " + event_id)
            if event_id not in needed_event_ids:
                needed_event_ids.append(event_id)
    return _write_alerts_and_events(chosen, events_by_id, needed_event_ids, automatic_ids, store)


def _base_alerts_first_key(alert):
    """Sort key that puts base alerts before correlated ones."""
    if alert["rule_id"].startswith("CORR_"):
        return 1
    return 0


def _alert_newest_first_key(alert):
    """Sort key: newest time_start first."""
    return -alert["time_start"].timestamp()


def _incident_ids_of_alert(store, alert_id):
    """The IDs of the incidents that contain this alert."""
    found = []
    for incident in store["incidents"].values():
        if alert_id in incident["alert_ids"]:
            found.append(incident["incident_id"])
    return found


def mock_get_alerts(db_path, filters=None):
    """
    Purpose: MOCK of get_alerts: stored alerts, newest first, with optional filters.
    Inputs: db_path (unused), filters (dict or None) with optional keys severity, confidence, rule_id, source_ip, incident_id.
    Output: list of alert dictionaries.
    Steps:
        1. Walk through the stored alerts.
        2. Skip an alert that fails the incident filter or any of the four value filters.
        3. Sort the rest newest first.
    Example: mock_get_alerts('db', {'severity': 'high'}) -> only high severity alerts.
    Errors: none.
    """
    store = _get_store()
    if filters is None:
        filters = {}
    matches = []
    for alert in store["alerts"].values():
        if "incident_id" in filters and filters["incident_id"] not in _incident_ids_of_alert(store, alert["alert_id"]):
            continue
        keep = True
        for key in ["severity", "confidence", "rule_id", "source_ip"]:
            if key in filters and alert[key] != filters[key]:
                keep = False
        if keep:
            matches.append(alert)
    return sorted(matches, key=_alert_newest_first_key)


def mock_get_events_for_alert(db_path, alert_id):
    """MOCK of get_events_for_alert: the stored events of one alert, oldest first."""
    store = _get_store()
    alert = store["alerts"].get(alert_id)
    if alert is None:
        return []
    events = []
    for event_id in alert["event_ids"]:
        events.append(store["events"][event_id])
    return sorted(events, key=_event_sort_key)


def mock_get_existing_alert_ids(db_path, alert_ids):
    """MOCK of get_existing_alert_ids: the subset of the given IDs that are stored."""
    store = _get_store()
    existing = []
    for alert_id in alert_ids:
        if alert_id in store["alerts"]:
            existing.append(alert_id)
    return existing


def mock_get_summary_counts(db_path):
    """MOCK of get_summary_counts: alerts_total, incidents_total, incidents_by_status, alerts_by_severity."""
    store = _get_store()
    by_status = {}
    for status in INCIDENT_STATUSES:
        by_status[status] = 0
    for incident in store["incidents"].values():
        by_status[incident["status"]] += 1
    by_severity = {}
    for severity in SEVERITIES:
        by_severity[severity] = 0
    for alert in store["alerts"].values():
        by_severity[alert["severity"]] += 1
    return {"alerts_total": len(store["alerts"]), "incidents_total": len(store["incidents"]),
            "incidents_by_status": by_status, "alerts_by_severity": by_severity}


# ----- incidents -----

def _expand_with_base_alerts(store, alert_ids):
    """Every alert ID must be stored (BrokenReferenceError otherwise); base alerts of
    correlated alerts are added (R2.5). Returns the full list without duplicates."""
    full_ids = []
    for alert_id in alert_ids:
        if alert_id not in store["alerts"]:
            raise BrokenReferenceError("Alert is not saved: " + alert_id)
        if alert_id not in full_ids:
            full_ids.append(alert_id)
        for base_id in store["alert_links"].get(alert_id, []):
            if base_id not in full_ids:
                full_ids.append(base_id)
    return full_ids


def _add_history(store, incident_id, action, old_value, new_value, changed_by):
    """Append one history row."""
    store["history"].append({
        "history_id": store["next_history_id"], "incident_id": incident_id, "action": action,
        "old_value": old_value, "new_value": new_value, "changed_by": changed_by, "changed_at": utc_now(),
    })
    store["next_history_id"] += 1


def _highest_severity(store, alert_ids):
    """The highest severity among the given stored alerts."""
    best = "low"
    for alert_id in alert_ids:
        severity = store["alerts"][alert_id]["severity"]
        if severity_rank(severity) > severity_rank(best):
            best = severity
    return best


def mock_create_incident(db_path, title, alert_ids, summary="", priority=None, created_by="analyst"):
    """
    Purpose: MOCK of create_incident (R2.5).
    Inputs: db_path (unused), title (1 to 120 characters), alert_ids (list of stored alert IDs),
        summary (str), priority (severity text or None), created_by (str).
    Output: int - the new incident number.
    Steps:
        1. Check the title and priority.
        2. Expand alert_ids with the base alerts of correlated alerts.
        3. Priority defaults to the highest severity of the full set.
        4. Store the incident (status open) and one created history row.
    Example: one correlated alert ID -> an incident holding 3 alerts, history "3 alerts".
    Errors: ValueError for a bad title or priority; BrokenReferenceError for an unsaved alert.
    """
    store = _get_store()
    if not isinstance(title, str) or len(title.strip()) < 1 or len(title) > 120:
        raise ValueError("The title must be 1 to 120 characters.")
    if priority is not None and priority not in SEVERITIES:
        raise ValueError("Unknown priority: " + str(priority))
    full_ids = _expand_with_base_alerts(store, alert_ids)
    if len(full_ids) == 0:
        raise ValueError("An incident needs at least one alert.")
    incident_id = store["next_incident_id"]
    store["next_incident_id"] += 1
    if priority is None:
        priority = _highest_severity(store, full_ids)
    now = utc_now()
    store["incidents"][incident_id] = {
        "incident_id": incident_id, "title": title.strip(), "summary": summary, "status": "open",
        "priority": priority, "created_at": now, "updated_at": now, "closed_at": None, "alert_ids": full_ids,
    }
    _add_history(store, incident_id, "created", None, str(len(full_ids)) + " alerts", created_by)
    return incident_id


def _get_incident_or_raise(store, incident_id):
    """The stored incident dictionary, or IncidentNotFound."""
    incident = store["incidents"].get(incident_id)
    if incident is None:
        raise IncidentNotFound("No incident with number " + str(incident_id))
    return incident


def _incidents_newest_updated_first_key(incident):
    """Sort key: most recently updated first."""
    return -incident["updated_at"].timestamp()


def mock_list_incidents(db_path, status=None):
    """MOCK of list_incidents: newest updated first, optionally one status only."""
    store = _get_store()
    listed = []
    for incident in store["incidents"].values():
        if status is None or incident["status"] == status:
            listed.append(dict(incident, alert_ids=list(incident["alert_ids"])))
    return sorted(listed, key=_incidents_newest_updated_first_key)


def mock_get_incident_details(db_path, incident_id):
    """
    Purpose: MOCK of get_incident_details (C.3): the incident plus alerts, events, notes, history.
    Inputs: db_path (unused), incident_id (int).
    Output: dict - incident keys plus alerts, events (no duplicates, oldest first), notes, history.
    Steps:
        1. Find the incident (IncidentNotFound if missing).
        2. Gather its alerts and the union of their events.
        3. Gather its notes and history, oldest first.
    Example: an incident with one correlated alert -> alerts has 3 entries.
    Errors: IncidentNotFound.
    """
    store = _get_store()
    incident = _get_incident_or_raise(store, incident_id)
    details = dict(incident, alert_ids=list(incident["alert_ids"]))
    details["alerts"] = [store["alerts"][alert_id] for alert_id in incident["alert_ids"]]
    events_by_id = {}
    for alert in details["alerts"]:
        for event_id in alert["event_ids"]:
            events_by_id[event_id] = store["events"][event_id]
    details["events"] = sorted(events_by_id.values(), key=_event_sort_key)
    details["notes"] = [note for note in store["notes"] if note["incident_id"] == incident_id]
    details["history"] = [row for row in store["history"] if row["incident_id"] == incident_id]
    return details


def mock_update_incident_status(db_path, incident_id, new_status, changed_by="analyst"):
    """
    Purpose: MOCK of update_incident_status using the C.3 transition table.
    Inputs: db_path (unused), incident_id (int), new_status (str), changed_by (str).
    Output: None.
    Steps:
        1. Find the incident; check the move is allowed.
        2. Set closed_at when resolved or false_positive, clear it otherwise.
        3. Update updated_at and write a status_changed history row.
    Example: open -> investigating is allowed; resolved -> open is not.
    Errors: IncidentNotFound, InvalidStatusTransition.
    """
    store = _get_store()
    incident = _get_incident_or_raise(store, incident_id)
    old_status = incident["status"]
    if new_status not in ALLOWED_STATUS_TRANSITIONS[old_status]:
        raise InvalidStatusTransition("Cannot change status from " + old_status + " to " + str(new_status))
    incident["status"] = new_status
    incident["updated_at"] = utc_now()
    if new_status in ["resolved", "false_positive"]:
        incident["closed_at"] = incident["updated_at"]
    else:
        incident["closed_at"] = None
    _add_history(store, incident_id, "status_changed", old_status, new_status, changed_by)


def mock_add_note(db_path, incident_id, text, author="analyst"):
    """MOCK of add_note: stores a note (1 to 2000 characters), writes history, returns the note ID."""
    store = _get_store()
    incident = _get_incident_or_raise(store, incident_id)
    if not isinstance(text, str) or len(text.strip()) < 1 or len(text) > 2000:
        raise ValueError("A note must be 1 to 2000 characters.")
    note_id = store["next_note_id"]
    store["next_note_id"] += 1
    store["notes"].append({"note_id": note_id, "incident_id": incident_id, "author": author,
                           "text": text.strip(), "created_at": utc_now()})
    incident["updated_at"] = utc_now()
    _add_history(store, incident_id, "note_added", None, str(note_id), author)
    return note_id


def mock_add_alerts_to_incident(db_path, incident_id, alert_ids, changed_by="analyst"):
    """MOCK of add_alerts_to_incident: links new alerts (and base alerts), one history row each; returns the count."""
    store = _get_store()
    incident = _get_incident_or_raise(store, incident_id)
    added_count = 0
    for alert_id in _expand_with_base_alerts(store, alert_ids):
        if alert_id not in incident["alert_ids"]:
            incident["alert_ids"].append(alert_id)
            _add_history(store, incident_id, "alert_added", None, alert_id, changed_by)
            added_count += 1
    if added_count > 0:
        incident["updated_at"] = utc_now()
    return added_count


# ---------------------------------------------------------------
# Mock reporting (stands in for reporting/pdf_report.py, the storage and reporting modules)
# ---------------------------------------------------------------

def _build_minimal_pdf(text_lines):
    """
    Purpose: write a tiny valid one-page PDF made of plain text lines.
    Inputs: text_lines (list of str) - at most 45 are used.
    Output: bytes - a PDF file (starts with %PDF).
    Steps:
        1. Build the page content: one line of text per list item.
        2. Write the five PDF objects, remembering where each one starts.
        3. Write the cross-reference table and the trailer.
    Example: _build_minimal_pdf(["hello"]).startswith(b"%PDF") -> True.
    Errors: none. Characters outside Latin-1 become question marks.
    """
    content = "BT /F1 11 Tf 50 800 Td 15 TL\n"
    for line in text_lines[:45]:
        safe_line = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content += "(" + safe_line[:95] + ") Tj T*\n"
    content += "ET"
    content = content.encode("latin-1", "replace").decode("latin-1")
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
        "/Resources << /Font << /F1 5 0 R >> >> >>",
        "<< /Length " + str(len(content)) + " >>\nstream\n" + content + "\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf_text = "%PDF-1.4\n"
    offsets = []
    for number in range(len(objects)):
        offsets.append(len(pdf_text))
        pdf_text += str(number + 1) + " 0 obj\n" + objects[number] + "\nendobj\n"
    xref_start = len(pdf_text)
    pdf_text += "xref\n0 " + str(len(objects) + 1) + "\n0000000000 65535 f \n"
    for offset in offsets:
        pdf_text += str(offset).zfill(10) + " 00000 n \n"
    pdf_text += "trailer\n<< /Size " + str(len(objects) + 1) + " /Root 1 0 R >>\nstartxref\n" + str(xref_start) + "\n%%EOF\n"
    return pdf_text.encode("latin-1")


_PDF_REMINDER = "Detections indicate suspicious activity. They do not prove an attack."


def mock_build_incident_report_pdf(incident_details, config):
    """MOCK of build_incident_report_pdf: a one-page placeholder PDF (not the real report layout)."""
    lines = [
        "MOCK REPORT - placeholder from dashboard/mock_backend.py, not reporting/pdf_report.py",
        "",
        "Incident: INC-" + str(incident_details["incident_id"]).zfill(4),
        "Title: " + incident_details["title"],
        "Status: " + incident_details["status"] + "    Priority: " + incident_details["priority"],
        "Alerts: " + str(len(incident_details["alerts"])) + "    Events: " + str(len(incident_details["events"])),
        "Notes: " + str(len(incident_details["notes"])) + "    History rows: " + str(len(incident_details["history"])),
        "",
        _PDF_REMINDER,
    ]
    return _build_minimal_pdf(lines)


def mock_build_alert_summary_pdf(alerts, analysis_summary, config):
    """MOCK of build_alert_summary_pdf: a one-page placeholder PDF listing alert counts."""
    lines = [
        "MOCK REPORT - placeholder from dashboard/mock_backend.py, not reporting/pdf_report.py",
        "",
        "Analysis summary (current session)",
        "Alerts: " + str(len(alerts)),
        "Events analysed: " + str(analysis_summary["events_analysed"]),
        "",
        _PDF_REMINDER,
    ]
    return _build_minimal_pdf(lines)
