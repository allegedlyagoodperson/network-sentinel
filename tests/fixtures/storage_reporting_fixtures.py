# tests/fixtures/storage_reporting_fixtures.py
# ---------------------------------------------------------------
# Purpose: hand-built synthetic data shared by test_storage.py, test_incidents.py
# and test_reporting.py (Stage 1C and 2B). No CSV files and no ingestion code
# are needed: events and alerts are built with make_event and make_alert.
# make_scenario: two base alerts and one correlated alert with their 12 events.
# make_success_alert: the 15-success dataset of R2.7 (21 events).
# read_pdf_text / count_pdf_pages / compact_text: look inside PDF bytes (compression off).
# Uses: core, config and the standard library. All addresses are documentation ranges.

import re
from datetime import datetime, timedelta, timezone

from core.contracts import datetime_to_iso, make_alert, make_event

START_TIME = datetime(2025, 3, 14, 9, 0, 0, tzinfo=timezone.utc)
ATTACKER_IP = "203.0.113.50"
TARGET_IP = "10.0.0.5"


def make_auth_event(index, username="admin", status="failure", source_ip=ATTACKER_IP,
                    source_file="auth_test.csv", seconds_offset=None):
    """One authentication event. index also decides the time, the row and the occurrence."""
    if seconds_offset is None:
        seconds_offset = index
    return make_event(
        "authentication", START_TIME + timedelta(seconds=seconds_offset), source_ip, status,
        source_file, index + 2, {"username": username, "status": status},
        occurrence=index + 1, destination_ip=TARGET_IP, username=username, service="ssh",
    )


def make_network_event(index, port, source_ip=ATTACKER_IP, source_file="net_test.csv",
                       seconds_offset=None, bytes_sent=60):
    """One rejected network connection to a port."""
    if seconds_offset is None:
        seconds_offset = index
    return make_event(
        "network_connection", START_TIME + timedelta(seconds=seconds_offset), source_ip, "rejected",
        source_file, index + 2, {"destination_port": str(port)}, occurrence=index + 1,
        destination_ip=TARGET_IP, destination_port=port, protocol="TCP", bytes_sent=bytes_sent,
        bytes_received=0,
    )


def make_evidence(extra=None):
    """The four required evidence keys, plus any extra keys."""
    evidence = {
        "rule_parameters": {"auth_failed_threshold": 5, "auth_window_seconds": 300},
        "observed": {"failure_count": 6},
        "explanation": ["6 failed logins from " + ATTACKER_IP + " in 5 seconds. The threshold is 5 in 300 seconds."],
        "limitations": ["A user may have forgotten a password."],
    }
    if extra is not None:
        evidence.update(extra)
    return evidence


def make_base_alert(rule_id, event_list, severity="medium", confidence="low", title="Test alert",
                    source_ip=ATTACKER_IP, evidence=None):
    """A base alert whose time range is exactly the range of its events (FS.3.2)."""
    event_ids = []
    for event in event_list:
        event_ids.append(event["event_id"])
    if evidence is None:
        evidence = make_evidence()
    return make_alert(
        rule_id, title, "Possible suspicious activity was recorded.", severity, confidence,
        event_list[0]["timestamp"], event_list[-1]["timestamp"], source_ip, event_ids, evidence,
        "Review the activity and consider blocking the address.", detected_at=START_TIME,
    )


def make_correlated_alert(auth_alert, network_alert, event_list, severity="high"):
    """A CORR_AUTH_NET alert that links the two base alerts (FS.3.4)."""
    evidence = make_evidence({"correlation": {
        "link_key": "source_ip",
        "link_value": ATTACKER_IP,
        "linked_alert_ids": [auth_alert["alert_id"], network_alert["alert_id"]],
        "gap_seconds": 0,
        "destination_match": True,
        "match_conditions": ["Both alerts have source address " + ATTACKER_IP + "."],
    }})
    event_ids = []
    for event in event_list:
        event_ids.append(event["event_id"])
    return make_alert(
        "CORR_AUTH_NET", "Related authentication and network activity from the same source",
        "Possible related activity was recorded.", severity, "medium", event_list[0]["timestamp"],
        event_list[-1]["timestamp"], ATTACKER_IP, event_ids, evidence,
        "Treat the source as a priority for investigation.", detected_at=START_TIME,
    )


def make_scenario(auth_severity="medium", network_severity="medium", correlated_severity="high"):
    """
    Six failed logins (an AUTH_BRUTE_FORCE alert), six rejected connections
    (a NET_PORT_SCAN alert) and the CORR_AUTH_NET alert that links them.
    Returns a dictionary: events, auth_alert, network_alert, correlated_alert.
    """
    auth_events = []
    for index in range(6):
        auth_events.append(make_auth_event(index))
    network_events = []
    for index in range(6):
        network_events.append(make_network_event(index, 20 + index, seconds_offset=10 + index))
    auth_alert = make_base_alert("AUTH_BRUTE_FORCE", auth_events, auth_severity, "low", "Repeated failed logins")
    network_alert = make_base_alert("NET_PORT_SCAN", network_events, network_severity, "medium", "Port scan")
    all_events = auth_events + network_events
    correlated_alert = make_correlated_alert(auth_alert, network_alert, all_events, correlated_severity)
    return {
        "events": all_events,
        "auth_alert": auth_alert,
        "network_alert": network_alert,
        "correlated_alert": correlated_alert,
    }


def make_success_alert(failure_count=6, success_count=15, detail_limit=10):
    """
    The R2.7 dataset: failures, then linked successes one every 10 seconds.
    event_ids holds ALL failures and successes; success_events lists only the
    first detail_limit successes. Returns (alert, events).
    """
    events = []
    for index in range(failure_count):
        events.append(make_auth_event(index, username="admin", status="failure"))
    success_events = []
    for number in range(success_count):
        offset = failure_count + 10 + number * 10
        success = make_auth_event(failure_count + number, username="user" + str(number + 1).zfill(2),
                                  status="success", seconds_offset=offset)
        events.append(success)
        success_events.append(success)
    detail_list = []
    for success in success_events[:detail_limit]:
        detail_list.append({
            "event_id": success["event_id"],
            "timestamp": datetime_to_iso(success["timestamp"]),
            "username": success["username"],
            "username_also_failed": False,
        })
    evidence = make_evidence({
        "failure_count": failure_count,
        "followed_by_success": True,
        "success_event_count": success_count,
        "success_events": detail_list,
        "success_events_not_detailed": success_count - len(detail_list),
    })
    alert = make_base_alert("AUTH_BRUTE_FORCE", events, "high", "medium", "Repeated failed logins", evidence=evidence)
    return alert, events


def make_details(alerts, events, notes=None, history=None, incident_id=7):
    """A hand-built incident_details dictionary (the shape of C.3) for the PDF tests."""
    alert_ids = []
    for alert in alerts:
        alert_ids.append(alert["alert_id"])
    if notes is None:
        notes = []
    if history is None:
        history = []
    return {
        "incident_id": incident_id,
        "title": "Test incident",
        "summary": "Analyst summary.",
        "status": "open",
        "priority": "high",
        "created_at": START_TIME,
        "updated_at": START_TIME,
        "closed_at": None,
        "alert_ids": alert_ids,
        "alerts": alerts,
        "events": events,
        "notes": notes,
        "history": history,
    }


# ---------------------------------------------------------------
# Reading PDF bytes. ReportLab normally compresses page content; the
# reporting tests switch compression off so the text can be found.
# ---------------------------------------------------------------

_TEXT_OPERATION = re.compile(rb"\(((?:\\.|[^\\()])*)\) Tj")
_ESCAPE = re.compile(rb"\\([0-7]{1,3}|.)", re.DOTALL)


def _decode_escape(match):
    """Turn one PDF string escape such as \\( or \\050 into a character."""
    code = match.group(1)
    if code[:1].isdigit():
        return bytes([int(code, 8)])
    return code


def read_pdf_text(pdf_bytes):
    """All text of an UNCOMPRESSED ReportLab PDF, one text line per space-joined piece."""
    pieces = []
    for match in _TEXT_OPERATION.finditer(pdf_bytes):
        raw = _ESCAPE.sub(_decode_escape, match.group(1))
        pieces.append(raw.decode("latin-1"))
    return " ".join(pieces)


def count_pdf_pages(pdf_bytes):
    """The number of pages: count the page objects (not the /Pages tree)."""
    return len(re.findall(rb"/Type /Page\b(?!s)", pdf_bytes))


def compact_text(text):
    """Remove all whitespace. ReportLab may split a word such as <b> into pieces,
    so tests that look for markup characters compare the text without spaces."""
    return "".join(text.split())
