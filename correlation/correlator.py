# correlation/correlator.py
# ---------------------------------------------------------------
# Purpose: link authentication alerts and network alerts into CORR_AUTH_NET
# alerts (FS.3.4, C.4). A link needs the SAME non-trusted source address and
# time ranges that overlap or are at most correlation_window_seconds apart.
# Close timestamps alone never link alerts. A matching destination address
# only raises confidence; it never creates a link.
# correlate_alerts: the public function. Everything else is a private helper.
# Uses: core.contracts (make_alert) and core.errors. It imports nothing else
# from the project, so it can be tested with hand-made alert dictionaries.

import ipaddress
from datetime import datetime, timedelta

from core.contracts import make_alert
from core.errors import ConfigError

RULE_ID = "CORR_AUTH_NET"
TITLE = "Related authentication and network activity from the same source"


# ---------------------------------------------------------------
# Small helpers (a few are repeated from detection/windowing.py on purpose:
# correlation may import only core, so it cannot borrow them)
# ---------------------------------------------------------------

def _get_window_setting(config):
    """Return correlation_window_seconds or raise ConfigError."""
    if not isinstance(config, dict) or "correlation_window_seconds" not in config:
        raise ConfigError("correlation needs the setting: correlation_window_seconds")
    return config["correlation_window_seconds"]


def _get_trusted_set(config):
    """The trusted addresses as a set of normalised text (missing key: nobody trusted)."""
    address_list = config.get("trusted_ips", [])
    if not isinstance(address_list, list):
        raise ConfigError("trusted_ips must be a list")
    trusted_set = set()
    for address_text in address_list:
        # try/except: ipaddress raises ValueError for text that is not an address;
        # we turn that into the project's own ConfigError.
        try:
            trusted_set.add(str(ipaddress.ip_address(str(address_text).strip())))
        except ValueError as error:
            raise ConfigError("trusted_ips has an invalid address: " + repr(address_text)) from error
    return trusted_set


def _is_aware_time(value):
    """True for a timezone-aware datetime."""
    return isinstance(value, datetime) and value.utcoffset() is not None


def _is_usable_alert(alert, trusted_ips):
    """
    True if the alert has what linking needs: a text rule_id, a non-empty text
    source_ip that is not trusted, two aware times, a list of event IDs, an
    alert_id and an evidence dictionary. Anything else is skipped, not raised.
    """
    if not isinstance(alert, dict):
        return False
    if not isinstance(alert.get("rule_id"), str) or not isinstance(alert.get("alert_id"), str):
        return False
    source_ip = alert.get("source_ip")
    if not isinstance(source_ip, str) or source_ip == "" or source_ip in trusted_ips:
        return False
    if not _is_aware_time(alert.get("time_start")) or not _is_aware_time(alert.get("time_end")):
        return False
    return isinstance(alert.get("event_ids"), list) and isinstance(alert.get("evidence"), dict)


def _alert_sort_key(alert):
    """Fixed order for pairing alerts, so the output never depends on input order."""
    return (alert["time_start"], alert["alert_id"])


def _split_alerts(alerts, trusted_ips):
    """Return (authentication alerts, network alerts), each sorted. Alerts whose
    rule_id starts with CORR_ (or anything else) are ignored."""
    auth_alerts = []
    network_alerts = []
    for alert in alerts:
        if not _is_usable_alert(alert, trusted_ips):
            continue
        if alert["rule_id"].startswith("AUTH_"):
            auth_alerts.append(alert)
        elif alert["rule_id"].startswith("NET_"):
            network_alerts.append(alert)
    return sorted(auth_alerts, key=_alert_sort_key), sorted(network_alerts, key=_alert_sort_key)


def _build_event_lookup(events):
    """A dictionary from event_id to event, for the events that have an ID."""
    lookup = {}
    for event in events:
        if isinstance(event, dict) and isinstance(event.get("event_id"), str):
            lookup[event["event_id"]] = event
    return lookup


def _format_count(count, word):
    """1 -> '1 second', 5 -> '5 seconds'."""
    if count == 1:
        return "1 " + word
    return str(count) + " " + word + "s"


# ---------------------------------------------------------------
# The gap between two alerts, the union of event IDs, destination match
# ---------------------------------------------------------------

def _find_gap(first_alert, second_alert):
    """
    Purpose: the time gap between two alert time ranges.
    Inputs: first_alert, second_alert (dict) - each with time_start and time_end.
    Output: timedelta - zero if the ranges overlap (or touch), otherwise the
        time from the end of the earlier range to the start of the later one.
    Steps:
        1. If each range starts no later than the other ends, they overlap.
        2. Otherwise subtract the end of the earlier range from the start of the later.
    Example: 09:15:02-09:16:40 and 09:16:00-09:16:17 overlap -> 0 seconds;
        09:00:00-09:01:00 and 09:05:00-09:06:00 -> 240 seconds.
    Errors: none.
    """
    if first_alert["time_start"] <= second_alert["time_end"] and second_alert["time_start"] <= first_alert["time_end"]:
        return timedelta(0)
    if first_alert["time_end"] < second_alert["time_start"]:
        return second_alert["time_start"] - first_alert["time_end"]
    return first_alert["time_start"] - second_alert["time_end"]


def _union_event_ids(auth_alert, network_alert, event_lookup):
    """
    Purpose: the event IDs of both alerts, each once, in time order.
    Inputs: auth_alert, network_alert (dict); event_lookup (dict event_id -> event).
    Output: list of str - no duplicates (the first copy of an ID is kept).
    Steps:
        1. Walk the authentication IDs, then the network IDs, keeping the first
           copy of each ID and remembering its position.
        2. Give each ID a time: its event's timestamp, or (if the event is not
           in the list) the start time of the alert that holds it.
        3. Sort by time; the position breaks ties, so the result is repeatable.
    Example: auth [a1, a2], network [n1, a2] -> [a1, a2, n1] if in that time order.
    Errors: none.
    """
    seen_ids = set()
    timed_ids = []
    for alert in [auth_alert, network_alert]:
        for event_id in alert["event_ids"]:
            if not isinstance(event_id, str) or event_id in seen_ids:
                continue
            seen_ids.add(event_id)
            event = event_lookup.get(event_id)
            if event is not None and _is_aware_time(event.get("timestamp")):
                event_time = event["timestamp"]
            else:
                event_time = alert["time_start"]
            timed_ids.append((event_time, len(timed_ids), event_id))
    timed_ids.sort()
    return [timed_id[2] for timed_id in timed_ids]


def _collect_destinations(alert, event_lookup):
    """The set of non-None destination addresses among the alert's events."""
    destinations = set()
    for event_id in alert["event_ids"]:
        event = event_lookup.get(event_id)
        if event is not None and event.get("destination_ip") is not None:
            destinations.add(event["destination_ip"])
    return destinations


# ---------------------------------------------------------------
# Building one correlated alert
# ---------------------------------------------------------------

def _write_conditions(auth_alert, network_alert, gap_seconds, window_seconds, shared_destinations):
    """The match_conditions list: one plain sentence for each condition that was met."""
    source_ip = auth_alert["source_ip"]
    conditions = [
        "One alert is an authentication alert (" + auth_alert["rule_id"] + ") and the other is a network alert ("
        + network_alert["rule_id"] + ").",
        "Both alerts have the same source address, " + source_ip + ", which is not a trusted address.",
    ]
    if gap_seconds == 0 and _find_gap(auth_alert, network_alert) == timedelta(0):
        conditions.append("The time ranges of the two alerts overlap.")
    else:
        conditions.append("The time ranges are " + _format_count(gap_seconds, "second") + " apart, within the "
                          + _format_count(window_seconds, "second") + " limit.")
    if len(shared_destinations) > 0:
        conditions.append("Both alerts involve the destination address " + ", ".join(sorted(shared_destinations)) + ".")
    return conditions


def _write_text(source_ip, auth_alert, network_alert, severity, confidence, destination_match, conditions):
    """
    Purpose: write the description, explanation list and limitations list of a correlated alert.
    Inputs: source_ip (str); auth_alert and network_alert (dict); severity and
        confidence (str); destination_match (bool); conditions (list of str).
    Output: tuple (description str, explanation list of str, limitations list of str).
    Steps:
        1. Describe the two linked rules and the shared source address.
        2. Repeat the conditions that were met, then explain severity and confidence.
        3. List the limitations (shared addresses, destination match only raises confidence).
    Example: critical severity adds 'the login burst has a successful login recorded'.
    Errors: none.
    """
    description = ("Possible related activity from " + source_ip + ": " + auth_alert["rule_id"] + " and "
                   + network_alert["rule_id"] + " alerts were recorded for the same source address within the allowed time gap.")
    explanation = list(conditions)
    if severity == "critical":
        explanation.append("Severity is critical because the login burst has a successful login recorded after the last failed attempt.")
    else:
        explanation.append("Severity is high because login activity and network activity were both recorded from one source.")
    if destination_match:
        explanation.append("Confidence is high because the login and network evidence involve the same destination address.")
    else:
        explanation.append("Confidence is medium because no shared destination address was found.")
    explanation.append("Close timestamps alone never link alerts; the shared source address is required.")
    explanation.append("This is an indicator of possible related activity, not proof that anyone gained access.")
    limitations = [
        "Only the source address is used to link alerts. Several people behind one shared address can create a false link.",
        "A matching destination address only raises confidence; it does not create a link.",
        "Each alert keeps its own limitations; read the linked alerts as well.",
    ]
    if severity == "critical":
        limitations.append("A successful login after failures does not show whether that login was authorised.")
    return description, explanation, limitations


def _build_correlated_alert(auth_alert, network_alert, gap, event_lookup, config):
    """
    Purpose: build one CORR_AUTH_NET alert from a linked pair.
    Inputs: auth_alert, network_alert (dict); gap (timedelta); event_lookup
        (dict); config (dict).
    Output: alert dict made by make_alert.
    Steps:
        1. Union the event IDs; span the two time ranges.
        2. destination_match: do the two alerts' events share a destination address?
        3. Severity high, or critical if the login alert has followed_by_success
           true. Confidence medium, or high if destination_match is true.
        4. Fill evidence['correlation'] and call make_alert.
    Example: a login burst with a linked success and a scan of the same host from
        the same address -> severity critical, confidence high.
    Errors: none.
    """
    # Longer than 30 lines only because the evidence dictionary lists every key once; splitting it would hide the key list.
    window_seconds = _get_window_setting(config)
    gap_seconds = int(gap.total_seconds())
    shared = _collect_destinations(auth_alert, event_lookup) & _collect_destinations(network_alert, event_lookup)
    destination_match = len(shared) > 0
    followed = auth_alert["evidence"].get("followed_by_success") is True
    severity = "critical" if followed else "high"
    confidence = "high" if destination_match else "medium"
    conditions = _write_conditions(auth_alert, network_alert, gap_seconds, window_seconds, shared)
    source_ip = auth_alert["source_ip"]
    texts = _write_text(source_ip, auth_alert, network_alert, severity, confidence, destination_match, conditions)
    event_ids = _union_event_ids(auth_alert, network_alert, event_lookup)
    evidence = {
        "rule_parameters": {"correlation_window_seconds": window_seconds},
        "observed": {"gap_seconds": gap_seconds, "linked_alert_count": 2, "event_count": len(event_ids)},
        "explanation": texts[1],
        "limitations": texts[2],
        "correlation": {
            "link_key": "source_ip",
            "link_value": source_ip,
            "linked_alert_ids": [auth_alert["alert_id"], network_alert["alert_id"]],
            "gap_seconds": gap_seconds,
            "destination_match": destination_match,
            "match_conditions": conditions,
        },
    }
    return make_alert(
        rule_id=RULE_ID,
        title=TITLE,
        description=texts[0],
        severity=severity,
        confidence=confidence,
        time_start=min(auth_alert["time_start"], network_alert["time_start"]),
        time_end=max(auth_alert["time_end"], network_alert["time_end"]),
        source_ip=source_ip,
        event_ids=event_ids,
        evidence=evidence,
        recommended_action=("Treat the source as a priority for investigation, review the login and network "
                            "evidence together, and consider creating an incident."),
    )


def _merge_same_evidence(existing_alert, duplicate_alert, network_alert):
    """
    Purpose: fold two correlated alerts that have the SAME alert_id into one.
    Inputs: existing_alert (dict) - the alert already kept; duplicate_alert
        (dict) - a second alert built from a different pair of base alerts;
        network_alert (dict) - the network base alert of that second pair.
    Output: none (existing_alert is updated in place).
    Steps:
        1. The alert ID depends only on rule, source, time range and event IDs,
           so two pairs that cover exactly the same events (for example a port
           scan and a rejection alert made of the same connections) get one ID.
        2. Saving two alerts with one ID would silently drop one of them, so
           instead the extra linked base alert IDs are added to the one alert.
        3. The smaller gap is kept, and destination_match stays true if either was.
    Example: login burst + scan, and login burst + rejections of the same events
        -> one CORR_AUTH_NET alert whose linked_alert_ids has three IDs.
    Errors: none.
    """
    kept_block = existing_alert["evidence"]["correlation"]
    new_block = duplicate_alert["evidence"]["correlation"]
    for linked_id in new_block["linked_alert_ids"]:
        if linked_id not in kept_block["linked_alert_ids"]:
            kept_block["linked_alert_ids"].append(linked_id)
    kept_block["gap_seconds"] = min(kept_block["gap_seconds"], new_block["gap_seconds"])
    kept_block["destination_match"] = kept_block["destination_match"] or new_block["destination_match"]
    existing_alert["evidence"]["observed"]["linked_alert_count"] = len(kept_block["linked_alert_ids"])
    existing_alert["evidence"]["observed"]["gap_seconds"] = kept_block["gap_seconds"]
    kept_block["match_conditions"].append(
        "The network alert " + network_alert["rule_id"] + " also meets all three linking conditions with the same "
        "authentication alert.")


# ---------------------------------------------------------------
# The public function
# ---------------------------------------------------------------

def correlate_alerts(alerts: list, events: list, config: dict) -> list:
    """
    Purpose: find every authentication alert and network alert that belong
        together, and return one CORR_AUTH_NET alert for each linked pair.
    Inputs:
        alerts (list of dict) - base alerts from the rules (anything that is not
            an AUTH_ or NET_ alert, or has no usable source address, is skipped).
        events (list of dict) - the normalised events; used only to compare
            destination addresses and to put event IDs in time order.
        config (dict) - needs correlation_window_seconds; trusted_ips optional.
    Output: list of NEW alert dictionaries (rule_id CORR_AUTH_NET) built by
        make_alert. The input alerts are not changed and not returned.
    Steps:
        1. Split the alerts into authentication and network alerts, ignoring
           trusted addresses.
        2. For every authentication alert and every network alert with the SAME
           source address, work out the time gap (0 if the ranges overlap).
        3. Link them only if the gap is at most correlation_window_seconds
           (inclusive).
        4. Build one correlated alert per linked pair.
    Example: a login burst 09:15:02-09:16:40 and a port scan 09:16:00-09:16:17
        from 203.0.113.50 -> one CORR_AUTH_NET alert with gap_seconds 0.
        The same alerts from two different addresses -> an empty list.
    Errors: ConfigError if correlation_window_seconds is missing or trusted_ips
        is invalid.
    """
    window_seconds = _get_window_setting(config)
    trusted_ips = _get_trusted_set(config)
    auth_alerts, network_alerts = _split_alerts(alerts, trusted_ips)
    event_lookup = _build_event_lookup(events)
    longest_gap = timedelta(seconds=window_seconds)
    correlated_alerts = []
    alerts_by_id = {}
    for auth_alert in auth_alerts:
        for network_alert in network_alerts:
            if auth_alert["source_ip"] != network_alert["source_ip"]:
                continue
            gap = _find_gap(auth_alert, network_alert)
            if gap > longest_gap:
                continue
            new_alert = _build_correlated_alert(auth_alert, network_alert, gap, event_lookup, config)
            if new_alert["alert_id"] in alerts_by_id:
                _merge_same_evidence(alerts_by_id[new_alert["alert_id"]], new_alert, network_alert)
            else:
                alerts_by_id[new_alert["alert_id"]] = new_alert
                correlated_alerts.append(new_alert)
    return correlated_alerts
