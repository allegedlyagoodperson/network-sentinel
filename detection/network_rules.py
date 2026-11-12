# detection/network_rules.py
# ---------------------------------------------------------------
# Purpose: the three network rules (FS.3.3, C.6, R1.3).
# detect_port_scans: NET_PORT_SCAN - many distinct ports on one host, fast.
# detect_repeated_rejections: NET_REPEATED_REJECTS - many rejected connections.
# detect_unusual_traffic_volume: NET_HIGH_VOLUME - a clock-aligned time bucket
#     much bigger than the same source address's own typical bucket.
# Each public rule returns (alerts, notes). Private helpers build the pieces.
# Uses: core.contracts (make_alert, datetime_to_iso), detection.windowing.

from datetime import datetime, timedelta, timezone

from core.contracts import datetime_to_iso, make_alert
from detection.windowing import (
    _clean_events,
    _copy_settings,
    _format_count,
    _format_time,
    _get_setting,
    _get_trusted_ip_set,
    _whole_seconds_between,
    find_bursts,
)

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_PORTS_SAMPLE = 20
_MAX_ADDRESSES_IN_NOTE = 10
_HIGH_SEVERITY_FACTOR = 3  # "at least three times the threshold" (C.6)
_NETWORK_STATUSES = ["allowed", "rejected"]


# ---------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------

def _is_whole_number(value):
    """True for an int. bool is excluded because True would count as 1."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_usable_network_event(event, trusted_ips):
    """True for a network_connection event with a destination address and a
    known status, and not from a trusted address."""
    if event.get("event_type") != "network_connection":
        return False
    destination_ip = event.get("destination_ip")
    if not isinstance(destination_ip, str) or destination_ip == "":
        return False
    if event.get("status") not in _NETWORK_STATUSES:
        return False
    return event["source_ip"] not in trusted_ips


def _collect_event_ids(events):
    """The event IDs of a list of events, in the same (time) order."""
    event_ids = []
    for event in events:
        event_ids.append(event["event_id"])
    return event_ids


def _count_status(events, status):
    """How many of the events have this status."""
    count = 0
    for event in events:
        if event.get("status") == status:
            count = count + 1
    return count


def _distinct_ports(events):
    """Sorted list of the distinct destination ports in the events (None skipped)."""
    ports = set()
    for event in events:
        if _is_whole_number(event.get("destination_port")):
            ports.add(event["destination_port"])
    return sorted(ports)


# ---------------------------------------------------------------
# NET_PORT_SCAN
# ---------------------------------------------------------------

def _group_scan_events(events, trusted_ips):
    """
    Purpose: group the usable events by (source address, destination address).
    Inputs: events (list) - cleaned, time order; trusted_ips (set).
    Output: dict from (source_ip, destination_ip) to a list of events in time
        order. Only events with a whole-number destination_port are kept.
    Steps:
        1. Skip events the rule cannot use (including a missing port).
        2. Add each event to the list for its pair of addresses.
    Example: scans of 10.0.0.5 and 10.0.0.6 by one source -> two groups.
    Errors: none.
    """
    groups = {}
    for event in events:
        if not _is_usable_network_event(event, trusted_ips):
            continue
        if not _is_whole_number(event.get("destination_port")):
            continue
        pair = (event["source_ip"], event["destination_ip"])
        if pair not in groups:
            groups[pair] = []
        groups[pair].append(event)
    return groups


def _decide_scan_confidence(rejected_count, total_count):
    """High if at least 70 percent were rejected, low if at least 70 percent were
    allowed, otherwise medium. Whole-number arithmetic avoids rounding errors."""
    allowed_count = total_count - rejected_count
    if rejected_count * 10 >= total_count * 7:
        return "high"
    if allowed_count * 10 >= total_count * 7:
        return "low"
    return "medium"


def _summarise_scan(burst_events, config):
    """
    Purpose: measure one port-scan burst once, so the text builders only read numbers.
    Inputs: burst_events (list) - one source to one destination, time order;
        config (dict).
    Output: dict with source_ip, destination_ip, ports (sorted distinct list),
        rejected_count, total_count, severity, confidence, time_start,
        time_end, seconds.
    Steps:
        1. Count distinct ports and rejected attempts.
        2. Severity: medium, or high if the ports reach 3 x the threshold.
        3. Confidence from the rejected share (_decide_scan_confidence).
    Example: 18 ports, 17 of 18 attempts rejected, threshold 15 -> severity
        medium, confidence high.
    Errors: ConfigError if a needed setting is missing.
    """
    threshold = _get_setting(config, "portscan_distinct_ports_threshold")
    ports = _distinct_ports(burst_events)
    rejected_count = _count_status(burst_events, "rejected")
    time_start = burst_events[0]["timestamp"]
    time_end = burst_events[-1]["timestamp"]
    return {
        "source_ip": burst_events[0]["source_ip"],
        "destination_ip": burst_events[0]["destination_ip"],
        "ports": ports,
        "rejected_count": rejected_count,
        "total_count": len(burst_events),
        "severity": "high" if len(ports) >= _HIGH_SEVERITY_FACTOR * threshold else "medium",
        "confidence": _decide_scan_confidence(rejected_count, len(burst_events)),
        "time_start": time_start,
        "time_end": time_end,
        "seconds": _whole_seconds_between(time_start, time_end),
    }


def _write_scan_text(summary, config):
    """
    Purpose: write the description, explanation list and limitations list of a scan alert.
    Inputs: summary (dict from _summarise_scan); config (dict) - for the thresholds.
    Output: tuple (description str, explanation list of str, limitations list of str).
    Steps:
        1. Describe how many ports, on which host, how fast, and how many were rejected.
        2. Explain the threshold, severity and confidence.
        3. List the harmless explanations and blind spots.
    Example: 18 ports on 10.0.0.5 in 17 s, 17 rejected -> 'Possible port scanning: ...'.
    Errors: ConfigError if a needed setting is missing.
    """
    threshold = _get_setting(config, "portscan_distinct_ports_threshold")
    window = _get_setting(config, "portscan_window_seconds")
    source_ip = summary["source_ip"]
    destination_ip = summary["destination_ip"]
    port_count = len(summary["ports"])
    rejected_text = str(summary["rejected_count"]) + " of " + str(summary["total_count"]) + " attempts were rejected."
    description = ("Possible port scanning: " + source_ip + " tried " + _format_count(port_count, "different port")
                   + " on " + destination_ip + " within " + _format_count(summary["seconds"], "second") + "; "
                   + rejected_text)
    explanation = [
        str(port_count) + " distinct ports on " + destination_ip + " were contacted by " + source_ip + " between "
        + _format_time(summary["time_start"]) + " and " + _format_time(summary["time_end"]) + ". The threshold is "
        + str(threshold) + " ports in " + _format_count(window, "second") + ".",
        rejected_text,
        _scan_severity_sentence(summary["severity"], threshold),
        _scan_confidence_sentence(summary["confidence"]),
        "This is an indicator of possible scanning, not proof of malicious intent.",
    ]
    limitations = [
        "An authorised vulnerability scanner or a legitimate application that talks to many services looks the same.",
        "Only one destination host is examined at a time, so a scan spread thinly over many hosts is not detected.",
        "A scan slower than the configured ports-per-window threshold is not detected.",
    ]
    return description, explanation, limitations


def _build_scan_alert(burst_events, config):
    """
    Purpose: build one NET_PORT_SCAN alert with make_alert (evidence keys: FS.3.3 / C.6).
    Inputs: burst_events (list of events, one source to one destination, time
        order); config (dict).
    Output: alert dict.
    Steps:
        1. Summarise the burst and write the texts.
        2. Fill the evidence: distinct_port_count, ports_sample (sorted, at most 20),
           destination_ip, rejected_ratio.
        3. Call make_alert with every event of the burst.
    Example: 40 rejected ports -> severity medium, confidence high, 40 event IDs.
    Errors: ConfigError if a needed setting is missing.
    """
    # Longer than 30 lines only because the evidence dictionary lists every key once; splitting it would hide the key list.
    summary = _summarise_scan(burst_events, config)
    description, explanation, limitations = _write_scan_text(summary, config)
    evidence = {
        "rule_parameters": _copy_settings(config, ["portscan_distinct_ports_threshold", "portscan_window_seconds"]),
        "observed": {
            "distinct_port_count": len(summary["ports"]),
            "connection_attempts": summary["total_count"],
            "rejected_count": summary["rejected_count"],
            "allowed_count": summary["total_count"] - summary["rejected_count"],
        },
        "explanation": explanation,
        "limitations": limitations,
        "distinct_port_count": len(summary["ports"]),
        "ports_sample": summary["ports"][:_MAX_PORTS_SAMPLE],
        "destination_ip": summary["destination_ip"],
        "rejected_ratio": round(summary["rejected_count"] / summary["total_count"], 4),
    }
    return make_alert(
        rule_id="NET_PORT_SCAN",
        title="Possible port scanning activity",
        description=description,
        severity=summary["severity"],
        confidence=summary["confidence"],
        time_start=summary["time_start"],
        time_end=summary["time_end"],
        source_ip=summary["source_ip"],
        event_ids=_collect_event_ids(burst_events),
        evidence=evidence,
        recommended_action=("Confirm whether the source is an authorised scanner, check the targeted host for "
                            "exposed services, and consider blocking the source."),
    )


def _scan_severity_sentence(severity, threshold):
    """Why the severity is medium or high."""
    if severity == "high":
        return "Severity is high because the number of ports is at least three times the threshold (" + str(3 * threshold) + ")."
    return "Severity is medium because the number of ports is below three times the threshold (" + str(3 * threshold) + ")."


def _scan_confidence_sentence(confidence):
    """Why the confidence has its value."""
    if confidence == "high":
        return "Confidence is high because at least 70 percent of the attempts were rejected."
    if confidence == "low":
        return "Confidence is low because at least 70 percent of the attempts were allowed, which a legitimate application could cause."
    return "Confidence is medium because the attempts were a mix of allowed and rejected."


def detect_port_scans(events: list, config: dict) -> tuple:
    """
    Purpose: rule NET_PORT_SCAN: one source touching many distinct ports on one
        destination host inside a short window.
    Inputs:
        events (list of dict) - normalised events (any order; bad ones skipped).
        config (dict) - needs portscan_distinct_ports_threshold,
            portscan_window_seconds and (optionally) trusted_ips.
    Output: tuple (alerts, notes). notes is always an empty list for this rule.
    Steps:
        1. Clean the events, ignore trusted addresses and events with no port.
        2. Group by (source_ip, destination_ip).
        3. Run find_bursts on the ports of each group (distinct counting).
        4. Build one alert per burst.
    Example: 18 ports on 10.0.0.5 within 17 s from 203.0.113.50 -> one alert,
        medium severity. 14 ports -> no alert.
    Errors: ConfigError if a setting is missing or trusted_ips is invalid.
    """
    threshold = _get_setting(config, "portscan_distinct_ports_threshold")
    window_seconds = _get_setting(config, "portscan_window_seconds")
    trusted_ips = _get_trusted_ip_set(config)
    groups = _group_scan_events(_clean_events(events), trusted_ips)
    alerts = []
    for pair in sorted(groups):
        group_events = groups[pair]
        timestamps = [event["timestamp"] for event in group_events]
        ports = [event["destination_port"] for event in group_events]
        for first_index, last_index in find_bursts(timestamps, ports, threshold, window_seconds):
            alerts.append(_build_scan_alert(group_events[first_index:last_index + 1], config))
    return alerts, []


# ---------------------------------------------------------------
# NET_REPEATED_REJECTS
# ---------------------------------------------------------------

def _group_rejected_events(events, trusted_ips):
    """Rejected network events grouped by source address, time order kept."""
    groups = {}
    for event in events:
        if not _is_usable_network_event(event, trusted_ips):
            continue
        if event.get("status") != "rejected":
            continue
        source_ip = event["source_ip"]
        if source_ip not in groups:
            groups[source_ip] = []
        groups[source_ip].append(event)
    return groups


def _find_top_port(events):
    """The most common destination port (smallest port wins a tie), or None."""
    counts = {}
    for event in events:
        port = event.get("destination_port")
        if _is_whole_number(port):
            counts[port] = counts.get(port, 0) + 1
    top_port = None
    top_count = 0
    for port in sorted(counts):
        if counts[port] > top_count:
            top_port = port
            top_count = counts[port]
    return top_port


def _all_same_target(events):
    """True if every event went to the same destination address AND port
    (a missing port counts as one value of its own)."""
    targets = set()
    for event in events:
        targets.add((event["destination_ip"], event.get("destination_port")))
    return len(targets) == 1


def _summarise_rejects(burst_events, config):
    """
    Purpose: measure one rejection burst once.
    Inputs: burst_events (list) - rejected events from one source, time order;
        config (dict).
    Output: dict with source_ip, count, destinations (count of distinct
        addresses), port_count, top_port, same_target, severity, confidence,
        time_start, time_end, seconds.
    Steps:
        1. Count rejections, distinct destinations and distinct ports.
        2. Severity low, or medium at 3 x the threshold.
        3. Confidence low if every rejection hit the same address and port.
    Example: 20 rejections, all to 10.0.0.9 port 514 -> low severity, low confidence.
    Errors: ConfigError if a needed setting is missing.
    """
    threshold = _get_setting(config, "reject_threshold")
    destinations = set()
    for event in burst_events:
        destinations.add(event["destination_ip"])
    same_target = _all_same_target(burst_events)
    time_start = burst_events[0]["timestamp"]
    time_end = burst_events[-1]["timestamp"]
    return {
        "source_ip": burst_events[0]["source_ip"],
        "count": len(burst_events),
        "destinations": len(destinations),
        "port_count": len(_distinct_ports(burst_events)),
        "top_port": _find_top_port(burst_events),
        "same_target": same_target,
        "severity": "medium" if len(burst_events) >= _HIGH_SEVERITY_FACTOR * threshold else "low",
        "confidence": "low" if same_target else "medium",
        "time_start": time_start,
        "time_end": time_end,
        "seconds": _whole_seconds_between(time_start, time_end),
    }


def _write_reject_text(summary, config):
    """
    Purpose: write the description, explanation list and limitations list of a rejection alert.
    Inputs: summary (dict from _summarise_rejects); config (dict) - for the thresholds.
    Output: tuple (description str, explanation list of str, limitations list of str).
    Steps:
        1. Describe how many rejections and over what time.
        2. Explain the threshold, destinations, severity and confidence.
        3. List the harmless explanations (a retrying client).
    Example: 20 rejections to one address and port -> confidence low sentence.
    Errors: ConfigError if a needed setting is missing.
    """
    threshold = _get_setting(config, "reject_threshold")
    window = _get_setting(config, "reject_window_seconds")
    source_ip = summary["source_ip"]
    count = summary["count"]
    description = ("Possible blocked-connection problem or probing: " + str(count) + " rejected connections were recorded from "
                   + source_ip + " within " + _format_count(summary["seconds"], "second") + ".")
    explanation = [
        str(count) + " rejected connections from " + source_ip + " were recorded between "
        + _format_time(summary["time_start"]) + " and " + _format_time(summary["time_end"]) + ". The threshold is "
        + str(threshold) + " rejections in " + _format_count(window, "second") + ".",
        "They reached " + _format_count(summary["destinations"], "different destination address", "different destination addresses")
        + " and " + _format_count(summary["port_count"], "different port") + ".",
        _reject_severity_sentence(summary["severity"], threshold),
        _reject_confidence_sentence(summary["same_target"]),
        "This is an indicator that something is being blocked repeatedly, not proof of malicious intent.",
    ]
    limitations = [
        "A misconfigured client or service that keeps retrying a blocked connection looks the same.",
        "Rejections spread over more than the configured window are not counted together.",
    ]
    return description, explanation, limitations


def _build_reject_alert(burst_events, config):
    """
    Purpose: build one NET_REPEATED_REJECTS alert with make_alert (evidence keys: FS.3.3 / C.6).
    Inputs: burst_events (list of rejected events from one source, time order);
        config (dict).
    Output: alert dict.
    Steps:
        1. Summarise the burst and write the texts.
        2. Fill the evidence: rejected_count, distinct_destinations, distinct_ports,
           top_destination_port.
        3. Call make_alert with every event of the burst.
    Example: 25 rejections to varied destinations -> severity low, confidence medium.
    Errors: ConfigError if a needed setting is missing.
    """
    # Longer than 30 lines only because the evidence dictionary lists every key once; splitting it would hide the key list.
    summary = _summarise_rejects(burst_events, config)
    description, explanation, limitations = _write_reject_text(summary, config)
    evidence = {
        "rule_parameters": _copy_settings(config, ["reject_threshold", "reject_window_seconds"]),
        "observed": {"rejected_count": summary["count"], "distinct_destinations": summary["destinations"]},
        "explanation": explanation,
        "limitations": limitations,
        "rejected_count": summary["count"],
        "distinct_destinations": summary["destinations"],
        "distinct_ports": summary["port_count"],
        "top_destination_port": summary["top_port"],
    }
    return make_alert(
        rule_id="NET_REPEATED_REJECTS",
        title="Repeated rejected network connections",
        description=description,
        severity=summary["severity"],
        confidence=summary["confidence"],
        time_start=summary["time_start"],
        time_end=summary["time_end"],
        source_ip=summary["source_ip"],
        event_ids=_collect_event_ids(burst_events),
        evidence=evidence,
        recommended_action=("Check the firewall rules and whether a legitimate client is misconfigured, "
                            "and monitor the source for escalation."),
    )


def _reject_severity_sentence(severity, threshold):
    """Why the severity is low or medium."""
    if severity == "medium":
        return "Severity is medium because the count is at least three times the threshold (" + str(3 * threshold) + ")."
    return "Severity is low because the count is below three times the threshold (" + str(3 * threshold) + ")."


def _reject_confidence_sentence(same_target):
    """Why the confidence is low or medium."""
    if same_target:
        return "Confidence is low because every rejection targeted the same address and port, which often means a client retrying."
    return "Confidence is medium because the rejections targeted more than one address or port."


def detect_repeated_rejections(events: list, config: dict) -> tuple:
    """
    Purpose: rule NET_REPEATED_REJECTS: many rejected connections from one source.
    Inputs:
        events (list of dict) - normalised events (any order; bad ones skipped).
        config (dict) - needs reject_threshold, reject_window_seconds and
            (optionally) trusted_ips.
    Output: tuple (alerts, notes). notes is always an empty list for this rule.
    Steps:
        1. Clean the events, keep rejected network events, ignore trusted addresses.
        2. Group by source address.
        3. Run find_bursts (counting events) on each group.
        4. Build one alert per burst.
    Example: exactly 20 rejections in 95 s from 10.0.0.31, all to one port ->
        one alert, low severity, low confidence. 19 rejections -> none.
    Errors: ConfigError if a setting is missing or trusted_ips is invalid.
    """
    threshold = _get_setting(config, "reject_threshold")
    window_seconds = _get_setting(config, "reject_window_seconds")
    trusted_ips = _get_trusted_ip_set(config)
    groups = _group_rejected_events(_clean_events(events), trusted_ips)
    alerts = []
    for source_ip in sorted(groups):
        group_events = groups[source_ip]
        timestamps = [event["timestamp"] for event in group_events]
        for first_index, last_index in find_bursts(timestamps, None, threshold, window_seconds):
            alerts.append(_build_reject_alert(group_events[first_index:last_index + 1], config))
    return alerts, []


# ---------------------------------------------------------------
# NET_HIGH_VOLUME
# ---------------------------------------------------------------

def _has_usable_byte_count(event):
    """True if bytes_sent is a whole number of zero or more. Anything else
    (None, text, a negative number, True/False) counts as 'no byte metric'."""
    value = event.get("bytes_sent")
    return _is_whole_number(value) and value >= 0


def _whole_seconds_since_epoch(timestamp):
    """Whole seconds since 1 January 1970 UTC, rounded down."""
    elapsed = timestamp - _EPOCH
    return elapsed.days * 86400 + elapsed.seconds


def _build_buckets(events, window_seconds):
    """
    Purpose: add up bytes_sent per source address and per clock-aligned bucket.
    Inputs: events (list) - network events that have a usable bytes_sent, time
        order; window_seconds (int) - bucket size.
    Output: dict from source_ip to a dict from bucket start (whole seconds since
        1970) to {"total": int, "events": list of events}.
    Steps:
        1. Take the event time as whole seconds since 1 January 1970 UTC.
        2. Whole-number divide by the window and multiply back: that is the
           bucket start, so buckets line up with the clock, not with the file.
        3. Add the event's bytes_sent to the bucket total and keep the event.
    Example: window 300. 09:17:42 and 09:19:59 both land in the 09:15:00
        bucket; 09:20:00 starts the next one.
    Errors: none.
    """
    buckets_by_source = {}
    for event in events:
        bucket_start = (_whole_seconds_since_epoch(event["timestamp"]) // window_seconds) * window_seconds
        source_ip = event["source_ip"]
        if source_ip not in buckets_by_source:
            buckets_by_source[source_ip] = {}
        source_buckets = buckets_by_source[source_ip]
        if bucket_start not in source_buckets:
            source_buckets[bucket_start] = {"total": 0, "events": []}
        source_buckets[bucket_start]["total"] = source_buckets[bucket_start]["total"] + event["bytes_sent"]
        source_buckets[bucket_start]["events"].append(event)
    return buckets_by_source


def _find_eligible_bucket_starts(source_buckets):
    """The bucket starts (sorted) whose total is above zero. Zero buckets are
    discarded, and quiet periods never become zero buckets."""
    eligible_starts = []
    for bucket_start in sorted(source_buckets):
        if source_buckets[bucket_start]["total"] > 0:
            eligible_starts.append(bucket_start)
    return eligible_starts


def _median(values):
    """
    Purpose: the median of a list of whole numbers, worked out by hand (R1.3).
    Inputs: values (list of int) - at least one value.
    Output: int when the answer is a whole number, otherwise float.
    Steps:
        1. Sort a copy from smallest to largest.
        2. Odd length: return the middle value.
        3. Even length: return the average of the two middle values.
    Example: [4, 1, 3] -> 3; [1, 2, 4, 10] -> 3 (that is (2 + 4) / 2).
    Errors: none (the caller guarantees the list is not empty).
    """
    sorted_values = sorted(values)
    middle = len(sorted_values) // 2
    if len(sorted_values) % 2 == 1:
        return sorted_values[middle]
    middle_sum = sorted_values[middle - 1] + sorted_values[middle]
    if middle_sum % 2 == 0:
        return middle_sum // 2
    return middle_sum / 2


def _build_skipped_note(skipped_addresses, min_windows):
    """One summary note listing at most 10 skipped addresses, then 'and N more'."""
    shown = ", ".join(skipped_addresses[:_MAX_ADDRESSES_IN_NOTE])
    if len(skipped_addresses) > _MAX_ADDRESSES_IN_NOTE:
        shown = shown + ", and " + str(len(skipped_addresses) - _MAX_ADDRESSES_IN_NOTE) + " more"
    count_text = _format_count(len(skipped_addresses), "source address", "source addresses")
    return "NET_HIGH_VOLUME: " + count_text + " skipped (fewer than " + str(min_windows) + " active buckets): " + shown + "."


def _write_volume_text(source_ip, start_time, total_bytes, baseline, eligible_count, config):
    """
    Purpose: write the description, explanation and limitations of a volume alert.
    Inputs: source_ip (str); start_time (datetime, bucket start); total_bytes
        (int); baseline (int or float, the source's own median); eligible_count
        (int); config (dict).
    Output: tuple (description, explanation list, limitations list).
    Steps:
        1. Describe the bucket and how many times bigger than normal it is.
        2. Explain the two comparisons that were made and why only this source
           was used.
        3. List the harmless explanations (backups, always-busy sources).
    Example: 12,000,000 bytes vs a median of 1,050,000 -> 'about 11.43 times'.
    Errors: ConfigError if a needed setting is missing.
    """
    window = _get_setting(config, "volume_window_seconds")
    multiplier_seen = round(total_bytes / baseline, 2)
    description = ("Possible unusual outbound traffic: " + source_ip + " sent " + format(total_bytes, ",") + " bytes in the "
                   + _format_count(window, "second") + " period starting " + _format_time(start_time) + ", about "
                   + str(multiplier_seen) + " times its own typical period.")
    explanation = [
        source_ip + " sent " + format(total_bytes, ",") + " bytes in the period starting " + _format_time(start_time)
        + ". Its own typical period (median of " + str(eligible_count) + " active periods) is " + format(baseline, ",") + " bytes.",
        "The period is at least " + format(_get_setting(config, "volume_min_bytes"), ",") + " bytes and at least "
        + str(_get_setting(config, "volume_multiplier")) + " times this source's own typical period, so it was flagged.",
        "Only this source's own traffic was used as the comparison; other machines were not compared.",
        "Severity is medium and confidence is low in version 1 because volume alone is weak evidence.",
        "This is an indicator of possible unusual activity, not proof of data theft.",
    ]
    limitations = [
        "A nightly backup or software update looks like this.",
        "A source that is always very busy never triggers, because its own normal is already high.",
        "Sources with fewer than " + str(_get_setting(config, "volume_min_windows")) + " active periods are not checked.",
        "Only the bytes sent are used, so this does not show where the data went.",
    ]
    return description, explanation, limitations


def _build_volume_alert(source_ip, bucket_start, bucket, baseline, eligible_count, config):
    """
    Purpose: build one NET_HIGH_VOLUME alert for one triggering bucket.
    Inputs: source_ip (str); bucket_start (int, seconds since 1970); bucket
        (dict with total and events); baseline (this source's own median);
        eligible_count (int); config (dict).
    Output: alert dict made by make_alert (severity medium, confidence low).
    Steps:
        1. Work out the bucket start and end as datetimes.
        2. Get the texts from _write_volume_text.
        3. Fill the evidence, including baseline_scope this_source_ip_only.
        4. Call make_alert with the events of this bucket (time_start and
           time_end are the first and last EVENT times, not the bucket edges).
    Example: bucket of 12,000,000 bytes, baseline 1,050,000 -> multiplier_observed 11.43.
    Errors: ConfigError if a needed setting is missing.
    """
    # Longer than 30 lines only because the evidence dictionary lists every key once; splitting it would hide the key list.
    window = _get_setting(config, "volume_window_seconds")
    bucket_events = bucket["events"]
    start_time = _EPOCH + timedelta(seconds=bucket_start)
    texts = _write_volume_text(source_ip, start_time, bucket["total"], baseline, eligible_count, config)
    multiplier_seen = round(bucket["total"] / baseline, 2)
    evidence = {
        "rule_parameters": _copy_settings(config, ["volume_window_seconds", "volume_min_bytes", "volume_multiplier",
                                                   "volume_min_windows", "volume_min_coverage"]),
        "observed": {"bucket_bytes_sent": bucket["total"], "baseline_bytes": baseline,
                     "multiplier_observed": multiplier_seen, "events_in_bucket": len(bucket_events)},
        "explanation": texts[1],
        "limitations": texts[2],
        "bucket_start": datetime_to_iso(start_time),
        "bucket_end": datetime_to_iso(start_time + timedelta(seconds=window)),
        "bucket_bytes_sent": bucket["total"],
        "baseline_bytes": baseline,
        "multiplier_observed": multiplier_seen,
        "eligible_bucket_count": eligible_count,
        "baseline_scope": "this_source_ip_only",
    }
    return make_alert(
        rule_id="NET_HIGH_VOLUME",
        title="Unusually high outbound traffic volume",
        description=texts[0],
        severity="medium",
        confidence="low",
        time_start=bucket_events[0]["timestamp"],
        time_end=bucket_events[-1]["timestamp"],
        source_ip=source_ip,
        event_ids=_collect_event_ids(bucket_events),
        evidence=evidence,
        recommended_action=("Identify what the host was sending and where, and compare it with normal "
                            "backups or updates."),
    )


def _check_one_source(source_ip, source_buckets, config):
    """
    Purpose: look at ONE source address on its own and return (alerts, skipped).
    Inputs: source_ip (str); source_buckets (dict from _build_buckets); config.
    Output: tuple (alerts, was_skipped) - was_skipped is True when the source
        has too few active buckets to estimate a typical value.
    Steps:
        1. Keep only the non-zero buckets.
        2. Skip the source if it has fewer than volume_min_windows of them.
        3. The baseline is the median of THIS source's bucket totals only.
        4. A bucket triggers if its total is at least volume_min_bytes AND at
           least volume_multiplier times the baseline (both inclusive).
    Example: totals 1,1,1,1,1,10 million with defaults: median 1,000,000, the
        10,000,000 bucket triggers (exactly the minimum, 10 x the median).
    Errors: ConfigError if a needed setting is missing.
    """
    min_windows = _get_setting(config, "volume_min_windows")
    min_bytes = _get_setting(config, "volume_min_bytes")
    multiplier = _get_setting(config, "volume_multiplier")
    eligible_starts = _find_eligible_bucket_starts(source_buckets)
    if len(eligible_starts) < min_windows:
        return [], True
    totals = []
    for bucket_start in eligible_starts:
        totals.append(source_buckets[bucket_start]["total"])
    baseline = _median(totals)  # this source only: no global baseline exists anywhere
    alerts = []
    for bucket_start in eligible_starts:
        bucket = source_buckets[bucket_start]
        if bucket["total"] >= min_bytes and bucket["total"] >= multiplier * baseline:
            alerts.append(_build_volume_alert(source_ip, bucket_start, bucket, baseline, len(eligible_starts), config))
    return alerts, False


def _prepare_volume_events(events, trusted_ips):
    """Split the usable network events into (all network events, those with a
    usable bytes_sent). The first list is the denominator of the coverage check."""
    network_events = []
    events_with_bytes = []
    for event in events:
        if event.get("event_type") != "network_connection" or event["source_ip"] in trusted_ips:
            continue
        network_events.append(event)
        if _has_usable_byte_count(event):
            events_with_bytes.append(event)
    return network_events, events_with_bytes


def detect_unusual_traffic_volume(events: list, config: dict) -> tuple:
    """
    Purpose: rule NET_HIGH_VOLUME: a time bucket far above the same source
        address's own normal, and above a minimum size.
    Inputs:
        events (list of dict) - normalised events (any order; bad ones skipped).
        config (dict) - needs volume_window_seconds, volume_min_bytes,
            volume_multiplier, volume_min_windows, volume_min_coverage and
            (optionally) trusted_ips.
    Output: tuple (alerts, notes). notes says when the rule was skipped for lack
        of byte data, and which sources had too few active buckets.
    Steps:
        1. Ignore trusted addresses. No network events: return nothing.
        2. If fewer than volume_min_coverage of the network events have a usable
           bytes_sent, skip the whole rule with a note.
        3. Build clock-aligned buckets per source and check each source alone.
        4. Add one summary note listing the skipped sources.
    Example: 10.0.0.40 with eight buckets near 1 MB and one of 12 MB ->
        one alert, severity medium, confidence low.
    Errors: ConfigError if a setting is missing or trusted_ips is invalid.
    """
    window_seconds = _get_setting(config, "volume_window_seconds")
    min_coverage = _get_setting(config, "volume_min_coverage")
    min_windows = _get_setting(config, "volume_min_windows")
    trusted_ips = _get_trusted_ip_set(config)
    network_events, events_with_bytes = _prepare_volume_events(_clean_events(events), trusted_ips)
    if len(network_events) == 0:
        return [], []
    if len(events_with_bytes) / len(network_events) < min_coverage:
        percent_text = format(min_coverage * 100, "g")
        return [], ["NET_HIGH_VOLUME skipped: fewer than " + percent_text + " percent of network events contain bytes_sent."]
    buckets_by_source = _build_buckets(events_with_bytes, window_seconds)
    alerts = []
    skipped_addresses = []
    for source_ip in sorted(buckets_by_source):
        source_alerts, was_skipped = _check_one_source(source_ip, buckets_by_source[source_ip], config)
        alerts.extend(source_alerts)
        if was_skipped:
            skipped_addresses.append(source_ip)
    notes = []
    if len(skipped_addresses) > 0:
        notes.append(_build_skipped_note(skipped_addresses, min_windows))
    return alerts, notes
