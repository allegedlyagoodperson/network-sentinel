# detection/auth_rules.py
# ---------------------------------------------------------------
# Purpose: the AUTH_BRUTE_FORCE rule (FS.3.3, R1.4, R2.2, R2.3): repeated failed
# logins from one source address, plus any successful login from that same
# address strictly after the last failure and inside the success window.
# detect_failed_logins: the public rule. Returns (alerts, notes).
# Everything else here is a small private helper that builds one piece of the
# alert (the linked successes, the confidence, the wording, the evidence).
# Uses: core.contracts (make_alert and constants), detection.windowing.

from datetime import timedelta

from core.contracts import MAX_DETAILED_SUCCESS_EVENTS, datetime_to_iso, make_alert
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

RULE_ID = "AUTH_BRUTE_FORCE"
TITLE = "Repeated failed logins from one source"
_PARAMETER_KEYS = ["auth_failed_threshold", "auth_window_seconds", "auth_success_after_failure_seconds"]
_MAX_USERNAMES_SAMPLE = 10
_MAX_NAMES_IN_TEXT = 10


# ---------------------------------------------------------------
# Step 1: sort authentication events into failures and successes
# ---------------------------------------------------------------

def _is_usable_auth_event(event, trusted_ips):
    """True for an authentication event this rule may use: right type, a
    username (the confidence rubric needs it), and not from a trusted address."""
    if event.get("event_type") != "authentication":
        return False
    username = event.get("username")
    if not isinstance(username, str) or username == "":
        return False
    return event["source_ip"] not in trusted_ips


def _group_auth_events(events, trusted_ips):
    """
    Purpose: split the authentication events into failures and successes, each
        grouped by source address.
    Inputs: events (list) - already cleaned and in time order; trusted_ips (set).
    Output: (failures_by_ip, successes_by_ip) - two dictionaries from address
        text to a list of events in time order.
    Steps:
        1. Skip events this rule cannot use.
        2. Put each failure and each success in the list for its address.
    Example: 3 failures and 1 success from 203.0.113.50 ->
        ({"203.0.113.50": [f1, f2, f3]}, {"203.0.113.50": [s1]}).
    Errors: none.
    """
    failures_by_ip = {}
    successes_by_ip = {}
    for event in events:
        if not _is_usable_auth_event(event, trusted_ips):
            continue
        if event.get("status") == "failure":
            target = failures_by_ip
        elif event.get("status") == "success":
            target = successes_by_ip
        else:
            continue
        source_ip = event["source_ip"]
        if source_ip not in target:
            target[source_ip] = []
        target[source_ip].append(event)
    return failures_by_ip, successes_by_ip


# ---------------------------------------------------------------
# Step 2: which successes are linked to a burst (R2.2)
# ---------------------------------------------------------------

def _find_linked_successes(burst_failures, ip_successes, success_window_seconds):
    """
    Purpose: pick the successes that belong to this burst.
    Inputs: burst_failures (list) - the burst's failures, time order;
        ip_successes (list) - successes from the same address, time order;
        success_window_seconds (int) - the inclusive window after the last failure.
    Output: list of success events in time order (possibly empty).
    Steps:
        1. Take T, the timestamp of the last failure in the burst.
        2. For each success work out the exact time from T to the success.
        3. Link it only if that time is MORE than 0 and AT MOST the window.
    Example: T = 09:15:58, window 300. A success at 09:15:58 (gap 0) is not
        linked; 09:16:40 (gap 42 s) is; 09:20:58 (gap exactly 300 s) is;
        09:20:59 (gap 301 s) is not.
    Errors: none.
    """
    last_failure_time = burst_failures[-1]["timestamp"]
    longest_gap = timedelta(seconds=success_window_seconds)
    linked_successes = []
    for success in ip_successes:
        gap = success["timestamp"] - last_failure_time  # a timedelta: exact, includes fractions
        if gap > timedelta(0) and gap <= longest_gap:
            linked_successes.append(success)
    return linked_successes


# ---------------------------------------------------------------
# Step 3: the numbers about one burst
# ---------------------------------------------------------------

def _decide_confidence(distinct_username_count, failure_count, threshold):
    """Confidence rubric (FS.3.3). A success never changes it."""
    if distinct_username_count >= 3 or failure_count >= 3 * threshold:
        return "high"
    if distinct_username_count == 1 and failure_count < 2 * threshold:
        return "low"
    return "medium"


def _lowercase_set(names):
    """The names written in lower case, as a set (for the 'also failed' check)."""
    lowered = set()
    for name in names:
        lowered.add(name.lower())
    return lowered


def _build_success_details(linked_successes, failed_lowercase_names):
    """The detail list: the first MAX_DETAILED_SUCCESS_EVENTS linked successes,
    earliest first. It is for display only; nothing is limited by it."""
    details = []
    for success in linked_successes[:MAX_DETAILED_SUCCESS_EVENTS]:
        username = success["username"]
        details.append({
            "event_id": success["event_id"],
            "timestamp": datetime_to_iso(success["timestamp"]),
            "username": username,
            "username_also_failed": username.lower() in failed_lowercase_names,
        })
    return details


def _summarise_burst(burst_failures, linked_successes, config):
    """
    Purpose: measure one burst once, so the text builders only read numbers.
    Inputs: burst_failures, linked_successes (lists of events, time order);
        config (dict) - for the thresholds.
    Output: dict with the measured values (counts, username lists, the
        severity and confidence, and the first success timing).
    Steps:
        1. Count failures and collect the distinct failed usernames.
        2. Collect the distinct successful usernames from ALL linked successes
           and compare each (ignoring capital letters) with ALL failed usernames.
        3. Decide severity (high if any success is linked) and confidence.
    Example: 8 failures with 4 usernames and 1 linked success for 'backup' ->
        failure_count 8, distinct 4, severity high, confidence high.
    Errors: ConfigError if a needed setting is missing.
    """
    threshold = _get_setting(config, "auth_failed_threshold")
    failed_names = set()
    for failure in burst_failures:
        failed_names.add(failure["username"])
    failed_lowercase = _lowercase_set(failed_names)
    successful_names = set()
    for success in linked_successes:
        successful_names.add(success["username"])
    names_also_failed = []
    for name in sorted(successful_names):
        if name.lower() in failed_lowercase:
            names_also_failed.append(name)
    summary = {
        "failure_count": len(burst_failures),
        "failed_names": sorted(failed_names),
        "failed_lowercase": failed_lowercase,
        "linked_successes": linked_successes,
        "successful_names": sorted(successful_names),
        "names_also_failed": names_also_failed,
        "severity": "high" if len(linked_successes) > 0 else "medium",
        "confidence": _decide_confidence(len(failed_names), len(burst_failures), threshold),
    }
    return summary


# ---------------------------------------------------------------
# Step 4: the plain-English text (R1.4, R2.2)
# ---------------------------------------------------------------

def _describe_gap(seconds_after):
    """'30 seconds', '1 second', or 'within 1 second' for a gap under one second."""
    if seconds_after < 1:
        return "within 1 second"
    return _format_count(seconds_after, "second")


def _join_names(names):
    """alice, bob, carol - cut to 10 names and 'and N more' if there are more."""
    if len(names) <= _MAX_NAMES_IN_TEXT:
        return ", ".join(names)
    shown = ", ".join(names[:_MAX_NAMES_IN_TEXT])
    return shown + ", and " + str(len(names) - _MAX_NAMES_IN_TEXT) + " more"


def _build_success_sentences(summary, last_failure_time):
    """
    Purpose: the sentences that describe the linked successes, using the real timing.
    Inputs: summary (dict from _summarise_burst); last_failure_time (datetime).
    Output: list of str - empty if no success is linked. The first sentence is
        always the 'was/were recorded ... after the last failed attempt' one.
    Steps:
        1. Work out how many whole seconds after the last failure the earliest
           linked success was recorded.
        2. One successful username: use the Match or No-match template (R2.2).
        3. Several usernames: use the Several template (R2.2).
    Example: success for admin 30 s after the last failure, admin also failed ->
        ["A successful login for admin was recorded from the same address 30
         seconds after the last failed attempt.", "That username also had
         failed attempts in this burst."].
    Errors: none.
    """
    linked = summary["linked_successes"]
    if len(linked) == 0:
        return []
    when_text = _describe_gap(_whole_seconds_between(last_failure_time, linked[0]["timestamp"]))
    names = summary["successful_names"]
    also_failed = summary["names_also_failed"]
    if len(names) == 1:
        sentences = ["A successful login for " + names[0] + " was recorded from the same address "
                     + when_text + " after the last failed attempt."]
        if len(also_failed) == 1:
            sentences.append("That username also had failed attempts in this burst.")
        else:
            sentences.append("That username did not appear among the failed attempts.")
        if len(linked) > 1:
            sentences.append("In total " + str(len(linked)) + " successful logins from this address are linked to this alert.")
        return sentences
    sentences = ["Successful logins for " + str(len(names)) + " usernames (" + _join_names(names)
                 + ") were recorded from the same address after the last failed attempt."]
    sentences.append("The first was recorded " + when_text + " after it.")
    if len(also_failed) == 0:
        sentences.append("None of them also had failed attempts.")
    else:
        sentences.append(str(len(also_failed)) + " of them (" + _join_names(also_failed) + ") also had failed attempts.")
    return sentences


def _build_explanation(summary, source_ip, time_start, last_failure_time, config):
    """
    Purpose: write the evidence 'explanation' list: what was seen, the thresholds,
        and why severity and confidence have the values they have.
    Inputs: summary (dict from _summarise_burst); source_ip (str); time_start and
        last_failure_time (datetime); config (dict) - for the thresholds.
    Output: list of str - plain sentences, never using the forbidden words.
    Steps:
        1. State the failures, the time range and the threshold.
        2. Add the success sentences (R2.2 templates) if a success is linked.
        3. Explain severity and confidence, and say a success never raises confidence.
        4. End with the reminder that an alert is an indicator, not proof.
    Example: 8 failures, 4 usernames, one linked success -> 8 sentences, the third
        being 'A successful login for backup was recorded ... after the last failed attempt.'
    Errors: ConfigError if a needed setting is missing.
    """
    threshold = _get_setting(config, "auth_failed_threshold")
    window = _get_setting(config, "auth_window_seconds")
    failure_count = summary["failure_count"]
    distinct_count = len(summary["failed_names"])
    explanation = [
        str(failure_count) + " failed logins were recorded from " + source_ip + " between "
        + _format_time(time_start) + " and " + _format_time(last_failure_time) + ". The threshold is "
        + str(threshold) + " failures in " + _format_count(window, "second") + ".",
        "The failed logins used " + _format_count(distinct_count, "different username") + ".",
    ]
    explanation.extend(_build_success_sentences(summary, last_failure_time))
    if len(summary["linked_successes"]) > 0:
        explanation.append("Severity is high because a successful login from the same address was recorded after the last failed attempt.")
        explanation.append("The successful login does not raise confidence: a person who mistyped a password and then succeeded produces the same pattern.")
    else:
        explanation.append("Severity is medium because no successful login from this address was recorded after the last failed attempt.")
    explanation.append(_confidence_sentence(summary["confidence"], distinct_count, failure_count, threshold))
    explanation.append("This is an indicator of possible suspicious activity, not proof that anyone gained access.")
    return explanation


def _confidence_sentence(confidence, distinct_count, failure_count, threshold):
    """One sentence that says why the confidence has its value."""
    if confidence == "high":
        return ("Confidence is high because three or more different usernames were used (" + str(distinct_count)
                + " here) or there were at least " + str(3 * threshold) + " failures (three times the threshold).")
    if confidence == "low":
        return ("Confidence is low because only one username was used and there were fewer than "
                + str(2 * threshold) + " failures (twice the threshold).")
    return "Confidence is medium because the evidence is neither very narrow nor very broad."


def _build_limitations(summary):
    """The evidence 'limitations' list: harmless explanations and blind spots."""
    limitations = [
        "A real user who mistyped or forgot a password produces the same pattern of failures.",
        "Several people sharing one address (for example an office router) look like one source.",
        "Failures spread over more than the configured window are not counted, so slow guessing is missed.",
    ]
    linked_count = len(summary["linked_successes"])
    if linked_count > 0:
        limitations.append("A real user who mistyped a password and then succeeded looks the same as this pattern.")
        limitations.append("Several people sharing one address (for example an office router) can look the same after the failures.")
        limitations.append("This alert does not show whether the successful login was authorised.")
    if linked_count > MAX_DETAILED_SUCCESS_EVENTS:
        limitations.append("Note: many successful logins from one address suggests a shared address such as an office router.")
    return limitations


def _build_description(summary, source_ip, time_start, last_failure_time):
    """One or two sentences for the dashboard list: what was recorded, with the
    success sentence added when a success is linked."""
    span_seconds = _whole_seconds_between(time_start, last_failure_time)
    description = ("Possible repeated password guessing: " + str(summary["failure_count"]) + " failed logins were recorded from "
                   + source_ip + " within " + _format_count(span_seconds, "second") + ", using "
                   + _format_count(len(summary["failed_names"]), "different username") + ".")
    success_sentences = _build_success_sentences(summary, last_failure_time)
    if len(success_sentences) > 0:
        description = description + " " + success_sentences[0]
    return description


def _build_recommended_action(summary):
    """Fixed wording per rule (C.2); longer when a success is linked."""
    action = ("Review the targeted accounts, consider temporarily blocking the address at the firewall, "
              "and enable multi-factor authentication.")
    if len(summary["linked_successes"]) > 0:
        action = action + (" Check whether the successful login was expected, review that account's recent "
                           "activity, and reset the password if there is any doubt.")
    return action


# ---------------------------------------------------------------
# Step 5: build the alert
# ---------------------------------------------------------------

def _build_evidence(summary, burst_failures, config):
    """
    Purpose: build the evidence dictionary of one alert (C.2 and FS.3.3).
    Inputs: summary (dict from _summarise_burst); burst_failures (list of
        events, time order); config (dict).
    Output: dict with the four required keys plus the AUTH_BRUTE_FORCE keys.
    Steps:
        1. Fill rule_parameters, observed, explanation and limitations.
        2. Add failure_count, distinct_usernames, usernames_sample,
           followed_by_success, success_event_count.
        3. Add the detail list success_events (first 10 only) and
           success_events_not_detailed (count minus detail length).
        4. Add successful_usernames and successful_usernames_also_failed,
           computed from ALL linked successes.
    Example: 15 linked successes -> success_event_count 15, len(success_events)
        10, success_events_not_detailed 5.
    Errors: ConfigError if a needed setting is missing.
    """
    # Longer than 30 lines only because the evidence dictionary lists every key once; splitting it would hide the key list.
    linked = summary["linked_successes"]
    details = _build_success_details(linked, summary["failed_lowercase"])
    time_start = burst_failures[0]["timestamp"]
    last_failure_time = burst_failures[-1]["timestamp"]
    source_ip = burst_failures[0]["source_ip"]
    evidence = {
        "rule_parameters": _copy_settings(config, _PARAMETER_KEYS),
        "observed": {
            "failure_count": summary["failure_count"],
            "distinct_usernames": len(summary["failed_names"]),
            "burst_seconds": _whole_seconds_between(time_start, last_failure_time),
            "success_event_count": len(linked),
        },
        "explanation": _build_explanation(summary, source_ip, time_start, last_failure_time, config),
        "limitations": _build_limitations(summary),
        "failure_count": summary["failure_count"],
        "distinct_usernames": len(summary["failed_names"]),
        "usernames_sample": summary["failed_names"][:_MAX_USERNAMES_SAMPLE],
        "followed_by_success": len(linked) > 0,
        "success_event_count": len(linked),
        "success_events": details,
        "success_events_not_detailed": len(linked) - len(details),
        "successful_usernames": summary["successful_names"],
        "successful_usernames_also_failed": summary["names_also_failed"],
    }
    return evidence


def _build_alert(burst_failures, linked_successes, config):
    """
    Purpose: build one AUTH_BRUTE_FORCE alert with make_alert (the only place
        alert IDs are made).
    Inputs: burst_failures (list of events, time order); linked_successes (list
        of events, time order, possibly empty); config (dict).
    Output: alert dict. event_ids = every failure, then every linked success, in
        time order and never trimmed. time_end = the latest of all of them.
    Steps:
        1. Summarise the burst (counts, severity, confidence).
        2. Take time_start from the first failure and time_end from the last
           linked success (or the last failure if none is linked).
        3. Collect the event IDs and call make_alert with the texts and evidence.
    Example: 6 failures + 1 success 30 s after the last failure -> 7 event IDs,
        severity high.
    Errors: ConfigError if a needed setting is missing; ContractError only if
        the factory rejects the values (for example a duplicate event ID).
    """
    summary = _summarise_burst(burst_failures, linked_successes, config)
    time_start = burst_failures[0]["timestamp"]
    last_failure_time = burst_failures[-1]["timestamp"]
    time_end = last_failure_time
    if len(linked_successes) > 0:
        time_end = linked_successes[-1]["timestamp"]  # successes are all later than the failures
    event_ids = []
    for event in burst_failures + linked_successes:
        event_ids.append(event["event_id"])
    source_ip = burst_failures[0]["source_ip"]
    return make_alert(
        rule_id=RULE_ID,
        title=TITLE,
        description=_build_description(summary, source_ip, time_start, last_failure_time),
        severity=summary["severity"],
        confidence=summary["confidence"],
        time_start=time_start,
        time_end=time_end,
        source_ip=source_ip,
        event_ids=event_ids,
        evidence=_build_evidence(summary, burst_failures, config),
        recommended_action=_build_recommended_action(summary),
    )


# ---------------------------------------------------------------
# The public rule
# ---------------------------------------------------------------

def detect_failed_logins(events: list, config: dict) -> tuple:
    """
    Purpose: rule AUTH_BRUTE_FORCE: find bursts of failed logins from one
        source address and link any success that follows (FS.3.3).
    Inputs:
        events (list of dict) - normalised events (any order; bad ones are skipped).
        config (dict) - needs auth_failed_threshold, auth_window_seconds,
            auth_success_after_failure_seconds and (optionally) trusted_ips.
    Output: tuple (alerts, notes). alerts is a list of alert dictionaries built
        by make_alert; notes is a list of str (always empty for this rule).
    Steps:
        1. Clean the events and ignore trusted addresses.
        2. Group authentication failures and successes by source address.
        3. For each address run find_bursts on its failure times.
        4. For each burst link the successes that come strictly after the last
           failure and no later than the success window.
        5. Build one alert per burst.
    Example: 8 failures in 56 s from 203.0.113.50 (4 usernames) followed 42 s
        later by a success -> one alert: severity high, confidence high,
        9 event IDs, time_end = the success time.
    Errors: ConfigError if a setting is missing or trusted_ips is invalid.
    """
    threshold = _get_setting(config, "auth_failed_threshold")
    window_seconds = _get_setting(config, "auth_window_seconds")
    success_window = _get_setting(config, "auth_success_after_failure_seconds")
    trusted_ips = _get_trusted_ip_set(config)
    failures_by_ip, successes_by_ip = _group_auth_events(_clean_events(events), trusted_ips)
    alerts = []
    for source_ip in sorted(failures_by_ip):
        ip_failures = failures_by_ip[source_ip]
        timestamps = [failure["timestamp"] for failure in ip_failures]
        for first_index, last_index in find_bursts(timestamps, None, threshold, window_seconds):
            burst_failures = ip_failures[first_index:last_index + 1]
            ip_successes = successes_by_ip.get(source_ip, [])
            linked_successes = _find_linked_successes(burst_failures, ip_successes, success_window)
            alerts.append(_build_alert(burst_failures, linked_successes, config))
    return alerts, []
