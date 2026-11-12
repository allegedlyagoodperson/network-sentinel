# dashboard/components.py
# ---------------------------------------------------------------
# Purpose: small reusable pieces shared by all dashboard pages.
# initialise_session_state: creates the FS.5 session keys (app.py calls it first).
# severity_badge_html / confidence_text_html / render_metric_card: visual building blocks.
# sort_alerts_for_display / filter_alerts / count_by_severity / top_sources /
#     group_alerts_by_hour: plain list-and-dictionary helpers (no Streamlit).
# alerts_to_dataframe / events_to_dataframe: turn dictionaries into readable tables.
# render_alert_details: the full evidence panel for one alert.
# Security rule (G.1): text from logs or users is shown with native widgets or
# passed through html.escape before it goes into custom HTML.
# Uses: streamlit, pandas (tables only), core.contracts, config.settings, dashboard.theme,
# dashboard.backend_calls (only to ask whether the backend is the mock).

import html

import pandas as pd
import streamlit as st

from config.settings import get_default_config
from core.contracts import MAX_DETAILED_SUCCESS_EVENTS, SEVERITIES, severity_rank
from dashboard import backend_calls
from dashboard.theme import SEVERITY_COLORS

DETECTION_REMINDER = "Detections are indicators of suspicious activity. They are not proof of an attack."
RAW_EVENT_EXPANDER_LIMIT = 20


# ---------------------------------------------------------------
# Session state (FS.5)
# ---------------------------------------------------------------

def initialise_session_state() -> None:
    """
    Purpose: create every FS.5 session key that does not exist yet.
    Inputs: none (reads and writes st.session_state).
    Output: None.
    Steps:
        1. List each FS.5 key with its starting value.
        2. Add the key only if it is missing, so existing data is never overwritten.
    Example: a brand new session gets analysis = None and alerts_view = "current".
    Errors: none.
    """
    defaults = {
        "config": get_default_config(),
        "events": [],
        "rejected_rows": [],
        "ingestion_summaries": [],
        "analysis": None,
        "selected_alert_ids": [],
        "selected_incident_id": None,
        "alerts_view": "current",
    }
    for key in defaults:
        if key not in st.session_state:
            st.session_state[key] = defaults[key]


# ---------------------------------------------------------------
# Visual building blocks
# ---------------------------------------------------------------

def severity_badge_html(severity: str) -> str:
    """
    Purpose: HTML for a severity badge (critical filled red, high red outline, medium amber, low green).
    Inputs: severity (str).
    Output: str - a span with a CSS class. Unknown values get a neutral badge.
    Steps:
        1. Pick the CSS class from the severity (neutral if unknown).
        2. Escape the text before it goes into HTML.
    Example: severity_badge_html("high") -> '<span class="ns-badge ns-badge-high">high</span>'.
    Errors: none.
    """
    if severity in SEVERITIES:
        css_class = "ns-badge-" + severity
    else:
        css_class = "ns-badge-unknown"
    return '<span class="ns-badge ' + css_class + '">' + html.escape(str(severity)) + "</span>"


def confidence_text_html(confidence: str) -> str:
    """Grey small text such as 'Confidence: medium'. Never uses a severity colour (G.1)."""
    return '<span class="ns-confidence">Confidence: ' + html.escape(str(confidence)) + "</span>"


def render_metric_card(label: str, value, caption: str = "") -> None:
    """
    Purpose: draw one metric card (label, big number, small caption).
    Inputs: label (str), value (any, shown as text), caption (str, optional).
    Output: None.
    Steps:
        1. Escape all three texts.
        2. Write the card HTML using the theme's CSS classes.
    Example: render_metric_card("Alerts found", 5, "4 base, 1 correlated").
    Errors: none.
    """
    card_html = (
        '<div class="ns-card"><div class="ns-card-label">' + html.escape(str(label)) + "</div>"
        '<div class="ns-card-value">' + html.escape(str(value)) + "</div>"
        '<div class="ns-card-caption">' + html.escape(str(caption)) + "</div></div>"
    )
    st.markdown(card_html, unsafe_allow_html=True)


def render_page_header(title: str, subtitle: str) -> None:
    """Page title, grey subtitle, and (in mock mode) the demo banner."""
    st.title(title)
    st.markdown('<div class="ns-subtitle">' + html.escape(subtitle) + "</div>", unsafe_allow_html=True)
    render_mock_banner()


def render_mock_banner() -> None:
    """A visible dashed banner when the development mock backend is explicitly enabled."""
    if backend_calls.is_mock_backend():
        st.markdown(
            '<div class="ns-banner ns-banner-mock"><b>DEMO MODE - MOCK DATA.</b> Ingestion, detection, storage '
            "and reporting are temporary stand-ins. Nothing here comes from real log analysis.</div>",
            unsafe_allow_html=True,
        )


def render_reminder() -> None:
    """The standing reminder that detections are indicators, not proof."""
    st.markdown('<div class="ns-reminder">' + html.escape(DETECTION_REMINDER) + "</div>", unsafe_allow_html=True)


def render_warning_banner(message: str) -> None:
    """An amber banner for something the user should notice (for example unsaved alerts)."""
    st.markdown('<div class="ns-banner ns-banner-warning">' + html.escape(message) + "</div>", unsafe_allow_html=True)


def render_empty_state(message: str) -> None:
    """A friendly instruction shown when there is nothing to display yet."""
    st.info(message)


def render_text_list(title: str, sentences: list) -> None:
    """A bold title followed by one bullet per sentence. Sentences are shown with st.write."""
    st.markdown("**" + title + "**")
    if len(sentences) == 0:
        st.caption("None recorded.")
    for sentence in sentences:
        st.write("- " + str(sentence))


# ---------------------------------------------------------------
# Plain helpers (no Streamlit): sorting, filtering, counting
# ---------------------------------------------------------------

def format_timestamp(value) -> str:
    """A datetime as 'YYYY-MM-DD HH:MM:SS' (always UTC), or empty text for None."""
    if value is None:
        return ""
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def _alert_display_key(alert):
    """Sort key: highest severity first, then newest time_start first."""
    return (-severity_rank(alert["severity"]), -alert["time_start"].timestamp())


def sort_alerts_for_display(alerts: list) -> list:
    """A new list of alerts sorted by severity (high to low) then time (newest first)."""
    return sorted(alerts, key=_alert_display_key)


def filter_alerts(alerts: list, severity: str = "All", confidence: str = "All",
                  rule_id: str = "All", source_text: str = "") -> list:
    """
    Purpose: keep only the alerts that match the filter choices of the Alerts page.
    Inputs: alerts (list); severity, confidence, rule_id (str, "All" means no filter);
        source_text (str, a part of the source address; empty means no filter).
    Output: list - the matching alerts, original order.
    Steps:
        1. For each alert, reject it if any chosen filter does not match.
        2. Keep the rest.
    Example: filter_alerts(alerts, severity="high") -> only high severity alerts.
    Errors: none.
    """
    wanted_text = source_text.strip()
    matches = []
    for alert in alerts:
        if severity != "All" and alert["severity"] != severity:
            continue
        if confidence != "All" and alert["confidence"] != confidence:
            continue
        if rule_id != "All" and alert["rule_id"] != rule_id:
            continue
        if wanted_text != "" and wanted_text not in str(alert["source_ip"]):
            continue
        matches.append(alert)
    return matches


def count_by_severity(alerts: list) -> dict:
    """A dictionary with every severity as a key and the number of alerts as the value."""
    counts = {}
    for severity in SEVERITIES:
        counts[severity] = 0
    for alert in alerts:
        counts[alert["severity"]] += 1
    return counts


def _source_count_key(pair):
    """Sort key for (address, count) pairs: biggest count first, then address."""
    return (-pair[1], pair[0])


def top_sources(alerts: list, limit: int = 5) -> list:
    """The addresses with the most alerts, as a list of (address, count) pairs."""
    counts = {}
    for alert in alerts:
        if alert["source_ip"] is None:
            continue
        counts[alert["source_ip"]] = counts.get(alert["source_ip"], 0) + 1
    pairs = list(counts.items())
    return sorted(pairs, key=_source_count_key)[:limit]


def group_alerts_by_hour(alerts: list) -> pd.DataFrame:
    """A table with one row per hour (by time_start) and the number of alerts, ready for a bar chart."""
    counts = {}
    for alert in alerts:
        hour_label = alert["time_start"].strftime("%Y-%m-%d %H:00")
        counts[hour_label] = counts.get(hour_label, 0) + 1
    hour_labels = sorted(counts.keys())
    values = []
    for hour_label in hour_labels:
        values.append(counts[hour_label])
    return pd.DataFrame({"Alerts": values}, index=hour_labels)


def events_for_alert(alert: dict, session_events: list) -> tuple:
    """
    Purpose: pick the session events that an alert refers to.
    Inputs: alert (dict), session_events (list of event dicts).
    Output: tuple (events, missing_count) - events in the order of alert['event_ids'];
        missing_count is how many IDs were not found in session_events.
    Steps:
        1. Index the session events by event_id.
        2. Walk alert['event_ids'] and collect the matching events.
    Example: an alert with 9 IDs and all events loaded -> (9 events, 0).
    Errors: none.
    """
    events_by_id = {}
    for event in session_events:
        events_by_id[event["event_id"]] = event
    found = []
    missing_count = 0
    for event_id in alert["event_ids"]:
        if event_id in events_by_id:
            found.append(events_by_id[event_id])
        else:
            missing_count += 1
    return found, missing_count


# ---------------------------------------------------------------
# Tables
# ---------------------------------------------------------------

def _severity_text_style(value):
    """CSS for one severity cell in a table (colour only; the text itself also says the severity)."""
    name = str(value).lower()
    if name in SEVERITY_COLORS:
        return "color: " + SEVERITY_COLORS[name] + "; font-weight: 600"
    return ""


def alerts_to_dataframe(alerts: list, saved_ids: list | None = None) -> pd.DataFrame:
    """
    Purpose: one table row per alert, sorted by severity then time.
    Inputs: alerts (list); saved_ids (list of alert IDs that are saved, or None to omit the Saved column).
    Output: pandas DataFrame with readable column names.
    Steps:
        1. Sort the alerts for display.
        2. Build one row dictionary per alert (timestamps as UTC text).
        3. Add Saved / Not saved when saved_ids is given.
    Example: 5 alerts -> a table of 5 rows.
    Errors: none.
    """
    rows = []
    for alert in sort_alerts_for_display(alerts):
        row = {
            "Severity": alert["severity"].upper(),
            "Confidence": alert["confidence"],
            "Rule": alert["rule_id"],
            "Source": alert["source_ip"] or "",
            "Start (UTC)": format_timestamp(alert["time_start"]),
            "End (UTC)": format_timestamp(alert["time_end"]),
            "Events": len(alert["event_ids"]),
            "Alert ID": alert["alert_id"],
        }
        if saved_ids is not None:
            row["Saved"] = "Saved" if alert["alert_id"] in saved_ids else "Not saved"
        rows.append(row)
    return pd.DataFrame(rows)


def _text_or_empty(value) -> str:
    """A table cell as text: empty for a missing value. Text keeps every column one type (no mixed numbers and blanks)."""
    if value is None:
        return ""
    return str(value)


def events_to_dataframe(events: list) -> pd.DataFrame:
    """
    Purpose: one table row per event for display; the raw_event dictionary is left out (it has its own expanders).
    Inputs: events (list of event dictionaries).
    Output: pandas DataFrame with readable column names; missing values are empty text.
    Steps:
        1. Walk through the events.
        2. Build one row dictionary per event, turning numbers and None into text so each column has one type.
    Example: 2 events -> a table with 2 rows and 14 columns.
    Errors: none.
    """
    rows = []
    for event in events:
        rows.append({
            "Time (UTC)": format_timestamp(event["timestamp"]),
            "Type": event["event_type"],
            "Source": event["source_ip"],
            "Destination": event["destination_ip"] or "",
            "Port": _text_or_empty(event["destination_port"]),
            "Protocol": event["protocol"] or "",
            "User": event["username"] or "",
            "Service": event["service"] or "",
            "Status": event["status"],
            "Bytes sent": _text_or_empty(event["bytes_sent"]),
            "Bytes received": _text_or_empty(event["bytes_received"]),
            "File": event["source_file"],
            "Row": event["source_row"],
            "Event ID": event["event_id"],
        })
    return pd.DataFrame(rows)


def show_alert_dataframe(table: pd.DataFrame) -> None:
    """Draw any table that has a Severity column, with that column coloured."""
    styled_table = table.style.map(_severity_text_style, subset=["Severity"])
    st.dataframe(styled_table, width="stretch", hide_index=True)


def show_alert_table(alerts: list, saved_ids: list | None = None) -> None:
    """Draw the alert table with the severity column coloured."""
    show_alert_dataframe(alerts_to_dataframe(alerts, saved_ids))


def show_events_table(events: list) -> None:
    """Draw an events table, or a short message if there are none."""
    if len(events) == 0:
        st.caption("No events to show.")
        return
    st.dataframe(events_to_dataframe(events), width="stretch", hide_index=True)


def show_raw_events(events: list) -> None:
    """One expander per raw CSV row, up to RAW_EVENT_EXPANDER_LIMIT. st.json shows the text safely."""
    for event in events[:RAW_EVENT_EXPANDER_LIMIT]:
        label = "Raw row " + str(event["source_row"]) + " of " + event["source_file"] + " - " + event["event_id"]
        with st.expander(label):
            st.json(event["raw_event"])
    if len(events) > RAW_EVENT_EXPANDER_LIMIT:
        st.caption("Raw rows are shown for the first " + str(RAW_EVENT_EXPANDER_LIMIT) + " of " + str(len(events)) + " events.")


# ---------------------------------------------------------------
# Alert detail panel
# ---------------------------------------------------------------

def _render_success_details(evidence: dict) -> None:
    """The linked-success detail table of an AUTH_BRUTE_FORCE alert (R2.3 wording, no claim about other tables)."""
    linked_count = evidence["success_event_count"]
    detail_list = evidence["success_events"]
    st.markdown("**Authentication successes linked to this alert**")
    st.write(
        "Linked: " + str(linked_count) + ". Shown in this detail table: " + str(len(detail_list))
        + " (limit " + str(MAX_DETAILED_SUCCESS_EVENTS) + "). Not shown in this table: "
        + str(evidence["success_events_not_detailed"]) + "."
    )
    if len(detail_list) > 0:
        st.dataframe(pd.DataFrame(detail_list), width="stretch", hide_index=True)


def _render_correlation(correlation: dict) -> None:
    """Linked alerts and the conditions that were met, for a CORR_AUTH_NET alert."""
    st.markdown("**Why these alerts were linked**")
    st.write("Link: " + correlation["link_key"] + " = " + str(correlation["link_value"])
             + ". Gap between the alerts: " + str(correlation["gap_seconds"]) + " seconds. Destination match: "
             + ("yes" if correlation["destination_match"] else "no") + ".")
    render_text_list("Conditions met", correlation["match_conditions"])
    render_text_list("Linked alert IDs", correlation["linked_alert_ids"])


def render_alert_details(alert: dict, events: list, events_caption: str, missing_events: int = 0) -> None:
    """
    Purpose: the full evidence panel for one alert (G.3 Alerts page).
    Inputs: alert (dict); events (list of the supporting events to show);
        events_caption (str, says where the events come from);
        missing_events (int, how many referenced events are not available).
    Output: None.
    Steps:
        1. Title, severity badge, confidence text, description, time range and source.
        2. Explanation and limitations lists, thresholds used, observed numbers.
        3. Extra panels for success details and correlation, when present.
        4. Recommended action, then the supporting events table and raw rows.
    Example: render_alert_details(alert, events, "Supporting events (from this session)").
    Errors: none.
    """
    evidence = alert["evidence"]
    st.subheader(alert["title"])
    st.markdown(severity_badge_html(alert["severity"]) + confidence_text_html(alert["confidence"]), unsafe_allow_html=True)
    st.write(alert["description"])
    st.caption("Source: " + str(alert["source_ip"]) + "  |  " + format_timestamp(alert["time_start"]) + " to "
               + format_timestamp(alert["time_end"]) + " UTC  |  Alert ID: " + alert["alert_id"])
    render_text_list("Why this alert was raised", evidence["explanation"])
    render_text_list("Possible harmless explanations", evidence["limitations"])
    left_column, right_column = st.columns(2)
    with left_column:
        st.markdown("**Thresholds used**")
        st.json(evidence["rule_parameters"])
    with right_column:
        st.markdown("**Observed values**")
        st.json(evidence["observed"])
    if "success_events" in evidence:
        _render_success_details(evidence)
    if "correlation" in evidence:
        _render_correlation(evidence["correlation"])
    st.markdown("**Recommended action**")
    st.write(alert["recommended_action"])
    st.markdown("**" + events_caption + "**")
    if missing_events > 0:
        st.warning(str(missing_events) + " supporting events are not available in this view.")
    show_events_table(events)
    show_raw_events(events)
