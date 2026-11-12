# dashboard/page_overview.py
# ---------------------------------------------------------------
# Purpose: the Overview page - a quick picture of what was found (G.3, R1.6).
# render_overview_page: FS.4 public function; draws the whole page.
# Two clearly labelled groups of numbers are shown: "This session" and
# "Saved in database". They are never added together, because one alert
# can be in both.
# Reads: st.session_state (events, rejected_rows, analysis).
# Backend calls (through dashboard/backend_calls.py): get_summary_counts, list_incidents.
# Uses: streamlit, core.errors, dashboard.components, dashboard.backend_calls.

import streamlit as st

from core.contracts import SEVERITIES, format_incident_id
from core.errors import DatabaseError
from dashboard import backend_calls
from dashboard.components import (
    count_by_severity,
    format_timestamp,
    group_alerts_by_hour,
    render_empty_state,
    render_metric_card,
    render_page_header,
    render_reminder,
    severity_badge_html,
    top_sources,
)


def _render_session_cards(analysis: dict | None) -> None:
    """
    Purpose: draw the metric cards for the current session (nothing here is saved).
    Inputs: analysis (dict from run_analysis, or None).
    Output: None.
    Steps:
        1. Show the empty-state instruction if nothing was analysed.
        2. Show events loaded, rows rejected, alerts found and events ignored (trusted).
    Example: after the sample files -> alerts found 5, '4 base, 1 correlated'.
    Errors: none.
    """
    st.subheader("This session")
    if analysis is None:
        render_empty_state("Nothing has been analysed in this session yet. Open the Log Upload page to load log files "
                           "and run the analysis.")
    columns = st.columns(4)
    alert_total = 0
    caption = "Run an analysis first"
    if analysis is not None:
        alert_total = len(analysis["alerts"])
        caption = str(analysis["base_alert_count"]) + " base, " + str(analysis["correlated_alert_count"]) + " correlated"
    with columns[0]:
        render_metric_card("Events loaded", len(st.session_state["events"]))
    with columns[1]:
        render_metric_card("Rows rejected", len(st.session_state["rejected_rows"]))
    with columns[2]:
        render_metric_card("Alerts found", alert_total, caption)
    with columns[3]:
        render_metric_card("Events ignored (trusted)", 0 if analysis is None else analysis["events_ignored_trusted"])


def _render_saved_cards(saved_counts: dict | None) -> None:
    """
    Purpose: draw the metric cards for what is stored in the database.
    Inputs: saved_counts (dict from get_summary_counts, or None).
    Output: None.
    Steps:
        1. Show a warning if the saved data could not be read.
        2. Show saved alerts, incidents, open incidents and investigating incidents.
    Example: 3 saved alerts, 1 open incident -> cards 3, 1, 1, 0.
    Errors: none.
    """
    st.subheader("Saved in database")
    if saved_counts is None:
        st.warning("The saved data could not be read.")
        return
    columns = st.columns(4)
    by_status = saved_counts["incidents_by_status"]
    with columns[0]:
        render_metric_card("Saved alerts", saved_counts["alerts_total"])
    with columns[1]:
        render_metric_card("Incidents", saved_counts["incidents_total"])
    with columns[2]:
        render_metric_card("Open incidents", by_status["open"])
    with columns[3]:
        render_metric_card("Investigating", by_status["investigating"])


def _render_severity_row(title: str, counts: dict) -> None:
    """One row of severity badges with their counts."""
    st.markdown("**" + title + "**")
    columns = st.columns(len(SEVERITIES))
    for index in range(len(SEVERITIES)):
        severity = SEVERITIES[len(SEVERITIES) - 1 - index]  # critical first
        with columns[index]:
            st.markdown(severity_badge_html(severity) + " &nbsp; **" + str(counts[severity]) + "**", unsafe_allow_html=True)


def _render_activity(session_alerts: list, incidents: list) -> None:
    """
    Purpose: show recent activity: the newest session alerts and the most recently updated incidents.
    Inputs: session_alerts (list), incidents (list from list_incidents).
    Output: None.
    Steps:
        1. Sort the alerts newest first and show the first 5.
        2. Show the first 5 incidents (they arrive newest updated first).
    Example: no incidents -> the caption 'No incidents yet.'
    Errors: none.
    """
    left_column, right_column = st.columns(2)
    with left_column:
        st.markdown("**Latest alerts (this session)**")
        newest_first = sorted(session_alerts, key=_newest_first_key)[:5]
        if len(newest_first) == 0:
            st.caption("No alerts yet.")
        for alert in newest_first:
            st.write(format_timestamp(alert["time_start"]) + " UTC - " + alert["rule_id"] + " - " + str(alert["source_ip"]))
    with right_column:
        st.markdown("**Recently updated incidents**")
        if len(incidents) == 0:
            st.caption("No incidents yet.")
        for incident in incidents[:5]:
            st.write(format_incident_id(incident["incident_id"]) + " - " + incident["title"] + " (" + incident["status"] + ")")


def _render_charts(session_alerts: list) -> None:
    """Alerts over time and the top five source addresses (this session)."""
    left_column, right_column = st.columns(2)
    with left_column:
        st.markdown("**Alerts over time (this session, by hour of first event)**")
        st.bar_chart(group_alerts_by_hour(session_alerts))
    with right_column:
        st.markdown("**Top source addresses (this session)**")
        rows = []
        for address, count in top_sources(session_alerts, 5):
            rows.append({"Source address": address, "Alerts": count})
        st.dataframe(rows, width="stretch", hide_index=True)


def _newest_first_key(alert):
    """Sort key: newest alert first."""
    return -alert["time_start"].timestamp()


def _render_notes(analysis: dict | None) -> None:
    """Analysis notes are always visible so the user knows what was NOT checked (G.3)."""
    st.markdown("**Analysis notes**")
    if analysis is None or len(analysis["notes"]) == 0:
        st.caption("No notes. Notes appear here when a rule is skipped or a source is not checked.")
        return
    for note in analysis["notes"]:
        st.write("- " + note)


def render_overview_page(config: dict, db_path: str) -> None:
    """
    Purpose: draw the Overview page.
    Inputs: config (dict, the current configuration); db_path (str, the database file).
    Output: None.
    Steps:
        1. Header (with the mock banner when the backend is the mock).
        2. Session cards, then saved-data cards (two separate groups).
        3. Alerts by severity for both groups, an alerts-over-time chart,
           the top five source addresses, recent activity and analysis notes.
        4. The reminder that detections are not proof.
    Example: called by app.py as render_overview_page(config, "data/network_sentinel.db").
    Errors: a DatabaseError while reading saved data is shown as a warning, not raised.
    """
    render_page_header("Overview", "A quick picture of the current session and the saved data.")
    analysis = st.session_state["analysis"]
    session_alerts = [] if analysis is None else analysis["alerts"]
    try:
        saved_counts = backend_calls.get_summary_counts(db_path)
        incidents = backend_calls.list_incidents(db_path)
    except DatabaseError as error:
        st.warning("Saved data could not be read: " + str(error))
        saved_counts = None
        incidents = []
    _render_session_cards(analysis)
    _render_saved_cards(saved_counts)
    st.divider()
    st.subheader("Alerts by severity")
    _render_severity_row("This session", count_by_severity(session_alerts))
    if saved_counts is not None:
        _render_severity_row("Saved in database", saved_counts["alerts_by_severity"])
    if len(session_alerts) > 0:
        _render_charts(session_alerts)
    st.divider()
    _render_activity(session_alerts, incidents)
    _render_notes(analysis)
    render_reminder()
