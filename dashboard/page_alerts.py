# dashboard/page_alerts.py
# ---------------------------------------------------------------
# Purpose: the Alerts page (G.3, R1.6). Review findings and their evidence.
# render_alerts_page: FS.4 public function.
# Two views, chosen by the session key alerts_view (FS.5):
#   current - this session's analysis; each alert shows Saved or Not saved, and an
#             amber banner warns about unsaved alerts. Alerts can be saved or turned into an incident.
#   saved   - alerts read from the database, with only their stored evidence events.
# Save always passes the FULL session alert list and event list (R1.2.2); the dashboard never
# decides which base alerts belong to a correlated alert - storage does.
# Backend calls (dashboard/backend_calls.py): get_alerts, get_events_for_alert,
# get_existing_alert_ids, save_alerts, create_incident.
# Uses: streamlit, core, dashboard.components.

import streamlit as st

from core.contracts import CONFIDENCES, RULE_IDS, SEVERITIES, format_incident_id
from core.errors import ContractError, DatabaseError
from dashboard import backend_calls
from dashboard.components import (
    events_for_alert,
    filter_alerts,
    render_alert_details,
    render_empty_state,
    render_page_header,
    render_reminder,
    render_warning_banner,
    show_alert_table,
    sort_alerts_for_display,
)

SAVED_EVENTS_CAPTION = "Supporting events stored with this alert"
SESSION_EVENTS_CAPTION = "Supporting events (from the uploaded files in this session)"


def _view_label(view_name: str) -> str:
    """Readable text for the two alert views."""
    if view_name == "saved":
        return "Saved in database"
    return "Current analysis"


def _alert_option_label(alert: dict) -> str:
    """One line that identifies an alert in a selection list."""
    return alert["alert_id"] + " | " + alert["rule_id"] + " | " + alert["severity"] + " | " + str(alert["source_ip"])


def _render_filters(alerts: list) -> list:
    """The four filters of G.3. Returns the alerts that match."""
    columns = st.columns(4)
    with columns[0]:
        severity = st.selectbox("Severity", ["All"] + SEVERITIES, key="filter_severity")
    with columns[1]:
        confidence = st.selectbox("Confidence", ["All"] + CONFIDENCES, key="filter_confidence")
    with columns[2]:
        rule_id = st.selectbox("Rule", ["All"] + RULE_IDS, key="filter_rule")
    with columns[3]:
        source_text = st.text_input("Source address contains", key="filter_source")
    return filter_alerts(alerts, severity, confidence, rule_id, source_text)


def _load_alerts(view_name: str, db_path: str) -> list:
    """The alerts of the chosen view. A DatabaseError becomes a visible error and an empty list."""
    if view_name == "current":
        analysis = st.session_state["analysis"]
        if analysis is None:
            return []
        return analysis["alerts"]
    try:
        return backend_calls.get_alerts(db_path)
    except DatabaseError as error:
        st.error("Saved alerts could not be read: " + str(error))
        return []


def _saved_ids_of(alerts: list, db_path: str) -> list:
    """Which of the session alerts are already saved (one backend call)."""
    alert_ids = []
    for alert in alerts:
        alert_ids.append(alert["alert_id"])
    try:
        return backend_calls.get_existing_alert_ids(db_path, alert_ids)
    except DatabaseError as error:
        st.error("Could not check which alerts are saved: " + str(error))
        return []


def _select_alerts(shown_alerts: list) -> list:
    """
    Purpose: show the alert multiselect (G.3) and remember the chosen IDs in session state.
    Inputs: shown_alerts (list) - the alerts that pass the filters.
    Output: list of the selected alert dictionaries among shown_alerts.
    Steps:
        1. Build a readable label for each shown alert.
        2. Pre-select the labels whose alert is already in selected_alert_ids.
        3. Keep earlier selections that a filter is hiding.
        4. Store the new list of IDs in selected_alert_ids.
    Example: choose 2 labels -> selected_alert_ids holds those 2 IDs.
    Errors: none.
    """
    labels_to_alerts = {}
    for alert in sort_alerts_for_display(shown_alerts):
        labels_to_alerts[_alert_option_label(alert)] = alert
    shown_ids = []
    defaults = []
    for label in labels_to_alerts:
        alert_id = labels_to_alerts[label]["alert_id"]
        shown_ids.append(alert_id)
        if alert_id in st.session_state["selected_alert_ids"]:
            defaults.append(label)
    chosen_labels = st.multiselect("Select alerts to save or turn into an incident",
                                   list(labels_to_alerts.keys()), default=defaults)
    kept_ids = []
    for alert_id in st.session_state["selected_alert_ids"]:
        if alert_id not in shown_ids:
            kept_ids.append(alert_id)  # selected earlier, hidden by the current filter
    selected_alerts = []
    for label in chosen_labels:
        kept_ids.append(labels_to_alerts[label]["alert_id"])
        selected_alerts.append(labels_to_alerts[label])
    st.session_state["selected_alert_ids"] = kept_ids
    return selected_alerts


def _selected_alerts_from_session(all_alerts: list) -> list:
    """The alert dictionaries for every selected ID (including ones hidden by a filter)."""
    selected = []
    for alert in all_alerts:
        if alert["alert_id"] in st.session_state["selected_alert_ids"]:
            selected.append(alert)
    return selected


def _save_alerts(selected_alerts: list, all_alerts: list, db_path: str):
    """Save the selected alerts. Passes the FULL session lists (R1.2.2). Returns the result or None on error."""
    try:
        result = backend_calls.save_alerts(db_path, selected_alerts, st.session_state["events"], all_alerts)
    except (DatabaseError, ContractError) as error:
        st.error("Nothing was saved: " + str(error))
        return None
    st.success("Saved. New alerts: " + str(result["alerts_inserted"]) + ", already saved: "
               + str(result["alerts_skipped_duplicate"]) + ", new events: " + str(result["events_inserted"]) + ".")
    automatic = result["base_alerts_added_automatically"]
    if len(automatic) > 0:
        st.info(str(len(automatic)) + " base alerts were also saved because a selected correlated alert depends on them.")
    return result


def _create_incident(title: str, selected_alerts: list, all_alerts: list, db_path: str) -> None:
    """
    Purpose: save the selected alerts and create an incident from them.
    Inputs: title (str), selected_alerts (list), all_alerts (list - the full session list), db_path (str).
    Output: None (shows messages).
    Steps:
        1. Refuse a title that is empty or longer than 120 characters, before saving anything.
        2. Save the alerts with save_alerts.
        3. Call create_incident and remember the new number in selected_incident_id.
    Example: title 'Scan from 203.0.113.50' -> message 'INC-0001 was created'.
    Errors: DatabaseError and ValueError are shown as messages, not raised.
    """
    clean_title = title.strip()
    if len(clean_title) < 1 or len(clean_title) > 120:
        st.error("Give the incident a title of 1 to 120 characters.")
        return
    if _save_alerts(selected_alerts, all_alerts, db_path) is None:
        return
    alert_ids = []
    for alert in selected_alerts:
        alert_ids.append(alert["alert_id"])
    try:
        incident_id = backend_calls.create_incident(db_path, clean_title, alert_ids)
    except (DatabaseError, ValueError) as error:
        st.error("The incident could not be created: " + str(error))
        return
    st.session_state["selected_incident_id"] = incident_id
    st.success(format_incident_id(incident_id) + " was created. Open the Incidents page to work on it.")


def _render_actions(selected_alerts: list, all_alerts: list, db_path: str) -> None:
    """The two actions of G.3 for the selected alerts (current view only)."""
    st.caption(str(len(selected_alerts)) + " alert(s) selected.")
    save_column, incident_column = st.columns(2)
    with save_column:
        save_clicked = st.button("Save selected alerts to database", key="save_alerts_button",
                                 disabled=(len(selected_alerts) == 0))
    with incident_column:
        title = st.text_input("Incident title", key="incident_title_input")
        incident_clicked = st.button("Create incident from selected alerts", key="create_incident_button",
                                     disabled=(len(selected_alerts) == 0))
    if save_clicked:
        _save_alerts(selected_alerts, all_alerts, db_path)
    if incident_clicked:
        _create_incident(title, selected_alerts, all_alerts, db_path)


def _render_detail_panel(shown_alerts: list, view_name: str, db_path: str) -> None:
    """
    Purpose: pick one alert and show its full evidence.
    Inputs: shown_alerts (list), view_name (str: current or saved), db_path (str).
    Output: None.
    Steps:
        1. Offer the shown alerts in a selection box.
        2. Current view: take the events from the uploaded session events.
        3. Saved view: read the stored events of the alert with get_events_for_alert.
        4. Draw the evidence panel.
    Example: saved view + one alert -> caption 'Supporting events stored with this alert'.
    Errors: DatabaseError is shown as a message.
    """
    st.subheader("Alert details")
    labels_to_alerts = {}
    for alert in sort_alerts_for_display(shown_alerts):
        labels_to_alerts[_alert_option_label(alert)] = alert
    if len(labels_to_alerts) == 0:
        st.caption("No alert to inspect.")
        return
    chosen_label = st.selectbox("Alert to inspect", list(labels_to_alerts.keys()), key="inspect_alert_choice")
    alert = labels_to_alerts[chosen_label]
    if view_name == "current":
        events, missing = events_for_alert(alert, st.session_state["events"])
        render_alert_details(alert, events, SESSION_EVENTS_CAPTION, missing)
        return
    try:
        stored_events = backend_calls.get_events_for_alert(db_path, alert["alert_id"])
    except DatabaseError as error:
        st.error("The stored events could not be read: " + str(error))
        return
    render_alert_details(alert, stored_events, SAVED_EVENTS_CAPTION)


def _render_no_alerts_message(view_name: str) -> None:
    """The empty state of the Alerts page, different for the two views."""
    if view_name == "current":
        render_empty_state("There are no alerts in this session. Load log files on the Log Upload page, or switch to "
                           "the saved view to see alerts stored in the database.")
    else:
        render_empty_state("No alerts have been saved yet.")


def _fill_banner_and_table(banner_area, table_area, view_name: str, all_alerts: list, shown_alerts: list, db_path: str) -> None:
    """Draw the unsaved banner and the alert table into their reserved places on the page."""
    saved_ids = None
    if view_name == "current":
        saved_ids = _saved_ids_of(all_alerts, db_path)
        unsaved_count = len(all_alerts) - len(saved_ids)
        if unsaved_count > 0:
            with banner_area:
                render_warning_banner(str(unsaved_count) + " alerts in this analysis are not saved. Unsaved results are "
                                      "lost when the application restarts or the page is refreshed.")
    with table_area:
        show_alert_table(shown_alerts, saved_ids)


def render_alerts_page(config: dict, db_path: str) -> None:
    """
    Purpose: draw the Alerts page.
    Inputs: config (dict, unused here); db_path (str, the database file).
    Output: None.
    Steps:
        1. Header and the view switch (current analysis or saved in database).
        2. For the current view: the Saved/Not saved column and the unsaved banner.
        3. Filters, the sorted alert table, then selection and actions (current view).
        4. The detail panel for one alert.
    Example: called by app.py as render_alerts_page(config, "data/network_sentinel.db").
    Errors: backend errors are shown as messages, not raised.
    """
    render_page_header("Alerts", "Review findings and the evidence behind them.")
    view_name = st.radio("View", ["current", "saved"], key="alerts_view", horizontal=True, format_func=_view_label)
    all_alerts = _load_alerts(view_name, db_path)
    if len(all_alerts) == 0:
        _render_no_alerts_message(view_name)
        return
    # The banner and the table are drawn AFTER the save/incident buttons have run, so that they
    # never show out-of-date Saved / Not saved information. The containers keep their place on the page.
    banner_area = st.container()
    shown_alerts = _render_filters(all_alerts)
    table_area = st.container()
    if view_name == "current":
        _select_alerts(shown_alerts)
        _render_actions(_selected_alerts_from_session(all_alerts), all_alerts, db_path)
    _fill_banner_and_table(banner_area, table_area, view_name, all_alerts, shown_alerts, db_path)
    st.divider()
    _render_detail_panel(shown_alerts, view_name, db_path)
    render_reminder()
