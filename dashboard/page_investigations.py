# dashboard/page_investigations.py
# ---------------------------------------------------------------
# Purpose: the Investigations page, labelled "Incidents" in the sidebar (G.3).
# render_investigations_page: FS.4 public function.
# Shows the incident list (filtered by status), then for the selected incident: summary,
# priority, linked alerts (base alerts of correlated alerts are labelled "Linked base alert"),
# evidence events, notes (oldest first), history, a note form, a status selector that offers
# ONLY the transitions of C.3, and a way to add more saved alerts.
# Backend calls (dashboard/backend_calls.py): list_incidents, get_incident_details,
# update_incident_status, add_note, add_alerts_to_incident, get_alerts.
# Session key used: selected_incident_id.
# Uses: streamlit, pandas, core, dashboard.components.

import pandas as pd
import streamlit as st

from core.contracts import ALLOWED_STATUS_TRANSITIONS, INCIDENT_STATUSES, format_incident_id
from core.errors import DatabaseError, IncidentNotFound, InvalidStatusTransition
from dashboard import backend_calls
from dashboard.components import (
    alerts_to_dataframe,
    events_for_alert,
    format_timestamp,
    render_alert_details,
    render_empty_state,
    render_page_header,
    render_reminder,
    severity_badge_html,
    show_alert_dataframe,
    show_events_table,
    sort_alerts_for_display,
)


def _incident_label(incident: dict) -> str:
    """One line that identifies an incident in a selection list."""
    return format_incident_id(incident["incident_id"]) + " | " + incident["title"] + " | " + incident["status"]


def _incident_table_rows(incidents: list) -> list:
    """Rows for the incident list table."""
    rows = []
    for incident in incidents:
        rows.append({
            "Incident": format_incident_id(incident["incident_id"]), "Title": incident["title"],
            "Status": incident["status"], "Priority": incident["priority"].upper(),
            "Alerts": len(incident["alert_ids"]), "Updated (UTC)": format_timestamp(incident["updated_at"]),
        })
    return rows


def _linked_base_alert_ids(alerts: list) -> list:
    """IDs of alerts that a correlated alert in this incident points to (labelled Linked base alert)."""
    linked_ids = []
    for alert in alerts:
        if alert["rule_id"] == "CORR_AUTH_NET":
            linked_ids.extend(alert["evidence"]["correlation"]["linked_alert_ids"])
    return linked_ids


def _choose_incident(incidents: list):
    """Select one incident; remembers the choice in selected_incident_id. Returns its number."""
    labels_to_ids = {}
    for incident in incidents:
        labels_to_ids[_incident_label(incident)] = incident["incident_id"]
    labels = list(labels_to_ids.keys())
    start_index = 0
    for index in range(len(labels)):
        if labels_to_ids[labels[index]] == st.session_state["selected_incident_id"]:
            start_index = index
    chosen_label = st.selectbox("Incident", labels, index=start_index, key="incident_choice")
    st.session_state["selected_incident_id"] = labels_to_ids[chosen_label]
    return labels_to_ids[chosen_label]


def _render_incident_header(details: dict) -> None:
    """Title, status, priority badge, dates and summary."""
    st.subheader(format_incident_id(details["incident_id"]) + " - " + details["title"])
    st.markdown("Status: **" + details["status"] + "** &nbsp; Priority: " + severity_badge_html(details["priority"]),
                unsafe_allow_html=True)
    st.caption("Created " + format_timestamp(details["created_at"]) + " UTC | Updated " + format_timestamp(details["updated_at"])
               + " UTC | Closed " + (format_timestamp(details["closed_at"]) or "not closed"))
    if details["summary"] != "":
        st.write(details["summary"])


def _render_alerts_tab(details: dict) -> None:
    """
    Purpose: show the linked alerts, all evidence events, and one alert's full details.
    Inputs: details (dict) from get_incident_details.
    Output: None.
    Steps:
        1. Label each alert as Alert or Linked base alert.
        2. Show the alert table and the combined events table.
        3. Show the full details of the chosen alert.
    Example: an incident from a correlated alert -> 1 Alert and 2 Linked base alerts.
    Errors: none.
    """
    alerts = details["alerts"]
    linked_ids = _linked_base_alert_ids(alerts)
    table = alerts_to_dataframe(alerts)
    roles = []
    for alert_id in table["Alert ID"]:
        roles.append("Linked base alert" if alert_id in linked_ids else "Alert")
    table["Role"] = roles
    show_alert_dataframe(table)
    st.markdown("**Evidence events of all linked alerts (" + str(len(details["events"])) + ")**")
    show_events_table(details["events"])
    labels_to_alerts = {}
    for alert in sort_alerts_for_display(alerts):
        labels_to_alerts[alert["alert_id"] + " | " + alert["rule_id"]] = alert
    chosen = st.selectbox("Alert details", list(labels_to_alerts.keys()), key="incident_alert_choice")
    events, missing = events_for_alert(labels_to_alerts[chosen], details["events"])
    render_alert_details(labels_to_alerts[chosen], events, "Supporting events (stored with this alert)", missing)


def _render_notes_tab(details: dict, db_path: str) -> None:
    """
    Purpose: show the notes (oldest first) and the form for a new note.
    Inputs: details (dict) from get_incident_details, db_path (str).
    Output: None.
    Steps:
        1. Show every note with its author and time.
        2. Show the note form; its text box clears after submitting.
        3. On submit call add_note, then refresh the page.
    Example: submit 'Checked the firewall logs.' -> a note and a note_added history row.
    Errors: ValueError, IncidentNotFound and DatabaseError are shown as messages.
    """
    if len(details["notes"]) == 0:
        st.caption("No notes yet.")
    for note in details["notes"]:
        st.markdown("**" + note["author"] + "** - " + format_timestamp(note["created_at"]) + " UTC")
        st.write(note["text"])
    with st.form("note_form", clear_on_submit=True):
        note_text = st.text_area("New note (up to 2000 characters)", key="new_note_text")
        submitted = st.form_submit_button("Add note")
    if submitted:
        try:
            backend_calls.add_note(db_path, details["incident_id"], note_text)
        except ValueError as error:
            st.error(str(error))
            return
        except (IncidentNotFound, DatabaseError) as error:
            st.warning("The note could not be added: " + str(error))
            return
        st.toast("Note added.")
        st.rerun()


def _render_history_tab(details: dict) -> None:
    """The history timeline, oldest first."""
    rows = []
    for entry in details["history"]:
        rows.append({"Time (UTC)": format_timestamp(entry["changed_at"]), "Action": entry["action"],
                     "From": entry["old_value"] or "", "To": entry["new_value"] or "", "By": entry["changed_by"]})
    if len(rows) == 0:
        st.caption("No history yet.")
        return
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


def _render_status_change(details: dict, db_path: str) -> None:
    """
    Purpose: let the user change the incident status, offering only the moves allowed by C.3.
    Inputs: details (dict), db_path (str).
    Output: None.
    Steps:
        1. Read the allowed moves for the current status from ALLOWED_STATUS_TRANSITIONS.
        2. Offer only those in the selection box.
        3. On click call update_incident_status and refresh.
    Example: status open -> the box offers investigating, resolved, false_positive.
    Errors: InvalidStatusTransition, IncidentNotFound and DatabaseError are shown as messages.
    """
    allowed_moves = ALLOWED_STATUS_TRANSITIONS[details["status"]]
    st.markdown("**Change status**")
    new_status = st.selectbox("New status", allowed_moves, key="new_status_choice")
    if st.button("Change status", key="change_status_button"):
        try:
            backend_calls.update_incident_status(db_path, details["incident_id"], new_status)
        except InvalidStatusTransition as error:
            st.error("That status change is not allowed: " + str(error))
            return
        except (IncidentNotFound, DatabaseError) as error:
            st.warning("The status could not be changed: " + str(error))
            return
        st.toast("Status changed to " + new_status + ".")
        st.rerun()


def _render_add_alerts(details: dict, db_path: str) -> None:
    """
    Purpose: link more saved alerts to the incident.
    Inputs: details (dict), db_path (str).
    Output: None.
    Steps:
        1. Read the saved alerts with get_alerts.
        2. Offer those not yet linked to this incident.
        3. On click call add_alerts_to_incident and refresh.
    Example: 2 saved alerts not linked -> both offered; after adding, none are offered.
    Errors: IncidentNotFound and DatabaseError are shown as messages.
    """
    st.markdown("**Add saved alerts to this incident**")
    try:
        saved_alerts = backend_calls.get_alerts(db_path)
    except DatabaseError as error:
        st.error("Saved alerts could not be read: " + str(error))
        return
    labels_to_ids = {}
    for alert in sort_alerts_for_display(saved_alerts):
        if alert["alert_id"] not in details["alert_ids"]:
            labels_to_ids[alert["alert_id"] + " | " + alert["rule_id"] + " | " + str(alert["source_ip"])] = alert["alert_id"]
    if len(labels_to_ids) == 0:
        st.caption("Every saved alert is already linked to this incident.")
        return
    chosen_labels = st.multiselect("Saved alerts", list(labels_to_ids.keys()), key="add_alerts_choice")
    if st.button("Add selected alerts", key="add_alerts_button", disabled=(len(chosen_labels) == 0)):
        chosen_ids = []
        for label in chosen_labels:
            chosen_ids.append(labels_to_ids[label])
        try:
            added = backend_calls.add_alerts_to_incident(db_path, details["incident_id"], chosen_ids)
        except (IncidentNotFound, DatabaseError) as error:
            st.warning("The alerts could not be added: " + str(error))
            return
        st.toast(str(added) + " alert(s) linked.")
        st.rerun()


def _render_incident_tabs(details: dict, db_path: str) -> None:
    """The four tabs under an incident: alerts and evidence, notes, history, update."""
    alerts_tab, notes_tab, history_tab, update_tab = st.tabs(["Alerts and evidence", "Notes", "History", "Update incident"])
    with alerts_tab:
        _render_alerts_tab(details)
    with notes_tab:
        _render_notes_tab(details, db_path)
    with history_tab:
        _render_history_tab(details)
    with update_tab:
        _render_status_change(details, db_path)
        _render_add_alerts(details, db_path)


def render_investigations_page(config: dict, db_path: str) -> None:
    """
    Purpose: draw the Investigations (Incidents) page.
    Inputs: config (dict, unused here); db_path (str, the database file).
    Output: None.
    Steps:
        1. Header, status filter and the incident list.
        2. Select an incident and read its details.
        3. Show its header, then four tabs: alerts and evidence, notes, history, update.
    Example: called by app.py as render_investigations_page(config, "data/network_sentinel.db").
    Errors: IncidentNotFound and InvalidStatusTransition are shown as friendly messages.
    """
    render_page_header("Incidents", "Group related alerts, record notes and track the status of each investigation.")
    status_choice = st.selectbox("Show incidents with status", ["All"] + INCIDENT_STATUSES, key="incident_status_filter")
    status_filter = None if status_choice == "All" else status_choice
    try:
        incidents = backend_calls.list_incidents(db_path, status_filter)
    except DatabaseError as error:
        st.error("Incidents could not be read: " + str(error))
        return
    if len(incidents) == 0:
        render_empty_state("There are no incidents to show. Create one from the Alerts page: select alerts, then use "
                           "Create incident from selected alerts.")
        return
    st.dataframe(pd.DataFrame(_incident_table_rows(incidents)), width="stretch", hide_index=True)
    incident_id = _choose_incident(incidents)
    try:
        details = backend_calls.get_incident_details(db_path, incident_id)
    except IncidentNotFound:
        st.warning("That incident no longer exists. Choose another one.")
        return
    except DatabaseError as error:
        st.error("The incident could not be read: " + str(error))
        return
    _render_incident_header(details)
    _render_incident_tabs(details, db_path)
    render_reminder()
