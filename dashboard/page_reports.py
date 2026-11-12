# dashboard/page_reports.py
# ---------------------------------------------------------------
# Purpose: the Reports page (G.3). Offers PDF downloads.
# render_reports_page: FS.4 public function.
# Incident report: choose an incident, then download its PDF. Session summary: the PDF of the
# current analysis; its button is DISABLED with a message until an analysis exists (R1.9).
# The PDF bytes are built on every page draw for the chosen incident; that is simple and fine
# while reports are small (the PDF module caps the events table at 50 rows per alert).
# Backend calls (dashboard/backend_calls.py): list_incidents, get_incident_details,
# build_incident_report_pdf, build_alert_summary_pdf.
# Uses: streamlit, core, dashboard.components.

import streamlit as st

from core.contracts import format_incident_id
from core.errors import DatabaseError, IncidentNotFound, ReportError
from dashboard import backend_calls
from dashboard.components import render_empty_state, render_page_header, render_reminder


def _incident_label(incident: dict) -> str:
    """One line that identifies an incident in a selection list."""
    return format_incident_id(incident["incident_id"]) + " | " + incident["title"] + " | " + incident["status"]


def _render_incident_report(config: dict, db_path: str) -> None:
    """
    Purpose: choose an incident and offer its PDF for download.
    Inputs: config (dict), db_path (str).
    Output: None.
    Steps:
        1. List the incidents; show an instruction if there are none.
        2. Read the chosen incident with get_incident_details.
        3. Build the PDF with build_incident_report_pdf and offer the download button.
    Example: incident 1 -> a button 'Download incident report (PDF)' with file name INC-0001_report.pdf.
    Errors: IncidentNotFound, DatabaseError and ReportError are shown as messages.
    """
    st.subheader("Incident report")
    try:
        incidents = backend_calls.list_incidents(db_path)
    except DatabaseError as error:
        st.error("Incidents could not be read: " + str(error))
        return
    if len(incidents) == 0:
        render_empty_state("There are no incidents yet. Create an incident on the Alerts page first. "
                           "Saved incidents can be reported even after a restart.")
        return
    labels_to_ids = {}
    for incident in incidents:
        labels_to_ids[_incident_label(incident)] = incident["incident_id"]
    chosen_label = st.selectbox("Incident", list(labels_to_ids.keys()), key="report_incident_choice")
    incident_id = labels_to_ids[chosen_label]
    try:
        details = backend_calls.get_incident_details(db_path, incident_id)
        pdf_bytes = backend_calls.build_incident_report_pdf(details, config)
    except IncidentNotFound:
        st.warning("That incident no longer exists.")
        return
    except (DatabaseError, ReportError) as error:
        st.error("The report could not be built: " + str(error))
        return
    st.download_button("Download incident report (PDF)", data=pdf_bytes,
                       file_name=format_incident_id(incident_id) + "_report.pdf", mime="application/pdf",
                       key="download_incident_report")


def _render_session_summary(config: dict) -> None:
    """
    Purpose: offer the PDF summary of the current analysis session.
    Inputs: config (dict).
    Output: None.
    Steps:
        1. With no analysis: show a message and a DISABLED download button.
        2. Otherwise build the PDF with build_alert_summary_pdf and offer it.
    Example: no analysis -> disabled button and the caption 'needs an analysis'.
    Errors: ReportError is shown as a message.
    """
    st.subheader("Analysis summary")
    analysis = st.session_state["analysis"]
    if analysis is None:
        st.caption("The session summary needs an analysis. Load log files on the Log Upload page first.")
        st.download_button("Download analysis summary (PDF)", data=b"", file_name="analysis_summary.pdf",
                           mime="application/pdf", disabled=True, key="download_summary_disabled")
        return
    try:
        pdf_bytes = backend_calls.build_alert_summary_pdf(analysis["alerts"], analysis, config)
    except ReportError as error:
        st.error("The summary could not be built: " + str(error))
        return
    st.download_button("Download analysis summary (PDF)", data=pdf_bytes, file_name="analysis_summary.pdf",
                       mime="application/pdf", key="download_summary")


def _render_contents_note() -> None:
    """What the incident PDF contains (G.3) and what it does not claim."""
    with st.expander("What the incident report contains"):
        st.write("- A header with the incident number, status, priority, and created and generated times.")
        st.write("- A short summary with the statement that detections indicate suspicious activity and do not prove an attack.")
        st.write("- An alert table, then one evidence block per alert: explanation, limitations, thresholds and observed values.")
        st.write("- A supporting events table per alert, limited to 50 rows. The report states how many events are shown "
                 "and how many are not; the complete list stays with the alert and can be viewed on the Alerts page.")
        st.write("- All notes, the status history, the recommended actions, and page numbers.")


def render_reports_page(config: dict, db_path: str) -> None:
    """
    Purpose: draw the Reports page.
    Inputs: config (dict, passed to the PDF builders); db_path (str, the database file).
    Output: None.
    Steps:
        1. Header (with the mock banner when the backend is the mock).
        2. Incident report: select an incident, build its PDF, offer the download.
        3. Analysis summary: offer the session PDF, or a disabled button with a message.
        4. A note describing what the incident report contains.
    Example: called by app.py as render_reports_page(config, "data/network_sentinel.db").
    Errors: ReportError, DatabaseError and IncidentNotFound are shown as messages, not raised.
    """
    render_page_header("Reports", "Download PDF reports for incidents and for the current analysis.")
    _render_incident_report(config, db_path)
    st.divider()
    _render_session_summary(config)
    _render_contents_note()
    render_reminder()
