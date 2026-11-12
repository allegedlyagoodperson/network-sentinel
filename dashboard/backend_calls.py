# dashboard/backend_calls.py
# ---------------------------------------------------------------
# Purpose: the single place where dashboard pages call backend functions.
# Each wrapper keeps the public interface defined by the project contract.
# Mock mode is retained for development and controlled demonstrations.
# The normal application configuration uses the real backend modules.
# Real modules are imported inside each wrapper to keep module loading simple.
# Uses: dashboard/mock_backend.py, ingestion, detection, storage and reporting.

from dashboard import mock_backend

USE_MOCK_BACKEND = False


def is_mock_backend() -> bool:
    """
    Purpose: tell the pages whether they are showing mock data.
    Inputs: none.
    Output: bool - True while USE_MOCK_BACKEND is True.
    Steps: 1. Return the constant.
    Example: the sidebar shows a MOCK label when this is True.
    Errors: none.
    """
    return USE_MOCK_BACKEND


def ingest_file(file_bytes: bytes, file_name: str, log_type: str, config: dict) -> dict:
    """
    Purpose: check and normalise one CSV file (ingestion module).
    Inputs: exactly the FS.4 parameters of ingest_file.
    Output: exactly what FS.4 / Section E says ingest_file returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from ingestion.csv_ingest.
    Example: see the FS.4 entry for ingest_file.
    Errors: IngestionError for a file-level problem (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_ingest_file(file_bytes, file_name, log_type, config)
    from ingestion.csv_ingest import ingest_file as real_function
    return real_function(file_bytes, file_name, log_type, config)

def combine_ingestion_results(results: list) -> dict:
    """
    Purpose: merge several ingestion results (ingestion module).
    Inputs: exactly the FS.4 parameters of combine_ingestion_results.
    Output: exactly what FS.4 / Section E says combine_ingestion_results returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from ingestion.csv_ingest.
    Example: see the FS.4 entry for combine_ingestion_results.
    Errors: none (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_combine_ingestion_results(results)
    from ingestion.csv_ingest import combine_ingestion_results as real_function
    return real_function(results)

def run_analysis(events: list, config: dict) -> dict:
    """
    Purpose: run the detection rules and correlation (detection and correlation modules).
    Inputs: exactly the FS.4 parameters of run_analysis.
    Output: exactly what FS.4 / Section E says run_analysis returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from detection.engine.
    Example: see the FS.4 entry for run_analysis.
    Errors: ConfigError if config is invalid (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_run_analysis(events, config)
    from detection.engine import run_analysis as real_function
    return real_function(events, config)

def initialise_database(db_path: str) -> None:
    """
    Purpose: create the database tables if missing (storage module).
    Inputs: exactly the FS.4 parameters of initialise_database.
    Output: exactly what FS.4 / Section E says initialise_database returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.database.
    Example: see the FS.4 entry for initialise_database.
    Errors: DatabaseError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_initialise_database(db_path)
    from storage.database import initialise_database as real_function
    return real_function(db_path)

def save_alerts(db_path: str, alerts: list, events: list, available_alerts: list | None = None) -> dict:
    """
    Purpose: save alerts and their events, adding base alerts of correlated alerts (storage module).
    Inputs: exactly the FS.4 parameters of save_alerts.
    Output: exactly what FS.4 / Section E says save_alerts returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.database.
    Example: see the FS.4 entry for save_alerts.
    Errors: BrokenReferenceError, DatabaseError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_save_alerts(db_path, alerts, events, available_alerts)
    from storage.database import save_alerts as real_function
    return real_function(db_path, alerts, events, available_alerts)

def get_alerts(db_path: str, filters: dict | None = None) -> list:
    """
    Purpose: read saved alerts, newest first (storage module).
    Inputs: exactly the FS.4 parameters of get_alerts.
    Output: exactly what FS.4 / Section E says get_alerts returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.database.
    Example: see the FS.4 entry for get_alerts.
    Errors: DatabaseError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_get_alerts(db_path, filters)
    from storage.database import get_alerts as real_function
    return real_function(db_path, filters)

def get_events_for_alert(db_path: str, alert_id: str) -> list:
    """
    Purpose: read the stored events of one saved alert (storage module).
    Inputs: exactly the FS.4 parameters of get_events_for_alert.
    Output: exactly what FS.4 / Section E says get_events_for_alert returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.database.
    Example: see the FS.4 entry for get_events_for_alert.
    Errors: DatabaseError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_get_events_for_alert(db_path, alert_id)
    from storage.database import get_events_for_alert as real_function
    return real_function(db_path, alert_id)

def get_existing_alert_ids(db_path: str, alert_ids: list) -> list:
    """
    Purpose: find which alert IDs are already saved (storage module).
    Inputs: exactly the FS.4 parameters of get_existing_alert_ids.
    Output: exactly what FS.4 / Section E says get_existing_alert_ids returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.database.
    Example: see the FS.4 entry for get_existing_alert_ids.
    Errors: DatabaseError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_get_existing_alert_ids(db_path, alert_ids)
    from storage.database import get_existing_alert_ids as real_function
    return real_function(db_path, alert_ids)

def get_summary_counts(db_path: str) -> dict:
    """
    Purpose: count saved alerts and incidents (storage module).
    Inputs: exactly the FS.4 parameters of get_summary_counts.
    Output: exactly what FS.4 / Section E says get_summary_counts returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.database.
    Example: see the FS.4 entry for get_summary_counts.
    Errors: DatabaseError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_get_summary_counts(db_path)
    from storage.database import get_summary_counts as real_function
    return real_function(db_path)

def create_incident(db_path: str, title: str, alert_ids: list, summary: str = '', priority: str | None = None, created_by: str = 'analyst') -> int:
    """
    Purpose: create an incident from saved alerts (storage module).
    Inputs: exactly the FS.4 parameters of create_incident.
    Output: exactly what FS.4 / Section E says create_incident returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.incidents.
    Example: see the FS.4 entry for create_incident.
    Errors: ValueError, DatabaseError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_create_incident(db_path, title, alert_ids, summary, priority, created_by)
    from storage.incidents import create_incident as real_function
    return real_function(db_path, title, alert_ids, summary, priority, created_by)

def list_incidents(db_path: str, status: str | None = None) -> list:
    """
    Purpose: list incidents, newest updated first (storage module).
    Inputs: exactly the FS.4 parameters of list_incidents.
    Output: exactly what FS.4 / Section E says list_incidents returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.incidents.
    Example: see the FS.4 entry for list_incidents.
    Errors: DatabaseError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_list_incidents(db_path, status)
    from storage.incidents import list_incidents as real_function
    return real_function(db_path, status)

def get_incident_details(db_path: str, incident_id: int) -> dict:
    """
    Purpose: read one incident with its alerts, events, notes and history (storage module).
    Inputs: exactly the FS.4 parameters of get_incident_details.
    Output: exactly what FS.4 / Section E says get_incident_details returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.incidents.
    Example: see the FS.4 entry for get_incident_details.
    Errors: IncidentNotFound (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_get_incident_details(db_path, incident_id)
    from storage.incidents import get_incident_details as real_function
    return real_function(db_path, incident_id)

def update_incident_status(db_path: str, incident_id: int, new_status: str, changed_by: str = 'analyst') -> None:
    """
    Purpose: change an incident status using the C.3 rules (storage module).
    Inputs: exactly the FS.4 parameters of update_incident_status.
    Output: exactly what FS.4 / Section E says update_incident_status returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.incidents.
    Example: see the FS.4 entry for update_incident_status.
    Errors: IncidentNotFound, InvalidStatusTransition (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_update_incident_status(db_path, incident_id, new_status, changed_by)
    from storage.incidents import update_incident_status as real_function
    return real_function(db_path, incident_id, new_status, changed_by)

def add_note(db_path: str, incident_id: int, text: str, author: str = 'analyst') -> int:
    """
    Purpose: add a note to an incident (storage module).
    Inputs: exactly the FS.4 parameters of add_note.
    Output: exactly what FS.4 / Section E says add_note returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.incidents.
    Example: see the FS.4 entry for add_note.
    Errors: IncidentNotFound, ValueError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_add_note(db_path, incident_id, text, author)
    from storage.incidents import add_note as real_function
    return real_function(db_path, incident_id, text, author)

def add_alerts_to_incident(db_path: str, incident_id: int, alert_ids: list, changed_by: str = 'analyst') -> int:
    """
    Purpose: link more saved alerts to an incident (storage module).
    Inputs: exactly the FS.4 parameters of add_alerts_to_incident.
    Output: exactly what FS.4 / Section E says add_alerts_to_incident returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from storage.incidents.
    Example: see the FS.4 entry for add_alerts_to_incident.
    Errors: IncidentNotFound, DatabaseError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_add_alerts_to_incident(db_path, incident_id, alert_ids, changed_by)
    from storage.incidents import add_alerts_to_incident as real_function
    return real_function(db_path, incident_id, alert_ids, changed_by)

def build_incident_report_pdf(incident_details: dict, config: dict) -> bytes:
    """
    Purpose: build the incident PDF (reporting module).
    Inputs: exactly the FS.4 parameters of build_incident_report_pdf.
    Output: exactly what FS.4 / Section E says build_incident_report_pdf returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from reporting.pdf_report.
    Example: see the FS.4 entry for build_incident_report_pdf.
    Errors: ReportError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_build_incident_report_pdf(incident_details, config)
    from reporting.pdf_report import build_incident_report_pdf as real_function
    return real_function(incident_details, config)

def build_alert_summary_pdf(alerts: list, analysis_summary: dict, config: dict) -> bytes:
    """
    Purpose: build the session summary PDF (reporting module).
    Inputs: exactly the FS.4 parameters of build_alert_summary_pdf.
    Output: exactly what FS.4 / Section E says build_alert_summary_pdf returns.
    Steps:
        1. In mock mode call the temporary mock.
        2. Otherwise import and call the real function from reporting.pdf_report.
    Example: see the FS.4 entry for build_alert_summary_pdf.
    Errors: ReportError (passed through from the backend).
    """
    if USE_MOCK_BACKEND:
        return mock_backend.mock_build_alert_summary_pdf(alerts, analysis_summary, config)
    from reporting.pdf_report import build_alert_summary_pdf as real_function
    return real_function(alerts, analysis_summary, config)
