# dashboard/page_upload.py
# ---------------------------------------------------------------
# Purpose: the Log Upload page (G.3). It has two tabs:
#   "Upload and validate" - upload files, edit thresholds, run the pipeline, see file feedback.
#   "Analysis"            - the results of the last analysis (detection summary, correlated
#                           alerts, skipped-source notes). It is a tab, not a sixth page,
#                           because FS.4 defines exactly five render_*_page functions.
# render_upload_page: FS.4 public function.
# run_upload_pipeline: calls ingest_file, combine_ingestion_results, run_analysis in order.
# Backend calls go through dashboard/backend_calls.py. Session keys written: events,
# rejected_rows, ingestion_summaries, analysis, selected_alert_ids, config.
# Uses: streamlit, pandas, config.settings, core.errors, dashboard.components.

from pathlib import Path

import pandas as pd
import streamlit as st

from config.settings import get_default_config, validate_config
from core.contracts import RULE_IDS, severity_rank
from core.errors import ConfigError, IngestionError, NetworkSentinelError
from dashboard import backend_calls
from dashboard.components import (
    format_timestamp,
    render_empty_state,
    render_metric_card,
    render_page_header,
    render_reminder,
    show_alert_table,
)

SAMPLE_FOLDER = Path(__file__).resolve().parent.parent / "data" / "sample"
REJECTED_ROWS_SHOWN = 100

# (config key, label) for the whole-number settings shown in the threshold editor.
_WHOLE_NUMBER_FIELDS = [
    ("auth_failed_threshold", "Failed logins needed"),
    ("auth_window_seconds", "Failed login window (seconds)"),
    ("auth_success_after_failure_seconds", "Success-after-failure window (seconds)"),
    ("portscan_distinct_ports_threshold", "Distinct ports needed"),
    ("portscan_window_seconds", "Port scan window (seconds)"),
    ("reject_threshold", "Rejected connections needed"),
    ("reject_window_seconds", "Rejection window (seconds)"),
    ("volume_window_seconds", "Traffic bucket size (seconds)"),
    ("volume_min_bytes", "Minimum bucket size to flag (bytes; 10 MB = 10,000,000)"),
    ("volume_min_windows", "Active buckets a source needs"),
    ("correlation_window_seconds", "Largest gap between linked alerts (seconds)"),
    ("max_upload_mb", "Largest accepted file (MB)"),
    ("max_rows_per_file", "Most data rows per file"),
]


# ---------------------------------------------------------------
# The pipeline (backend calls in the order of A.3)
# ---------------------------------------------------------------

def _failed_file_entry(file_name, log_type, message):
    """A dashboard-made summary entry for a file that could not be processed."""
    return {"file_name": file_name, "log_type": log_type, "error": message}


def _add_combine_warnings(summaries, combined):
    """Duplicates and overlap warnings from combine_ingestion_results are shown on the
    first file card, so they stay visible without a new session key."""
    extra_warnings = []
    if combined["duplicates_removed"] > 0:
        extra_warnings.append(str(combined["duplicates_removed"]) + " duplicate events were removed "
                              "(the same file was added more than once).")
    extra_warnings.extend(combined["overlap_warnings"])
    for summary in summaries:
        if "error" not in summary and len(extra_warnings) > 0:
            summary["warnings"] = list(summary["warnings"]) + extra_warnings
            return


def run_upload_pipeline(file_specs: list, config: dict) -> dict:
    """
    Purpose: ingest each file, merge the results and run the analysis (A.3 steps 1 to 3).
    Inputs: file_specs (list of (file_name, file_bytes, log_type) tuples); config (dict).
    Output: dict - events, rejected_rows, summaries, analysis (dict or None), errors (list of str).
        summaries has one dashboard-made dictionary per file: the D.6 summary plus file_name
        and log_type, or file_name, log_type and error for a file that failed.
    Steps:
        1. Call ingest_file for each file. An IngestionError is recorded and the other files go on.
        2. Call combine_ingestion_results on the files that worked.
        3. If there are events, call run_analysis.
    Example: one good and one corrupt file -> the good file is analysed and one error is returned.
    Errors: ConfigError (from run_analysis) is not caught here; the caller shows it.
    """
    results = []
    summaries = []
    errors = []
    for file_name, file_bytes, log_type in file_specs:
        try:
            result = backend_calls.ingest_file(file_bytes, file_name, log_type, config)
        except IngestionError as error:
            errors.append(str(error))
            summaries.append(_failed_file_entry(file_name, log_type, str(error)))
            continue
        results.append(result)
        summary = dict(result["summary"])
        summary["file_name"] = file_name
        summary["log_type"] = log_type
        summaries.append(summary)
    outcome = {"events": [], "rejected_rows": [], "summaries": summaries, "analysis": None, "errors": errors}
    if len(results) == 0:
        return outcome
    combined = backend_calls.combine_ingestion_results(results)
    _add_combine_warnings(summaries, combined)
    outcome["events"] = combined["events"]
    outcome["rejected_rows"] = combined["rejected_rows"]
    if len(combined["events"]) > 0:
        outcome["analysis"] = backend_calls.run_analysis(combined["events"], config)
    return outcome


def _store_outcome(outcome: dict) -> None:
    """Write the pipeline outcome into the FS.5 session keys."""
    st.session_state["events"] = outcome["events"]
    st.session_state["rejected_rows"] = outcome["rejected_rows"]
    st.session_state["ingestion_summaries"] = outcome["summaries"]
    st.session_state["analysis"] = outcome["analysis"]
    st.session_state["selected_alert_ids"] = []


def _run_and_store(file_specs: list) -> None:
    """
    Purpose: run the pipeline, store the outcome in session state and show a short status message.
    Inputs: file_specs (list of (file_name, bytes, log_type) tuples).
    Output: None.
    Steps:
        1. Call run_upload_pipeline with the current configuration.
        2. Store the outcome in the FS.5 session keys.
        3. Show warnings for failed files and a success message with the alert count.
    Example: both sample files -> 'Analysis finished: 5 alerts.'
    Errors: ConfigError and other project errors are shown as messages.
    """
    try:
        outcome = run_upload_pipeline(file_specs, st.session_state["config"])
    except ConfigError as error:
        st.error("The settings are invalid: " + str(error))
        return
    except NetworkSentinelError as error:
        st.error("The analysis could not be completed: " + str(error))
        return
    _store_outcome(outcome)
    if len(outcome["errors"]) > 0:
        st.warning(str(len(outcome["errors"])) + " file(s) could not be processed. See the file cards below.")
    if outcome["analysis"] is not None:
        st.success("Analysis finished: " + str(len(outcome["analysis"]["alerts"])) + " alerts. "
                   "Open the Analysis tab or the Alerts page.")


def _clear_session_data() -> None:
    """Button callback: forget uploaded events and results (the config and saved data stay)."""
    st.session_state["events"] = []
    st.session_state["rejected_rows"] = []
    st.session_state["ingestion_summaries"] = []
    st.session_state["analysis"] = None
    st.session_state["selected_alert_ids"] = []


# ---------------------------------------------------------------
# Threshold editor
# ---------------------------------------------------------------

def _reset_thresholds() -> None:
    """Button callback: put the default settings back, including the widget values."""
    defaults = get_default_config()
    st.session_state["config"] = defaults
    _copy_config_into_widgets(defaults)


def _copy_config_into_widgets(config: dict) -> None:
    """Set the value of every threshold widget from a configuration dictionary."""
    for key, label in _WHOLE_NUMBER_FIELDS:
        st.session_state["cfg_" + key] = config[key]
    st.session_state["cfg_volume_multiplier"] = float(config["volume_multiplier"])
    st.session_state["cfg_volume_min_coverage"] = float(config["volume_min_coverage"])
    st.session_state["cfg_assume_utc"] = config["assume_utc"]
    st.session_state["cfg_trusted_ips"] = "\n".join(config["trusted_ips"])


def _read_config_from_widgets() -> dict:
    """Build a configuration dictionary from the threshold widgets."""
    new_config = dict(st.session_state["config"])
    for key, label in _WHOLE_NUMBER_FIELDS:
        new_config[key] = st.session_state["cfg_" + key]
    new_config["volume_multiplier"] = st.session_state["cfg_volume_multiplier"]
    new_config["volume_min_coverage"] = st.session_state["cfg_volume_min_coverage"]
    new_config["assume_utc"] = st.session_state["cfg_assume_utc"]
    addresses = []
    for line in st.session_state["cfg_trusted_ips"].splitlines():
        if line.strip() != "":
            addresses.append(line.strip())
    new_config["trusted_ips"] = addresses
    return new_config


def _render_threshold_editor() -> None:
    """
    Purpose: draw the adjustable thresholds inside an expander (decision D4: teaching defaults, not standards).
    Inputs: none (reads and writes st.session_state).
    Output: None.
    Steps:
        1. Fill the widget values from the configuration the first time.
        2. Draw one number box per whole-number setting, the multiplier, the coverage, assume_utc and trusted addresses.
        3. Apply settings with validate_config, or reset to the defaults.
    Example: set reject threshold 30 and Apply -> session config reject_threshold is 30.
    Errors: ConfigError is shown as a message and the old settings stay.
    """
    with st.expander("Detection thresholds and settings"):
        st.caption("These are teaching defaults for a small organisation. They are adjustable and are not "
                   "universal security standards. Changes apply to the next analysis.")
        if "cfg_trusted_ips" not in st.session_state:
            _copy_config_into_widgets(st.session_state["config"])
        columns = st.columns(3)
        for index in range(len(_WHOLE_NUMBER_FIELDS)):
            key, label = _WHOLE_NUMBER_FIELDS[index]
            with columns[index % 3]:
                st.number_input(label, min_value=1, step=1, key="cfg_" + key)
        with columns[0]:
            st.number_input("Traffic multiplier (times the source's own median)", min_value=0.1, step=0.5, key="cfg_volume_multiplier")
        with columns[1]:
            st.number_input("Share of network events that need bytes_sent", min_value=0.01, max_value=1.0, step=0.05, key="cfg_volume_min_coverage")
        with columns[2]:
            st.checkbox("Treat timestamps without a timezone as UTC", key="cfg_assume_utc")
        st.text_area("Trusted addresses (one per line; ignored by detection)", key="cfg_trusted_ips")
        apply_column, reset_column = st.columns(2)
        with apply_column:
            apply_clicked = st.button("Apply settings", key="apply_thresholds_button")
        with reset_column:
            st.button("Reset to defaults", key="reset_thresholds_button", on_click=_reset_thresholds)
        if apply_clicked:
            try:
                st.session_state["config"] = validate_config(_read_config_from_widgets())
                st.success("Settings applied. Run the analysis again to use them.")
            except ConfigError as error:
                st.error("These settings are not valid: " + str(error))


# ---------------------------------------------------------------
# Upload tab
# ---------------------------------------------------------------

def _describe_upload(label: str, uploaded_file) -> str:
    """One status line for an upload slot."""
    if uploaded_file is None:
        return label + ": no file selected"
    return label + ": " + uploaded_file.name + " (" + str(round(uploaded_file.size / 1024, 1)) + " KB) ready"


def _read_sample_specs() -> list:
    """The two sample files from data/sample as (file_name, bytes, log_type) tuples."""
    return [
        ("auth_sample.csv", (SAMPLE_FOLDER / "auth_sample.csv").read_bytes(), "authentication"),
        ("network_sample.csv", (SAMPLE_FOLDER / "network_sample.csv").read_bytes(), "network_connection"),
    ]


def _render_file_summaries(summaries: list) -> None:
    """
    Purpose: draw one card row per processed file: counts, time range and warnings, or its error.
    Inputs: summaries (list of dicts from the pipeline).
    Output: None.
    Steps:
        1. For each file show its name and log type.
        2. A failed file shows its error and nothing else.
        3. Otherwise show rows read, accepted, rejected, earliest and latest, then every warning.
    Example: a good and a corrupt file -> one card row and one red error.
    Errors: none.
    """
    for summary in summaries:
        st.markdown("**" + summary["file_name"] + "** (" + summary["log_type"] + ")")
        if "error" in summary:
            st.error(summary["error"])
            continue
        columns = st.columns(5)
        with columns[0]:
            render_metric_card("Rows read", summary["rows_read"])
        with columns[1]:
            render_metric_card("Accepted", summary["events_accepted"])
        with columns[2]:
            render_metric_card("Rejected", summary["rows_rejected"])
        with columns[3]:
            render_metric_card("Earliest (UTC)", format_timestamp(summary["earliest_timestamp"]))
        with columns[4]:
            render_metric_card("Latest (UTC)", format_timestamp(summary["latest_timestamp"]))
        for warning in summary["warnings"]:
            st.warning(warning)


def _render_rejected_rows(rejected_rows: list) -> None:
    """The first 100 rejected rows with their reasons."""
    if len(rejected_rows) == 0:
        return
    st.markdown("**Rejected rows** (first " + str(REJECTED_ROWS_SHOWN) + " of " + str(len(rejected_rows)) + ")")
    rows = []
    for rejected in rejected_rows[:REJECTED_ROWS_SHOWN]:
        rows.append({"File": rejected["source_file"], "Row": rejected["source_row"],
                     "Reason": rejected["reason"], "Original row": str(rejected["raw_row"])})
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


def _collect_upload_specs(auth_upload, network_upload) -> list:
    """The uploaded files as (file_name, bytes, log_type) tuples. A slot with no file is skipped."""
    file_specs = []
    if auth_upload is not None:
        file_specs.append((auth_upload.name, auth_upload.getvalue(), "authentication"))
    if network_upload is not None:
        file_specs.append((network_upload.name, network_upload.getvalue(), "network_connection"))
    return file_specs


def _render_action_buttons(auth_upload, network_upload) -> None:
    """
    Purpose: draw the three buttons of the Upload tab and react to them.
    Inputs: auth_upload, network_upload (uploaded file objects or None).
    Output: None.
    Steps:
        1. Draw Validate and analyse (disabled until a file is chosen), Use the sample files and Clear session data.
        2. Analyse the uploaded files, or the two sample files from data/sample, when asked.
    Example: click Use the sample files -> both sample files are processed.
    Errors: FileNotFoundError for missing sample files is shown as a message.
    """
    analyse_column, sample_column, clear_column = st.columns(3)
    with analyse_column:
        analyse_clicked = st.button("Validate and analyse", key="analyse_button", type="primary",
                                    disabled=(auth_upload is None and network_upload is None))
    with sample_column:
        sample_clicked = st.button("Use the sample files", key="use_sample_button")
    with clear_column:
        st.button("Clear session data", key="clear_button", on_click=_clear_session_data)
    if analyse_clicked:
        _run_and_store(_collect_upload_specs(auth_upload, network_upload))
    if sample_clicked:
        try:
            _run_and_store(_read_sample_specs())
        except FileNotFoundError:
            st.error("The sample files were not found in data/sample/.")


def _render_upload_tab() -> None:
    """
    Purpose: draw the Upload and validate tab: uploaders, status lines, settings, buttons and file feedback.
    Inputs: none (reads and writes st.session_state).
    Output: None.
    Steps:
        1. Show the timezone notice and the two uploaders with their status lines.
        2. Show the settings expander.
        3. Handle the three buttons: Validate and analyse, Use the sample files, Clear session data.
        4. Show the file cards and rejected rows.
    Example: click 'Use the sample files' -> both files are processed.
    Errors: FileNotFoundError for missing sample files is shown as a message.
    """
    st.info("Timestamps without a timezone are treated as UTC. Export your logs in UTC or include an offset "
            "such as +05:00, otherwise times can appear shifted and correlation can mislead.")
    auth_column, network_column = st.columns(2)
    with auth_column:
        auth_upload = st.file_uploader("Authentication log (.csv)", key="auth_upload")
    with network_column:
        network_upload = st.file_uploader("Network connection log (.csv)", key="network_upload")
    st.caption(_describe_upload("Authentication log", auth_upload))
    st.caption(_describe_upload("Network connection log", network_upload))
    st.caption("Sample files are in data/sample/ (auth_sample.csv and network_sample.csv).")
    _render_threshold_editor()
    _render_action_buttons(auth_upload, network_upload)
    summaries = st.session_state["ingestion_summaries"]
    if len(summaries) > 0:
        st.subheader("Upload status")
        _render_file_summaries(summaries)
        _render_rejected_rows(st.session_state["rejected_rows"])


# ---------------------------------------------------------------
# Analysis tab
# ---------------------------------------------------------------

def _detection_summary_rows(alerts: list) -> list:
    """
    Purpose: one table row per rule: number of alerts, highest severity and source addresses.
    Inputs: alerts (list).
    Output: list of row dictionaries, one for every rule in RULE_IDS (also rules with 0 alerts).
    Steps:
        1. For each rule walk through the alerts.
        2. Count the matching alerts, track the highest severity and collect the sources.
    Example: sample alerts -> NET_PORT_SCAN: 1 alert, MEDIUM, 203.0.113.50.
    Errors: none.
    """
    rows = []
    for rule_id in RULE_IDS:
        count = 0
        highest = ""
        sources = []
        for alert in alerts:
            if alert["rule_id"] != rule_id:
                continue
            count += 1
            if highest == "" or severity_rank(alert["severity"]) > severity_rank(highest):
                highest = alert["severity"]
            if alert["source_ip"] is not None and alert["source_ip"] not in sources:
                sources.append(alert["source_ip"])
        rows.append({"Rule": rule_id, "Alerts": count, "Highest severity": highest.upper(), "Sources": ", ".join(sources)})
    return rows


def _correlated_rows(alerts: list) -> list:
    """One row per correlated alert with its link details."""
    rows = []
    for alert in alerts:
        if alert["rule_id"] != "CORR_AUTH_NET":
            continue
        link = alert["evidence"]["correlation"]
        rows.append({
            "Severity": alert["severity"].upper(), "Confidence": alert["confidence"], "Source": link["link_value"],
            "Gap (s)": link["gap_seconds"], "Destination match": "yes" if link["destination_match"] else "no",
            "Linked alerts": ", ".join(link["linked_alert_ids"]), "Alert ID": alert["alert_id"],
        })
    return rows


def _render_analysis_metrics(analysis: dict) -> None:
    """The five metric cards at the top of the Analysis tab."""
    columns = st.columns(5)
    with columns[0]:
        render_metric_card("Events analysed", analysis["events_analysed"])
    with columns[1]:
        render_metric_card("Ignored (trusted)", analysis["events_ignored_trusted"])
    with columns[2]:
        render_metric_card("Base alerts", analysis["base_alert_count"])
    with columns[3]:
        render_metric_card("Correlated alerts", analysis["correlated_alert_count"])
    with columns[4]:
        render_metric_card("Analysed at (UTC)", format_timestamp(analysis["analysed_at"]))


def _render_analysis_tab() -> None:
    """
    Purpose: draw the Analysis tab: metrics, detection summary, correlated alerts, skipped-source notes and the alert table.
    Inputs: none (reads st.session_state['analysis']).
    Output: None.
    Steps:
        1. Show an instruction if no analysis exists.
        2. Show the metric cards and the detection summary.
        3. Show correlated alerts, then every analysis note (warnings for skipped sources).
        4. Show the table of all alerts.
    Example: after the sample files -> 1 correlated alert and a 'source addresses skipped' warning.
    Errors: none.
    """
    analysis = st.session_state["analysis"]
    if analysis is None:
        render_empty_state("No analysis has been run in this session. Use the Upload and validate tab first.")
        return
    _render_analysis_metrics(analysis)
    st.subheader("Detection summary")
    st.dataframe(pd.DataFrame(_detection_summary_rows(analysis["alerts"])), width="stretch", hide_index=True)
    st.subheader("Correlated alerts")
    correlated = _correlated_rows(analysis["alerts"])
    if len(correlated) == 0:
        st.caption("No correlated alerts. An authentication alert and a network alert need the same source address and close times.")
    else:
        st.dataframe(pd.DataFrame(correlated), width="stretch", hide_index=True)
    st.subheader("Skipped sources and rule notes")
    if len(analysis["notes"]) == 0:
        st.caption("No rules or sources were skipped.")
    for note in analysis["notes"]:
        if "skipped" in note.lower():
            st.warning(note)
        else:
            st.info(note)
    st.subheader("All alerts from this analysis")
    if len(analysis["alerts"]) > 0:
        show_alert_table(analysis["alerts"])
    render_reminder()


def render_upload_page(config: dict, db_path: str) -> None:
    """
    Purpose: draw the Log Upload page with its Upload and Analysis tabs.
    Inputs: config (dict, the current configuration); db_path (str, unused here).
    Output: None.
    Steps:
        1. Header (with the mock banner when the backend is the mock).
        2. Tab 1: upload files, edit settings, run the pipeline, show file feedback.
        3. Tab 2: show the analysis results.
    Example: called by app.py as render_upload_page(config, "data/network_sentinel.db").
    Errors: IngestionError and other backend errors are shown as messages, not raised.
    """
    render_page_header("Log Upload", "Load authentication and network logs, then run the analysis.")
    upload_tab, analysis_tab = st.tabs(["Upload and validate", "Analysis"])
    with upload_tab:
        _render_upload_tab()
    with analysis_tab:
        _render_analysis_tab()
