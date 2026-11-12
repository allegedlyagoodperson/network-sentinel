# tests/test_dashboard.py
# ---------------------------------------------------------------
# Purpose: Stage 3 tests (FS.6) for the dashboard, which runs on MOCK data for now.
# - every page renders empty and filled (Streamlit AppTest);
# - the alerts_view switch, the unsaved banner, save, incident and status flows work;
# - the theme matches Section G.1;
# - the dashboard contains no SQL and no detection logic (import boundaries);
# - backend_calls.py has the exact FS.4 signatures and, in real mode, calls the real modules
#   with the FS.4 argument order (checked with stand-in modules);
# - the mock backend returns data in the Section C / D shapes.
# Run from the project folder: python -m pytest tests/test_dashboard.py -v
# Uses: pytest, streamlit.testing, core, dashboard.

import inspect
import json
import sys
import types
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from core.contracts import (
    CONTRACT_VERSION,
    SEVERITIES,
    validate_alert,
    validate_event,
)
from core.errors import IngestionError
from config.settings import get_default_config
from dashboard import backend_calls, mock_backend, theme
from dashboard.components import (
    count_by_severity,
    confidence_text_html,
    filter_alerts,
    group_alerts_by_hour,
    severity_badge_html,
    sort_alerts_for_display,
    top_sources,
)
from dashboard.page_upload import run_upload_pipeline

PROJECT_FOLDER = Path(__file__).resolve().parent.parent
APP_PATH = str(PROJECT_FOLDER / "app.py")
PAGE_NAMES = ["Overview", "Log Upload", "Alerts", "Incidents", "Reports"]
FS5_SESSION_KEYS = ["config", "events", "rejected_rows", "ingestion_summaries", "analysis",
                    "selected_alert_ids", "selected_incident_id", "alerts_view"]


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

def new_app():
    """A fresh AppTest of app.py, already run once (Overview page, empty session)."""
    app = AppTest.from_file(APP_PATH, default_timeout=60)
    app.run()
    return app


def go_to(app, page_name):
    """Choose a page in the sidebar and run."""
    app.sidebar.radio(key="navigation").set_value(page_name).run()


def app_with_sample_data():
    """An app whose session already holds the sample analysis (mock data)."""
    app = new_app()
    go_to(app, "Log Upload")
    app.button(key="use_sample_button").click().run()
    return app


def exception_texts(app):
    """The text of every exception shown by the app (empty list = no error)."""
    texts = []
    for exception in app.exception:
        texts.append(str(exception.value))
    return texts


def markdown_text(app):
    """All markdown text on the page joined together (banners, cards)."""
    pieces = []
    for element in app.markdown:
        pieces.append(element.value)
    return "\n".join(pieces)


def find_option(options, text):
    """The first option that contains the given text."""
    for option in options:
        if text in option:
            return option
    pytest.fail("no option contains " + repr(text))


def select_alerts_by_rule(app, rule_ids):
    """On the Alerts page, select the alerts of the given rules in the multiselect."""
    selection = app.multiselect[0]
    chosen = []
    for rule_id in rule_ids:
        chosen.append(find_option(selection.options, rule_id + " |"))
    selection.set_value(chosen).run()


def find_button_by_label(app, label):
    """The button with this label (form buttons have no key we can use)."""
    for button in app.button:
        if button.label == label:
            return button
    pytest.fail("no button labelled " + repr(label))


def mock_database(app):
    return app.session_state["mock_database"]


def sample_analysis_in_a_bare_run():
    """Mock events and the mock analysis, without the Streamlit page (for plain function tests)."""
    config = get_default_config()
    auth = mock_backend.mock_ingest_file(b"x", "auth_sample.csv", "authentication", config)
    network = mock_backend.mock_ingest_file(b"x", "network_sample.csv", "network_connection", config)
    combined = mock_backend.mock_combine_ingestion_results([auth, network])
    return combined, mock_backend.mock_run_analysis(combined["events"], config)


# ---------------------------------------------------------------
# Pages render (FS.6 Stage 3 acceptance)
# ---------------------------------------------------------------

def test_app_starts_on_overview_with_fs5_session_keys():
    app = new_app()
    assert exception_texts(app) == []
    assert app.title[0].value == "Overview"
    for key in FS5_SESSION_KEYS:
        assert key in app.session_state, key
    assert app.session_state["alerts_view"] == "current"
    assert app.session_state["analysis"] is None


def test_all_five_pages_render_when_empty():
    app = new_app()
    expected_titles = {"Overview": "Overview", "Log Upload": "Log Upload", "Alerts": "Alerts",
                       "Incidents": "Incidents", "Reports": "Reports"}
    for page_name in PAGE_NAMES:
        go_to(app, page_name)
        assert exception_texts(app) == [], page_name
        assert app.title[0].value == expected_titles[page_name]


def test_all_five_pages_render_with_data():
    app = app_with_sample_data()
    for page_name in PAGE_NAMES:
        go_to(app, page_name)
        assert exception_texts(app) == [], page_name


def test_mock_mode_is_visible_everywhere():
    app = new_app()
    for page_name in PAGE_NAMES:
        go_to(app, page_name)
        assert "DEMO MODE - MOCK DATA" in markdown_text(app), page_name
    assert "MOCK" in app.sidebar.warning[0].value


def test_empty_states_tell_the_user_what_to_do():
    app = new_app()
    assert "Log Upload" in app.info[0].value
    go_to(app, "Alerts")
    assert "no alerts" in app.info[0].value.lower()
    go_to(app, "Incidents")
    assert "Create one from the Alerts page" in app.info[0].value


def test_session_summary_report_is_disabled_until_an_analysis_exists():
    app = new_app()
    go_to(app, "Reports")
    buttons = app.get("download_button")
    assert len(buttons) == 1
    assert buttons[0].proto.disabled is True
    assert "needs an analysis" in app.caption[0].value


# ---------------------------------------------------------------
# Upload and analysis
# ---------------------------------------------------------------

def test_sample_files_produce_the_expected_alerts_of_the_fixture():
    app = app_with_sample_data()
    analysis = app.session_state["analysis"]
    expected = json.loads((PROJECT_FOLDER / "tests" / "fixtures" / "expected_results.json").read_text(encoding="utf-8"))
    expected_keys = []
    for item in expected["expected_alerts"]:
        expected_keys.append((item["rule_id"], item["source_ip"], item["severity"], item["confidence"], item["supporting_event_count"]))
    produced_keys = []
    for alert in analysis["alerts"]:
        produced_keys.append((alert["rule_id"], alert["source_ip"], alert["severity"], alert["confidence"], len(alert["event_ids"])))
    assert sorted(produced_keys) == sorted(expected_keys)
    assert analysis["base_alert_count"] == 4
    assert analysis["correlated_alert_count"] == 1


def test_upload_page_shows_file_cards_and_analysis_tab():
    app = app_with_sample_data()
    assert exception_texts(app) == []
    assert len(app.session_state["ingestion_summaries"]) == 2
    assert app.session_state["ingestion_summaries"][0]["file_name"] == "auth_sample.csv"
    assert len(app.session_state["events"]) == 72
    labels = []
    for subheader in app.subheader:
        labels.append(subheader.value)
    for wanted in ["Upload status", "Detection summary", "Correlated alerts", "Skipped sources and rule notes"]:
        assert wanted in labels, wanted


def test_analysis_notes_include_the_skipped_sources_note():
    app = app_with_sample_data()
    warning_texts = []
    for warning in app.warning:
        warning_texts.append(warning.value)
    assert find_option(warning_texts, "source addresses skipped") != ""


def test_clear_session_data_resets_results_but_not_config():
    app = app_with_sample_data()
    app.button(key="clear_button").click().run()
    assert app.session_state["analysis"] is None
    assert app.session_state["events"] == []
    assert app.session_state["ingestion_summaries"] == []
    assert app.session_state["config"]["auth_failed_threshold"] == 5


def test_applying_valid_and_invalid_settings():
    app = new_app()
    go_to(app, "Log Upload")
    app.number_input(key="cfg_reject_threshold").set_value(30).run()
    app.button(key="apply_thresholds_button").click().run()
    assert app.session_state["config"]["reject_threshold"] == 30
    app.number_input(key="cfg_volume_multiplier").set_value(4.0).run()
    app.text_area(key="cfg_trusted_ips").set_value("not-an-ip").run()
    app.button(key="apply_thresholds_button").click().run()
    assert "not valid" in app.error[0].value
    assert app.session_state["config"]["reject_threshold"] == 30  # the bad settings were not applied
    app.button(key="reset_thresholds_button").click().run()
    assert app.session_state["config"]["reject_threshold"] == 20


def test_trusted_address_is_ignored_by_the_analysis():
    app = new_app()
    go_to(app, "Log Upload")
    app.text_area(key="cfg_trusted_ips").set_value("203.0.113.50").run()
    app.button(key="apply_thresholds_button").click().run()
    app.button(key="use_sample_button").click().run()
    analysis = app.session_state["analysis"]
    assert analysis["events_ignored_trusted"] > 0
    sources = []
    for alert in analysis["alerts"]:
        sources.append(alert["source_ip"])
    assert "203.0.113.50" not in sources
    assert analysis["correlated_alert_count"] == 0


def test_corrupt_file_does_not_stop_the_good_file():
    config = get_default_config()
    specs = [("notes.txt", b"hello", "authentication"),
             ("network_sample.csv", b"timestamp\n", "network_connection")]
    outcome = run_upload_pipeline(specs, config)
    assert len(outcome["errors"]) == 1
    assert "extension" in outcome["errors"][0]
    assert len(outcome["events"]) == 52
    assert "error" in outcome["summaries"][0]
    assert "error" not in outcome["summaries"][1]
    assert outcome["analysis"] is not None


def test_only_bad_files_gives_no_analysis_and_clear_errors():
    outcome = run_upload_pipeline([("empty.csv", b"", "authentication")], get_default_config())
    assert outcome["analysis"] is None
    assert outcome["events"] == []
    assert "empty" in outcome["errors"][0]


def test_same_file_twice_reports_duplicates():
    specs = [("auth_sample.csv", b"x", "authentication"), ("auth_sample.csv", b"x", "authentication")]
    outcome = run_upload_pipeline(specs, get_default_config())
    assert len(outcome["events"]) == 20
    joined_warnings = " ".join(outcome["summaries"][0]["warnings"])
    assert "20 duplicate events were removed" in joined_warnings


def test_upload_pipeline_returns_dictionaries_in_the_d6_summary_shape():
    outcome = run_upload_pipeline([("auth_sample.csv", b"x", "authentication")], get_default_config())
    summary = outcome["summaries"][0]
    for key in ["rows_read", "rows_blank", "events_accepted", "rows_rejected",
                "earliest_timestamp", "latest_timestamp", "warnings", "file_name", "log_type"]:
        assert key in summary, key


# ---------------------------------------------------------------
# Alerts page: banner, views, save, incident
# ---------------------------------------------------------------

def test_unsaved_banner_and_saved_column():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    assert "5 alerts in this analysis are not saved" in markdown_text(app)
    assert "lost when the application restarts" in markdown_text(app)


def test_alerts_view_switch_between_current_and_saved():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    app.radio(key="alerts_view").set_value("saved").run()
    assert app.session_state["alerts_view"] == "saved"
    assert "No alerts have been saved yet" in app.info[0].value
    assert "are not saved" not in markdown_text(app)
    app.radio(key="alerts_view").set_value("current").run()
    assert "5 alerts in this analysis are not saved" in markdown_text(app)


def test_alert_filters_narrow_the_table():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    app.selectbox(key="filter_severity").set_value("critical").run()
    assert exception_texts(app) == []
    assert len(app.dataframe[0].value) == 1
    app.selectbox(key="filter_severity").set_value("All").run()
    app.text_input(key="filter_source").set_value("10.0.0.40").run()
    assert len(app.dataframe[0].value) == 1


def test_alert_details_show_evidence_sections():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    app.selectbox(key="inspect_alert_choice").set_value(
        find_option(app.selectbox(key="inspect_alert_choice").options, "AUTH_BRUTE_FORCE")).run()
    assert exception_texts(app) == []
    bold_text = []
    for element in app.markdown:
        bold_text.append(element.value)
    joined = "\n".join(bold_text)
    for wanted in ["Why this alert was raised", "Possible harmless explanations", "Thresholds used",
                   "Observed values", "Authentication successes linked to this alert", "Recommended action"]:
        assert wanted in joined, wanted


def test_saving_only_a_correlated_alert_also_saves_its_base_alerts():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    select_alerts_by_rule(app, ["CORR_AUTH_NET"])
    app.button(key="save_alerts_button").click().run()
    assert exception_texts(app) == []
    assert len(mock_database(app)["alerts"]) == 3
    assert len(mock_database(app)["alert_links"]) == 1
    info_texts = []
    for info in app.info:
        info_texts.append(info.value)
    assert find_option(info_texts, "2 base alerts were also saved") != ""
    assert "2 alerts in this analysis are not saved" in markdown_text(app)


def test_saving_twice_reports_duplicates_and_adds_nothing():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    select_alerts_by_rule(app, ["NET_HIGH_VOLUME"])
    app.button(key="save_alerts_button").click().run()
    app.button(key="save_alerts_button").click().run()
    assert len(mock_database(app)["alerts"]) == 1
    assert "already saved: 1" in app.success[-1].value


def test_create_incident_from_a_correlated_alert():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    select_alerts_by_rule(app, ["CORR_AUTH_NET"])
    app.text_input(key="incident_title_input").set_value("Login burst and scan from 203.0.113.50").run()
    app.button(key="create_incident_button").click().run()
    assert exception_texts(app) == []
    store = mock_database(app)
    assert len(store["incidents"]) == 1
    incident = store["incidents"][1]
    assert len(incident["alert_ids"]) == 3
    assert incident["priority"] == "critical"
    assert incident["status"] == "open"
    assert store["history"][0]["action"] == "created"
    assert store["history"][0]["new_value"] == "3 alerts"
    assert "INC-0001" in app.success[-1].value
    assert app.session_state["selected_incident_id"] == 1


def test_create_incident_needs_a_title_and_saves_nothing_without_one():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    select_alerts_by_rule(app, ["NET_PORT_SCAN"])
    app.button(key="create_incident_button").click().run()
    assert "title" in app.error[0].value
    assert len(mock_database(app)["alerts"]) == 0
    assert len(mock_database(app)["incidents"]) == 0


def test_save_buttons_are_disabled_with_nothing_selected():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    assert app.button(key="save_alerts_button").disabled is True
    assert app.button(key="create_incident_button").disabled is True


def app_with_one_incident():
    """An app with the correlated alert saved and one incident created from it."""
    app = app_with_sample_data()
    go_to(app, "Alerts")
    select_alerts_by_rule(app, ["CORR_AUTH_NET"])
    app.text_input(key="incident_title_input").set_value("Test incident").run()
    app.button(key="create_incident_button").click().run()
    return app


# ---------------------------------------------------------------
# Incidents page and reports
# ---------------------------------------------------------------

def test_incident_page_lists_details_and_labels_base_alerts():
    app = app_with_one_incident()
    go_to(app, "Incidents")
    assert exception_texts(app) == []
    assert len(app.dataframe) >= 2
    incident_table = app.dataframe[0].value
    assert incident_table["Incident"][0] == "INC-0001"
    alert_table = app.dataframe[1].value
    roles = sorted(alert_table["Role"])
    assert roles == ["Alert", "Linked base alert", "Linked base alert"]


def test_status_selector_offers_only_the_allowed_transitions():
    app = app_with_one_incident()
    go_to(app, "Incidents")
    assert app.selectbox(key="new_status_choice").options == ["investigating", "resolved", "false_positive"]
    app.selectbox(key="new_status_choice").set_value("resolved").run()
    app.button(key="change_status_button").click().run()
    store = mock_database(app)
    assert store["incidents"][1]["status"] == "resolved"
    assert store["incidents"][1]["closed_at"] is not None
    assert app.selectbox(key="new_status_choice").options == ["investigating"]
    app.selectbox(key="new_status_choice").set_value("investigating").run()
    app.button(key="change_status_button").click().run()
    assert store["incidents"][1]["status"] == "investigating"
    assert store["incidents"][1]["closed_at"] is None


def test_adding_a_note_updates_notes_and_history():
    app = app_with_one_incident()
    go_to(app, "Incidents")
    app.text_area(key="new_note_text").set_value("Checked the firewall logs.")  # no run here: form values count on submit
    find_button_by_label(app, "Add note").click().run()
    store = mock_database(app)
    assert len(store["notes"]) == 1
    assert store["notes"][0]["text"] == "Checked the firewall logs."
    actions = []
    for row in store["history"]:
        actions.append(row["action"])
    assert actions == ["created", "note_added"]


def test_incident_report_download_is_offered():
    app = app_with_one_incident()
    go_to(app, "Reports")
    assert exception_texts(app) == []
    assert len(app.get("download_button")) == 2
    assert app.get("download_button")[0].proto.disabled is False


def test_reports_page_with_analysis_enables_the_summary_download():
    app = app_with_sample_data()
    go_to(app, "Reports")
    assert len(app.get("download_button")) == 1
    assert app.get("download_button")[0].proto.disabled is False


def test_overview_keeps_session_and_saved_numbers_separate():
    app = app_with_one_incident()
    go_to(app, "Overview")
    page_text = markdown_text(app)
    headings = []
    for subheader in app.subheader:
        headings.append(subheader.value)
    assert "This session" in headings
    assert "Saved in database" in headings
    assert ">5<" in page_text  # alerts found in the session
    assert ">3<" in page_text  # saved alerts (a correlated alert and its two base alerts)


# ---------------------------------------------------------------
# Plain helper functions
# ---------------------------------------------------------------

def test_severity_badges_use_the_right_classes():
    for severity in SEVERITIES:
        assert "ns-badge-" + severity in severity_badge_html(severity)
    assert "ns-badge-unknown" in severity_badge_html("banana")


def test_badge_and_confidence_text_escape_html():
    assert "<script>" not in severity_badge_html("<script>alert(1)</script>")
    assert "&lt;script&gt;" in severity_badge_html("<script>")
    assert "<b>" not in confidence_text_html("<b>x</b>")


def test_confidence_text_never_uses_a_severity_colour_class():
    text = confidence_text_html("high")
    assert "ns-confidence" in text
    for severity in SEVERITIES:
        assert "ns-badge-" + severity not in text


def test_sorting_filtering_and_counting_alerts():
    _, analysis = sample_analysis_in_a_bare_run()
    alerts = analysis["alerts"]
    ordered = sort_alerts_for_display(alerts)
    assert ordered[0]["severity"] == "critical"
    assert ordered[-1]["severity"] == "low"
    assert len(filter_alerts(alerts, severity="medium")) == 2
    assert len(filter_alerts(alerts, rule_id="NET_PORT_SCAN")) == 1
    assert len(filter_alerts(alerts, source_text="203.0.113")) == 3
    assert len(filter_alerts(alerts, confidence="low", severity="medium")) == 1
    assert len(filter_alerts(alerts)) == 5
    counts = count_by_severity(alerts)
    assert counts == {"low": 1, "medium": 2, "high": 1, "critical": 1}


def test_top_sources_and_hourly_grouping():
    _, analysis = sample_analysis_in_a_bare_run()
    assert top_sources(analysis["alerts"], 5)[0] == ("203.0.113.50", 3)
    assert len(top_sources(analysis["alerts"], 2)) == 2
    hourly = group_alerts_by_hour(analysis["alerts"])
    assert hourly["Alerts"].sum() == 5
    assert list(hourly.index)[0] == "2025-03-14 09:00"


# ---------------------------------------------------------------
# Theme (Section G.1)
# ---------------------------------------------------------------

def test_theme_colours_match_section_g1():
    assert theme.COLOR_BACKGROUND == "#0B0D10"
    assert theme.COLOR_PANEL == "#14181D"
    assert theme.COLOR_BORDER == "#232A32"
    assert theme.COLOR_TEXT == "#E6E8EB"
    assert theme.COLOR_TEXT_MUTED == "#8A94A0"
    assert theme.COLOR_RED == "#E5484D"
    assert theme.COLOR_AMBER == "#F5A524"
    assert theme.COLOR_GREEN == "#30A46C"
    assert theme.COLOR_STEEL == "#6B7A8F"
    assert theme.SEVERITY_COLORS == {"critical": "#E5484D", "high": "#E5484D", "medium": "#F5A524", "low": "#30A46C"}


def test_config_toml_uses_the_dark_theme_colours():
    text = (PROJECT_FOLDER / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    for wanted in ['base = "dark"', 'backgroundColor = "#0B0D10"', 'secondaryBackgroundColor = "#14181D"',
                   'textColor = "#E6E8EB"', 'primaryColor = "#6B7A8F"']:
        assert wanted in text, wanted


def test_css_has_every_colour_filled_in_and_the_badge_styles():
    css = theme.build_css()
    assert "@" not in css
    assert "#E5484D" in css and "#F5A524" in css and "#30A46C" in css
    for name in ["ns-card", "ns-badge-critical", "ns-badge-high", "ns-badge-medium", "ns-badge-low", "ns-confidence"]:
        assert name in css, name
    assert "background: #E5484D" in css.split(".ns-badge-critical")[1].split("}")[0]  # critical is filled
    assert "background: transparent" in css.split(".ns-badge-high")[1].split("}")[0]  # high is an outline


# ---------------------------------------------------------------
# Boundaries: no SQL, no detection logic, mock isolated
# ---------------------------------------------------------------

def dashboard_files():
    return sorted((PROJECT_FOLDER / "dashboard").glob("*.py")) + [PROJECT_FOLDER / "app.py"]


def test_dashboard_contains_no_sql():
    for path in dashboard_files():
        text = path.read_text(encoding="utf-8")
        assert "sqlite3" not in text, path.name
        for sql_word in ["SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM", "CREATE TABLE"]:
            assert sql_word not in text, path.name + " contains " + sql_word


def test_only_backend_calls_imports_backend_modules_and_only_inside_functions():
    backend_packages = ["ingestion", "detection", "correlation", "storage", "reporting"]
    for path in dashboard_files():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            for package in backend_packages:
                is_import = stripped.startswith("from " + package + ".") or stripped.startswith("import " + package)
                if not is_import:
                    continue
                assert path.name == "backend_calls.py", path.name + ": " + stripped
                assert line.startswith("    "), "must be inside a function: " + stripped


def test_only_backend_calls_knows_about_the_mock():
    for path in dashboard_files():
        if path.name in ["backend_calls.py", "mock_backend.py"]:
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            assert "import mock_backend" not in line and "dashboard.mock_backend" not in line, path.name


def test_no_detection_logic_in_pages():
    forbidden = ["find_bursts", "detect_failed_logins", "detect_port_scans", "correlate_alerts", "make_event(", "make_alert("]
    for path in dashboard_files():
        if path.name == "mock_backend.py":
            continue
        text = path.read_text(encoding="utf-8")
        for word in forbidden:
            assert word not in text, path.name + " contains " + word


def test_contract_version_is_still_one_point_zero():
    assert CONTRACT_VERSION == 1.0


# ---------------------------------------------------------------
# backend_calls.py: FS.4 signatures and real mode
# ---------------------------------------------------------------

FS4_PARAMETERS = {
    "ingest_file": ["file_bytes", "file_name", "log_type", "config"],
    "combine_ingestion_results": ["results"],
    "run_analysis": ["events", "config"],
    "initialise_database": ["db_path"],
    "save_alerts": ["db_path", "alerts", "events", "available_alerts"],
    "get_alerts": ["db_path", "filters"],
    "get_events_for_alert": ["db_path", "alert_id"],
    "get_existing_alert_ids": ["db_path", "alert_ids"],
    "get_summary_counts": ["db_path"],
    "create_incident": ["db_path", "title", "alert_ids", "summary", "priority", "created_by"],
    "list_incidents": ["db_path", "status"],
    "get_incident_details": ["db_path", "incident_id"],
    "update_incident_status": ["db_path", "incident_id", "new_status", "changed_by"],
    "add_note": ["db_path", "incident_id", "text", "author"],
    "add_alerts_to_incident": ["db_path", "incident_id", "alert_ids", "changed_by"],
    "build_incident_report_pdf": ["incident_details", "config"],
    "build_alert_summary_pdf": ["alerts", "analysis_summary", "config"],
}
FS4_DEFAULTS = {
    "save_alerts": {"available_alerts": None}, "get_alerts": {"filters": None},
    "create_incident": {"summary": "", "priority": None, "created_by": "analyst"},
    "list_incidents": {"status": None}, "update_incident_status": {"changed_by": "analyst"},
    "add_note": {"author": "analyst"}, "add_alerts_to_incident": {"changed_by": "analyst"},
}
REAL_MODULES = {
    "ingest_file": "ingestion.csv_ingest", "combine_ingestion_results": "ingestion.csv_ingest",
    "run_analysis": "detection.engine", "initialise_database": "storage.database",
    "save_alerts": "storage.database", "get_alerts": "storage.database",
    "get_events_for_alert": "storage.database", "get_existing_alert_ids": "storage.database",
    "get_summary_counts": "storage.database", "create_incident": "storage.incidents",
    "list_incidents": "storage.incidents", "get_incident_details": "storage.incidents",
    "update_incident_status": "storage.incidents", "add_note": "storage.incidents",
    "add_alerts_to_incident": "storage.incidents", "build_incident_report_pdf": "reporting.pdf_report",
    "build_alert_summary_pdf": "reporting.pdf_report",
}


def test_backend_calls_have_exactly_the_fs4_signatures():
    for name in FS4_PARAMETERS:
        signature = inspect.signature(getattr(backend_calls, name))
        assert list(signature.parameters) == FS4_PARAMETERS[name], name
        for parameter_name in FS4_DEFAULTS.get(name, {}):
            assert signature.parameters[parameter_name].default == FS4_DEFAULTS[name][parameter_name], name


def test_mock_mode_is_on_by_default():
    assert backend_calls.USE_MOCK_BACKEND is True
    assert backend_calls.is_mock_backend() is True


def test_real_mode_calls_the_real_modules_with_the_fs4_argument_order(monkeypatch):
    calls = []
    for name in REAL_MODULES:
        module_name = REAL_MODULES[name]
        package_name = module_name.split(".")[0]
        if module_name not in sys.modules or not hasattr(sys.modules[module_name], "_is_stand_in"):
            stand_in = types.ModuleType(module_name)
            stand_in._is_stand_in = True
            monkeypatch.setitem(sys.modules, module_name, stand_in)
            monkeypatch.setitem(sys.modules, package_name, types.ModuleType(package_name))
    for name in REAL_MODULES:
        setattr(sys.modules[REAL_MODULES[name]], name, make_recording_function(name, calls))
    monkeypatch.setattr(backend_calls, "USE_MOCK_BACKEND", False)
    for name in FS4_PARAMETERS:
        wrapper = getattr(backend_calls, name)
        arguments = list(FS4_PARAMETERS[name])  # use the parameter names as marker values
        wrapper(*arguments)  # the star unpacks the list into separate arguments
        assert calls[-1] == (name, arguments), name
    assert len(calls) == len(FS4_PARAMETERS)


def make_recording_function(name, calls):
    """A stand-in for a real backend function: it records its name and the arguments it was given.
    No backend function has more than six parameters, and unused ones stay None."""
    def recording_function(first=None, second=None, third=None, fourth=None, fifth=None, sixth=None):
        arguments = []
        for value in [first, second, third, fourth, fifth, sixth]:
            if value is not None:
                arguments.append(value)
        calls.append((name, arguments))
    return recording_function


# ---------------------------------------------------------------
# The mock backend returns the documented shapes
# ---------------------------------------------------------------

def test_mock_ingest_result_has_the_d6_keys_and_valid_events():
    result = mock_backend.mock_ingest_file(b"x", "auth_sample.csv", "authentication", get_default_config())
    assert sorted(result.keys()) == ["events", "file_name", "log_type", "rejected_rows", "summary"]
    for event in result["events"]:
        assert validate_event(event) == []
    summary = result["summary"]
    assert summary["rows_read"] == summary["events_accepted"] + summary["rows_rejected"]
    assert "MOCK" in summary["warnings"][0]


def test_mock_ingest_rejects_bad_files_with_ingestion_error():
    config = get_default_config()
    for file_name, file_bytes, log_type in [("a.txt", b"x", "authentication"), ("a.csv", b"", "authentication"),
                                            ("a.csv", b"x", "firewall")]:
        with pytest.raises(IngestionError):
            mock_backend.mock_ingest_file(file_bytes, file_name, log_type, config)


def test_mock_events_take_the_uploaded_file_name_so_ids_differ_between_files():
    config = get_default_config()
    first = mock_backend.mock_ingest_file(b"x", "one.csv", "authentication", config)
    second = mock_backend.mock_ingest_file(b"x", "two.csv", "authentication", config)
    assert first["events"][0]["event_id"] != second["events"][0]["event_id"]
    assert first["events"][0]["source_file"] == "one.csv"


def test_mock_analysis_has_the_fs4_keys_and_consistent_alerts():
    combined, analysis = sample_analysis_in_a_bare_run()
    assert sorted(analysis.keys()) == ["alerts", "analysed_at", "base_alert_count", "correlated_alert_count",
                                       "events_analysed", "events_ignored_trusted", "notes"]
    event_ids = set()
    for event in combined["events"]:
        event_ids.add(event["event_id"])
    for alert in analysis["alerts"]:
        assert validate_alert(alert) == []
        for event_id in alert["event_ids"]:
            assert event_id in event_ids
    correlated = analysis["alerts"][0]
    for alert in analysis["alerts"]:
        if alert["rule_id"] == "CORR_AUTH_NET":
            correlated = alert
    union = set()
    for alert in analysis["alerts"]:
        if alert["alert_id"] in correlated["evidence"]["correlation"]["linked_alert_ids"]:
            union.update(alert["event_ids"])
    assert set(correlated["event_ids"]) == union
    assert len(correlated["event_ids"]) == len(union)


def test_mock_analysis_timing_rules_hold_for_every_alert():
    combined, analysis = sample_analysis_in_a_bare_run()
    events_by_id = {}
    for event in combined["events"]:
        events_by_id[event["event_id"]] = event
    for alert in analysis["alerts"]:
        timestamps = []
        for event_id in alert["event_ids"]:
            timestamps.append(events_by_id[event_id]["timestamp"])
        assert min(timestamps) == alert["time_start"]
        assert max(timestamps) == alert["time_end"]


def test_mock_auth_alert_follows_the_success_timing_rule():
    _, analysis = sample_analysis_in_a_bare_run()
    for alert in analysis["alerts"]:
        if alert["rule_id"] == "AUTH_BRUTE_FORCE":
            evidence = alert["evidence"]
            assert evidence["followed_by_success"] is True
            assert evidence["success_event_count"] == 1
            assert evidence["success_events_not_detailed"] == 0
            assert alert["severity"] == "high" and alert["confidence"] == "high"
            assert len(alert["event_ids"]) == 9


def test_mock_pdfs_are_bytes_that_start_with_pdf_marker():
    _, analysis = sample_analysis_in_a_bare_run()
    summary_pdf = mock_backend.mock_build_alert_summary_pdf(analysis["alerts"], analysis, get_default_config())
    assert summary_pdf.startswith(b"%PDF")
    assert summary_pdf.rstrip().endswith(b"%%EOF")


def test_mock_storage_error_cases_use_the_project_exceptions():
    app = app_with_sample_data()
    go_to(app, "Alerts")
    select_alerts_by_rule(app, ["CORR_AUTH_NET"])
    app.button(key="create_incident_button").click().run()  # blank title: nothing is stored
    assert len(mock_database(app)["incidents"]) == 0


def test_mock_bad_operations_raise_the_documented_errors():
    app = AppTest.from_function(raising_script, default_timeout=30)
    app.run()
    assert exception_texts(app) == []
    assert app.session_state["outcomes"] == {
        "unknown_incident": "IncidentNotFound", "resolved_to_open": "InvalidStatusTransition",
        "unsaved_alert": "BrokenReferenceError", "empty_note": "ValueError", "long_title": "ValueError",
    }


def raising_script():
    """Runs inside AppTest so the mock store can use session state."""
    import streamlit as st
    from config.settings import get_default_config
    from core.errors import BrokenReferenceError, IncidentNotFound, InvalidStatusTransition
    from dashboard import mock_backend

    config = get_default_config()
    auth = mock_backend.mock_ingest_file(b"x", "a.csv", "authentication", config)
    combined = mock_backend.mock_combine_ingestion_results([auth])
    analysis = mock_backend.mock_run_analysis(combined["events"], config)
    alert = analysis["alerts"][0]
    mock_backend.mock_save_alerts("db", [alert], combined["events"], analysis["alerts"])
    incident_id = mock_backend.mock_create_incident("db", "Case", [alert["alert_id"]])
    outcomes = {}
    try:
        mock_backend.mock_get_incident_details("db", 99)
    except IncidentNotFound as error:
        outcomes["unknown_incident"] = type(error).__name__
    mock_backend.mock_update_incident_status("db", incident_id, "resolved")
    try:
        mock_backend.mock_update_incident_status("db", incident_id, "open")
    except InvalidStatusTransition as error:
        outcomes["resolved_to_open"] = type(error).__name__
    try:
        mock_backend.mock_create_incident("db", "Case", ["ALT-0000000000000000"])
    except BrokenReferenceError as error:
        outcomes["unsaved_alert"] = type(error).__name__
    try:
        mock_backend.mock_add_note("db", incident_id, "   ")
    except ValueError as error:
        outcomes["empty_note"] = type(error).__name__
    try:
        mock_backend.mock_create_incident("db", "x" * 121, [alert["alert_id"]])
    except ValueError as error:
        outcomes["long_title"] = type(error).__name__
    st.session_state["outcomes"] = outcomes
