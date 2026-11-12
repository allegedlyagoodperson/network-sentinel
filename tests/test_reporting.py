# tests/test_reporting.py
# ---------------------------------------------------------------
# Purpose: tests for reporting/pdf_report.py (Stage 2B): valid PDFs, the 50-row
# general events limit, the 10-row authentication success limit, the exact
# total/shown/not-shown wording (FS.10 C), empty and missing data, escaping,
# long text, multi-page reports, and errors.
# Run from the project folder with: python -m pytest tests/test_reporting.py -v
# ReportLab compression is switched off in these tests so the text can be read.
# Uses: reporting, storage (one integration test), pytest, and the shared fixtures.

import re
import sys
from pathlib import Path

import pytest
from reportlab import rl_config

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

import storage_reporting_fixtures as fx  # noqa: E402
from core.errors import ReportError  # noqa: E402
from reporting import pdf_report  # noqa: E402
from reporting.pdf_report import (  # noqa: E402
    MAX_EVENT_ROWS,
    MAX_SUCCESS_ROWS,
    _events_table_line,
    _success_table_line,
    build_alert_summary_pdf,
    build_incident_report_pdf,
)

PROJECT_FOLDER = Path(__file__).resolve().parent.parent
CONFIG = {"trusted_ips": ["10.0.0.1"]}


@pytest.fixture(autouse=True)
def uncompressed_pdfs(monkeypatch):
    """Switch ReportLab page compression off so the tests can read the text."""
    monkeypatch.setattr(rl_config, "pageCompression", 0)


def report_text(details):
    """Build an incident report and return (pdf bytes, extracted text)."""
    pdf = build_incident_report_pdf(details, CONFIG)
    return pdf, fx.read_pdf_text(pdf)


def many_events_alert(event_count, status="failure"):
    """One alert with event_count authentication events. Returns (alert, events)."""
    events = []
    for index in range(event_count):
        events.append(fx.make_auth_event(index, username="user" + str(index), status=status))
    return fx.make_base_alert("AUTH_BRUTE_FORCE", events), events


def count_event_ids(text):
    return len(re.findall(r"EVT-[0-9a-f]{16}", text))


# ---------------------------------------------------------------
# The wording functions (they take plain numbers and return text)
# ---------------------------------------------------------------

@pytest.mark.parametrize("total", [0, 1, 30, 49, 50])
def test_events_line_says_all_when_nothing_is_left_out(total):
    assert _events_table_line(total, total) == "This table shows all " + str(total) + " supporting events."


@pytest.mark.parametrize("total, displayed", [(51, 50), (120, 50), (1000, 50), (10, 3)])
def test_events_line_gives_all_three_numbers_when_rows_are_left_out(total, displayed):
    line = _events_table_line(total, displayed)
    omitted = total - displayed
    assert line.startswith("This table shows " + str(displayed) + " of " + str(total) + " supporting events; ")
    assert str(omitted) + " are not shown here." in line
    assert "can be viewed in the dashboard" in line
    assert "shows all" not in line
    assert displayed + omitted == total


def test_events_line_rejects_impossible_numbers():
    for total, displayed in [(5, 6), (-1, 0), (5, -1)]:
        with pytest.raises(ValueError):
            _events_table_line(total, displayed)


def test_success_line_wording_for_15_successes_and_10_shown():
    assert _success_table_line(15, 10) == (
        "Authentication successes linked to this alert: 15. Shown in this detail table: 10 (limit 10). "
        "Not shown in this table: 5.")


def test_success_line_when_all_successes_are_shown():
    assert _success_table_line(3, 3) == (
        "Authentication successes linked to this alert: 3. Shown in this detail table: 3 (limit 10). "
        "Not shown in this table: 0.")


def test_success_line_never_says_where_the_other_successes_are():
    for total, shown in [(15, 10), (11, 10), (100, 10), (3, 3)]:
        line = _success_table_line(total, shown).lower()
        assert "events table" not in line
        assert "listed" not in line
        assert "included" not in line
        assert "above" not in line and "below" not in line


def test_success_line_rejects_impossible_numbers():
    with pytest.raises(ValueError):
        _success_table_line(5, 6)
    with pytest.raises(ValueError):
        _success_table_line(-1, 0)


def test_the_limits_are_the_specified_ones():
    assert MAX_EVENT_ROWS == 50
    assert MAX_SUCCESS_ROWS == 10


# ---------------------------------------------------------------
# A valid PDF with the required content
# ---------------------------------------------------------------

def test_incident_report_is_a_valid_pdf():
    alert, events = many_events_alert(6)
    pdf = build_incident_report_pdf(fx.make_details([alert], events), CONFIG)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert fx.count_pdf_pages(pdf) >= 1


def test_incident_report_contains_the_required_sections():
    scenario = fx.make_scenario()
    notes = [{"note_id": 1, "incident_id": 7, "author": "analyst", "text": "Checked the firewall.",
              "created_at": fx.START_TIME}]
    history = [{"history_id": 1, "incident_id": 7, "action": "created", "old_value": None,
                "new_value": "3 alerts", "changed_by": "analyst", "changed_at": fx.START_TIME}]
    alerts = [scenario["correlated_alert"], scenario["auth_alert"], scenario["network_alert"]]
    details = fx.make_details(alerts, scenario["events"], notes, history)
    pdf, text = report_text(details)
    for expected in [
        "Network Sentinel - Incident Report", "INC-0007", "Test incident", "Status", "Priority",
        "Created (UTC)", "2025-03-14 09:00:00", "Analyst summary.",
        "do not prove an attack", "Alerts in this report",
        scenario["correlated_alert"]["alert_id"], scenario["auth_alert"]["alert_id"],
        "CORR_AUTH_NET", "AUTH_BRUTE_FORCE", "NET_PORT_SCAN",
        "Explanation", "Limitations", "Thresholds used (rule parameters)", "Observed values",
        "Correlation", "Checked the firewall.", "Status history", "created", "3 alerts",
        "Recommended actions", "Review the activity and consider blocking the address.",
        "Supporting events", "Page 1 of",
    ]:
        assert expected in text, "missing from the report: " + expected


def test_report_prints_page_numbers_that_match_the_real_page_count():
    alerts = []
    all_events = []
    for number in range(8):
        alert, events = many_events_alert(60)
        alert = dict(alert)
        alert["title"] = "Alert number " + str(number)
        alerts.append(alert)
        all_events.extend(events)
    pdf, text = report_text(fx.make_details(alerts, all_events))
    pages = fx.count_pdf_pages(pdf)
    assert pages > 3
    for page_number in range(1, pages + 1):
        assert "Page " + str(page_number) + " of " + str(pages) in text
    assert "Page 1 of ?" not in text


def test_only_helvetica_fonts_are_used():
    alert, events = many_events_alert(5)
    pdf = build_incident_report_pdf(fx.make_details([alert], events), CONFIG)
    font_names = set(re.findall(rb"/BaseFont /([A-Za-z0-9-]+)", pdf))
    assert len(font_names) > 0
    for name in font_names:
        assert name.startswith(b"Helvetica"), name


# ---------------------------------------------------------------
# 50-row general event limit and its counts
# ---------------------------------------------------------------

def test_fifty_events_are_all_displayed():
    alert, events = many_events_alert(50)
    pdf, text = report_text(fx.make_details([alert], events))
    assert "This table shows all 50 supporting events." in text
    assert count_event_ids(text) == 50


def test_fifty_one_events_show_fifty_rows_and_one_omitted():
    alert, events = many_events_alert(51)
    pdf, text = report_text(fx.make_details([alert], events))
    assert "This table shows 50 of 51 supporting events; 1 are not shown here." in text
    assert count_event_ids(text) == 50
    assert events[50]["event_id"] not in text  # the 51st event is not displayed
    assert events[49]["event_id"] in text


def test_large_evidence_set_shows_50_rows_and_the_right_counts():
    alert, events = many_events_alert(500)
    pdf, text = report_text(fx.make_details([alert], events))
    assert "This table shows 50 of 500 supporting events; 450 are not shown here." in text
    assert count_event_ids(text) == 50
    assert "shows all" not in text


def test_the_first_fifty_events_in_time_order_are_the_ones_shown():
    alert, events = many_events_alert(80)
    pdf, text = report_text(fx.make_details([alert], events))
    for event in events[:50]:
        assert event["event_id"] in text
    for event in events[50:]:
        assert event["event_id"] not in text


def test_few_events_say_all_and_do_not_mention_omitted_rows():
    alert, events = many_events_alert(6)
    pdf, text = report_text(fx.make_details([alert], events))
    assert "This table shows all 6 supporting events." in text
    assert "are not shown here" not in text


def test_the_limit_applies_to_each_alert_separately():
    first, first_events = many_events_alert(70)
    second_events = []
    for index in range(1000, 1060):
        second_events.append(fx.make_auth_event(index, source_ip="198.51.100.9"))
    second = fx.make_base_alert("AUTH_BRUTE_FORCE", second_events, source_ip="198.51.100.9")
    pdf, text = report_text(fx.make_details([first, second], first_events + second_events))
    assert "This table shows 50 of 70 supporting events; 20 are not shown here." in text
    assert "This table shows 50 of 60 supporting events; 10 are not shown here." in text
    assert count_event_ids(text) == 100


def test_events_missing_from_the_supplied_data_are_reported_not_invented():
    alert, events = many_events_alert(10)
    pdf, text = report_text(fx.make_details([alert], events[:7]))
    assert "This table shows 7 of 10 supporting events; 3 are not shown here." in text
    assert "3 supporting events could not be found in the event data given to this report." in text
    assert count_event_ids(text) == 7


# ---------------------------------------------------------------
# 10-row authentication success limit and its counts (R2.7)
# ---------------------------------------------------------------

def test_fifteen_successes_show_ten_detail_rows_and_the_separate_counts():
    alert, events = fx.make_success_alert(failure_count=6, success_count=15)
    pdf, text = report_text(fx.make_details([alert], events))
    assert ("Authentication successes linked to this alert: 15. Shown in this detail table: 10 (limit 10). "
            "Not shown in this table: 5.") in text
    assert "This table shows all 21 supporting events." in text
    assert "Authentication success detail" in text
    # 21 rows in the general table + 10 rows in the detail table.
    assert count_event_ids(text) == 21 + 10


def test_omitted_successes_are_not_claimed_to_be_in_the_general_table():
    # 60 failures first, then 15 successes: the 50-row general table holds only
    # failures, so the 5 undetailed successes appear NOWHERE in the report.
    alert, events = fx.make_success_alert(failure_count=60, success_count=15)
    pdf, text = report_text(fx.make_details([alert], events))
    assert "This table shows 50 of 75 supporting events; 25 are not shown here." in text
    assert "Shown in this detail table: 10 (limit 10). Not shown in this table: 5." in text
    undetailed = events[-5:]
    for event in undetailed:
        assert event["event_id"] not in text
    lowered = text.lower()
    assert "included in the events table" not in lowered
    assert "listed in the events table" not in lowered
    assert "shown in the events table" not in lowered
    # General table: 50 rows. Detail table: 10 rows.
    assert count_event_ids(text) == 50 + 10


def test_exactly_ten_successes_are_all_shown_in_the_detail_table():
    alert, events = fx.make_success_alert(failure_count=6, success_count=10)
    pdf, text = report_text(fx.make_details([alert], events))
    assert "Authentication successes linked to this alert: 10. Shown in this detail table: 10 (limit 10). " \
           "Not shown in this table: 0." in text


def test_fewer_than_ten_successes():
    alert, events = fx.make_success_alert(failure_count=6, success_count=3, detail_limit=10)
    pdf, text = report_text(fx.make_details([alert], events))
    assert "Authentication successes linked to this alert: 3. Shown in this detail table: 3 (limit 10). " \
           "Not shown in this table: 0." in text


def test_no_success_section_when_there_are_no_successes():
    alert, events = many_events_alert(6)
    pdf, text = report_text(fx.make_details([alert], events))
    assert "Authentication success detail" not in text
    assert "Authentication successes linked" not in text


def test_success_detail_never_exceeds_ten_rows_even_if_given_more():
    alert, events = fx.make_success_alert(failure_count=2, success_count=14, detail_limit=14)
    assert len(alert["evidence"]["success_events"]) == 14  # a producer that ignored the limit
    pdf, text = report_text(fx.make_details([alert], events))
    assert "Authentication successes linked to this alert: 14. Shown in this detail table: 10 (limit 10). " \
           "Not shown in this table: 4." in text


# ---------------------------------------------------------------
# Empty and missing data
# ---------------------------------------------------------------

def test_incident_with_no_alerts_notes_or_history():
    details = fx.make_details([], [])
    pdf, text = report_text(details)
    assert pdf.startswith(b"%PDF-")
    assert "No alerts are linked to this incident." in text
    assert "No notes have been recorded for this incident." in text
    assert "No history rows are recorded." in text


def test_alert_with_empty_evidence_and_no_events():
    alert = {"alert_id": "ALT-0123456789abcdef", "rule_id": "AUTH_BRUTE_FORCE", "title": "Bare alert",
             "description": "d", "severity": "low", "confidence": "low", "detected_at": fx.START_TIME,
             "time_start": fx.START_TIME, "time_end": fx.START_TIME, "source_ip": None, "event_ids": [],
             "evidence": {}, "recommended_action": "Check."}
    pdf, text = report_text(fx.make_details([alert], []))
    assert "This table shows all 0 supporting events." in text
    assert "None recorded." in text
    assert "Authentication success detail" not in text


def test_missing_and_none_values_print_as_dashes_without_crashing():
    event = fx.make_auth_event(0)
    for key in ["destination_ip", "destination_port", "protocol", "username", "service", "bytes_sent"]:
        event[key] = None
    alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [event])
    alert["source_ip"] = None
    details = fx.make_details([alert], [event])
    details["summary"] = ""
    details["created_at"] = None
    details["updated_at"] = None
    details["closed_at"] = None
    pdf, text = report_text(details)
    assert "No summary was written for this incident." in text
    assert " - " in text or "-" in text
    assert event["event_id"] in text


def test_alert_dictionary_with_missing_keys_still_builds():
    alert = {"alert_id": "ALT-0123456789abcdef"}
    pdf, text = report_text(fx.make_details([alert], []))
    assert "ALT-0123456789abcdef" in text


def test_notes_history_and_events_keys_may_be_absent():
    details = {"incident_id": 3, "title": "Minimal", "status": "open", "priority": "low", "alerts": []}
    pdf, text = report_text(details)
    assert "INC-0003" in text


def test_unknown_evidence_keys_and_nested_values_are_shown_not_dropped():
    evidence = fx.make_evidence({"custom_numbers": [1, 2, 3], "custom_map": {"a": 1}, "flag": True,
                                 "long_list": list(range(25))})
    event = fx.make_auth_event(0)
    alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [event], evidence=evidence)
    pdf, text = report_text(fx.make_details([alert], [event]))
    assert "custom_numbers" in text and "1, 2, 3" in text
    assert "a: 1" in text
    assert "and 15 more" in text  # 25 items, 10 shown


# ---------------------------------------------------------------
# Escaping, long text, odd characters, page breaks
# ---------------------------------------------------------------

def test_markup_in_log_data_is_printed_literally():
    hostile = "<b>admin</b> & <script>alert(1)</script> </para> <br/> <unclosed"
    event = fx.make_auth_event(0, username=hostile)
    evidence = fx.make_evidence({"explanation": ["Saw " + hostile]})
    alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [event], title=hostile, evidence=evidence)
    details = fx.make_details([alert], [event], notes=[{
        "note_id": 1, "incident_id": 7, "author": hostile, "text": hostile, "created_at": fx.START_TIME}])
    details["summary"] = hostile
    pdf, text = report_text(details)
    compact = fx.compact_text(text)
    assert fx.compact_text("<b>admin</b>&<script>alert(1)</script></para><br/><unclosed") in compact
    assert compact.count(fx.compact_text(hostile)) >= 4


def test_very_long_unbroken_text_does_not_crash_and_is_clipped():
    long_word = "A" * 100000
    event = fx.make_auth_event(0)
    event["username"] = long_word  # make_event would refuse this; the report must still cope
    alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [event], title="t",
                               evidence=fx.make_evidence({"explanation": [long_word], "limitations": [long_word]}))
    alert["title"] = long_word
    alert["description"] = long_word
    details = fx.make_details([alert], [event], notes=[{
        "note_id": 1, "incident_id": 7, "author": "analyst", "text": long_word, "created_at": fx.START_TIME}])
    details["title"] = long_word
    details["summary"] = long_word
    pdf, text = report_text(details)
    assert pdf.startswith(b"%PDF-")
    assert "A" * 100000 not in fx.compact_text(text)  # clipped, not dumped
    assert "..." in text


def test_a_long_note_with_many_lines_flows_over_pages():
    note_text = "\n".join(["Line " + str(number) + " of a very long analyst note." for number in range(150)])
    alert, events = many_events_alert(3)
    details = fx.make_details([alert], events, notes=[{
        "note_id": 1, "incident_id": 7, "author": "analyst", "text": note_text, "created_at": fx.START_TIME}])
    pdf, text = report_text(details)
    assert "Line 0 of a very long analyst note." in text
    assert "Line 149 of a very long analyst note." not in text  # clipped at 3000 characters
    assert "Line 50 of a very long analyst note." in text


def test_unicode_and_control_characters_do_not_crash():
    odd = "Zoë 你好 😀 \x00\x01\x1b[31m tab\there\r\nnext line"
    event = fx.make_auth_event(0)
    event["username"] = odd  # make_event would refuse control characters; the report must still cope
    alert = fx.make_base_alert("AUTH_BRUTE_FORCE", [event], title="t")
    alert["title"] = odd
    details = fx.make_details([alert], [event], notes=[{
        "note_id": 1, "incident_id": 7, "author": odd, "text": odd, "created_at": fx.START_TIME}])
    pdf, text = report_text(details)
    assert pdf.startswith(b"%PDF-")
    assert "\x00" not in text


def test_a_report_with_many_alerts_spans_many_pages_and_repeats_table_headers():
    alerts = []
    all_events = []
    for number in range(12):
        events = []
        for index in range(60):
            events.append(fx.make_auth_event(number * 100 + index, source_ip="198.51.100." + str(number + 1)))
        alerts.append(fx.make_base_alert("AUTH_BRUTE_FORCE", events, source_ip="198.51.100." + str(number + 1),
                                         title="Alert " + str(number)))
        all_events.extend(events)
    pdf, text = report_text(fx.make_details(alerts, all_events))
    assert fx.count_pdf_pages(pdf) >= 8
    assert text.count("User (service)") > 12  # the events table header repeats after page breaks
    assert text.count("This table shows 50 of 60 supporting events; 10 are not shown here.") == 12


# ---------------------------------------------------------------
# Errors
# ---------------------------------------------------------------

def test_incident_report_rejects_bad_arguments():
    alert, events = many_events_alert(3)
    good = fx.make_details([alert], events)
    with pytest.raises(ReportError):
        build_incident_report_pdf("not a dictionary", CONFIG)
    with pytest.raises(ReportError):
        build_incident_report_pdf(good, "not a dictionary")
    for missing_key in ["incident_id", "title", "status", "priority", "alerts"]:
        broken = dict(good)
        del broken[missing_key]
        with pytest.raises(ReportError):
            build_incident_report_pdf(broken, CONFIG)
    for bad_id in [-1, "7", None]:
        broken = dict(good)
        broken["incident_id"] = bad_id
        with pytest.raises(ReportError):
            build_incident_report_pdf(broken, CONFIG)
    broken = dict(good)
    broken["alerts"] = "nope"
    with pytest.raises(ReportError):
        build_incident_report_pdf(broken, CONFIG)
    broken = dict(good)
    broken["events"] = ["not a dictionary"]
    with pytest.raises(ReportError):
        build_incident_report_pdf(broken, CONFIG)


# ---------------------------------------------------------------
# Alert summary report
# ---------------------------------------------------------------

ANALYSIS_SUMMARY = {
    "analysed_at": fx.START_TIME, "events_analysed": 1000, "events_ignored_trusted": 3,
    "base_alert_count": 2, "correlated_alert_count": 1,
    "notes": ["NET_HIGH_VOLUME was skipped: no byte counts in the uploaded data."],
}


def test_alert_summary_is_a_valid_pdf_with_the_main_facts():
    scenario = fx.make_scenario(network_severity="critical")
    alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    pdf = build_alert_summary_pdf(alerts, ANALYSIS_SUMMARY, CONFIG)
    text = fx.read_pdf_text(pdf)
    assert pdf.startswith(b"%PDF-")
    for expected in ["Analysis Summary", "do not prove an attack", "Events analysed", "1000",
                     "Events ignored (trusted addresses)", "Alerts by severity", "Analysis notes",
                     "NET_HIGH_VOLUME was skipped", "10.0.0.1", "Findings", "Page 1 of 1"]:
        assert expected in text, expected
    for alert in alerts:
        assert alert["alert_id"] in text


def test_alert_summary_lists_the_most_severe_alert_first():
    scenario = fx.make_scenario(network_severity="critical")
    alerts = [scenario["auth_alert"], scenario["correlated_alert"], scenario["network_alert"]]
    text = fx.read_pdf_text(build_alert_summary_pdf(alerts, ANALYSIS_SUMMARY, CONFIG))
    table_part = text[text.index("Alert ID"):text.index("Findings")]
    positions = [table_part.index(scenario["network_alert"]["alert_id"]),
                 table_part.index(scenario["correlated_alert"]["alert_id"]),
                 table_part.index(scenario["auth_alert"]["alert_id"])]
    assert positions == sorted(positions)  # critical, then high, then medium


def test_alert_summary_shows_event_counts_not_event_lists():
    alert, events = many_events_alert(120)
    text = fx.read_pdf_text(build_alert_summary_pdf([alert], ANALYSIS_SUMMARY, CONFIG))
    assert "120" in text
    assert count_event_ids(text) == 0
    assert "supporting events are not listed" in text


def test_alert_summary_with_no_alerts_and_missing_summary_keys():
    text = fx.read_pdf_text(build_alert_summary_pdf([], {}, {}))
    assert "No alerts were produced in this analysis." in text
    assert "No analysis notes were recorded" in text


def test_alert_summary_escapes_markup_and_handles_odd_alerts():
    hostile = "<b>bad</b> & <i>worse"
    alert = {"alert_id": hostile, "title": hostile, "description": hostile, "severity": "unknown",
             "recommended_action": hostile}
    pdf = build_alert_summary_pdf([alert], {"notes": [hostile]}, CONFIG)
    assert fx.compact_text("<b>bad</b>&<i>worse") in fx.compact_text(fx.read_pdf_text(pdf))


def test_alert_summary_rejects_bad_arguments():
    with pytest.raises(ReportError):
        build_alert_summary_pdf("x", {}, {})
    with pytest.raises(ReportError):
        build_alert_summary_pdf([], "x", {})
    with pytest.raises(ReportError):
        build_alert_summary_pdf([], {}, "x")
    with pytest.raises(ReportError):
        build_alert_summary_pdf(["x"], {}, {})


# ---------------------------------------------------------------
# Integration with storage, and the import rules
# ---------------------------------------------------------------

def test_report_built_from_a_real_saved_incident(tmp_path):
    from storage.database import initialise_database, save_alerts
    from storage.incidents import add_note, create_incident, get_incident_details, update_incident_status

    path = str(tmp_path / "report.db")
    initialise_database(path)
    scenario = fx.make_scenario()
    session_alerts = [scenario["auth_alert"], scenario["network_alert"], scenario["correlated_alert"]]
    save_alerts(path, [scenario["correlated_alert"]], scenario["events"], session_alerts)
    incident_id = create_incident(path, "Scan then login", [scenario["correlated_alert"]["alert_id"]],
                                  summary="Both activities came from one address.")
    add_note(path, incident_id, "Blocked the address at the firewall.")
    update_incident_status(path, incident_id, "resolved")
    details = get_incident_details(path, incident_id)  # read back from SQLite only
    pdf, text = report_text(details)
    assert pdf.startswith(b"%PDF-")
    assert "INC-0001" in text
    assert "resolved" in text
    assert "Closed (UTC)" in text
    assert "Blocked the address at the firewall." in text
    assert "status_changed" in text and "note_added" in text
    assert "This table shows all 12 supporting events." in text  # the correlated alert
    for alert in session_alerts:
        assert alert["alert_id"] in text


def test_reporting_imports_only_core_reportlab_and_the_standard_library():
    source = (PROJECT_FOLDER / "reporting" / "pdf_report.py").read_text(encoding="utf-8")
    import_lines = re.findall(r"^(?:import|from) (\S+)", source, re.MULTILINE)
    allowed = {"io", "datetime", "xml.sax.saxutils", "reportlab.lib", "reportlab.lib.pagesizes",
               "reportlab.lib.styles", "reportlab.platypus", "core.contracts", "core.errors"}
    assert set(import_lines) <= allowed, set(import_lines) - allowed
    for forbidden in ["sqlite3", "streamlit", "storage", "dashboard", "detection", "ingestion"]:
        assert forbidden not in import_lines


def test_the_module_does_not_change_after_import():
    assert pdf_report.MAX_EVENT_ROWS == 50
