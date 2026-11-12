# reporting/pdf_report.py
# ---------------------------------------------------------------
# Purpose: turn dictionaries into PDF bytes with ReportLab (Section G.3, FS.10 C).
# build_incident_report_pdf: one incident report (header, alerts, evidence, notes, history).
# build_alert_summary_pdf: summary of the current analysis session.
# Rules: max 50 rows in each general events table, max 10 rows in each
# authentication-success detail table, with total/shown/not-shown counts stated.
# Built-in Helvetica only (D9). All text from logs or users is escaped.
# Uses: core and reportlab only. No database, no Streamlit.

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.contracts import (
    MAX_DETAILED_SUCCESS_EVENTS,
    SEVERITIES,
    format_incident_id,
    iso_to_datetime,
    severity_rank,
    utc_now,
)
from core.errors import ReportError

MAX_EVENT_ROWS = 50  # general events table, per alert (FS.10 C)
MAX_SUCCESS_ROWS = MAX_DETAILED_SUCCESS_EVENTS  # authentication success detail table (10)

_PAGE_MARGIN = 36
_CONTENT_WIDTH = A4[0] - 2 * _PAGE_MARGIN  # about 523 points
_CELL_LIMIT = 90  # longest text printed in one table cell
_VALUE_LIMIT = 400  # longest value printed in a key/value table
_TEXT_LIMIT = 3000  # longest paragraph of free text
_LIST_ITEM_LIMIT = 10  # list values show at most this many items
_DISCLAIMER = (
    "Detections indicate suspicious activity and do not prove an attack. "
    "Severity (how serious it could be) and confidence (how strongly the evidence supports it) "
    "are separate judgements. Each alert lists harmless explanations under Limitations. "
    "A dash (-) in a table means the value was not recorded."
)
_GREY = colors.HexColor("#E6E8EB")
_LINE_GREY = colors.HexColor("#9AA3AD")


# ---------------------------------------------------------------
# Wording of the count lines (FS.10 C rules 2 and 3). They take plain
# numbers and return text, so the tests can check them directly.
# ---------------------------------------------------------------

def _events_table_line(total_count, displayed_count):
    """
    Purpose: the one line printed with the general events table.
    Inputs: total_count (int) - supporting events of the alert (length of
        event_ids); displayed_count (int) - rows shown, at most 50.
    Output: str. The word "all" is used only when nothing is left out.
    Example: (30, 30) -> "This table shows all 30 supporting events."
        (120, 50) -> "This table shows 50 of 120 supporting events; 70 are not shown here. ..."
    Errors: ValueError if the numbers are negative or displayed exceeds total.
    """
    if total_count < 0 or displayed_count < 0 or displayed_count > total_count:
        raise ValueError("displayed_count must be between 0 and total_count")
    omitted_count = total_count - displayed_count
    if omitted_count == 0:
        return "This table shows all " + str(total_count) + " supporting events."
    return (
        "This table shows " + str(displayed_count) + " of " + str(total_count)
        + " supporting events; " + str(omitted_count) + " are not shown here. "
        "The complete list is kept with the alert and can be viewed in the dashboard."
    )


def _success_table_line(success_total, shown_count):
    """
    Purpose: the line printed above the authentication success detail table.
    Inputs: success_total (int) - linked successes S; shown_count (int) -
        rows in the detail table D (at most 10).
    Output: str. It only says what is shown and what is not shown. It never
        says where the missing successes are listed, because the general
        events table can be limited too (FS.10 C rule 4).
    Example: (15, 10) -> "Authentication successes linked to this alert: 15.
        Shown in this detail table: 10 (limit 10). Not shown in this table: 5."
    Errors: ValueError if the numbers are negative or shown exceeds the total.
    """
    if success_total < 0 or shown_count < 0 or shown_count > success_total:
        raise ValueError("shown_count must be between 0 and success_total")
    not_shown_count = success_total - shown_count
    return (
        "Authentication successes linked to this alert: " + str(success_total) + ". "
        "Shown in this detail table: " + str(shown_count) + " (limit " + str(MAX_SUCCESS_ROWS) + "). "
        "Not shown in this table: " + str(not_shown_count) + "."
    )


# ---------------------------------------------------------------
# Text safety. ReportLab paragraphs read simple markup (<b>, <br/>), so
# every value that came from a log file or a user is escaped first (E.10).
# ---------------------------------------------------------------

def _replace_control_characters(text, keep_newlines):
    """Replace control characters with spaces (a newline may be kept)."""
    cleaned_characters = []
    for character in text:
        code = ord(character)
        if character == "\n" and keep_newlines:
            cleaned_characters.append(character)
        elif code < 32 or code == 127:
            cleaned_characters.append(" ")
        else:
            cleaned_characters.append(character)
    return "".join(cleaned_characters)


def _clip(text, limit):
    """Cut text that is longer than limit and end it with three dots."""
    if len(text) > limit:
        return text[:limit - 3] + "..."
    return text


def _safe(value, limit=_CELL_LIMIT):
    """
    One line of safe paragraph text. None becomes "-". Control characters
    become spaces, long text is clipped, then & < > are escaped so that a
    username such as <b>x</b> prints literally instead of being interpreted.
    """
    if value is None:
        return "-"
    text = _replace_control_characters(str(value), False).strip()
    if text == "":
        return "-"
    return escape(_clip(text, limit))


def _safe_multiline(value, limit=_TEXT_LIMIT):
    """Like _safe, but line breaks in the text become <br/> (used for notes and summaries)."""
    if value is None:
        return "-"
    text = _replace_control_characters(str(value), True).strip()
    if text == "":
        return "-"
    return escape(_clip(text, limit)).replace("\n", "<br/>")


def _format_time(value):
    """A datetime (or text, or None) as 'YYYY-MM-DD HH:MM:SS' in UTC, with a fraction only if there is one."""
    if value is None:
        return "-"
    if isinstance(value, str):
        # evidence lists such as success_events keep their times as ISO text
        try:
            value = iso_to_datetime(value)
        except ValueError:
            return value
    if not isinstance(value, datetime):
        return str(value)
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc)
    text = value.strftime("%Y-%m-%d %H:%M:%S")
    if value.microsecond != 0:
        text = text + "." + str(value.microsecond).zfill(6).rstrip("0")
    return text


def _format_simple(value):
    """One simple value as plain text (no recursion into lists or dictionaries)."""
    if value is None:
        return "-"
    if isinstance(value, bool):
        if value:
            return "yes"
        return "no"
    if isinstance(value, datetime):
        return _format_time(value)
    return str(value)


def _format_value(value):
    """
    Any evidence value as plain text. A list shows its first 10 items and
    "and N more"; a dictionary shows its first 10 key: value pairs.
    """
    if isinstance(value, list):
        shown_items = []
        for item in value[:_LIST_ITEM_LIMIT]:
            shown_items.append(_format_simple(item))
        text = ", ".join(shown_items)
        if len(value) > _LIST_ITEM_LIMIT:
            text = text + " and " + str(len(value) - _LIST_ITEM_LIMIT) + " more"
        if text == "":
            return "(empty)"
        return text
    if isinstance(value, dict):
        pairs = []
        for key in list(value.keys())[:_LIST_ITEM_LIMIT]:
            pairs.append(str(key) + ": " + _format_simple(value[key]))
        if len(value) > _LIST_ITEM_LIMIT:
            pairs.append("and " + str(len(value) - _LIST_ITEM_LIMIT) + " more")
        if len(pairs) == 0:
            return "(empty)"
        return "; ".join(pairs)
    return _format_simple(value)


# ---------------------------------------------------------------
# Styles, tables and other small building blocks
# ---------------------------------------------------------------

def _make_styles():
    """The paragraph styles used in both reports (built-in Helvetica only)."""
    styles = {}
    styles["title"] = ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=18, leading=22, spaceAfter=4)
    styles["heading"] = ParagraphStyle(
        "heading", fontName="Helvetica-Bold", fontSize=13, leading=16, spaceBefore=12, spaceAfter=5, keepWithNext=1
    )
    styles["subheading"] = ParagraphStyle(
        "subheading", fontName="Helvetica-Bold", fontSize=10, leading=13, spaceBefore=7, spaceAfter=3, keepWithNext=1
    )
    styles["body"] = ParagraphStyle("body", fontName="Helvetica", fontSize=9, leading=12, spaceAfter=3)
    styles["small"] = ParagraphStyle("small", fontName="Helvetica-Oblique", fontSize=8, leading=10.5, spaceAfter=4)
    styles["bullet"] = ParagraphStyle(
        "bullet", fontName="Helvetica", fontSize=9, leading=12, leftIndent=14, bulletIndent=4, spaceAfter=2
    )
    styles["cell"] = ParagraphStyle("cell", fontName="Helvetica", fontSize=7, leading=8.6, splitLongWords=1)
    styles["cell_bold"] = ParagraphStyle("cell_bold", fontName="Helvetica-Bold", fontSize=7, leading=8.6, splitLongWords=1)
    return styles


def _cell(value, styles, limit=_CELL_LIMIT):
    """A table cell: a safe, wrapping paragraph."""
    return Paragraph(_safe(value, limit), styles["cell"])


def _header_cell(text, styles):
    """A bold header cell (the text is written by us, so it is not escaped)."""
    return Paragraph(text, styles["cell_bold"])


def _header_row(names, styles):
    """A row of bold header cells."""
    cells = []
    for name in names:
        cells.append(_header_cell(name, styles))
    return cells


def _join_or_none(parts):
    """Join text parts with spaces; an empty list becomes None (a missing value)."""
    if len(parts) == 0:
        return None
    return " ".join(parts)


def _make_table(rows, column_widths):
    """A grid table whose first row is a grey header that repeats on every page."""
    table = Table(rows, colWidths=column_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _GREY),
        ("GRID", (0, 0), (-1, -1), 0.25, _LINE_GREY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return table


def _key_value_table(mapping, styles):
    """A two-column table of 'name | value' rows, or a short sentence when empty."""
    if not isinstance(mapping, dict) or len(mapping) == 0:
        return Paragraph("None recorded.", styles["body"])
    rows = []
    for key in mapping:
        rows.append([
            Paragraph("<b>" + _safe(key, 60) + "</b>", styles["cell"]),
            Paragraph(_safe(_format_value(mapping[key]), _VALUE_LIMIT), styles["cell"]),
        ])
    table = Table(rows, colWidths=[150, _CONTENT_WIDTH - 150])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, _LINE_GREY),
        ("BACKGROUND", (0, 0), (0, -1), _GREY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return table


def _bullet_flowables(heading_text, sentences, styles):
    """A sub-heading followed by one bullet per sentence."""
    flowables = [Paragraph(heading_text, styles["subheading"])]
    if not isinstance(sentences, list) or len(sentences) == 0:
        flowables.append(Paragraph("None recorded.", styles["body"]))
        return flowables
    for sentence in sentences:
        flowables.append(Paragraph(_safe(sentence, 600), styles["bullet"], bulletText="-"))
    return flowables


def _get_list_of_dicts(mapping, key):
    """mapping[key] as a list of dictionaries. A missing key or None means an empty list."""
    value = mapping.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ReportError(key + " must be a list")
    for item in value:
        if not isinstance(item, dict):
            raise ReportError(key + " must contain only dictionaries")
    return value


def _evidence_of(alert):
    """The evidence dictionary of an alert, or an empty dictionary if it is missing."""
    evidence = alert.get("evidence")
    if isinstance(evidence, dict):
        return evidence
    return {}


def _time_range_text(alert):
    """'start to end' for an alert."""
    return _format_time(alert.get("time_start")) + " to " + _format_time(alert.get("time_end"))


# ---------------------------------------------------------------
# Alert evidence blocks (one per alert)
# ---------------------------------------------------------------

def _event_row(event, styles):
    """One row of the general events table."""
    destination_parts = []
    if event.get("destination_ip") is not None:
        destination_parts.append(str(event["destination_ip"]))
    if event.get("destination_port") is not None:
        destination_parts.append("port " + str(event["destination_port"]))
    if event.get("protocol") is not None:
        destination_parts.append(str(event["protocol"]))
    person_parts = []
    if event.get("username") is not None:
        person_parts.append(str(event["username"]))
    if event.get("service") is not None:
        person_parts.append("(" + str(event["service"]) + ")")
    status_text = _safe(event.get("status"), 20)
    if event.get("bytes_sent") is not None:
        status_text = status_text + ", sent " + _safe(event["bytes_sent"], 20)
    event_type = event.get("event_type")
    if event_type == "authentication":
        event_type = "auth"
    elif event_type == "network_connection":
        event_type = "network"
    return [
        _cell(_format_time(event.get("timestamp")), styles, 30),
        _cell(event.get("event_id"), styles, 30),
        _cell(event_type, styles, 20),
        _cell(event.get("source_ip"), styles, 45),
        _cell(_join_or_none(destination_parts), styles),
        _cell(_join_or_none(person_parts), styles),
        Paragraph(status_text, styles["cell"]),
    ]


def _events_flowables(alert, events_by_id, styles):
    """The general events table of one alert: at most 50 rows, with the counts line."""
    event_ids = alert.get("event_ids")
    if not isinstance(event_ids, list):
        event_ids = []
    event_rows = []
    missing_count = 0
    for event_id in event_ids:
        event = events_by_id.get(event_id)
        if event is None:
            missing_count = missing_count + 1
        elif len(event_rows) < MAX_EVENT_ROWS:
            event_rows.append(_event_row(event, styles))
    flowables = [Paragraph("Supporting events", styles["subheading"])]
    flowables.append(Paragraph(_events_table_line(len(event_ids), len(event_rows)), styles["body"]))
    if missing_count > 0:
        flowables.append(Paragraph(
            str(missing_count) + " supporting events could not be found in the event data given to this report.",
            styles["body"],
        ))
    if len(event_rows) > 0:
        header = _header_row(
            ["Time (UTC)", "Event ID", "Type", "Source", "Destination", "User (service)", "Status"], styles
        )
        widths = [74, 92, 36, 68, 84, 80, 89]
        flowables.append(_make_table([header] + event_rows, widths))
    return flowables


def _success_counts(count_value, detail_list):
    """Return (success_total, shown_count) so that shown <= total <= and shown <= 10."""
    shown_count = min(len(detail_list), MAX_SUCCESS_ROWS)
    success_total = len(detail_list)
    if isinstance(count_value, int) and not isinstance(count_value, bool) and count_value >= 0:
        success_total = count_value
    if success_total < shown_count:
        success_total = shown_count
    return success_total, shown_count


def _success_flowables(alert, styles):
    """
    The authentication success detail table (at most 10 rows) and its counts
    line. Returns an empty list for an alert with no linked successes.
    """
    evidence = _evidence_of(alert)
    detail_list = evidence.get("success_events")
    if not isinstance(detail_list, list):
        detail_list = []
    success_total, shown_count = _success_counts(evidence.get("success_event_count"), detail_list)
    if success_total == 0:
        return []
    flowables = [Paragraph("Authentication success detail", styles["subheading"])]
    flowables.append(Paragraph(_success_table_line(success_total, shown_count), styles["body"]))
    if shown_count > 0:
        rows = [_header_row(["Time (UTC)", "Event ID", "Username", "Username also failed"], styles)]
        for entry in detail_list[:shown_count]:
            if not isinstance(entry, dict):
                entry = {}
            rows.append([
                _cell(_format_time(entry.get("timestamp")), styles, 40),
                _cell(entry.get("event_id"), styles, 30),
                _cell(entry.get("username"), styles),
                _cell(_format_simple(entry.get("username_also_failed")), styles),
            ])
        flowables.append(_make_table(rows, [110, 120, 150, 143]))
    return flowables


def _correlation_flowables(alert, styles):
    """The correlation block of a CORR_AUTH_NET alert (empty list for other alerts)."""
    block = _evidence_of(alert).get("correlation")
    if not isinstance(block, dict):
        return []
    flowables = [Paragraph("Correlation", styles["subheading"])]
    flowables.append(_key_value_table(block, styles))
    return flowables


def _extra_evidence(alert):
    """Evidence keys beyond the four required ones (rule-specific numbers and lists)."""
    skipped_keys = ["rule_parameters", "observed", "explanation", "limitations", "correlation", "success_events"]
    extra = {}
    for key, value in _evidence_of(alert).items():
        if key not in skipped_keys:
            extra[key] = value
    return extra


def _alert_flowables(alert, position, events_by_id, styles):
    """Everything printed for one alert: description, explanation, limitations, numbers, tables."""
    evidence = _evidence_of(alert)
    heading = "Alert " + str(position) + ": " + _safe(alert.get("title"), 100)
    flowables = [Paragraph(heading, styles["heading"])]
    details = {
        "Alert ID": alert.get("alert_id"),
        "Rule": alert.get("rule_id"),
        "Severity": alert.get("severity"),
        "Confidence": alert.get("confidence"),
        "Source address": alert.get("source_ip"),
        "Time range (UTC)": _time_range_text(alert),
        "Detected at (UTC)": _format_time(alert.get("detected_at")),
    }
    flowables.append(_key_value_table(details, styles))
    flowables.append(Spacer(1, 4))
    flowables.append(Paragraph("<b>Description:</b> " + _safe_multiline(alert.get("description")), styles["body"]))
    flowables.extend(_bullet_flowables("Explanation", evidence.get("explanation"), styles))
    flowables.extend(_bullet_flowables("Limitations", evidence.get("limitations"), styles))
    flowables.append(Paragraph("Thresholds used (rule parameters)", styles["subheading"]))
    flowables.append(_key_value_table(evidence.get("rule_parameters"), styles))
    flowables.append(Paragraph("Observed values", styles["subheading"]))
    flowables.append(_key_value_table(evidence.get("observed"), styles))
    extra = _extra_evidence(alert)
    if len(extra) > 0:
        flowables.append(Paragraph("Other evidence recorded by the rule", styles["subheading"]))
        flowables.append(_key_value_table(extra, styles))
    flowables.extend(_correlation_flowables(alert, styles))
    flowables.extend(_success_flowables(alert, styles))
    flowables.extend(_events_flowables(alert, events_by_id, styles))
    return flowables


def _index_events(events):
    """event_id -> event dictionary."""
    events_by_id = {}
    for event in events:
        if event.get("event_id") is not None:
            events_by_id[event["event_id"]] = event
    return events_by_id


def _alert_table_flowables(alerts, styles):
    """The overview table of alerts (rule, severity, confidence, time range, source)."""
    flowables = [Paragraph("Alerts in this report", styles["heading"])]
    if len(alerts) == 0:
        flowables.append(Paragraph("No alerts are linked to this incident.", styles["body"]))
        return flowables
    rows = [_header_row(["Alert ID", "Rule", "Severity", "Confidence", "Time range (UTC)", "Source"], styles)]
    for alert in alerts:
        rows.append([
            _cell(alert.get("alert_id"), styles, 30),
            _cell(alert.get("rule_id"), styles, 40),
            _cell(alert.get("severity"), styles, 20),
            _cell(alert.get("confidence"), styles, 20),
            _cell(_time_range_text(alert), styles, 80),
            _cell(alert.get("source_ip"), styles, 45),
        ])
    flowables.append(_make_table(rows, [88, 92, 46, 50, 150, 97]))
    return flowables


def _recommended_action_flowables(alerts, styles):
    """One bullet per alert with its recommended action."""
    flowables = [Paragraph("Recommended actions", styles["heading"])]
    if len(alerts) == 0:
        flowables.append(Paragraph("None recorded.", styles["body"]))
        return flowables
    for alert in alerts:
        text = ("<b>" + _safe(alert.get("alert_id"), 30) + "</b> (" + _safe(alert.get("rule_id"), 40) + "): "
                + _safe_multiline(alert.get("recommended_action"), 800))
        flowables.append(Paragraph(text, styles["bullet"], bulletText="-"))
    return flowables


# ---------------------------------------------------------------
# Incident report sections
# ---------------------------------------------------------------

def _check_incident_details(incident_details, config):
    """Check the shape of the arguments of build_incident_report_pdf."""
    if not isinstance(config, dict):
        raise ReportError("config must be a dictionary")
    if not isinstance(incident_details, dict):
        raise ReportError("incident_details must be a dictionary")
    for key in ["incident_id", "title", "status", "priority", "alerts"]:
        if key not in incident_details:
            raise ReportError("incident_details is missing key: " + key)
    try:
        format_incident_id(incident_details["incident_id"])
    except ValueError as error:
        raise ReportError("incident_id is not valid: " + str(error)) from error


def _incident_header_flowables(details, generated_text, styles):
    """Title, then a table with the INC- ID, status, priority and the times."""
    incident_label = format_incident_id(details["incident_id"])
    flowables = [Paragraph("Network Sentinel - Incident Report", styles["title"])]
    flowables.append(Paragraph(incident_label + ": " + _safe(details.get("title"), 140), styles["heading"]))
    facts = {
        "Incident ID": incident_label,
        "Status": details.get("status"),
        "Priority": details.get("priority"),
        "Created (UTC)": _format_time(details.get("created_at")),
        "Last updated (UTC)": _format_time(details.get("updated_at")),
        "Closed (UTC)": _format_time(details.get("closed_at")),
        "Report generated (UTC)": generated_text,
        "Linked alerts": len(_get_list_of_dicts(details, "alerts")),
    }
    flowables.append(_key_value_table(facts, styles))
    return flowables


def _incident_summary_flowables(details, styles):
    """The analyst's summary text and the standard statement that detections are not proof."""
    flowables = [Paragraph("Summary", styles["heading"])]
    summary_text = details.get("summary")
    if summary_text is None or str(summary_text).strip() == "":
        flowables.append(Paragraph("No summary was written for this incident.", styles["body"]))
    else:
        flowables.append(Paragraph(_safe_multiline(summary_text), styles["body"]))
    flowables.append(Paragraph(_DISCLAIMER, styles["small"]))
    return flowables


def _notes_flowables(notes, styles):
    """All notes, oldest first (the storage layer already sorts them)."""
    flowables = [Paragraph("Notes", styles["heading"])]
    if len(notes) == 0:
        flowables.append(Paragraph("No notes have been recorded for this incident.", styles["body"]))
        return flowables
    for note in notes:
        label = ("<b>" + _safe(note.get("author"), 60) + "</b> - " + _format_time(note.get("created_at"))
                 + " UTC (note " + _safe(note.get("note_id"), 12) + ")")
        flowables.append(Paragraph(label, styles["subheading"]))
        flowables.append(Paragraph(_safe_multiline(note.get("text")), styles["body"]))
    return flowables


def _history_flowables(history, styles):
    """The status history as a table, oldest first."""
    flowables = [Paragraph("Status history", styles["heading"])]
    if len(history) == 0:
        flowables.append(Paragraph("No history rows are recorded.", styles["body"]))
        return flowables
    rows = [_header_row(["Time (UTC)", "Action", "From", "To", "By"], styles)]
    for entry in history:
        rows.append([
            _cell(_format_time(entry.get("changed_at")), styles, 30),
            _cell(entry.get("action"), styles, 30),
            _cell(entry.get("old_value"), styles),
            _cell(entry.get("new_value"), styles),
            _cell(entry.get("changed_by"), styles),
        ])
    flowables.append(_make_table(rows, [95, 80, 110, 150, 88]))
    return flowables


def _build_incident_story(details, generated_text, styles):
    """The full list of flowables of the incident report."""
    alerts = _get_list_of_dicts(details, "alerts")
    events_by_id = _index_events(_get_list_of_dicts(details, "events"))
    story = []
    story.extend(_incident_header_flowables(details, generated_text, styles))
    story.extend(_incident_summary_flowables(details, styles))
    story.extend(_alert_table_flowables(alerts, styles))
    position = 1
    for alert in alerts:
        story.extend(_alert_flowables(alert, position, events_by_id, styles))
        position = position + 1
    story.extend(_notes_flowables(_get_list_of_dicts(details, "notes"), styles))
    story.extend(_history_flowables(_get_list_of_dicts(details, "history"), styles))
    story.extend(_recommended_action_flowables(alerts, styles))
    return story


# ---------------------------------------------------------------
# Rendering (page numbers need two passes: count the pages, then print them)
# ---------------------------------------------------------------

def _draw_footer(canvas, document):
    """Called by ReportLab for every page: footer text and 'Page N of M'."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#555555"))
    canvas.drawString(_PAGE_MARGIN, 24, document.footer_text)
    page_text = "Page " + str(document.page) + " of " + document.total_pages_text
    canvas.drawRightString(A4[0] - _PAGE_MARGIN, 24, page_text)
    canvas.restoreState()


def _render_once(story, title, footer_text, total_pages_text):
    """Build one PDF in memory. Returns (pdf bytes, number of pages)."""
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=_PAGE_MARGIN, rightMargin=_PAGE_MARGIN,
        topMargin=_PAGE_MARGIN, bottomMargin=48, title=title, author="Network Sentinel",
    )
    # ReportLab hands the document object to _draw_footer, so we keep the
    # footer text and the page total on it.
    document.footer_text = footer_text
    document.total_pages_text = total_pages_text
    document.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return buffer.getvalue(), document.page


def build_incident_report_pdf(incident_details: dict, config: dict) -> bytes:
    """
    Purpose: build the PDF report of one incident (Section G.3, FS.10 C).
    Inputs:
        incident_details (dict) - the bundle from get_incident_details: the
            incident keys plus alerts, events, notes, history. Missing
            optional values (empty summary, no notes, None fields) print as
            "-" or a short sentence; they never stop the report.
        config (dict) - the configuration dictionary. It is only checked to
            be a dictionary; nothing in it changes the layout in version 1.
    Output: bytes - a PDF file (starts with %PDF).
    Steps:
        1. Check the shape of the arguments.
        2. Build the sections: header (INC- ID, status, priority, times),
           summary and the "detections are not proof" statement, alert
           table, one evidence block per alert, notes, status history,
           recommended actions.
        3. In each alert block print the general events table (at most 50
           rows) with its total/shown/not-shown line, and for alerts with
           linked successes a separate detail table (at most 10 rows) with
           its own line. Omitted rows are counted, never hidden.
        4. Build the PDF twice: the first pass counts the pages so that the
           second pass can print "Page N of M".
    Example: an incident with one alert of 120 events -> the events table
        has 50 rows and the line "This table shows 50 of 120 supporting
        events; 70 are not shown here. ...".
    Errors: ReportError if the arguments have the wrong shape or ReportLab
        cannot build the document.
    """
    _check_incident_details(incident_details, config)
    styles = _make_styles()
    generated_text = _format_time(utc_now().replace(microsecond=0))
    incident_label = format_incident_id(incident_details["incident_id"])
    footer_text = "Network Sentinel - " + incident_label + " - generated " + generated_text + " UTC"
    title = "Network Sentinel incident report " + incident_label
    try:
        first_story = _build_incident_story(incident_details, generated_text, styles)
        ignored_pdf, page_count = _render_once(first_story, title, footer_text, "?")
        # ReportLab uses up the flowables while building, so make a fresh list.
        second_story = _build_incident_story(incident_details, generated_text, styles)
        final_pdf, page_count = _render_once(second_story, title, footer_text, str(page_count))
    except ReportError:
        raise
    except Exception as error:
        raise ReportError("Could not build the incident report: " + str(error)) from error
    return final_pdf


# ---------------------------------------------------------------
# Alert summary report (current analysis session)
# ---------------------------------------------------------------

def _check_summary_arguments(alerts, analysis_summary, config):
    """Check the shape of the arguments of build_alert_summary_pdf."""
    if not isinstance(config, dict):
        raise ReportError("config must be a dictionary")
    if not isinstance(analysis_summary, dict):
        raise ReportError("analysis_summary must be a dictionary")
    if not isinstance(alerts, list):
        raise ReportError("alerts must be a list")
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ReportError("alerts must contain only dictionaries")


def _alert_sort_key(alert):
    """Most severe first, then earliest time, then alert ID."""
    try:
        rank = severity_rank(alert.get("severity"))
    except ValueError:
        rank = 0
    return (-rank, _format_time(alert.get("time_start")), str(alert.get("alert_id")))


def _analysis_facts(alerts, analysis_summary, config):
    """The key/value facts printed at the top of the summary."""
    trusted_ips = config.get("trusted_ips")
    if not isinstance(trusted_ips, list) or len(trusted_ips) == 0:
        trusted_text = "none"
    else:
        trusted_text = ", ".join([str(address) for address in trusted_ips])
    return {
        "Analysis run at (UTC)": _format_time(analysis_summary.get("analysed_at")),
        "Events analysed": analysis_summary.get("events_analysed"),
        "Events ignored (trusted addresses)": analysis_summary.get("events_ignored_trusted"),
        "Alerts in this report": len(alerts),
        "Base alerts (from analysis)": analysis_summary.get("base_alert_count"),
        "Correlated alerts (from analysis)": analysis_summary.get("correlated_alert_count"),
        "Trusted addresses configured": trusted_text,
    }


def _severity_count_flowables(alerts, styles):
    """A small table with the number of alerts per severity."""
    counts = {}
    for severity in SEVERITIES:
        counts[severity] = 0
    other_count = 0
    for alert in alerts:
        if alert.get("severity") in counts:
            counts[alert["severity"]] = counts[alert["severity"]] + 1
        else:
            other_count = other_count + 1
    if other_count > 0:
        counts["other"] = other_count
    return [Paragraph("Alerts by severity", styles["subheading"]), _key_value_table(counts, styles)]


def _summary_alert_rows(sorted_alerts, styles):
    """Table of all alerts for the summary, with the number of supporting events."""
    rows = [_header_row(
        ["Alert ID", "Rule", "Severity", "Confidence", "Time range (UTC)", "Source", "Events"], styles
    )]
    for alert in sorted_alerts:
        event_ids = alert.get("event_ids")
        event_count = None
        if isinstance(event_ids, list):
            event_count = len(event_ids)
        rows.append([
            _cell(alert.get("alert_id"), styles, 30),
            _cell(alert.get("rule_id"), styles, 40),
            _cell(alert.get("severity"), styles, 20),
            _cell(alert.get("confidence"), styles, 20),
            _cell(_time_range_text(alert), styles, 80),
            _cell(alert.get("source_ip"), styles, 45),
            _cell(event_count, styles, 10),
        ])
    return rows


def _summary_findings_flowables(sorted_alerts, styles):
    """A short paragraph per alert: title, description and recommended action."""
    flowables = [Paragraph("Findings", styles["heading"])]
    for alert in sorted_alerts:
        flowables.append(Paragraph(
            _safe(alert.get("title"), 100) + " (" + _safe(alert.get("alert_id"), 30) + ")", styles["subheading"]
        ))
        flowables.append(Paragraph("<b>Description:</b> " + _safe_multiline(alert.get("description")), styles["body"]))
        flowables.append(Paragraph(
            "<b>Recommended action:</b> " + _safe_multiline(alert.get("recommended_action"), 800), styles["body"]
        ))
    return flowables


def _build_summary_story(alerts, analysis_summary, config, generated_text, styles):
    """The full list of flowables of the analysis summary."""
    sorted_alerts = sorted(alerts, key=_alert_sort_key)
    story = [Paragraph("Network Sentinel - Analysis Summary", styles["title"])]
    story.append(Paragraph("Report generated (UTC): " + generated_text, styles["body"]))
    story.append(Paragraph(
        "This summary covers the current analysis session. Alerts listed here may not be saved in the "
        "database, and supporting events are not listed: only the number of events per alert is shown.",
        styles["body"],
    ))
    story.append(Paragraph(_DISCLAIMER, styles["small"]))
    story.append(_key_value_table(_analysis_facts(alerts, analysis_summary, config), styles))
    story.extend(_severity_count_flowables(alerts, styles))
    story.append(Paragraph("Analysis notes", styles["heading"]))
    notes = analysis_summary.get("notes")
    if isinstance(notes, list) and len(notes) > 0:
        for note in notes:
            story.append(Paragraph(_safe(note, 600), styles["bullet"], bulletText="-"))
    else:
        story.append(Paragraph("No analysis notes were recorded (no rule was skipped).", styles["body"]))
    story.append(Paragraph("Alerts", styles["heading"]))
    if len(sorted_alerts) == 0:
        story.append(Paragraph("No alerts were produced in this analysis.", styles["body"]))
        return story
    story.append(_make_table(_summary_alert_rows(sorted_alerts, styles), [84, 88, 44, 48, 140, 79, 40]))
    story.extend(_summary_findings_flowables(sorted_alerts, styles))
    return story


def build_alert_summary_pdf(alerts: list, analysis_summary: dict, config: dict) -> bytes:
    """
    Purpose: build a PDF summary of the current analysis session.
    Inputs:
        alerts (list of dict) - the alerts to include (alert dictionaries).
        analysis_summary (dict) - the run_analysis result (keys such as
            analysed_at, events_analysed, events_ignored_trusted,
            base_alert_count, correlated_alert_count, notes). Missing keys
            print as "-".
        config (dict) - the configuration dictionary (its trusted_ips list
            is printed).
    Output: bytes - a PDF file (starts with %PDF).
    Steps:
        1. Check the shape of the arguments.
        2. Print the title, a statement that detections are not proof, the
           analysis facts, alert counts per severity and the analysis notes
           (for example skipped rules).
        3. Print one table with every alert (most severe first) and the
           NUMBER of supporting events of each; the events themselves are
           not listed in this summary, and the report says so.
        4. Print a short finding for each alert. Build twice for page numbers.
    Example: build_alert_summary_pdf(result["alerts"], result, config)[:4] == b"%PDF".
    Errors: ReportError if the arguments have the wrong shape or ReportLab
        cannot build the document.
    """
    _check_summary_arguments(alerts, analysis_summary, config)
    styles = _make_styles()
    generated_text = _format_time(utc_now().replace(microsecond=0))
    footer_text = "Network Sentinel - analysis summary - generated " + generated_text + " UTC"
    title = "Network Sentinel analysis summary"
    try:
        first_story = _build_summary_story(alerts, analysis_summary, config, generated_text, styles)
        ignored_pdf, page_count = _render_once(first_story, title, footer_text, "?")
        second_story = _build_summary_story(alerts, analysis_summary, config, generated_text, styles)
        final_pdf, page_count = _render_once(second_story, title, footer_text, str(page_count))
    except ReportError:
        raise
    except Exception as error:
        raise ReportError("Could not build the analysis summary: " + str(error)) from error
    return final_pdf
