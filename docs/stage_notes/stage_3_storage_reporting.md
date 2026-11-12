This note covers Stage 3: the SQLite storage layer, incident management and the PDF reports. It explains what the code does and why, in the order you would read it. Read the code next to this note.

## 1. Code walkthrough

### The big picture

Network Sentinel keeps two kinds of data.

- **Session data** (uploaded events, analysis results, unsaved alerts) lives in memory. It disappears when the browser session ends.
- **Saved data** (alerts you chose to save, the events those alerts point to, incidents, notes, history) lives in the SQLite file `data/network_sentinel.db`. It is still there after you restart the app.

SQLite is **not** a log archive. We never store every uploaded event, only the ones a saved alert needs as evidence.

```
dashboard  ->  storage/database.py   ->  data/network_sentinel.db
                       ->  storage/incidents.py  ->  (same file)
                       ->  reporting/pdf_report.py -> PDF bytes (no database access)
```

Only `storage/` contains SQL. Only `reporting/` imports ReportLab. Neither imports Streamlit. The tests check these rules.

### storage/database.py

| Function | What it does |
|---|---|
| `get_connection(db_path)` | Opens the file, switches on foreign keys, lets us read columns by name. |
| `initialise_database(db_path)` | Creates the 8 tables and 10 indexes (safe to run many times). |
| `save_alerts(...)` | Saves alerts, their events and the links between alerts, all-or-nothing. |
| `get_alerts`, `get_alert` | Read saved alerts back as the same dictionaries the rules produced. |
| `get_events_for_alert` | Reads an alert's stored events, oldest first, no cap. |
| `get_existing_alert_ids` | Tells the dashboard which session alerts are already saved. |
| `get_summary_counts` | Totals for the Overview page. |

**The eight tables.**

- `events` holds one row per *saved* event. `raw_event_json` keeps the original row.
- `alerts` holds one row per saved alert. `evidence_json` keeps the evidence dictionary as text.
- `alert_events` says which events belong to which alert. `position` remembers the original order.
- `alert_links` says which base alerts a correlated alert was built from.
- `incidents`, `incident_alerts`, `incident_notes`, `incident_history` hold incident data.

**Reading `save_alerts`.** It is a pipeline of small steps, and every *check* happens before the first *write*:

1. Validate the chosen alerts with `validate_alert`.
2. For every correlated alert, find each linked base alert: first in the chosen list, then in `available_alerts` (the whole session), then in the database. A missing one raises `BrokenReferenceError`.
3. Check every event ID an alert uses is either in the session events or already in the database.
4. Write events, base alerts, correlated alerts, `alert_events` rows, `alert_links` rows, in that order (foreign keys need the parent row to exist first).
5. Commit. If *anything* went wrong, roll back.

`INSERT OR IGNORE` is how duplicates are handled. Alert and event IDs are built from their content, so the same alert always gets the same ID. Saving it again is silently skipped and reported as `alerts_skipped_duplicate`. An existing alert is never overwritten.

### storage/incidents.py

| Function | What it does |
|---|---|
| `create_incident` | Creates an `open` incident, links alerts, writes one `created` history row. |
| `add_alerts_to_incident` | Links more alerts, one `alert_added` history row each. |
| `update_incident_status` | Applies an allowed status change, sets or clears `closed_at`, writes history. |
| `add_note` | Adds a note, updates `updated_at`, writes a `note_added` history row. |
| `get_incident`, `list_incidents` | Read incidents. |
| `get_incident_details` | The full bundle the dashboard and PDF need: incident, alerts, events, notes, history. |

Rules worth remembering:

- Every alert you link must already be saved. Otherwise `BrokenReferenceError`, and nothing is created.
- If you link a correlated alert, its base alerts are linked automatically, so the incident is never missing half the story.
- If you do not give a priority, it is the highest severity among all linked alerts. Adding alerts later never changes it.
- Status changes must follow `ALLOWED_STATUS_TRANSITIONS`. A resolved incident can only go back to `investigating`.
- There is **no delete function** anywhere. That is a deliberate v1 decision (D8).

### reporting/pdf_report.py

Two public functions: `build_incident_report_pdf` and `build_alert_summary_pdf`. Both return `bytes`; the dashboard decides what to do with them (for example a download button).

The incident report has these parts: header with `INC-0007` style ID, summary and the "detections are not proof" statement, a table of alerts, one evidence block per alert, notes, status history, recommended actions.

**The counting rules (FS.10 C).** For each alert there are two tables with two separate limits and two separate sentences:

- General events table: at most **50** rows. Sentence: `This table shows 50 of 120 supporting events; 70 are not shown here. ...` (or `shows all N` when nothing is left out).
- Authentication success detail table: at most **10** rows. Sentence: `Authentication successes linked to this alert: 15. Shown in this detail table: 10 (limit 10). Not shown in this table: 5.`

The success sentence never says *where* the other five are. That is on purpose: the general table can be cut at 50 rows too, so the five might not appear anywhere. The two sentences are built by `_events_table_line` and `_success_table_line`. They take plain numbers and return text, which makes them easy to test.

**Safety.** Report text can contain anything an attacker typed into a log (a username like `<b>x</b>`). ReportLab paragraphs read tags such as `<b>`, so every outside value goes through `_safe()` first: control characters become spaces, long text is clipped, and `& < >` are escaped. The test `test_markup_in_log_data_is_printed_literally` proves this.

**Page numbers.** "Page 2 of 5" needs the total before printing page 1. The report is built twice: the first pass only counts pages; the second pass prints them.

## 2. Key concepts introduced in this stage

**Persistence.** Data is *persistent* if it survives the program stopping. Variables are not. A file on disk is. SQLite is a database stored in one ordinary file; Python includes it (`import sqlite3`), so no server is needed.

**Tables, rows, primary keys.** A table is like a spreadsheet sheet. Each row is one record. A *primary key* is the column that identifies a row (for example `alert_id`). No two rows can share it. That is what makes duplicate detection easy.

**Foreign keys.** A column that points at a row in another table. `alert_events.event_id` must match a real `events.event_id`. SQLite only enforces this if you run `PRAGMA foreign_keys = ON` on **every connection**, which `get_connection` does. Without it, SQLite would happily store a link to nothing.

**Parameterised queries (preventing SQL injection).** Compare:

```python
# DANGEROUS: the user's text becomes part of the SQL command
connection.execute("SELECT * FROM alerts WHERE source_ip = '" + user_text + "'")

# SAFE: the ? is a slot; the value is sent separately and is only ever data
connection.execute("SELECT * FROM alerts WHERE source_ip = ?", (user_text,))
```

If `user_text` is `' OR '1'='1`, the dangerous version returns every row. The safe version looks for an address literally spelled `' OR '1'='1` and finds none. Our tests store the text `x'); DROP TABLE alerts;--` as a title and show the table survives. You cannot use `?` for table or column names, so `get_alerts` only accepts filter names from a fixed list that we wrote.

**Transactions.** A transaction groups several writes into one unit: **all happen or none do**. Imagine saving a correlated alert: events, two base alerts, the correlated alert, links. If the power fails after the base alerts but before the links, you would have half an answer. With a transaction, SQLite undoes the partial work (`ROLLBACK`). The pattern in this project:

```python
connection.execute("BEGIN IMMEDIATE")   # start; take the write lock
... checks and inserts ...
connection.execute("COMMIT")            # make it all permanent
# on any error: ROLLBACK, then re-raise the error
```

We open the connection with `isolation_level=None` so Python does not start transactions secretly; every BEGIN and COMMIT is written where you can see it.

**`INSERT OR IGNORE`.** "Insert this row, but if the primary key already exists, skip it quietly." `cursor.rowcount` tells us whether the row was really inserted (1) or skipped (0), which is how we count duplicates. Caution: it also ignores a row that breaks a `CHECK` or `NOT NULL` rule. That is why we validate alerts and events *first*.

**Storing structured data as JSON text.** `evidence` is a dictionary with a different shape for each rule. Instead of one table per rule, we store it as JSON text with `canonical_json` and read it back with `json.loads`. Times are stored as ISO text (`2025-03-14T09:15:02.000000+00:00`) and converted back to `datetime` objects when read.

**Custom exceptions as a contract.** `BrokenReferenceError`, `IncidentNotFound`, `InvalidStatusTransition`, `DatabaseError`, `ReportError` say *what* went wrong, so the dashboard can show a clear message instead of crashing. Storage converts raw `sqlite3.Error` into `DatabaseError` so the dashboard never needs to import `sqlite3`.

**PDF generation with ReportLab.** You build a *story*: a list of *flowables* (`Paragraph`, `Table`, `Spacer`). ReportLab places them on pages and starts a new page when one is full. `Table(..., repeatRows=1)` repeats the header row on each page. We use only the built-in font Helvetica, so nothing needs to be installed or embedded. Characters Helvetica cannot draw (some emoji, many non-Latin letters) may show as boxes. That is a known limitation (D9).

**Testing with temporary databases.** pytest's `tmp_path` gives every test its own empty folder. Tests never touch `data/network_sentinel.db`.

**Fault injection.** To prove rollback works, a test uses `monkeypatch` to replace one write step with a function that raises an error, then checks every table is still empty.

## 3. Questions for the reader

Try to answer each one aloud before reading the answer.

**Q1. Why does the project store only the events that saved alerts reference, not every uploaded event?**
A. A log file can hold hundreds of thousands of rows. The database is for evidence the analyst decided to keep. Keeping everything would make the database huge and turn the tool into a log archive, which is not its job. Unsaved events stay in the session.

**Q2. What is a parameterised query and what attack does it stop?**
A. It is an SQL command with `?` placeholders; the values are passed separately. The database treats them as data only, never as SQL. It stops SQL injection, where an attacker hides SQL commands inside text such as a username.

**Q3. Why can't we use `?` for a column name, and what do we do instead?**
A. Placeholders only stand in for *values*. For optional filters in `get_alerts`, the column names come from a whitelist list written in our code; any other filter name is refused. User input never becomes SQL text.

**Q4. What is a transaction, and what does `ROLLBACK` do?**
A. A transaction is a group of database changes treated as one unit. `COMMIT` makes them permanent; `ROLLBACK` throws all of them away. We use it so a failed save never leaves half an alert (for example base alerts without their links).

**Q5. Where in `save_alerts` do the checks happen, and why before the writes?**
A. Inside the transaction but before the first INSERT: validation, link resolution, event existence. If a check fails we raise an error and nothing has been written. Even so, the `except` block rolls back as a safety net.

**Q6. What does `INSERT OR IGNORE` do here, and what is its danger?**
A. It skips a row whose primary key already exists, which gives us duplicate handling. The danger is that it also silently skips rows that break `CHECK` or `NOT NULL` rules, so we validate everything before inserting.

**Q7. Why do `get_connection` and the tests care about `PRAGMA foreign_keys = ON`?**
A. SQLite ignores foreign keys by default, per connection. Without it a link to a missing alert would be accepted. A test inserts a bad link directly and expects `IntegrityError`.

**Q8. What happens if you save a correlated alert but its base alerts are nowhere (not chosen, not in the session, not in the database)?**
A. `BrokenReferenceError` is raised and nothing is written. If the base alerts are in `available_alerts`, they are added automatically and their IDs are returned in `base_alerts_added_automatically`.

**Q9. How does the program know an alert was already saved?**
A. Alert IDs are built from the alert's content (rule, source, time range, event IDs), so the same alert always has the same ID. The alerts table's primary key then rejects the second copy. This works even after a restart and a fresh analysis of the same files.

**Q10. What does "persistence after restart" mean and how is it tested?**
A. Saved data must still be there when the program starts again. The test saves data, throws away every Python object, then reads using only the file path, once with raw `sqlite3` and once with our functions.

**Q11. Why is there no function to delete an incident or alert?**
A. A v1 design decision (D8): an incident history should not be erasable, and an accidental delete would destroy evidence. A test checks that no function name starts with `delete`, `remove` or `clear` and that the source has no `DELETE FROM`.

**Q12. Which status changes are allowed for an incident? What happens to `closed_at`?**
A. open to investigating, resolved or false_positive; investigating to open, resolved or false_positive; resolved or false_positive back to investigating only. `closed_at` is set when the new status is resolved or false_positive and cleared when the incident is reopened. Any other change, including "same status again", raises `InvalidStatusTransition`.

**Q13. In the PDF, an alert has 120 supporting events and 15 authentication successes. What does the report say?**
A. The general table shows 50 rows with "This table shows 50 of 120 supporting events; 70 are not shown here..." and the success table shows 10 rows with "Authentication successes linked to this alert: 15. Shown in this detail table: 10 (limit 10). Not shown in this table: 5." The two sets of numbers are separate.

**Q14. Why must the report never say the five omitted successes are "in the events table"?**
A. The events table is itself limited to 50 rows, so they may not be there. Claiming they are would be false evidence. The report only states what is shown and what is not shown.

**Q15. Why is every value escaped before going into a ReportLab `Paragraph`?**
A. Paragraphs interpret tags like `<b>`. A username such as `<b>admin</b>` or a broken tag could change the formatting or crash the build. Escaping `& < >` makes it print literally.

**Q16. Why is the report built twice?**
A. To print "Page N of M" the total page count must be known first. Pass one counts pages; pass two prints them. ReportLab uses up the flowables, so a fresh list is built for each pass.

## 4. A small practical modification exercise

**Task.** Change the general events table limit from 50 rows to 25 rows.

1. Open `reporting/pdf_report.py` and find `MAX_EVENT_ROWS = 50`. Change it to `25`.
2. Run `python -m pytest tests/test_reporting.py -q`. Several tests fail. Read the failure messages. Each one expects `50`.
3. Decide which tests describe the *specification* (the frozen spec says 50) and which describe your *experiment*. In a real project you would not change a frozen number without changing the specification first.
4. Update the tests that mention 50 to use 25, rerun, and confirm they pass.
5. Look at the PDF: build one with 40 events and read the sentence. It should now say `25 of 40 ... 15 are not shown here`.
6. **Put it back to 50** and rerun all tests so the project matches the specification again.

**Extension (optional).** Add a "Bytes sent" column to the general events table. You will need to change `_event_row`, the header list and the `widths` list in `_events_flowables` (the widths must add up to about 523). Predict first: will the 50-row limit change? (No, only the columns.)

**Hint for step 3.** Run `python -m pytest tests/test_reporting.py -q -k "fifty"` to see just the limit tests.

## 5. Concepts to study before moving to the next stage

- **The dashboard calling storage.** Public functions take `db_path` and return dictionaries; the dashboard never sees `sqlite3`. Think about which errors the dashboard must catch (`DatabaseError`, `BrokenReferenceError`, `IncidentNotFound`, `InvalidStatusTransition`, `ReportError`) and what message it should show.
- **Streamlit session state.** The dashboard keeps unsaved alerts and events in `st.session_state`. Learn how it works and why session data is lost on refresh while saved data is not.
- **Streamlit `download_button`.** It takes `bytes`, which is what the PDF functions return.
- **More SQL.** `SELECT ... WHERE`, `JOIN`, `GROUP BY`, `ORDER BY`. Try them on a test database with the `sqlite3` command line or Python.
- **Primary key vs foreign key vs index.** Be able to explain each in one sentence.
- **ACID.** Atomicity, Consistency, Isolation, Durability: the four promises of a database transaction. You have used atomicity directly.
- **Python `datetime` and time zones.** Why every stored time is UTC and timezone-aware, and what `iso_to_datetime` does.
- **Escaping and injection in general.** SQL injection (this stage) and markup injection (the PDF) are the same idea: untrusted text must never be treated as instructions.
- **Reading a traceback.** When a test fails, practise reading from the bottom up.
- **The frozen specification.** Re-read FS.5 (database rules), FS.6 (acceptance) and FS.10 (clarifications) and find, for each rule, the test that proves it.
