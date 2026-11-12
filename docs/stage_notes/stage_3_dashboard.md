**Network Sentinel, Stage 3 learning pack: dashboard implementation (initial mock-backend phase).** This is a historical development handover explaining the dashboard code. Final integration has since been completed; `dashboard/backend_calls.py` is configured with `USE_MOCK_BACKEND = False`, and the normal application uses the real backend modules. The mock backend remains available only for controlled development and tests. The mock-mode descriptions and Stage 4 references below document the earlier development phase, not the final runtime configuration.

## 1. Code walkthrough

Data flows like this: `app.py` starts the app, a page function draws the screen, the page calls `dashboard/backend_calls.py`, and that file calls either the mock (now) or the real modules (Stage 4). The files are covered in that order.

**app.py**

- **Purpose:** the entry point (`streamlit run app.py`). It sets the page, applies the theme, creates the session keys, makes sure the database exists, draws the sidebar and calls exactly one `render_*_page` function.
- **Inputs / outputs:** none. It runs top to bottom every time the user clicks something (this is how Streamlit works).
- **Important lines:** `page_name = st.sidebar.radio("Navigate", PAGE_NAMES, key="navigation")` picks the page, then an `if/elif` chain calls the matching function with `(current_config, DATABASE_PATH)`, as FS.4 requires.
- **Limitations:** it contains no detection logic and no SQL. A `DatabaseError` while opening the database stops the app with a red message.

**dashboard/theme.py**

- **Purpose:** the only place where colours are defined (Section G.1) and the CSS for cards, badges and banners. `apply_theme()` is an FS.4 public function.
- **Logic:** the CSS template contains markers such as `@RED@`, and `build_css` swaps each marker for the matching constant. Example: `.ns-badge-critical` becomes a filled `#E5484D` badge, and `.ns-badge-high` becomes a red outline.
- **Limitations:** the CSS is plain text injected with `unsafe_allow_html=True`. That is safe only because the text is written by us and holds no log data.

**dashboard/components.py**

- **Purpose:** small pieces shared by every page: the session keys, badges, metric cards, sorting and filtering helpers, table builders and the alert detail panel.
- **Important functions:**
  - `initialise_session_state` adds each FS.5 key only if it is missing, so it never overwrites existing data.
  - `severity_badge_html` and `confidence_text_html` build badges. Everything goes through `html.escape`, so a hostile value such as `<script>` is shown as plain text.
  - `sort_alerts_for_display`, `filter_alerts`, `count_by_severity`, `top_sources` and `group_alerts_by_hour` are plain list-and-dictionary functions with no Streamlit inside, so they are easy to test.
  - `render_alert_details` draws the evidence panel: explanation, limitations, thresholds, observed values, success and correlation panels, recommended action, then the events table and raw rows.
- **Worked example (sorting):** the sort key is

```python
    return (-severity_rank(alert["severity"]), -alert["time_start"].timestamp())
```

  Python sorts tuples item by item. The minus signs make the highest severity come first, and then the newest time first. A critical alert at 09:15 sorts before a high alert at 10:00.
- **Limitations:** table columns that mix numbers and blanks confuse Streamlit's table engine, so port and byte columns are turned into text. Dataframes cannot show HTML, so severity in tables is coloured with a pandas Styler and also written in capital letters.

**dashboard/backend_calls.py**

- **Purpose:** the ONE place where the dashboard talks to the backend. Each function has the same name and parameters as its FS.4 original, so a page written against it is already written against the final API.
- **The switch:** `USE_MOCK_BACKEND = True` at the top. Every wrapper has the same two-branch shape:

```python
    if USE_MOCK_BACKEND:
        return mock_backend.mock_ingest_file(file_bytes, file_name, log_type, config)
```

  and, below it, a lazy import of the real function from `ingestion.csv_ingest` and a call with the same arguments. The real modules are imported inside the function, so this file loads even while those modules do not exist.
- **Stage 4 change:** set `USE_MOCK_BACKEND = False`, delete `mock_backend.py`, and run the tests.
- **Limitations:** the real branch is tested only with stand-in modules that record their arguments. It has not run against real code, because the real code does not exist yet.

**dashboard/mock_backend.py (TEMPORARY, deleted at Stage 4)**

- **Purpose:** stand-ins for ingestion, detection, storage and reporting, returning exactly the shapes of FS.4, Section C and Section D. It never reads the uploaded bytes: it returns a fixed scenario that matches `data/sample/*.csv` and `expected_results.json`.
- **What it does:**
  - `mock_ingest_file` and `mock_combine_ingestion_results` return events built with `make_event`, named after the uploaded file, so IDs differ between files exactly as D2 says.
  - `mock_run_analysis` builds the five sample alerts with `make_alert`. It honours trusted addresses and copies thresholds into `rule_parameters`, but it does not recompute detection.
  - The storage functions keep a dictionary in `st.session_state["mock_database"]`. They follow R1.2 (adding missing base alerts, raising `BrokenReferenceError`), the C.3 status table and R2.5 (an incident links the base alerts of a correlated alert).
  - The PDF functions write a tiny valid PDF that says MOCK.
- **Limitations:** the mock database disappears on refresh and is not a real database, which is intentional. The mock analysis ignores most thresholds.

**dashboard/page_overview.py**

- **Purpose:** the Overview. It shows two clearly separated groups of numbers, "This session" and "Saved in database", and never adds them (R1.6, because one alert can be in both). It also shows alerts by severity, an alerts-over-time chart, the top five sources, recent activity and the analysis notes.
- **Inputs / outputs:** `render_overview_page(config, db_path)`. It reads the session keys and calls `get_summary_counts` and `list_incidents`.
- **Limitations:** the chart groups alerts by the hour of their first event. A `DatabaseError` is shown as a warning and the session numbers still appear.

**dashboard/page_upload.py**

- **Purpose:** the Log Upload page with two tabs. "Upload and validate" has the uploaders, the settings editor and the file feedback. "Analysis" has the metrics, the detection summary, correlated alerts and skipped-source notes. The Analysis part is a tab, not a sixth page, because FS.4 defines exactly five page functions.
- **Important function:** `run_upload_pipeline(file_specs, config)` calls `ingest_file` for each file, `combine_ingestion_results` once, and `run_analysis` if there are events. A bad file is recorded as an error and the good files still go on.
- **Worked example:** one corrupt `notes.txt` and one good network file give `errors` with 1 message, 52 events and a finished analysis. The dashboard builds each file card itself:

```python
        summary = dict(result["summary"])
```

  It copies the D.6 summary and adds `file_name` and `log_type`, because the summary has no file name. A failed file gets an `error` entry instead.
- **Limitations:** overlap and duplicate warnings from `combine_ingestion_results` are appended to the first file card, because FS.5 has no session key for them.

**dashboard/page_alerts.py**

- **Purpose:** review alerts in two views chosen by `alerts_view`: the current analysis, and the alerts saved in the database. Filters, a sorted table, selection, save, create incident, and the detail panel.
- **Important lines:** save always passes the FULL session lists:

```python
        result = backend_calls.save_alerts(db_path, selected_alerts, st.session_state["events"], all_alerts)
```

  The dashboard never works out which base alerts belong to a correlated alert; storage does and reports it.
- **Logic:** the unsaved banner and the table are drawn AFTER the save and incident buttons have run, using reserved containers. Otherwise the banner would still say "5 unsaved" for one more click after saving. A test found this bug.
- **Limitations:** raw rows are shown for the first 20 events only (the full table has every event).

**dashboard/page_investigations.py** (labelled "Incidents" in the sidebar)

- **Purpose:** the incident list with a status filter, and for the chosen incident: summary, priority, linked alerts, evidence events, notes (oldest first), history, a note form, a status selector and a way to add more saved alerts.
- **Important lines:** the status selector cannot offer an illegal move:

```python
    allowed_moves = ALLOWED_STATUS_TRANSITIONS[details["status"]]
```

  From `resolved` the only choice is `investigating`. `InvalidStatusTransition` and `IncidentNotFound` still have friendly messages as a second safety net.
- **Limitations:** after a change the page calls `st.rerun()` and a short toast confirms it.

**dashboard/page_reports.py**

- **Purpose:** PDF download buttons for an incident and for the current analysis. The summary button is disabled, with a message, until an analysis exists.
- **Limitations:** the PDF bytes are rebuilt every time the page is drawn for the chosen incident. This is simple and fine while reports are small.

**tests/test_dashboard.py**

- **Purpose:** 56 tests. They drive the real `app.py` with Streamlit's `AppTest` (click buttons, choose options, read what is on the page), check the helper functions, the theme, the "no SQL and no detection logic" boundaries, the FS.4 signatures, the real-mode call order, and the mock's data shapes.
- **Limitations:** `AppTest` cannot upload a file, so uploads are tested through the sample-files button and through `run_upload_pipeline`. It also cannot show how the page looks, so the look was not checked in a browser here.

## 2. Key concepts introduced in this stage

- **Streamlit's rerun model:** the whole script runs again after every click, so anything that must survive is kept in `st.session_state`.
- **Session state versus saved data:** session data is lost on refresh; saved data lives in the database. The dashboard never merges the two counts.
- **Adapter (bridge) module:** `backend_calls.py` hides which backend is behind it, so pages do not change when the mock is replaced.
- **Mock data:** fake but correctly shaped data, clearly marked and kept in one deletable file.
- **Lazy import:** importing inside a function so the file loads even when the imported module does not exist yet.
- **Escaping:** `html.escape` turns `<` into `&lt;` so log text can never become HTML.
- **Separation of concerns:** pages draw; helpers sort and filter; the backend decides what is suspicious or saved.
- **Reserved containers:** `st.container()` keeps a place on the page that can be filled later in the script.
- **Callback versus rerun:** a button `on_click` function runs before the rerun, which is the only safe time to change a widget's value.
- **Forms:** values typed into an `st.form` only count when the form is submitted.
- **AppTest:** driving the app from Python in a test, like a user would.

## 3. Questions for the reader

1. Why is the mock isolated in one file, and why does `backend_calls.py` use the FS.4 names exactly?
2. What happens, step by step, when you click "Use the sample files"? Name each backend call in order.
3. Why does the Overview show "This session" and "Saved in database" separately and never add them?
4. Why does save pass the full list of session alerts and events, even when only one alert is selected?
5. Why is the Analysis a tab on the Log Upload page and not a sixth page?
6. Why are log values passed through `html.escape`, and where is `unsafe_allow_html` still used?
7. Why does the status selector offer only some statuses? Where does the list come from?
8. Why are the banner and table drawn after the buttons in `render_alerts_page`?
9. **Edge case:** one uploaded file is corrupt and the other is good. What does the user see, and is the good file analysed?
10. **Edge case:** the same file is added twice. What does `combine_ingestion_results` report, and where does the dashboard show it?
11. **Edge case:** the user saves only a correlated alert. How many alerts end up saved, and which message appears?
12. **Edge case:** the user restarts the app after saving. What is lost, and what still works on the Alerts, Incidents and Reports pages?
13. **Edge case:** an incident is `resolved`. Which status changes can the user make, and what would happen if the backend were called with `open` anyway?

## 4. A small practical modification exercise

About 30 minutes. Do this on a **scratch copy** of the project.

1. In `dashboard/components.py`, find `filter_alerts`. Add a new rule so that `source_text` also matches the alert title (use `alert["title"]`, in lower case for both sides).
2. In `tests/test_dashboard.py`, find `test_sorting_filtering_and_counting_alerts`. Add one assertion: `filter_alerts(alerts, source_text="port scanning")` returns 1 alert.
3. Run `python -m pytest tests/test_dashboard.py -v`. **Expected result:** all tests pass.
4. Run the app (`streamlit run app.py`), load the sample files, open Alerts, and type `scanning` in the source box. Describe what you see, and why the box label "Source address contains" would now be wrong.
5. Write two sentences: why is this safe to change in the dashboard, while changing a key in an alert dictionary would not be?
6. Throw the scratch copy away.

## 5. Concepts to study before moving to the next stage

- How `st.session_state`, widget `key`s and `on_click` callbacks work, and why a widget value cannot be set after the widget is drawn.
- `st.form`, `st.tabs`, `st.container` and `st.rerun`.
- pandas DataFrames and Styler (what a column type is and why mixed types cause trouble).
- `html.escape` and why untrusted text must never be inserted into HTML.
- Python's `importlib` idea behind lazy imports (importing inside a function) and how `sys.modules` stand-ins work in tests.
- The integration requirement: what must be true before `USE_MOCK_BACKEND` can become `False` (the real modules exist and follow FS.4 exactly).
