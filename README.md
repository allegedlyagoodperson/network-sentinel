# Network Sentinel

**Network Security Monitoring and Incident Reporting System**  
**Contract version:** 1.0  
**Project type:** Local academic prototype

## Overview

Network Sentinel is a local, rule-based application for reviewing supported authentication and network-connection CSV logs. It validates and normalises uploaded records, applies explainable detection rules, correlates qualifying alerts across log sources, and presents findings in a Streamlit dashboard. Analysts can save selected alerts and their supporting events in SQLite, organise alerts into incidents, record investigation notes and status changes, and generate PDF reports.

An alert is an indicator that requires human review. It is not proof that an attack occurred. Network Sentinel does not automatically block traffic, disable accounts, or prevent attacks.

## Main capabilities

- **CSV ingestion:** validates supported authentication and network-connection CSV files, normalises field values, and reports rejected rows.
- **Detection:** applies rules for repeated failed logins, possible port scanning, repeated rejected connections, and unusually high traffic volume.
- **Correlation:** links qualifying authentication and network alerts when the defined source-address and time conditions are met.
- **Alert review:** displays alerts, evidence, severity, confidence, rule parameters, and limitations.
- **Incident management:** saves selected alerts and referenced evidence, creates incidents, records notes, and tracks status history.
- **PDF reporting:** generates alert-summary and incident reports.

## Technology

- Python 3.10 or newer
- Streamlit 1.65.0
- SQLite (Python standard library)
- ReportLab 5.1.0
- pytest 9.2.0

## Project structure

```text
app.py
config/                 Configuration defaults and validation
core/                   Shared event/alert contracts and exceptions
ingestion/               CSV parsing, validation and normalisation
detection/               Detection rules and analysis engine
correlation/             Cross-source alert correlation
storage/                 SQLite persistence and incident management
reporting/               PDF report generation
dashboard/               Streamlit pages and backend interface
data/sample/              Synthetic example CSV files
docs/stage_notes/         Development learning notes
tests/                    Automated tests and test fixtures
requirements.txt
```

## Installation

1. Install Python 3.10 or newer.
2. Download or clone this repository.
3. Open a terminal in the repository folder.
4. Create and activate a virtual environment (recommended).

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, use the environment's Python executable directly, for example `.\.venv\Scripts\python.exe`.

## Run the application

From the project root:

```powershell
python -m streamlit run app.py
```

Streamlit will print a local address to open in a browser. The application creates its SQLite database at `data/network_sentinel.db` on first run. The database is runtime data and is intentionally excluded from source distributions.

The standard configuration uses the real ingestion, detection, storage and reporting modules. A deterministic mock backend is retained for controlled development and testing, but it is disabled by default.

## Run the tests

```powershell
python -m pytest -q
```

The project test suite covers shared contracts, CSV ingestion, detection, correlation, dashboard behaviour, storage, incident management and PDF reporting. The integrated project was previously verified locally on Windows with **628 tests passing** and two non-failing third-party deprecation warnings. Re-run the command above on the exact copy being reviewed to confirm its current state.

## Supported input scope

Version 1 accepts CSV files that follow the project's defined authentication-log or network-connection-log schemas. It does not directly ingest every vendor-specific log format, network-flow export, packet capture or arbitrary SIEM export. Other sources require a format-specific adapter that maps available fields into the internal event structure. Missing values must not be invented during conversion; rules that need unavailable fields cannot run reliably.

Timestamps without an explicit timezone are treated as UTC under the default configuration. Exporting source logs in UTC or with an explicit timezone offset is recommended.

## Security and privacy notes

- This is a **single-user local prototype**. Version 1 does not provide user authentication or multi-user access control.
- Run it on a trusted local machine. Do not expose the Streamlit service directly to the public internet or an untrusted network.
- Treat uploaded logs, saved evidence, notes and the runtime SQLite database as potentially sensitive operational data.
- Do not commit real organisation logs, production databases, credentials, API keys, `.env` files or Streamlit secrets.
- Use the supplied synthetic sample files for demonstrations. The IP addresses in the sample data and tests are documentation/private-range examples, not real network telemetry.
- The test fixtures contain intentionally unusual strings to check that input is handled as data rather than executed as markup or SQL. They are test inputs, not application instructions.
- SQL values use parameter placeholders, and report text originating from users or logs is escaped before being placed into PDF paragraphs.

## Configuration and limitations

Detection thresholds are adjustable starting values for demonstration and evaluation; they are not universal security standards. The quality of findings depends on the completeness, accuracy and semantics of the source logs. Shared source addresses can cause false correlations, and legitimate activities such as backups, automated updates or authorised scanning can resemble suspicious patterns.

The CIC-IDS2017 flow-data trial was exploratory. The production port-scan rule requires connection-status information that the selected flow export does not provide, so the production rule was not evaluated against those labels. The existing traffic-volume rule generated zero alerts on that trial; this is not evidence of high accuracy or failure by itself.

## Documentation

The implementation follows a frozen Master Architecture and Interface Specification (Contract Version 1.0), which defines the shared event and alert structures, module interfaces, detection behaviour, database rules and acceptance criteria. Stage learning notes in `docs/stage_notes/` provide implementation walkthroughs and testing concepts.

## License

No open-source license is currently included. Contact the project owner before reusing or redistributing the source beyond the intended academic review.
