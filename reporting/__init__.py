# reporting/__init__.py
# Purpose: marks the reporting folder as a Python package so the dashboard
# can write "from reporting.pdf_report import build_incident_report_pdf".
# It is deliberately empty of code: the real work is in reporting/pdf_report.py.
# This folder never touches the database; it only reads the dictionaries it is given.
# Uses: nothing.
