# ingestion/__init__.py
# Purpose: marks the ingestion folder as a Python package so other modules
# can write "from ingestion.csv_ingest import ingest_file".
# It is deliberately empty of code: the real work is in validators.py
# (one function per kind of value) and csv_ingest.py (whole files).
# Uses: nothing.
