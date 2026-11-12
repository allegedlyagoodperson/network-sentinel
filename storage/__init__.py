# storage/__init__.py
# Purpose: marks the storage folder as a Python package so the dashboard
# can write "from storage.database import save_alerts".
# It is deliberately empty of code: the real work is in storage/database.py
# (alerts, events, schema) and storage/incidents.py (incidents, notes, history).
# This is the ONLY folder in the project that contains SQL (FS.4).
# Uses: nothing.
