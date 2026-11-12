# app.py
# ---------------------------------------------------------------
# Purpose: the Streamlit entry point of Network Sentinel. Run it with:
#   streamlit run app.py
# It sets the page, applies the dark theme, creates the FS.5 session keys, makes sure the
# database exists, draws the sidebar navigation and calls ONE render_*_page function.
# It contains no detection logic and no SQL.
# While dashboard/backend_calls.py has USE_MOCK_BACKEND = True, every page runs on mock data
# and a banner says so.
# Uses: streamlit, core.errors, dashboard (theme, components, backend_calls, five pages).

import streamlit as st

from core.errors import DatabaseError
from dashboard import backend_calls
from dashboard.components import initialise_session_state
from dashboard.page_alerts import render_alerts_page
from dashboard.page_investigations import render_investigations_page
from dashboard.page_overview import render_overview_page
from dashboard.page_reports import render_reports_page
from dashboard.page_upload import render_upload_page
from dashboard.theme import apply_theme

DATABASE_PATH = "data/network_sentinel.db"
PAGE_NAMES = ["Overview", "Log Upload", "Alerts", "Incidents", "Reports"]

# set_page_config must be the first Streamlit command in the script.
st.set_page_config(page_title="Network Sentinel", page_icon="\U0001F6E1", layout="wide")
apply_theme()
initialise_session_state()

try:
    backend_calls.initialise_database(DATABASE_PATH)
except DatabaseError as database_error:
    st.error("The database could not be opened: " + str(database_error))
    st.stop()

st.sidebar.title("Network Sentinel")
st.sidebar.caption("Log analysis for small organisations")
page_name = st.sidebar.radio("Navigate", PAGE_NAMES, key="navigation")
if backend_calls.is_mock_backend():
    st.sidebar.warning("Backend: MOCK (demo data)")
else:
    st.sidebar.success("Backend: connected modules")
st.sidebar.caption("Detections are indicators, not proof of an attack.")

current_config = st.session_state["config"]
if page_name == "Overview":
    render_overview_page(current_config, DATABASE_PATH)
elif page_name == "Log Upload":
    render_upload_page(current_config, DATABASE_PATH)
elif page_name == "Alerts":
    render_alerts_page(current_config, DATABASE_PATH)
elif page_name == "Incidents":
    render_investigations_page(current_config, DATABASE_PATH)
else:
    render_reports_page(current_config, DATABASE_PATH)
