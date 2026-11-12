# dashboard/theme.py
# ---------------------------------------------------------------
# Purpose: the ONLY place where dashboard colours are defined (Section G.1),
# plus the small block of CSS that styles cards, badges and banners.
# build_css: returns the CSS text (static text written by us, never log data).
# apply_theme: injects that CSS into the page (FS.4 public function).
# SEVERITY_COLORS: which colour each severity badge uses.
# Uses: streamlit only.

import streamlit as st

COLOR_BACKGROUND = "#0B0D10"
COLOR_PANEL = "#14181D"
COLOR_BORDER = "#232A32"
COLOR_TEXT = "#E6E8EB"
COLOR_TEXT_MUTED = "#8A94A0"
COLOR_RED = "#E5484D"
COLOR_AMBER = "#F5A524"
COLOR_GREEN = "#30A46C"
COLOR_STEEL = "#6B7A8F"

# critical = filled red, high = red outline, medium = amber, low = green.
SEVERITY_COLORS = {
    "critical": COLOR_RED,
    "high": COLOR_RED,
    "medium": COLOR_AMBER,
    "low": COLOR_GREEN,
}

# The CSS uses @NAME@ markers so the colour constants above stay the single
# source of truth. (Curly braces are everywhere in CSS, so str.format is awkward.)
_CSS_TEMPLATE = """
.ns-card { background: @PANEL@; border: 1px solid @BORDER@; border-radius: 8px;
           padding: 14px 16px; margin-bottom: 8px; }
.ns-card-label { color: @MUTED@; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }
.ns-card-value { color: @TEXT@; font-size: 1.9rem; font-weight: 600; line-height: 1.2; }
.ns-card-caption { color: @MUTED@; font-size: 0.8rem; }
.ns-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.78rem;
            font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; border: 1px solid; }
.ns-badge-critical { background: @RED@; border-color: @RED@; color: #FFFFFF; }
.ns-badge-high { background: transparent; border-color: @RED@; color: @RED@; }
.ns-badge-medium { background: transparent; border-color: @AMBER@; color: @AMBER@; }
.ns-badge-low { background: transparent; border-color: @GREEN@; color: @GREEN@; }
.ns-badge-unknown { background: transparent; border-color: @STEEL@; color: @STEEL@; }
.ns-confidence { color: @MUTED@; font-size: 0.82rem; margin-left: 8px; }
.ns-mono { font-family: Consolas, "Courier New", monospace; }
.ns-banner { border-radius: 6px; padding: 8px 14px; margin-bottom: 12px; font-size: 0.88rem; }
.ns-banner-mock { border: 1px dashed @AMBER@; color: @AMBER@; background: @PANEL@; }
.ns-banner-warning { border: 1px solid @AMBER@; color: @TEXT@; background: @PANEL@; }
.ns-reminder { color: @MUTED@; font-size: 0.82rem; border-left: 3px solid @STEEL@; padding-left: 10px; margin: 8px 0; }
.ns-subtitle { color: @MUTED@; margin-top: -10px; margin-bottom: 14px; }
"""


def build_css() -> str:
    """
    Purpose: produce the CSS text with the real colour values filled in.
    Inputs: none.
    Output: str - CSS rules (static text, safe to inject).
    Steps:
        1. Start from the template that contains @NAME@ markers.
        2. Replace each marker with the matching colour constant.
    Example: "@RED@" becomes "#E5484D".
    Errors: none.
    """
    replacements = {
        "@PANEL@": COLOR_PANEL,
        "@BORDER@": COLOR_BORDER,
        "@TEXT@": COLOR_TEXT,
        "@MUTED@": COLOR_TEXT_MUTED,
        "@RED@": COLOR_RED,
        "@AMBER@": COLOR_AMBER,
        "@GREEN@": COLOR_GREEN,
        "@STEEL@": COLOR_STEEL,
    }
    css_text = _CSS_TEMPLATE
    for marker in replacements:
        css_text = css_text.replace(marker, replacements[marker])
    return css_text


def apply_theme() -> None:
    """
    Purpose: inject the dashboard CSS into the Streamlit page.
    Inputs: none.
    Output: None.
    Steps:
        1. Build the CSS text.
        2. Write it into the page inside a style tag.
    Example: called once per run by app.py, before any page is drawn.
    Errors: none. unsafe_allow_html is used only because this text is
        written by us and contains no log or user data.
    """
    st.markdown("<style>" + build_css() + "</style>", unsafe_allow_html=True)
