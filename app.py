"""YARA Deep Validator"""
import re, os, sys
_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

import importlib as _il
_v = _il.import_module('yara_web.validator_engine')
validate, parse_rule = _v.validate, _v.parse_rule

import streamlit as st

st.set_page_config(page_title="YARA Validator", page_icon="\u25bd", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

* { font-family: 'Inter', -apple-system, sans-serif; }

#MainMenu, .stApp header, footer, .stDeployButton {display: none !important;}
.stApp { margin-top: 0; padding-top: 0; }

body {
    background: #1e1e1e;
}

.block-container {
    max-width: 960px; padding: 0.6rem 1rem 1.5rem;
}
@media (max-width: 640px) {
    .block-container { padding: 0.5rem 0.5rem 1rem; }
}

/* ─── VSCode-style title bar ─── */
.title-bar {
    display: flex; align-items: center; gap: 0.75rem;
    padding: 0.5rem 0 1rem 0;
    margin-bottom: 0.25rem;
    border-bottom: 1px solid #2d2d2d;
}
.title-icon {
    width: 20px; height: 20px; border-radius: 4px;
    background: #007acc;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
}
.title-icon svg { width: 14px; height: 14px; fill: #fff; }
.title-text {
    font-size: 0.82rem; font-weight: 500; color: #cccccc;
    letter-spacing: 0.01em;
}

/* ─── Editor card ─── */
.editor-card {
    background: #1e1e1e;
    border: 1px solid #2d2d2d;
    border-radius: 0;
    padding: 0;
    position: relative; z-index: 1;
}
.editor-card:focus-within {
    border-color: #007acc;
}

/* ─── Validate button ─── */
div[data-testid="stVerticalBlock"] > div:has(button[data-testid="baseButton-primary"]) {
    width: 100% !important;
    position: relative; z-index: 1;
    margin-top: 1rem;
}
button[data-testid="baseButton-primary"] {
    background: #0e639c !important;
    color: #fff !important; border: none !important;
    border-radius: 0 !important;
    font-size: 0.82rem !important; font-weight: 500 !important;
    padding: 0.6rem 0 !important; width: 100% !important;
    cursor: pointer !important;
    letter-spacing: 0.02em !important;
    transition: background 0.15s !important;
}
button[data-testid="baseButton-primary"]:hover {
    background: #1177bb !important;
}
button[data-testid="baseButton-primary"]:active {
    background: #0e639c !important;
}
button[data-testid="baseButton-primary"] p {
    font-size: 0.82rem !important; font-weight: 500 !important;
    color: #fff !important;
}

/* ─── Section titles ─── */
.section-title {
    font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #858585;
    padding: 0.6rem 0 0.4rem 0;
    border-bottom: 1px solid #2d2d2d;
    margin: 1rem 0 0.6rem 0;
    display: flex; align-items: center; gap: 0.5rem;
}

/* ─── Diagnostics ─── */
.diag {
    display: flex; gap: 0.6rem; align-items: flex-start;
    padding: 0.35rem 0.75rem; margin: 0;
    font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;
    line-height: 1.5;
    position: relative; z-index: 1;
}
.diag-icon { flex-shrink: 0; width: 18px; text-align: center; font-size: 0.8rem; }
.diag-body { flex: 1; min-width: 0; }
.diag-loc {
    color: #858585; margin-right: 0.5rem;
    font-size: 0.72rem; font-weight: 500; font-family: 'Inter', sans-serif;
}
.diag-err  .diag-icon { color: #f48771; }
.diag-warn .diag-icon { color: #cca700; }

.diag-err {
    background: rgba(244, 135, 113, 0.06);
    border-left: 3px solid #f48771;
}
.diag-warn {
    background: rgba(204, 167, 0, 0.05);
    border-left: 3px solid #cca700;
}

.diag-msg {
    color: #d4d4d4;
    font-family: 'JetBrains Mono', monospace;
}

/* ─── Code context ─── */
.code-ctx {
    margin: 0.1rem 0 0.4rem 1.7rem;
    background: #1e1e1e;
    border: 1px solid #2d2d2d;
    border-top: none;
    padding: 0.4rem 0.7rem; overflow-x: auto;
    font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;
    line-height: 1.6;
    position: relative; z-index: 1;
}
.code-ctx .arrow { color: #f48771; font-size: 0.6rem; margin-right: 0.3rem; }
.code-ctx .num {
    color: #858585;
    margin-right: 0.6rem;
    font-size: 0.7rem;
}

/* ─── Success banner ─── */
.success-banner {
    background: rgba(78, 201, 176, 0.06);
    border: 1px solid rgba(78, 201, 176, 0.15);
    padding: 0.7rem 1rem; margin: 0.5rem 0;
    display: flex; align-items: center; gap: 0.7rem;
    position: relative; z-index: 1;
}
.success-icon {
    width: 28px; height: 28px; border-radius: 50%;
    background: rgba(78, 201, 176, 0.12);
    display: flex; align-items: center; justify-content: center;
    font-size: 0.9rem; flex-shrink: 0;
}

/* ─── Scrollbar ─── */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #424242; border-radius: 0; }
::-webkit-scrollbar-thumb:hover { background: #4f4f4f; }

/* ─── Mobile ─── */
@media (max-width: 640px) {
    .block-container { padding: 0.8rem 0.5rem; }
    .diag { font-size: 0.72rem; padding: 0.35rem 0.5rem; }
}
</style>
""", unsafe_allow_html=True)

DEFAULT = """rule SampleRule {
    meta:
        description = "Example rule"
        author = "analyst"
    strings:
        $a = "malicious"
    condition:
        $a
}"""

# ── Header ──
st.markdown("""
<div class="title-bar">
    <div class="title-icon">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
    </div>
    <span class="title-text">YARA Validator — Syntax Analysis Engine</span>
</div>
""", unsafe_allow_html=True)

# ── Editor ──
from yara_editor import yara_editor

if "yara_code" not in st.session_state:
    st.session_state.yara_code = DEFAULT

st.markdown('<div class="editor-card">', unsafe_allow_html=True)
editor_resp = yara_editor(
    code=DEFAULT, height=30, response_mode="blur", key="yara_editor",
)
st.markdown('</div>', unsafe_allow_html=True)

if editor_resp and isinstance(editor_resp, dict) and editor_resp.get("text"):
    st.session_state.yara_code = editor_resp["text"]
rule_text = st.session_state.yara_code

# ── Validate button ──
clicked = st.button("\u25b6 Validate", type="primary", key="val_btn", use_container_width=True)

if clicked:
    if not rule_text.strip():
        st.markdown('<div class="diag diag-err"><span class="diag-icon">!</span><span class="diag-body diag-msg">No YARA rule provided</span></div>', unsafe_allow_html=True)
    else:
        is_valid, errors, rule_name = validate(rule_text)
        lines = rule_text.splitlines()

        if not is_valid or errors:
            st.markdown('<div class="section-title">PROBLEMS</div>', unsafe_allow_html=True)
            for err in errors:
                raw_line, msg = err['line'], err['message']
                cls = 'warn' if err['type'] == 'warning' else 'err'
                icon = '\u26a0' if err['type'] == 'warning' else '!'
                loc = "EOF" if raw_line == 0 else f"L{raw_line}"
                st.markdown(
                    f'<div class="diag diag-{cls}">'
                    f'<span class="diag-icon">{icon}</span>'
                    f'<span class="diag-body">'
                    f'<span class="diag-loc">{loc}</span><span class="diag-msg">{msg}</span>'
                    f'</span></div>',
                    unsafe_allow_html=True
                )
                if raw_line > 0 and raw_line <= len(lines):
                    s, e = max(0, raw_line - 2), min(len(lines), raw_line + 1)
                    ctx = []
                    for i in range(s, e):
                        arrow = '<span class="arrow">></span>' if i + 1 == raw_line else '<span class="arrow" style="color:#858585">.</span>'
                        ctx.append(f'<span class="num">{i+1}</span>{arrow} {lines[i]}')
                    st.markdown(f'<div class="code-ctx">{"<br>".join(ctx)}</div>', unsafe_allow_html=True)
                elif raw_line == 0 and lines:
                    s = max(0, len(lines) - 3)
                    ctx = [f'<span class="num">{i+1}</span><span style="color:#858585">.</span> {lines[i]}' for i in range(s, len(lines))]
                    st.markdown(f'<div class="code-ctx">{"<br>".join(ctx)}</div>', unsafe_allow_html=True)
        else:
            st.markdown(
                f'<div class="success-banner">'
                f'<div class="success-icon">\u2713</div>'
                f'<div><b style="color:#4ec9b0;">No problems detected</b><br>'
                f'<span style="color:#858585;font-size:0.78rem;">{rule_name or "unknown"}</span></div>'
                f'</div>',
                unsafe_allow_html=True
            )
