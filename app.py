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

/* ─── Background ─── */
body {
    background: #1a1b26;
    background-image:
        radial-gradient(ellipse 800px 500px at 10% 20%, rgba(137, 180, 250, 0.04) 0%, transparent 60%),
        radial-gradient(ellipse 500px 500px at 90% 30%, rgba(203, 166, 247, 0.03) 0%, transparent 60%);
    background-attachment: fixed;
}

.block-container {
    max-width: 960px; padding: 1.2rem 1rem 1.5rem;
}
@media (max-width: 640px) {
    .block-container { padding: 0.8rem 0.5rem 1rem; }
}

/* ─── Header ─── */
.header {
    display: flex; align-items: center; gap: 0.9rem;
    margin-bottom: 1.5rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid rgba(255,255,255,0.04);
}
.header-icon {
    width: 40px; height: 40px; border-radius: 10px;
    background: linear-gradient(135deg, #89b4fa, #cba6f7);
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
    box-shadow: 0 4px 16px rgba(137, 180, 250, 0.25);
}
.header-icon svg { width: 22px; height: 22px; fill: #1e1e2e; }
.header-text h1 {
    font-size: 1.25rem; font-weight: 700; color: #cdd6f4;
    margin: 0; line-height: 1.3;
    letter-spacing: -0.01em;
}
.header-text p {
    font-size: 0.7rem; color: #6c7086; margin: 0;
    font-weight: 500; letter-spacing: 0.04em;
}

/* ─── Editor card ─── */
.editor-card {
    background: rgba(30, 30, 46, 0.85);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid rgba(255,255,255,0.05);
    border-radius: 12px;
    padding: 0.4rem;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    position: relative; z-index: 1;
    transition: border-color 0.3s, box-shadow 0.3s;
}
.editor-card:focus-within {
    border-color: rgba(137, 180, 250, 0.2);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4), 0 0 24px rgba(137, 180, 250, 0.04);
}

/* ─── Button ─── */
div[data-testid="stVerticalBlock"] > div:has(button[data-testid="baseButton-primary"]) {
    width: 100% !important;
    position: relative; z-index: 1;
    margin-top: 1rem;
}
button[data-testid="baseButton-primary"] {
    background: linear-gradient(135deg, #89b4fa, #b4befe) !important;
    color: #1e1e2e !important; border: none !important;
    border-radius: 10px !important;
    font-size: 0.88rem !important; font-weight: 600 !important;
    padding: 0.72rem 0 !important; width: 100% !important;
    cursor: pointer !important;
    letter-spacing: 0.01em !important;
    transition: all 0.25s !important;
    box-shadow: 0 4px 20px rgba(137, 180, 250, 0.2) !important;
}
button[data-testid="baseButton-primary"]:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 28px rgba(137, 180, 250, 0.35) !important;
    background: linear-gradient(135deg, #74c7ec, #89b4fa) !important;
}
button[data-testid="baseButton-primary"]:active {
    transform: translateY(0) !important;
    box-shadow: 0 2px 12px rgba(137, 180, 250, 0.2) !important;
}
button[data-testid="baseButton-primary"] p {
    font-size: 0.88rem !important; font-weight: 600 !important;
    color: #1e1e2e !important;
}

/* ─── Section titles ─── */
.section-title {
    font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #6c7086;
    margin: 1.4rem 0 0.6rem 0;
    display: flex; align-items: center; gap: 0.5rem;
}

/* ─── Diagnostics ─── */
.diag {
    display: flex; gap: 0.6rem; align-items: flex-start;
    padding: 0.5rem 0.8rem; margin: 2px 0;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
    line-height: 1.5;
    transition: all 0.15s;
    animation: diagIn 0.2s ease-out;
    position: relative; z-index: 1;
}
@keyframes diagIn {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: translateY(0); }
}
.diag:hover { background: rgba(255,255,255,0.02); }
.diag-icon { flex-shrink: 0; width: 18px; text-align: center; font-size: 0.75rem; }
.diag-body { flex: 1; min-width: 0; display: flex; align-items: baseline; gap: 0.5rem; flex-wrap: wrap; }
.diag-loc {
    color: #585b70; font-size: 0.7rem;
    font-weight: 500; font-family: 'Inter', sans-serif;
    white-space: nowrap;
}
.diag-err  { border-left: 3px solid #f38ba8; }
.diag-err .diag-icon { color: #f38ba8; }
.diag-warn { border-left: 3px solid #f9e2af; }
.diag-warn .diag-icon { color: #f9e2af; }

.diag-msg {
    color: #cdd6f4;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
}

/* ─── Code context ─── */
.code-ctx {
    margin: 2px 0 6px 1.6rem;
    background: rgba(0,0,0,0.25);
    border: 1px solid rgba(255,255,255,0.03);
    border-radius: 6px;
    padding: 0.4rem 0.6rem; overflow-x: auto;
    font-family: 'JetBrains Mono', monospace; font-size: 0.74rem;
    line-height: 1.6;
    position: relative; z-index: 1;
}
.code-ctx .arrow { font-size: 0.6rem; margin-right: 0.3rem; }
.code-ctx .arrow.err { color: #f38ba8; }
.code-ctx .arrow.dot { color: #45475a; }
.code-ctx .num {
    color: #45475a;
    margin-right: 0.6rem;
    font-size: 0.68rem;
}

/* ─── Success banner ─── */
.success-banner {
    background: rgba(166, 227, 161, 0.06);
    border: 1px solid rgba(166, 227, 161, 0.12);
    border-radius: 10px; padding: 0.9rem 1rem; margin: 0.5rem 0;
    display: flex; align-items: center; gap: 0.7rem;
    animation: diagIn 0.2s ease-out;
    position: relative; z-index: 1;
}
.success-icon {
    width: 32px; height: 32px; border-radius: 8px;
    background: rgba(166, 227, 161, 0.1);
    display: flex; align-items: center; justify-content: center;
    font-size: 0.85rem; flex-shrink: 0;
}

/* ─── Scrollbar ─── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.06); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.1); }

/* ─── Mobile ─── */
@media (max-width: 640px) {
    .block-container { padding: 0.8rem 0.5rem; }
    .diag { font-size: 0.72rem; padding: 0.4rem 0.6rem; }
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
<div class="header">
    <div class="header-icon">
        <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
    </div>
    <div class="header-text">
        <h1>YARA Validator</h1>
        <p>Syntax Analysis Engine</p>
    </div>
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
clicked = st.button("\u25b6  Validate Rule", type="primary", key="val_btn", use_container_width=True)

if clicked:
    if not rule_text.strip():
        st.markdown('<div class="diag diag-err"><span class="diag-icon">\u2716</span><span class="diag-body"><span class="diag-msg">No YARA rule provided</span></span></div>', unsafe_allow_html=True)
    else:
        is_valid, errors, rule_name = validate(rule_text)
        lines = rule_text.splitlines()

        if not is_valid or errors:
            st.markdown('<div class="section-title">\u2716  Problems</div>', unsafe_allow_html=True)
            for err in errors:
                raw_line, msg = err['line'], err['message']
                cls = 'warn' if err['type'] == 'warning' else 'err'
                icon = '\u26a0' if err['type'] == 'warning' else '\u2716'
                loc = "EOF" if raw_line == 0 else f"L{raw_line}"
                st.markdown(
                    f'<div class="diag diag-{cls}">'
                    f'<span class="diag-icon">{icon}</span>'
                    f'<span class="diag-body">'
                    f'<span class="diag-loc">{loc}</span>'
                    f'<span class="diag-msg">{msg}</span>'
                    f'</span></div>',
                    unsafe_allow_html=True
                )
                if raw_line > 0 and raw_line <= len(lines):
                    s, e = max(0, raw_line - 2), min(len(lines), raw_line + 1)
                    ctx = []
                    for i in range(s, e):
                        arrow = '<span class="arrow err">\u25b6</span>' if i + 1 == raw_line else '<span class="arrow dot">\u2022</span>'
                        ctx.append(f'<span class="num">{i+1}</span>{arrow} {lines[i]}')
                    st.markdown(f'<div class="code-ctx">{"<br>".join(ctx)}</div>', unsafe_allow_html=True)
                elif raw_line == 0 and lines:
                    s = max(0, len(lines) - 3)
                    ctx = [f'<span class="num">{i+1}</span><span class="arrow dot">\u2022</span> {lines[i]}' for i in range(s, len(lines))]
                    st.markdown(f'<div class="code-ctx">{"<br>".join(ctx)}</div>', unsafe_allow_html=True)
        else:
            st.markdown(
                f'<div class="success-banner">'
                f'<div class="success-icon">\u2713</div>'
                f'<div><b style="color:#a6e3a1;">No problems detected</b><br>'
                f'<span style="color:#585b70;font-size:0.78rem;">{rule_name or "unknown"}</span></div>'
                f'</div>',
                unsafe_allow_html=True
            )
