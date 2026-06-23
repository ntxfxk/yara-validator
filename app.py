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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap');

* { font-family: 'Inter', -apple-system, sans-serif; }

#MainMenu, .stApp header, footer, .stDeployButton {display: none !important;}
.stApp { margin-top: 0; padding-top: 0; }

body {
    background: #07070d;
    background-image:
        radial-gradient(ellipse 600px 400px at 15% 20%, rgba(79, 139, 249, 0.07) 0%, transparent 60%),
        radial-gradient(ellipse 500px 500px at 85% 30%, rgba(249, 115, 22, 0.04) 0%, transparent 60%),
        radial-gradient(ellipse 400px 300px at 50% 80%, rgba(99, 102, 241, 0.05) 0%, transparent 60%);
    background-attachment: fixed;
}

.block-container {
    max-width: 960px; padding: 0.6rem 1rem 1.5rem;
}
@media (max-width: 640px) {
    .block-container { padding: 0.5rem 0.5rem 1rem; }
}

/* ─── Animated background orbs ─── */
body::before, body::after {
    content: ''; position: fixed; border-radius: 50%;
    pointer-events: none; z-index: 0;
}
body::before {
    width: 500px; height: 500px;
    background: radial-gradient(circle, rgba(79, 139, 249, 0.06), transparent 70%);
    top: -100px; left: -100px;
    animation: floatOrb 12s ease-in-out infinite;
}
body::after {
    width: 400px; height: 400px;
    background: radial-gradient(circle, rgba(249, 115, 22, 0.04), transparent 70%);
    bottom: -80px; right: -80px;
    animation: floatOrb 15s ease-in-out infinite reverse;
}
@keyframes floatOrb {
    0%, 100% { transform: translate(0, 0) scale(1); }
    33% { transform: translate(30px, -20px) scale(1.05); }
    66% { transform: translate(-20px, 15px) scale(0.95); }
}

/* ─── Glass Header ─── */
.app-header {
    display: flex; align-items: center; gap: 1rem;
    margin-bottom: 1.5rem;
    position: relative; z-index: 1;
}
.app-logo {
    width: 44px; height: 44px; border-radius: 14px;
    background: linear-gradient(135deg, #4f8bf9, #f97316);
    display: flex; align-items: center; justify-content: center;
    font-size: 1.4rem; font-weight: 900; color: #fff;
    box-shadow: 0 4px 20px rgba(79, 139, 249, 0.35);
    position: relative;
    overflow: hidden;
}
.app-logo::after {
    content: ''; position: absolute; inset: 0;
    background: linear-gradient(135deg, rgba(255,255,255,0.2), transparent 50%);
}
.app-title-group { display: flex; flex-direction: column; gap: 0.1rem; }
.app-title {
    font-size: 1.35rem; font-weight: 900;
    background: linear-gradient(135deg, #f0f4ff 0%, #a5b4fc 50%, #f472b6 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    letter-spacing: -0.03em;
}
.app-sub {
    font-size: 0.7rem; color: rgba(255,255,255,0.3);
    font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase;
}

/* ─── Editor glass card ─── */
.editor-card {
    background: rgba(18, 18, 28, 0.7);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 14px;
    padding: 0.5rem;
    box-shadow: 0 8px 40px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.05);
    position: relative; z-index: 1;
    transition: border-color 0.3s;
}
.editor-card:focus-within {
    border-color: rgba(79, 139, 249, 0.3);
    box-shadow: 0 8px 40px rgba(0,0,0,0.4), 0 0 30px rgba(79, 139, 249, 0.08);
}

/* ─── Validate button ─── */
div[data-testid="stVerticalBlock"] > div:has(button[data-testid="baseButton-primary"]) {
    width: 100% !important;
    position: relative; z-index: 1;
    margin-top: 1rem;
}
button[data-testid="baseButton-primary"] {
    background: linear-gradient(135deg, #4f8bf9, #6366f1, #8b5cf6) !important;
    background-size: 200% 200% !important;
    color: #fff !important; border: none !important;
    border-radius: 12px !important;
    font-size: 1rem !important; font-weight: 700 !important;
    padding: 0.8rem 0 !important; width: 100% !important;
    cursor: pointer !important;
    position: relative !important;
    overflow: hidden !important;
    transition: transform 0.2s, box-shadow 0.3s !important;
    box-shadow: 0 4px 24px rgba(79, 139, 249, 0.3), 0 0 0 0 rgba(79, 139, 249, 0) !important;
    animation: buttonPulse 3s ease-in-out infinite !important;
}
@keyframes buttonPulse {
    0%, 100% { box-shadow: 0 4px 24px rgba(79, 139, 249, 0.3); }
    50% { box-shadow: 0 4px 32px rgba(79, 139, 249, 0.5); }
}
button[data-testid="baseButton-primary"]:hover {
    transform: translateY(-2px) scale(1.01) !important;
    box-shadow: 0 8px 36px rgba(79, 139, 249, 0.45), 0 0 60px rgba(79, 139, 249, 0.15) !important;
    animation: none !important;
    background-position: 100% 100% !important;
}
button[data-testid="baseButton-primary"]:active {
    transform: translateY(0) scale(0.99) !important;
}
button[data-testid="baseButton-primary"]::before {
    content: ''; position: absolute; inset: -2px;
    border-radius: 13px;
    background: linear-gradient(135deg, #4f8bf9, #f97316, #8b5cf6, #4f8bf9);
    background-size: 300% 300%;
    z-index: -1;
    animation: borderGlow 4s linear infinite;
    opacity: 0;
    transition: opacity 0.3s;
}
button[data-testid="baseButton-primary"]:hover::before {
    opacity: 1;
}
@keyframes borderGlow {
    0% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}
button[data-testid="baseButton-primary"] p {
    font-size: 1rem !important; font-weight: 700 !important;
    position: relative; z-index: 1;
}

/* ─── Section titles ─── */
.section-title {
    font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.1em;
    color: rgba(255,255,255,0.4);
    margin: 1.4rem 0 0.7rem 0;
    display: flex; align-items: center; gap: 0.6rem;
    position: relative; z-index: 1;
}
.section-title::after {
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(90deg, rgba(255,255,255,0.08), transparent);
}

/* ─── Diagnostics ─── */
.diag {
    display: flex; gap: 0.7rem; align-items: flex-start;
    padding: 0.7rem 1rem; margin: 3px 0;
    border-radius: 10px;
    font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
    line-height: 1.5;
    transition: all 0.2s;
    animation: slideIn 0.3s ease-out;
    position: relative; z-index: 1;
}
@keyframes slideIn {
    from { opacity: 0; transform: translateY(-6px); }
    to { opacity: 1; transform: translateY(0); }
}
.diag:hover { transform: translateX(3px); }
.diag-icon { flex-shrink: 0; width: 20px; text-align: center; font-size: 0.9rem; }
.diag-body { flex: 1; min-width: 0; }
.diag-loc {
    color: rgba(255,255,255,0.3); margin-right: 0.5rem;
    font-size: 0.7rem; font-weight: 600; font-family: 'Inter', sans-serif;
}
.diag-err  .diag-icon { color: #ff6b6b; }
.diag-warn .diag-icon { color: #ffc107; }

.diag-err {
    background: rgba(255, 75, 75, 0.06);
    border-left: 2.5px solid rgba(255, 68, 68, 0.6);
}
.diag-warn {
    background: rgba(255, 170, 0, 0.05);
    border-left: 2.5px solid rgba(255, 170, 0, 0.5);
}

.diag-msg { color: rgba(255,255,255,0.85); font-family: 'JetBrains Mono', monospace; }

/* ─── Code context ─── */
.code-ctx {
    margin: 0.3rem 0 0.3rem 1.8rem;
    background: rgba(0,0,0,0.35);
    border: 1px solid rgba(255,255,255,0.04);
    border-radius: 8px;
    padding: 0.5rem 0.7rem; overflow-x: auto;
    font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;
    line-height: 1.6;
    position: relative; z-index: 1;
}
.code-ctx .arrow { color: #ff6b6b; font-size: 0.65rem; margin-right: 0.3rem; }
.code-ctx .num { color: rgba(255,255,255,0.15); margin-right: 0.6rem; font-size: 0.7rem; }

/* ─── Success banner ─── */
.success-banner {
    background: linear-gradient(135deg, rgba(34,197,94,0.08), rgba(34,197,94,0.02));
    border: 1px solid rgba(34,197,94,0.15);
    border-radius: 12px; padding: 1rem 1.2rem; margin: 0.5rem 0;
    display: flex; align-items: center; gap: 0.8rem;
    animation: slideIn 0.3s ease-out;
    position: relative; z-index: 1;
}
.success-icon {
    width: 36px; height: 36px; border-radius: 50%;
    background: rgba(34,197,94,0.15);
    display: flex; align-items: center; justify-content: center;
    font-size: 1.1rem; flex-shrink: 0;
    box-shadow: 0 0 20px rgba(34,197,94,0.15);
}

/* ─── Custom scrollbar ─── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }

/* ─── None ─── */
.none-msg { color: rgba(255,255,255,0.15); font-size: 0.8rem; font-style: italic; padding: 0.3rem 0; }

/* ─── Mobile ─── */
@media (max-width: 640px) {
    .block-container { padding: 0.8rem 0.5rem; }
    .diag { font-size: 0.73rem; padding: 0.5rem 0.7rem; }
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
<div class="app-header">
    <div class="app-logo">Y</div>
    <div class="app-title-group">
        <div class="app-title">YARA Validator</div>
        <div class="app-sub">Syntax Analysis Engine</div>
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
clicked = st.button("\u26a1 Validate", type="primary", key="val_btn", use_container_width=True)

if clicked:
    if not rule_text.strip():
        st.markdown('<div class="diag diag-err"><span class="diag-icon">\u274c</span><span class="diag-body diag-msg">No YARA rule provided</span></div>', unsafe_allow_html=True)
    else:
        is_valid, errors, rule_name = validate(rule_text)
        lines = rule_text.splitlines()

        if not is_valid or errors:
            st.markdown('<div class="section-title">\u274c Syntax Errors</div>', unsafe_allow_html=True)
            for err in errors:
                raw_line, msg = err['line'], err['message']
                cls = 'warn' if err['type'] == 'warning' else 'err'
                icon = '\u26a0\ufe0f' if err['type'] == 'warning' else '\u274c'
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
                        arrow = '<span class="arrow">\u25b6</span>' if i + 1 == raw_line else '<span style="color:rgba(255,255,255,0.15)">\u00b7</span>'
                        ctx.append(f'<span class="num">{i+1}</span>{arrow} {lines[i]}')
                    st.markdown(f'<div class="code-ctx">{"<br>".join(ctx)}</div>', unsafe_allow_html=True)
                elif raw_line == 0 and lines:
                    s = max(0, len(lines) - 3)
                    ctx = [f'<span class="num">{i+1}</span><span style="color:rgba(255,255,255,0.15)">\u00b7</span> {lines[i]}' for i in range(s, len(lines))]
                    st.markdown(f'<div class="code-ctx">{"<br>".join(ctx)}</div>', unsafe_allow_html=True)
        else:
            st.markdown(
                f'<div class="success-banner">'
                f'<div class="success-icon">\u2713</div>'
                f'<div><b style="color:#22c55e;">Valid YARA Rule</b><br>'
                f'<span style="color:rgba(255,255,255,0.35);font-size:0.8rem;">{rule_name or "unknown"}</span></div>'
                f'</div>',
                unsafe_allow_html=True
            )
