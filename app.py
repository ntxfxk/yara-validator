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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

* { font-family: 'Inter', -apple-system, sans-serif; }

#MainMenu, .stApp header, footer, .stDeployButton {display: none !important;}
.stApp { margin-top: 0; padding-top: 0.5rem; }

body {
    background: #0a0a0f;
    background-image:
        radial-gradient(ellipse at 20% 50%, rgba(79, 139, 249, 0.06) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 50%, rgba(255, 107, 107, 0.04) 0%, transparent 50%);
}

.block-container {
    max-width: 960px; padding: 0.8rem 1rem 1.5rem;
}
@media (max-width: 640px) {
    .block-container { padding: 0.5rem 0.5rem 1rem; }
}

/* ─── Header ─── */
.app-header {
    display: flex; align-items: center; gap: 0.8rem;
    margin-bottom: 1.2rem;
}
.app-logo {
    width: 42px; height: 42px; border-radius: 12px;
    background: linear-gradient(135deg, #4f8bf9, #f97316);
    display: flex; align-items: center; justify-content: center;
    font-size: 1.3rem; font-weight: 800; color: #fff;
    box-shadow: 0 4px 16px rgba(79, 139, 249, 0.3);
}
.app-title {
    font-size: 1.3rem; font-weight: 800;
    background: linear-gradient(135deg, #e2e8f0, #94a3b8);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    letter-spacing: -0.02em;
}
.app-sub {
    font-size: 0.75rem; color: rgba(255,255,255,0.35);
    font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase;
}

/* ─── Editor ─── */

/* ─── Validate button ─── */
div[data-testid="stVerticalBlock"] > div:has(button[data-testid="baseButton-primary"]) button[data-testid="baseButton-primary"] {
    background: linear-gradient(135deg, #4f8bf9, #6366f1) !important;
    color: #fff !important; border: none !important; border-radius: 10px !important;
    font-size: 0.95rem !important; font-weight: 600 !important;
    padding: 0.7rem 0 !important; width: 100% !important;
    box-shadow: 0 4px 20px rgba(79, 139, 249, 0.25) !important;
    transition: transform 0.15s, box-shadow 0.2s !important;
}
div[data-testid="stVerticalBlock"] > div:has(button[data-testid="baseButton-primary"]) button[data-testid="baseButton-primary"]:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 28px rgba(79, 139, 249, 0.35) !important;
}
div[data-testid="stVerticalBlock"] > div:has(button[data-testid="baseButton-primary"]) {
    width: 100% !important;
}
div[data-testid="stVerticalBlock"] > div:has(button[data-testid="baseButton-primary"]) button p {
    font-size: 0.95rem !important; font-weight: 600 !important;
}

/* ─── Section titles ─── */
.section-title {
    font-size: 0.8rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.08em;
    color: rgba(255,255,255,0.4);
    margin: 1.2rem 0 0.6rem 0;
    display: flex; align-items: center; gap: 0.5rem;
}
.section-title::after {
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(90deg, rgba(255,255,255,0.08), transparent);
}

/* ─── Diagnostics ─── */
.diag {
    display: flex; gap: 0.6rem; align-items: flex-start;
    padding: 0.6rem 0.8rem; margin: 2px 0;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
    line-height: 1.45;
    transition: background 0.15s;
}
.diag:hover { background: rgba(255,255,255,0.03); }
.diag-icon { flex-shrink: 0; width: 18px; text-align: center; }
.diag-body { flex: 1; min-width: 0; }
.diag-loc {
    color: rgba(255,255,255,0.35); margin-right: 0.5rem;
    font-size: 0.75rem; font-weight: 500;
}
.diag-err  .diag-icon { color: #ff6b6b; }
.diag-warn .diag-icon { color: #ffc107; }
.diag-info .diag-icon { color: #6ea8fe; }

.diag-err  { background: rgba(255,75,75,0.08); border-left: 2px solid #ff4444; }
.diag-warn { background: rgba(255,170,0,0.06); border-left: 2px solid #ffaa00; }
.diag-info { background: rgba(100,100,255,0.05); border-left: 2px solid #6666ff; }

.diag-id {
    display: inline-block; padding: 0 5px; border-radius: 4px;
    font-size: 0.65rem; font-weight: 600; font-family: 'JetBrains Mono', monospace;
    margin-right: 0.4rem;
}
.diag-err .diag-id  { background: rgba(255,75,75,0.15); color: #ff6b6b; }
.diag-warn .diag-id { background: rgba(255,170,0,0.15); color: #ffc107; }
.diag-info .diag-id { background: rgba(100,100,255,0.15); color: #6ea8fe; }

.diag-score {
    color: rgba(255,255,255,0.3); font-size: 0.75rem;
    font-family: 'JetBrains Mono', monospace;
}
.diag-msg { color: rgba(255,255,255,0.85); }
.diag-rec {
    font-family: 'Inter', sans-serif; font-size: 0.78rem;
    color: rgba(255,255,255,0.4); margin-top: 0.15rem;
}
.diag-rec::before { content: '\u2192 '; }

/* ─── Code context ─── */
.code-ctx {
    margin: 0.2rem 0 0.2rem 1.6rem;
    background: rgba(0,0,0,0.3); border-radius: 6px;
    padding: 0.4rem 0.6rem; overflow-x: auto;
    font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;
    line-height: 1.5;
}
.code-ctx .arrow { color: #ff6b6b; }
.code-ctx .num { color: rgba(255,255,255,0.2); margin-right: 0.5rem; }

/* ─── Success banner ─── */
.success-banner {
    background: linear-gradient(135deg, rgba(34,197,94,0.1), rgba(34,197,94,0.02));
    border: 1px solid rgba(34,197,94,0.2);
    border-radius: 10px; padding: 0.8rem 1rem; margin: 0.5rem 0;
    display: flex; align-items: center; gap: 0.7rem;
}
.success-icon {
    width: 32px; height: 32px; border-radius: 50%;
    background: rgba(34,197,94,0.15);
    display: flex; align-items: center; justify-content: center;
    font-size: 1rem; flex-shrink: 0;
}

/* ─── Summary bar ─── */
.summary-bar {
    display: flex; gap: 1.5rem; flex-wrap: wrap;
    padding: 0.7rem 1rem; margin: 0.5rem 0 0 0;
    background: rgba(255,255,255,0.02);
    border: 1px solid rgba(255,255,255,0.04);
    border-radius: 8px;
    font-size: 0.8rem;
}
.summary-stat { display: flex; align-items: center; gap: 0.4rem; }
.summary-stat .num { font-weight: 700; font-variant-numeric: tabular-nums; }
.summary-stat .lbl { color: rgba(255,255,255,0.4); }
.summary-stat.total .num { color: #e2e8f0; }
.summary-stat.err .num { color: #ff6b6b; }
.summary-stat.warn .num { color: #ffc107; }
.summary-stat.info .num { color: #6ea8fe; }

/* ─── None ─── */
.none-msg { color: rgba(255,255,255,0.2); font-size: 0.8rem; font-style: italic; padding: 0.3rem 0; }

/* ─── Mobile ─── */
@media (max-width: 640px) {
    .block-container { padding: 0.8rem 0.5rem; }
    .summary-bar { gap: 0.8rem; font-size: 0.75rem; }
    .diag { font-size: 0.73rem; padding: 0.5rem 0.6rem; }
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
    <div>
        <div class="app-title">YARA Validator</div>
        <div class="app-sub">Deep Analysis Engine</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Editor ──
from yara_editor import yara_editor

if "yara_code" not in st.session_state:
    st.session_state.yara_code = DEFAULT

editor_resp = yara_editor(
    code=DEFAULT, height=30, response_mode="blur", key="yara_editor",
)

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
                f'<span style="color:rgba(255,255,255,0.4);font-size:0.8rem;">{rule_name or "unknown"}</span></div>'
                f'</div>',
                unsafe_allow_html=True
            )
