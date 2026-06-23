# YARA Validator

A web-based YARA rule syntax validator with Ace editor and syntax highlighting.

![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?logo=streamlit&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB)
![YARA](https://img.shields.io/badge/YARA-4.5+-A9225C)

## Features

- Syntax validation via `yara-python` (cross-platform) or `yarac64.exe` (Windows fallback)
- Colored YARA syntax highlighting (Monokai theme)
- Error display with context lines
- Mobile-responsive dark glassmorphism UI

## Local Development

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

On Windows, place `yarac64.exe` at `yara-bin/yarac64.exe` for validation fallback.

## Deploy to Streamlit Community Cloud

1. Go to https://share.streamlit.io
2. Sign in with GitHub
3. Click **New app**
4. Select repo: `ntxfxk/yara-validator`
5. Branch: `master`, Main file: `app.py`
6. Click **Deploy**
