# YARA Validator

A web-based YARA rule syntax validator with Ace editor and syntax highlighting.

## Features

- Syntax validation via `yarac64.exe` (YARA 4.5.5)
- Colored YARA syntax highlighting (Monokai theme)
- Error display with context lines
- Mobile-responsive dark glassmorphism UI

## Local Development

```bash
python -m streamlit run app.py
```

Requires `yarac64.exe` at `yara-bin/yarac64.exe`.

## Deployment

### Streamlit Community Cloud (Recommended)

1. Push this repo to GitHub
2. Go to https://share.streamlit.io
3. Deploy from your GitHub repo

### Render.com (Alternative)

1. Create a new Web Service on Render
2. Set build command: `pip install -r requirements.txt`
3. Set start command: `streamlit run app.py --server.port $PORT`
