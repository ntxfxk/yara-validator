"""Launcher for the YARA Deep Validator."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from streamlit.web import cli as stcli

if __name__ == "__main__":
    sys.argv = ["streamlit", "run", os.path.join(os.path.dirname(__file__), "app.py")]
    sys.exit(stcli.main())
