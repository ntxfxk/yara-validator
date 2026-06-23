import re
import os
import subprocess
import tempfile
import plyara

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
YARAC_PATH = os.path.join(PROJECT_DIR, "yara-bin", "yarac64.exe")

YARA_LINE_RE = re.compile(
    r'(?:error|warning):\s+'
    r'(?:rule\s+"[^"]*"\s+in\s+)?'
    r'[^(]+\((\d+)\):\s*(.+)'
)

try:
    import yara as _yara
    HAS_YARA_PYTHON = True
except ImportError:
    HAS_YARA_PYTHON = False


def _validate_via_yara_python(rule_text):
    errors = []
    name = None

    m = re.search(r'rule\s+(\w+)\s*\{', rule_text)
    if m:
        name = m.group(1)

    try:
        _yara.compile(source=rule_text)
        return True, errors, name
    except _yara.SyntaxError as e:
        msg = str(e)
        line_no = 1
        for line in msg.splitlines():
            m2 = re.match(r'.*\((\d+)\):\s*(.*)', line)
            if m2:
                line_no = int(m2.group(1))
                msg = m2.group(2).strip()
                break
        errors.append({'line': line_no, 'message': msg, 'type': 'error'})
        return False, errors, name
    except Exception as e:
        return False, [{'line': 1, 'message': str(e), 'type': 'error'}], name


def _validate_via_yarac(rule_text):
    fd, tmp_path = tempfile.mkstemp(suffix='.yara', prefix='yara_val_', text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(rule_text)

        proc = subprocess.run(
            [YARAC_PATH, tmp_path, tmp_path + 'c'],
            capture_output=True, text=True, timeout=30
        )

        errors = []
        name = None
        for line in (proc.stderr or '').splitlines():
            if not line.strip():
                continue
            m = YARA_LINE_RE.match(line)
            if m:
                line_no = int(m.group(1))
                message = m.group(2).strip()
                ltype = 'warning' if line.startswith('warning') else 'error'
                errors.append({'line': line_no, 'message': message, 'type': ltype})

        is_valid = proc.returncode == 0

        if not errors and not is_valid:
            errors.append({'line': 1, 'message': 'Unknown compilation error', 'type': 'error'})

        m_name = re.search(r'rule\s+"([^"]+)"', proc.stderr or '')
        if m_name:
            name = m_name.group(1)

        if not name and is_valid:
            m2 = re.search(r'warning:\s+rule\s+"([^"]+)"', proc.stderr or '')
            if m2:
                name = m2.group(1)
            else:
                m3 = re.search(r'rule\s+(\w+)\s*\{', rule_text)
                if m3:
                    name = m3.group(1)

        return is_valid, errors, name

    except FileNotFoundError:
        return False, [{'line': 1, 'message': 'YARA compiler not found', 'type': 'error'}], None
    except Exception as e:
        return False, [{'line': 1, 'message': f'Validation error: {e}', 'type': 'error'}], None
    finally:
        try:
            os.remove(tmp_path)
            os.remove(tmp_path + 'c')
        except OSError:
            pass


def validate(rule_text):
    if not rule_text.strip():
        return False, [{'line': 1, 'message': 'No YARA rule provided', 'type': 'error'}], None

    if HAS_YARA_PYTHON:
        return _validate_via_yara_python(rule_text)

    if os.path.exists(YARAC_PATH):
        return _validate_via_yarac(rule_text)

    return False, [{'line': 1, 'message': 'No YARA validator available (install yara-python or place yarac64.exe in yara-bin/)', 'type': 'error'}], None


def parse_rule(rule_text):
    try:
        parser = plyara.Plyara()
        parsed = parser.parse_string(rule_text)
        if not parsed:
            return None, "No rules found"
        return parsed[0], None
    except Exception as e:
        return None, str(e)
