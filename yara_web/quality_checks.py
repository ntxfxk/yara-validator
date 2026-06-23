import re
import string
import binascii

RE_PDB = re.compile(r'\.(pdb|PDB)$')
RE_PDB_FOLDER = re.compile(r'^\\.*\.(pdb|PDB)$')
RE_FILEPATH_SECTION = re.compile(r'^\\.+\\$')
RE_NUM_OF_THEM = re.compile(r'([\d]) of')
RE_AT_POS = re.compile(r'(\$[a-zA-Z0-9]{1,50}) at ([^\s]+)')
RE_FW_START_CHARS = re.compile(r'^[\.\)_]')
RE_FW_END_CHARS = re.compile(r'[\(\/\\_-]$')
RE_REPEATING_CHARS = re.compile(r'^(.)\1{1,}$')
RE_NOCASE_SAVE = re.compile(r'[^a-zA-Z]')
RE_SHORT_REGEX_ANCHOR = re.compile(r'[a-zA-Z0-9_\s\.=\"\']{4,}')
RE_CONDITION_FAILS = re.compile(r'\([\s]?[0-9]{1,3},[\s]?filesize[\s]?[\-]?[0-9]{0,3}[\s]?\)')
RE_X_OF_THEM_1 = re.compile(r'(^|or )([0-9]{1,3}|any|all) of them$')
RE_X_OF_THEM_2 = re.compile(r'^([0-9]{1,3}|any|all) of them($| or)')

FULLWORD_ALLOWED_1ST = [
    r'\\.', r'\\device', r'\\global', r'\\dosdevices',
    r'\\basenamedobjects', r'\\?', r'\?', r'\\*', r'\\%', r'.?', r'./', '_vba',
    r'\\registry', r'\registry', r'\systemroot', r'\\systemroot', r'.\\',
    r'. ', r'/tmp/', r'/etc/', r'/home/', r'/root/', r'/var/', '\t'
]
FULLWORD_ALLOWED_LAST = [r'*/', r'---', r' //', r';//', r'; //', r'# //', r'ipc$', r'c$', r'admin$']
LESS_AVOIDABLE_SHORT_ATOMS = ['<?', '<%', '<% ', '<?=', 'GET', '%>']
SAVE_MODULES = ['math', 'hash']


def check_yara_quality(rule, all_rules=None, total_rules=None):
    """
    Run quality checks on a parsed YARA rule.
    rule: parsed plyara rule dict
    returns list of dicts: {id, issue, level, type, element, recommendation}
    """
    issues = []
    issues.extend(_check_condition(rule))
    issues.extend(_check_strings(rule))
    issues.extend(_check_combinations(rule))
    return issues


def _check_condition(rule):
    issues = []
    condition_raw = rule.get('raw_condition', '')
    condition_terms = rule.get('condition_terms', [])
    condition_combined = ' '.join(condition_terms)

    # CF1: calculation over full file
    m = RE_CONDITION_FAILS.search(condition_raw)
    if m:
        issues.append({
            "id": "CF1",
            "issue": "Condition includes a calculation over the full file content which hurts performance",
            "level": "warning",
            "type": "performance",
            "element": m.group(0),
            "recommendation": "Place the most restrictive conditions first (short-circuit evaluation)"
        })

    # CF2: too many math ops
    math_count = condition_raw.count('math.')
    if math_count > 3:
        issues.append({
            "id": "CF2",
            "issue": f"Condition uses {math_count} mathematical operations, severe performance impact",
            "level": "error",
            "type": "performance",
            "element": condition_raw[:120],
            "recommendation": "Rewrite condition to use fewer mathematical calculations"
        })
    elif math_count > 0:
        issues.append({
            "id": "CF2",
            "issue": "Condition uses a mathematical calculation which has performance impact",
            "level": "info",
            "type": "performance",
            "element": condition_raw[:120],
            "recommendation": "Avoid mathematical calculations in conditions if possible"
        })

    # CE1: N of them with fewer strings
    if 'strings' in rule:
        m = RE_NUM_OF_THEM.search(condition_combined)
        if m:
            num = int(m.group(1))
            if num > len(rule['strings']):
                issues.append({
                    "id": "CE1",
                    "issue": f"Condition requires '{num} of them' but rule only has {len(rule['strings'])} string(s) - will never match",
                    "level": "error",
                    "type": "logic",
                    "element": m.group(0),
                    "recommendation": "Fix the condition to match the number of strings"
                })

    # PA1: short string at position
    if 'strings' in rule and " at 0" in condition_combined:
        m = RE_AT_POS.search(condition_combined)
        if m:
            at_string = m.group(1)
            at_pos = m.group(2)
            at_expr = m.group(0)
            for s in rule['strings']:
                if at_string == s['name']:
                    val = s['value']
                    stype = s['type']
                    if (stype == "text" and len(val) < 3) or (stype == "byte" and len(val.replace(' ', '')) < 7):
                        replacement = _calc_uint_replacement(val, stype, at_pos)
                        issues.append({
                            "id": "PA1",
                            "issue": f"Short string at position - could use uint() instead for better performance",
                            "level": "info",
                            "type": "performance",
                            "element": f"{at_expr} = {val}",
                            "recommendation": f"Rewrite as: {replacement}"
                        })

    return issues


def _check_strings(rule):
    issues = []
    if 'strings' not in rule:
        return issues

    # Duplicate strings (DS1)
    string_list = [{'name': s['name'], 'value': s['value']} for s in rule['strings']]
    reported_pairs = set()
    for s in rule['strings']:
        for s2 in string_list:
            if s['value'] == s2['value'] and s['name'] != s2['name']:
                pair = tuple(sorted([s['name'], s2['name']]))
                if pair not in reported_pairs:
                    reported_pairs.add(pair)
                    issues.append({
                        "id": "DS1",
                        "issue": f"Duplicate string value between '{s['name']}' and '{s2['name']}'",
                        "level": "warning",
                        "type": "logic",
                        "element": f"{s['name']} = {s['value']}",
                        "recommendation": "Remove the duplicate string"
                    })

    # High string count (HS1/HS2)
    filter_prefixes = ['$filter', '$fp', '$false', '$exclu']
    active_count = sum(1 for s in rule['strings']
                       if not any(s['name'].startswith(p) for p in filter_prefixes))
    if active_count > 40:
        issues.append({
            "id": "HS2",
            "issue": f"Rule has {active_count} active strings - very high count",
            "level": "warning",
            "type": "resources",
            "element": f"{active_count} strings",
            "recommendation": "Try to reduce the number of strings; identify the most relevant ones"
        })
    elif active_count > 20:
        issues.append({
            "id": "HS1",
            "issue": f"Rule has {active_count} active strings - high count",
            "level": "info",
            "type": "resources",
            "element": f"{active_count} strings",
            "recommendation": "Consider reducing the number of strings if possible"
        })

    # High regex count (HS3/HS4)
    regex_count = sum(1 for s in rule['strings'] if s['type'] == 'regex')
    if regex_count > 4:
        issues.append({
            "id": "HS4",
            "issue": f"Rule has {regex_count} regex strings - very high count",
            "level": "warning",
            "type": "resources",
            "element": f"{regex_count} regex strings",
            "recommendation": "Try to replace regex strings with text/hex strings where possible"
        })
    elif regex_count > 2:
        issues.append({
            "id": "HS3",
            "issue": f"Rule has {regex_count} regex strings - high count",
            "level": "info",
            "type": "resources",
            "element": f"{regex_count} regex strings",
            "recommendation": "Most YARA rules can be written without regexes"
        })

    for s in rule['strings']:
        val = s['value']
        val_lower = val.lower()
        stype = s['type']
        modifiers = s.get('modifiers', [])

        # SV1: repeating characters
        if RE_REPEATING_CHARS.search(val):
            issues.append({
                "id": "SV1",
                "issue": f"String contains repeating character - can cause 'too many strings' errors on large files",
                "level": "warning",
                "type": "logic",
                "element": f"{s['name']} = {val}",
                "recommendation": "Anchor the string with a different character at the beginning or end"
            })

        # SV2: hex that can be text
        if stype == 'byte':
            hex_str = val.replace(' ', '').replace('{', '').replace('}', '')
            try:
                decoded = binascii.unhexlify(hex_str)
                ascii_str = decoded.decode('ascii')
                acceptable = set(string.ascii_letters + string.digits + string.punctuation + ' ')
                if all(c in acceptable for c in ascii_str):
                    issues.append({
                        "id": "SV2",
                        "issue": f"Hex string can be written as readable text: '{ascii_str}'",
                        "level": "info",
                        "type": "style",
                        "element": f"{s['name']} = {val}",
                        "recommendation": f"Write as text instead of hex: \"{ascii_str}\""
                    })
            except (binascii.Error, UnicodeDecodeError, ValueError):
                pass

        # NO1: ascii + wide + nocase
        if all(mod in modifiers for mod in ['ascii', 'wide', 'nocase']):
            issues.append({
                "id": "NO1",
                "issue": f"String uses ascii + wide + nocase - likely overkill",
                "level": "info",
                "type": "performance",
                "element": f"{s['name']} = {val}",
                "recommendation": "Limit modifiers to what is actually present in the target"
            })

        # PA2: short atom
        if (stype == "text" and len(val) < 4) or (stype == "byte" and len(val.replace(' ', '')) < 9):
            level = "info" if any(v == val for v in LESS_AVOIDABLE_SHORT_ATOMS) else "warning"
            issues.append({
                "id": "PA2",
                "issue": f"Very short atom in string - can reduce scan performance",
                "level": level,
                "type": "performance",
                "element": f"{s['name']} = {val}",
                "recommendation": "Add a few more bytes to the beginning or end (every byte helps)"
            })

        # RE1: regex without sufficient anchors
        if stype == 'regex':
            if not RE_SHORT_REGEX_ANCHOR.search(val):
                issues.append({
                    "id": "RE1",
                    "issue": f"Regex lacks anchors with at least 4 fixed bytes - poor performance",
                    "level": "warning",
                    "type": "performance",
                    "element": f"{s['name']} = {val}",
                    "recommendation": "Add longer anchors (space, binary zero, or fixed string prefix)"
                })

        # SM1/SM6: PDB with wide
        if RE_PDB.search(val):
            if 'wide' in modifiers and 'ascii' not in modifiers:
                issues.append({
                    "id": "SM6",
                    "issue": f"PDB string uses 'wide' - PDB strings are ASCII-only, rule may not match",
                    "level": "error",
                    "type": "logic",
                    "element": f"{s['name']} = {val}",
                    "recommendation": "Replace 'wide' with 'ascii'"
                })
            elif 'wide' in modifiers:
                issues.append({
                    "id": "SM1",
                    "issue": f"PDB string uses unnecessary 'wide' modifier",
                    "level": "info",
                    "type": "logic",
                    "element": f"{s['name']} = {val}",
                    "recommendation": "Remove the 'wide' modifier (PDB strings are ASCII)"
                })

        # SM2: PDB with fullword
        if RE_PDB_FOLDER.search(val) and 'fullword' in modifiers:
            issues.append({
                "id": "SM2",
                "issue": f"PDB path with 'fullword' may cause non-matching rule",
                "level": "warning",
                "type": "logic",
                "element": f"{s['name']} = {val}",
                "recommendation": "Remove the 'fullword' modifier"
            })

        # SM3: filepath section with fullword
        if RE_FILEPATH_SECTION.search(val) and 'fullword' in modifiers:
            issues.append({
                "id": "SM3",
                "issue": f"File path segment with 'fullword' - starts and ends with backslash, may not match",
                "level": "warning",
                "type": "logic",
                "element": f"{s['name']} = {val}",
                "recommendation": "Remove the 'fullword' modifier"
            })

        # fullword checks: SM4 (path segment), SM5 (problematic start/end chars)
        if 'fullword' in modifiers:
            # SM4: path segment
            if val.startswith('\\'):
                allowed = any(val_lower.startswith(a) for a in FULLWORD_ALLOWED_1ST)
                allowed = allowed or any(val_lower.endswith(a) for a in FULLWORD_ALLOWED_LAST)
                if not allowed:
                    issues.append({
                        "id": "SM4",
                        "issue": f"Path-like string with 'fullword' modifier may not match",
                        "level": "warning",
                        "type": "logic",
                        "element": f"{s['name']} = {val}",
                        "recommendation": "Remove the 'fullword' modifier"
                    })

            # SM5: problematic start chars
            if RE_FW_START_CHARS.search(val) and stype == "text" and len(val) > 8:
                allowed = any(val_lower.startswith(a) for a in FULLWORD_ALLOWED_1ST)
                if not allowed:
                    issues.append({
                        "id": "SM5",
                        "issue": f"String with 'fullword' starts with a character that may prevent matching",
                        "level": "info",
                        "type": "logic",
                        "element": f"{s['name']} = {val}",
                        "recommendation": "Remove the 'fullword' modifier"
                    })

            if RE_FW_END_CHARS.search(val) and stype == "text" and len(val) > 6:
                allowed = any(val_lower.endswith(a) for a in FULLWORD_ALLOWED_LAST)
                if not allowed:
                    issues.append({
                        "id": "SM5",
                        "issue": f"String with 'fullword' ends with a character that may prevent matching",
                        "level": "warning",
                        "type": "logic",
                        "element": f"{s['name']} = {val}",
                        "recommendation": "Remove the 'fullword' modifier"
                    })

        # NC1: nocase without special chars
        if 'nocase' in modifiers and len(val) > 3 and not RE_NOCASE_SAVE.search(val):
            issues.append({
                "id": "NC1",
                "issue": f"Nocase string contains only letters - poor atom quality",
                "level": "info",
                "type": "performance",
                "element": f"{s['name']} = {val}",
                "recommendation": "Add a non-letter character (space, digit) to improve atom quality"
            })

    return issues


def _check_combinations(rule):
    issues = []
    if 'strings' not in rule:
        return issues

    condition_combined = ' '.join(rule.get('condition_terms', []))
    has_x_of_them = bool(RE_X_OF_THEM_1.search(condition_combined) or RE_X_OF_THEM_2.search(condition_combined))

    string_list = [{'name': s['name'], 'value': s['value']} for s in rule['strings']]

    for s in rule['strings']:
        for s2 in string_list:
            if s['value'] in s2['value'] and s['name'] != s2['name'] and s['value'] != s2['value']:
                if has_x_of_them:
                    issues.append({
                        "id": "CS1",
                        "issue": f"String '{s['name']}' is a substring of '{s2['name']}' - redundant with 'N of them' condition",
                        "level": "warning",
                        "type": "logic",
                        "element": f"{s['name']} = {s['value']}  ⊆  {s2['name']} = {s2['value']}",
                        "recommendation": "Check if both strings are needed, or use a more specific condition"
                    })
                else:
                    issues.append({
                        "id": "CS1",
                        "issue": f"String '{s['name']}' is a substring of '{s2['name']}'",
                        "level": "info",
                        "type": "logic",
                        "element": f"{s['name']} = {s['value']}  ⊆  {s2['name']} = {s2['value']}",
                        "recommendation": "Check if the substring string is redundant"
                    })
                break

    return issues


def _calc_uint_replacement(value, value_type, position):
    try:
        pos_int = int(position, 16) if position.startswith("0x") else int(position)
    except (ValueError, TypeError):
        return "(could not calculate replacement)"

    if value_type == 'text':
        if len(value) == 1:
            h = binascii.hexlify(value.encode()).decode()
            return f"uint8({pos_int}) == 0x{h}"
        elif len(value) == 2:
            h = binascii.hexlify(value.encode()).decode()
            return f"uint16be({pos_int}) == 0x{h}"
        elif len(value) == 3:
            h = binascii.hexlify(value.encode()).decode()
            return f"uint16be({pos_int}) == 0x{h[:4]} and uint8({pos_int + 2}) == 0x{h[4:]}"
        elif len(value) == 4:
            h = binascii.hexlify(value.encode()).decode()
            return f"uint32be({pos_int}) == 0x{h}"
    elif value_type == 'byte':
        clean = value.replace(' ', '').replace('{', '').replace('}', '')
        byte_len = len(clean) // 2
        if byte_len == 1:
            return f"uint8({pos_int}) == 0x{clean}"
        elif byte_len == 2:
            return f"uint16be({pos_int}) == 0x{clean}"
        elif byte_len <= 4:
            return f"uint32be({pos_int}) == 0x{clean}"
    return "(could not calculate replacement)"
