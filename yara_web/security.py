"""Security and threat intelligence for YARA rules.

Analyzes false-positive risk, detection strength, IOC quality,
and anti-evasion characteristics."""
import re


COMMON_PUBLIC_STRINGS = {
    'Mozilla', 'Windows', 'Microsoft', 'Adobe', 'Http', 'http',
    'Content-Type', 'User-Agent', 'Server:', '404', '200 OK',
    'www.', '.com', '.exe', '.dll', '.php', '.asp', 'javascript',
    'function', 'var ', 'return', 'NULL', 'true', 'false',
    'Error', 'error', 'Warning', 'warning', 'Debug', 'debug',
    'Name', 'Type', 'Size', 'Date', 'Time', 'Path',
}


def _public_string_risk(strings):
    """Detect strings that are too common and cause FPs."""
    issues = []
    for s in strings:
        val = s['value']
        if s['type'] == 'text':
            if val in COMMON_PUBLIC_STRINGS:
                issues.append({
                    'id': 'SI1',
                    'issue': f"'{val}' is a common public string - high false-positive risk",
                    'level': 'warning',
                    'type': 'security',
                    'element': f"{s['name']} = {val}",
                    'recommendation': "Pair with more specific strings or use in combination with 'and' conditions",
                })
            if re.match(r'^[a-z]{2,5}$', val, re.IGNORECASE) and val.lower() not in {
                'http', 'https', 'www', 'file', 'null', 'true', 'false', 'none',
                'this', 'that', 'with', 'from', 'have', 'been', 'were',
            }:
                issues.append({
                    'id': 'SI2',
                    'issue': f"String '{val}' is very short ({len(val)} chars) - high FP potential",
                    'level': 'info',
                    'type': 'security',
                    'element': f"{s['name']} = {val}",
                    'recommendation': "Lengthen the string or combine with other conditions",
                })
        elif s['type'] == 'hex':
            clean = val.replace(' ', '').replace('{', '').replace('}', '')
            if len(clean) <= 4:
                issues.append({
                    'id': 'SI2',
                    'issue': f"Hex string {s['name']} is very short ({len(clean)//2} bytes) - high FP potential",
                    'level': 'warning',
                    'type': 'security',
                    'element': f"{s['name']} = {val}",
                    'recommendation': "Expand the hex string or anchor with additional fixed bytes",
                })
    return issues


def _detection_strength_scoring(parsed):
    """Estimate detection strength and specificity."""
    issues = []
    strings = parsed.get('strings', [])
    condition = ' '.join(parsed.get('condition_terms', []))

    num_strings = len(strings)
    if num_strings == 0:
        issues.append({
            'id': 'DS1',
            'issue': "Rule has no strings - relies entirely on condition expressions",
            'level': 'info',
            'type': 'security',
            'recommendation': "Add string signatures for better specificity",
        })
        return issues

    if num_strings < 2 and 'or' in condition and 'them' not in condition:
        pass

    unique_modifiers = set()
    for s in strings:
        for m in s.get('modifiers', []):
            unique_modifiers.add(m)

    has_specific_strings = any(
        len(s['value']) > 20 and s['type'] == 'text'
        for s in strings
    )
    if not has_specific_strings and num_strings > 0:
        long_count = sum(1 for s in strings if len(s['value']) > 10)
        if long_count == 0:
            issues.append({
                'id': 'DS2',
                'issue': "No long strings (>10 chars) - all strings are short, reducing specificity",
                'level': 'info',
                'type': 'security',
                'recommendation': "Include at least one longer, distinctive string if possible",
            })

    all_of_them = 'all of them' in condition or 'all of ($' in condition
    if all_of_them and num_strings > 5:
        issues.append({
            'id': 'DS3',
            'issue': f"'all of them' with {num_strings} strings is very strict - may miss variants",
            'level': 'info',
            'type': 'security',
            'recommendation': "Consider 'N of them' with a lower threshold for variant detection",
        })

    has_filesize = 'filesize' in condition
    has_module = any(
        m in condition for m in ['pe.', 'elf.', 'dotnet.', 'math.', 'hash.']
    )
    strength = 30
    if num_strings >= 3:
        strength += 20
    if num_strings >= 5:
        strength += 15
    if has_filesize:
        strength += 10
    if has_module:
        strength += 15
    if 'and' in condition:
        strength += 10
    if 'them' in condition:
        strength += 5
    strength = min(100, strength)

    if strength < 40:
        issues.append({
            'id': 'DS4',
            'issue': f"Detection strength estimate: {strength}/100 - rule may produce false positives",
            'level': 'info',
            'type': 'security',
            'recommendation': "Add more string constraints or module conditions (e.g., filesize, pe characteristics)",
            'score': strength,
        })

    return issues


def _anti_evasion_check(parsed):
    """Check if rule can be easily evaded."""
    issues = []
    strings = parsed.get('strings', [])
    condition = ' '.join(parsed.get('condition_terms', []))

    text_strings_without_nocase = []
    for s in strings:
        if s['type'] == 'text':
            val = s['value']
            mods = s.get('modifiers', [])
            if 'nocase' not in mods:
                has_alpha = any(c.isalpha() for c in val)
                if has_alpha:
                    text_strings_without_nocase.append(s)

    if text_strings_without_nocase and len(text_strings_without_nocase) == len(
        [s for s in strings if s['type'] == 'text']
    ):
        names = ', '.join(s['name'] for s in text_strings_without_nocase)
        issues.append({
            'id': 'AE1',
            'issue': f"No text strings have 'nocase' modifier ({names}) - case changes may evade detection",
            'level': 'info',
            'type': 'security',
            'recommendation': "Add 'nocase' modifier to case-sensitive text strings if case varies",
        })

    hex_count = sum(1 for s in strings if s['type'] == 'hex')
    if hex_count == 0 and len(strings) > 0:
        issues.append({
            'id': 'AE2',
            'issue': "No hex strings - rule may be evaded by string encoding obfuscation",
            'level': 'info',
            'type': 'security',
            'recommendation': "Consider adding hex-encoded byte patterns for obfuscation-resilient detection",
        })

    single_string_condition = len(strings) == 1 and not any(
        op in condition for op in ['and', 'or', ' not ', ' them', 'for ']
    )
    if single_string_condition:
        issues.append({
            'id': 'AE3',
            'issue': "Rule depends on a single string - trivial to evade",
            'level': 'warning',
            'type': 'security',
            'recommendation': "Add additional strings or conditions for layered detection",
        })

    return issues


def _maintainability_check(parsed):
    """Check rule maintainability and clarity."""
    issues = []
    condition = ' '.join(parsed.get('condition_terms', []))
    strings = parsed.get('strings', [])

    if strings:
        anonymous = [s for s in strings if s['name'] == '$']
        if len(anonymous) > 5:
            issues.append({
                'id': 'MT1',
                'issue': f"{len(anonymous)} anonymous strings make rule hard to maintain",
                'level': 'info',
                'type': 'security',
                'recommendation': "Give meaningful names to anonymous strings for clarity",
            })

    meta = parsed.get('metadata', [])
    has_desc = any('description' in m for m in meta)
    has_author = any('author' in m for m in meta)
    if not has_desc:
        issues.append({
            'id': 'MT2',
            'issue': "Rule has no 'description' in metadata - hard to understand intent",
            'level': 'info',
            'type': 'security',
            'recommendation': "Add a 'description' field explaining what this rule detects",
        })
    if not has_author:
        issues.append({
            'id': 'MT3',
            'issue': "Rule has no 'author' in metadata - hard to attribute ownership",
            'level': 'info',
            'type': 'security',
            'recommendation': "Add an 'author' field",
        })

    return issues


def analyze_security(parsed):
    """Run all security analyses on a parsed rule."""
    issues = []
    if 'strings' in parsed:
        issues.extend(_public_string_risk(parsed['strings']))
    issues.extend(_detection_strength_scoring(parsed))
    issues.extend(_anti_evasion_check(parsed))
    issues.extend(_maintainability_check(parsed))
    return issues
