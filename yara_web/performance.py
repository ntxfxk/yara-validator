"""Performance intelligence for YARA rules.

Analyzes atom quality, regex complexity, condition ordering,
and estimates scan-time cost based on YARA execution model."""
import re
import math as py_math


def _atom_quality(text):
    """Score atom quality (0-100). YARA uses Aho-Corasick with 3-byte minimum atoms."""
    if len(text) < 3:
        return 0
    score = 100
    repeats = re.search(r'(.)\1{3,}', text)
    if repeats:
        score -= 30
    common_short = {'GET', 'POST', 'http', 'www', 'com', 'exe', 'dll'}
    if text.lower() in common_short:
        score -= 20
    entropy = 0
    if len(text) > 0:
        freqs = {}
        for c in text:
            freqs[c] = freqs.get(c, 0) + 1
        for f in freqs.values():
            p = f / len(text)
            if p > 0:
                entropy -= p * py_math.log2(p)
    if entropy < 1.5:
        score -= 15
    if text.isalpha():
        score -= 10
    return max(0, score)


def _regex_complexity(regex_str):
    """Estimate regex execution cost (0-100 scale, higher = more expensive)."""
    cost = 10
    if re.search(r'\([^)]*\*', regex_str):
        cost += 15
    if re.search(r'\([^)]*\+', regex_str):
        cost += 10
    if regex_str.count('|') > 3:
        cost += 15 * min(5, regex_str.count('|'))
    if r'.*' in regex_str or r'.+' in regex_str:
        cost += 20
    if re.search(r'\{[\d,]*\}', regex_str):
        cost += 15
    if re.search(r'\[[^\]]{10,}\]', regex_str):
        cost += 10
    if regex_str.count('\\') > 5:
        cost += 5
    return min(100, cost)


def _condition_cost(condition_terms, num_strings):
    """Estimate condition evaluation cost (0-100)."""
    cond = ' '.join(condition_terms)
    cost = 10
    cost += 10 * cond.count(' for ')
    cost += 15 * cond.count('math.')
    cost += 10 * cond.count('hash.')
    cost += 5 * cond.count('pe.')
    cost += 5 * cond.count('elf.')
    if 'filesize' in cond:
        cost += 5
    depth = 0
    max_depth = 0
    for c in cond:
        if c == '(':
            depth += 1
            max_depth = max(max_depth, depth)
        elif c == ')':
            depth -= 1
    cost += max_depth * 3
    if num_strings > 0:
        them_count = cond.count(' them')
        if them_count > 0 and them_count > 1:
            cost += 10 * them_count
    return min(100, cost)


def analyze_performance(parsed):
    """Run performance analysis on a parsed rule."""
    issues = []
    if 'strings' not in parsed:
        return issues

    strings = parsed['strings']

    for s in strings:
        val = s['value']
        stype = s['type']

        if stype == 'text':
            quality = _atom_quality(val)
            if quality < 40:
                issues.append({
                    'id': 'PF1',
                    'issue': f"Atom quality score {quality}/100 for {s['name']} - poor scan performance",
                    'level': 'warning' if quality < 20 else 'info',
                    'type': 'performance',
                    'element': f"{s['name']} = {val}",
                    'recommendation': "Add more distinctive bytes or avoid common short words",
                    'score': quality,
                })

        elif stype == 'regex':
            cost = _regex_complexity(val)
            if cost > 50:
                issues.append({
                    'id': 'PF2',
                    'issue': f"Regex complexity score {cost}/100 for {s['name']} - high performance impact",
                    'level': 'warning',
                    'type': 'performance',
                    'element': f"{s['name']} = {val}",
                    'recommendation': "Simplify regex: avoid excessive alternation '|', unbounded '*', or nested groups",
                    'score': cost,
                })

        elif stype == 'hex':
            clean = val.replace(' ', '').replace('{', '').replace('}', '')
            qmark_count = clean.count('?')
            jump_pattern = r'\[\d+-\d+\]'
            jumps = re.findall(jump_pattern, val)
            total_wild = qmark_count + sum(
                int(j.split('-')[1].rstrip(']')) - int(j.split('-')[0].lstrip('['))
                for j in jumps
            ) if jumps else qmark_count
            if total_wild > 8:
                issues.append({
                    'id': 'PF3',
                    'issue': f"Hex string {s['name']} has {total_wild} wildcard bytes - high false positive risk",
                    'level': 'warning',
                    'type': 'performance',
                    'element': f"{s['name']} = {val}",
                    'recommendation': "Reduce wildcard bytes or anchor with known fixed bytes",
                })

    condition_terms = parsed.get('condition_terms', [])
    if condition_terms:
        cost = _condition_cost(condition_terms, len(strings))
        if cost > 50:
            issues.append({
                'id': 'PF4',
                'issue': f"Condition complexity score {cost}/100 - potential scan slowdown",
                'level': 'warning',
                'type': 'performance',
                'recommendation': "Move cheaper checks (string presence) before expensive operations (math, hash, loops)",
                'score': cost,
            })
        cond_text = ' '.join(condition_terms)
        cheap_keywords = ['$', '#', '@', '!', 'them', 'of', 'any', 'all', 'filesize']
        expensive_keywords = ['math.', 'hash.', 'pe.', 'elf.', 'dotnet.', 'for ', 'entrypoint']
        first_expensive = len(cond_text)
        for ek in expensive_keywords:
            pos = cond_text.find(ek)
            if pos != -1 and pos < first_expensive:
                first_expensive = pos
        if first_expensive < len(cond_text) // 2:
            cheap_before = cond_text[:first_expensive]
            if not any(k in cheap_before for k in cheap_keywords):
                issues.append({
                    'id': 'PF5',
                    'issue': "Expensive condition elements appear early - short-circuit evaluation may not help",
                    'level': 'info',
                    'type': 'performance',
                    'recommendation': "Reorder condition: put fast string checks before expensive module calls",
                })

    return issues
