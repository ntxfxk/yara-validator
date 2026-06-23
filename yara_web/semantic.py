"""Semantic analysis for YARA rules.

Validates beyond syntax - checks module field/function references,
deprecated features, type consistency, identifier resolution,
and semantic rules from the official YARA grammar."""
import re
import plyara

YARA_4_5_KEYWORDS = {
    'all', 'and', 'any', 'ascii', 'at', 'base64', 'base64wide',
    'condition', 'contains', 'endswith', 'entrypoint', 'false',
    'filesize', 'for', 'fullword', 'global', 'icontains',
    'iendswith', 'iequals', 'import', 'in', 'include', 'int16',
    'int16be', 'int32', 'int32be', 'int8', 'int8be',
    'istartswith', 'matches', 'meta', 'nocase', 'none', 'not',
    'of', 'or', 'private', 'rule', 'startswith', 'strings',
    'them', 'true', 'uint16', 'uint16be', 'uint32', 'uint32be',
    'uint8', 'uint8be', 'wide', 'xor', 'defined',
}

DEPRECATED_KEYWORDS = {'entrypoint'}

INTEGER_FUNCTIONS = {
    'int8', 'int16', 'int32', 'uint8', 'uint16', 'uint32',
    'int8be', 'int16be', 'int32be', 'uint8be', 'uint16be', 'uint32be',
}

MODULE_FUNCTIONS_MAP = {
    'pe': {
        'attributes': {
            'is_pe', 'is_dll', 'is_32bit', 'is_64bit',
            'machine', 'checksum', 'subsystem', 'timestamp',
            'pointer_to_symbol_table', 'number_of_symbols',
            'size_of_optional_header', 'opthdr_magic',
            'size_of_code', 'size_of_initialized_data',
            'size_of_uninitialized_data', 'entry_point',
            'entry_point_raw', 'base_of_code', 'base_of_data',
            'image_base', 'section_alignment', 'file_alignment',
            'win32_version_value', 'size_of_image', 'size_of_headers',
            'characteristics', 'number_of_sections', 'number_of_exports',
            'number_of_imports', 'number_of_imported_functions',
            'number_of_delayed_imports', 'number_of_delay_imported_functions',
            'number_of_resources', 'number_of_signatures',
            'is_signed', 'number_of_certificates',
            'number_of_countersignatures', 'length_of_chain',
            'number_of_guids', 'number_of_streams', 'number_of_classes',
            'number_of_resources', 'number_of_user_strings',
            'number_of_assembly_refs', 'number_of_constants',
            'number_of_modulerefs', 'number_of_field_offsets',
            'number_of_streams', 'overlay', 'rich_signature',
            'pdb_path', 'dll_name', 'export_timestamp',
        },
        'functions': {
            'exports', 'exports_index', 'imports', 'imphash',
            'section_index', 'is_dll', 'is_32bit', 'is_64bit',
            'locale', 'language', 'rva_to_offset', 'calculate_checksum',
            'import_rva', 'delayed_import_rva',
            'valid_on',
        },
    },
    'elf': {
        'attributes': {
            'type', 'machine', 'entry_point',
            'number_of_sections', 'number_of_segments',
            'dynamic_section_entries', 'symtab_entries',
        },
        'functions': {
            'telfhash', 'import_md5',
        },
    },
    'dotnet': {
        'attributes': {
            'version', 'module_name', 'number_of_streams',
            'streams', 'number_of_guids', 'guids',
            'number_of_classes', 'classes',
            'number_of_resources', 'resources',
            'assembly', 'number_of_modulerefs', 'modulerefs',
            'typelib', 'number_of_constants', 'constants',
            'number_of_assembly_refs', 'assembly_refs',
            'number_of_user_strings', 'user_strings',
            'number_of_field_offsets', 'field_offsets',
        },
        'functions': {
            'is_dotnet',
        },
    },
    'hash': {
        'attributes': set(),
        'functions': {'md5', 'sha1', 'sha256'},
    },
    'math': {
        'attributes': set(),
        'functions': {
            'mean', 'entropy', 'in_range', 'max', 'min',
            'count', 'deviation', 'variance', 'standard_deviation',
            'correlation',
        },
    },
    'magic': {
        'attributes': {'type', 'mime_type'},
        'functions': set(),
    },
    'time': {
        'attributes': set(),
        'functions': {'now', 'unix_time_to_iso8601'},
    },
    'cuckoo': {
        'attributes': {
            'http', 'filesystem', 'registry', 'processes',
            'network', 'droidmon', 'synchronization', 'memory',
            'api_calls',
        },
        'functions': set(),
    },
    'console': {
        'attributes': set(),
        'functions': {'log'},
    },
    'string': {
        'attributes': set(),
        'functions': {'utf16le', 'utf16be', 'uint8be_at', 'uint16be_at',
                      'uint32be_at', 'uint8le_at', 'uint16le_at',
                      'uint32le_at'},
    },
    'lnk': {
        'attributes': set(),
        'functions': set(),
    },
}

ALL_MODULE_NAMES = set(MODULE_FUNCTIONS_MAP.keys())

PE_CONSTANTS = {
    'MACHINE_UNKNOWN', 'MACHINE_AM33', 'MACHINE_AMD64',
    'MACHINE_ARM', 'MACHINE_ARMNT', 'MACHINE_ARM64',
    'MACHINE_EBC', 'MACHINE_I386', 'MACHINE_IA64',
    'MACHINE_M32R', 'MACHINE_MIPS16', 'MACHINE_MIPSFPU',
    'MACHINE_MIPSFPU16', 'MACHINE_POWERPC', 'MACHINE_POWERPCFP',
    'MACHINE_R4000', 'MACHINE_SH3', 'MACHINE_SH3DSP',
    'MACHINE_SH4', 'MACHINE_SH5', 'MACHINE_THUMB',
    'MACHINE_WCEMIPSV2', 'MACHINE_TARGET_HOST',
    'MACHINE_R3000', 'MACHINE_R10000', 'MACHINE_ALPHA',
    'MACHINE_SH3E', 'MACHINE_ALPHA64', 'MACHINE_AXP64',
    'MACHINE_TRICORE', 'MACHINE_CEF', 'MACHINE_CEE',
    'SUBSYSTEM_UNKNOWN', 'SUBSYSTEM_NATIVE',
    'SUBSYSTEM_WINDOWS_GUI', 'SUBSYSTEM_WINDOWS_CUI',
    'SUBSYSTEM_OS2_CUI', 'SUBSYSTEM_POSIX_CUI',
    'SUBSYSTEM_NATIVE_WINDOWS', 'SUBSYSTEM_WINDOWS_CE_GUI',
    'SUBSYSTEM_EFI_APPLICATION', 'SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER',
    'SUBSYSTEM_EFI_RUNTIME_DRIVER', 'SUBSYSTEM_EFI_ROM_IMAGE',
    'SUBSYSTEM_XBOX', 'SUBSYSTEM_WINDOWS_BOOT_APPLICATION',
    'DLL', 'EXECUTABLE_IMAGE', 'RELOCS_STRIPPED',
    'LINE_NUMS_STRIPPED', 'LOCAL_SYMS_STRIPPED',
    'AGGRESIVE_WS_TRIM', 'LARGE_ADDRESS_AWARE',
    'BYTES_REVERSED_LO', 'MACHINE_32BIT', 'DEBUG_STRIPPED',
    'REMOVABLE_RUN_FROM_SWAP', 'NET_RUN_FROM_SWAP',
    'SYSTEM', 'UP_SYSTEM_ONLY', 'BYTES_REVERSED_HI',
    'DYNAMIC_BASE', 'FORCE_INTEGRITY', 'NX_COMPAT',
    'NO_ISOLATION', 'NO_SEH', 'NO_BIND', 'APPCONTAINER',
    'WDM_DRIVER', 'GUARD_CF', 'TERMINAL_SERVER_AWARE',
    'HIGH_ENTROPY_VA',
    'IMAGE_DIRECTORY_ENTRY_EXPORT', 'IMAGE_DIRECTORY_ENTRY_IMPORT',
    'IMAGE_DIRECTORY_ENTRY_RESOURCE',
    'IMAGE_DIRECTORY_ENTRY_EXCEPTION',
    'IMAGE_DIRECTORY_ENTRY_SECURITY',
    'IMAGE_DIRECTORY_ENTRY_BASERELOC',
    'IMAGE_DIRECTORY_ENTRY_DEBUG',
    'IMAGE_DIRECTORY_ENTRY_ARCHITECTURE',
    'IMAGE_DIRECTORY_ENTRY_COPYRIGHT',
    'IMAGE_DIRECTORY_ENTRY_TLS',
    'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',
    'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',
    'IMAGE_DIRECTORY_ENTRY_IAT',
    'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',
    'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',
    'IMPORT_STANDARD', 'IMPORT_DELAYED', 'IMPORT_ANY',
    'RESOURCE_TYPE_CURSOR', 'RESOURCE_TYPE_BITMAP',
    'RESOURCE_TYPE_ICON', 'RESOURCE_TYPE_MENU',
    'RESOURCE_TYPE_DIALOG', 'RESOURCE_TYPE_STRING',
    'RESOURCE_TYPE_FONTDIR', 'RESOURCE_TYPE_FONT',
    'RESOURCE_TYPE_ACCELERATOR', 'RESOURCE_TYPE_RCDATA',
    'RESOURCE_TYPE_MESSAGETABLE', 'RESOURCE_TYPE_GROUP_CURSOR',
    'RESOURCE_TYPE_GROUP_ICON', 'RESOURCE_TYPE_VERSION',
    'RESOURCE_TYPE_DLGINCLUDE', 'RESOURCE_TYPE_PLUGPLAY',
    'RESOURCE_TYPE_VXD', 'RESOURCE_TYPE_ANICURSOR',
    'RESOURCE_TYPE_ANIICON', 'RESOURCE_TYPE_HTML',
    'RESOURCE_TYPE_MANIFEST',
    'SECTION_NO_PAD', 'SECTION_CNT_CODE',
    'SECTION_CNT_INITIALIZED_DATA', 'SECTION_CNT_UNINITIALIZED_DATA',
    'SECTION_LNK_OTHER', 'SECTION_LNK_INFO', 'SECTION_LNK_REMOVE',
    'SECTION_LNK_COMDAT', 'SECTION_NO_DEFER_SPEC_EXC',
    'SECTION_GPREL', 'SECTION_MEM_FARDATA', 'SECTION_MEM_PURGEABLE',
    'SECTION_MEM_16BIT', 'SECTION_LNK_NRELOC_OVFL',
    'SECTION_MEM_LOCKED', 'SECTION_MEM_PRELOAD',
    'SECTION_ALIGN_1BYTES', 'SECTION_ALIGN_2BYTES',
    'SECTION_ALIGN_4BYTES', 'SECTION_ALIGN_8BYTES',
    'SECTION_ALIGN_16BYTES', 'SECTION_ALIGN_32BYTES',
    'SECTION_ALIGN_64BYTES', 'SECTION_ALIGN_128BYTES',
    'SECTION_ALIGN_256BYTES', 'SECTION_ALIGN_512BYTES',
    'SECTION_ALIGN_1024BYTES', 'SECTION_ALIGN_2048BYTES',
    'SECTION_ALIGN_4096BYTES', 'SECTION_ALIGN_8192BYTES',
    'SECTION_ALIGN_MASK', 'SECTION_MEM_DISCARDABLE',
    'SECTION_MEM_NOT_CACHED', 'SECTION_MEM_NOT_PAGED',
    'SECTION_MEM_SHARED', 'SECTION_MEM_EXECUTE',
    'SECTION_MEM_READ', 'SECTION_MEM_WRITE', 'SECTION_SCALE_INDEX',
    'IMAGE_DEBUG_TYPE_UNKNOWN', 'IMAGE_DEBUG_TYPE_COFF',
    'IMAGE_DEBUG_TYPE_CODEVIEW', 'IMAGE_DEBUG_TYPE_FPO',
    'IMAGE_DEBUG_TYPE_MISC', 'IMAGE_DEBUG_TYPE_EXCEPTION',
    'IMAGE_DEBUG_TYPE_FIXUP', 'IMAGE_DEBUG_TYPE_OMAP_TO_SRC',
    'IMAGE_DEBUG_TYPE_OMAP_FROM_SRC', 'IMAGE_DEBUG_TYPE_BORLAND',
    'IMAGE_DEBUG_TYPE_RESERVED10', 'IMAGE_DEBUG_TYPE_CLSID',
    'IMAGE_DEBUG_TYPE_VC_FEATURE', 'IMAGE_DEBUG_TYPE_POGO',
    'IMAGE_DEBUG_TYPE_ILTCG', 'IMAGE_DEBUG_TYPE_MPX',
    'IMAGE_DEBUG_TYPE_REPRO',
    'IMAGE_NT_OPTIONAL_HDR32_MAGIC',
    'IMAGE_NT_OPTIONAL_HDR64_MAGIC',
    'IMAGE_ROM_OPTIONAL_HDR_MAGIC',
}

ELF_CONSTANTS = {
    'ET_NONE', 'ET_REL', 'ET_EXEC', 'ET_DYN', 'ET_CORE',
    'EM_NONE', 'EM_M32', 'EM_SPARC', 'EM_386', 'EM_68K',
    'EM_88K', 'EM_860', 'EM_MIPS', 'EM_MIPS_RS3_LE',
    'EM_PPC', 'EM_PPC64', 'EM_ARM', 'EM_X86_64', 'EM_AARCH64',
    'SHT_NULL', 'SHT_PROGBITS', 'SHT_SYMTAB', 'SHT_STRTAB',
    'SHT_RELA', 'SHT_HASH', 'SHT_DYNAMIC', 'SHT_NOTE',
    'SHT_NOBITS', 'SHT_REL', 'SHT_SHLIB', 'SHT_DYNSYM',
    'SHF_WRITE', 'SHF_ALLOC', 'SHF_EXECINSTR',
    'PF_R', 'PF_W', 'PF_X',
    'PT_NULL', 'PT_LOAD', 'PT_DYNAMIC', 'PT_INTERP',
    'PT_NOTE', 'PT_SHLIB', 'PT_PHDR', 'PT_LOPROC',
    'PT_HIPROC', 'PT_GNU_STACK',
    'DT_NULL', 'DT_NEEDED', 'DT_PLTRELSZ', 'DT_PLTGOT',
    'DT_HASH', 'DT_STRTAB', 'DT_SYMTAB', 'DT_RELA',
    'DT_RELASZ', 'DT_RELAENT', 'DT_STRSZ', 'DT_SYMENT',
    'DT_INIT', 'DT_FINI', 'DT_SONAME', 'DT_RPATH',
    'DT_SYMBOLIC', 'DT_REL', 'DT_RELSZ', 'DT_RELENT',
    'DT_PLTREL', 'DT_DEBUG', 'DT_TEXTREL', 'DT_JMPREL',
    'DT_BIND_NOW', 'DT_INIT_ARRAY', 'DT_FINI_ARRAY',
    'DT_INIT_ARRAYSZ', 'DT_FINI_ARRAYSZ', 'DT_RUNPATH',
    'DT_FLAGS', 'DT_ENCODING',
    'STT_NOTYPE', 'STT_OBJECT', 'STT_FUNC', 'STT_SECTION',
    'STT_FILE', 'STT_COMMON', 'STT_TLS',
    'STB_LOCAL', 'STB_GLOBAL', 'STB_WEAK',
}


def _find_all_keywords(rule_text):
    """Find all module-qualified identifiers in rule text."""
    module_refs = re.findall(r'(?<!\w)(\w+)\.(\w+)(?!\w)', rule_text)
    return module_refs


def _find_module_uses(rule_text, imported_modules):
    """Find all module.field accesses to validate they exist."""
    issues = []
    refs = _find_all_keywords(rule_text)
    for mod_name, field in refs:
        if mod_name not in imported_modules:
            continue
        if mod_name not in ALL_MODULE_NAMES:
            continue
        mod_info = MODULE_FUNCTIONS_MAP.get(mod_name, {})
        all_valid = mod_info.get('attributes', set()) | mod_info.get('functions', set())
        if field not in all_valid:
            next_char_pattern = re.compile(
                re.escape(f'{mod_name}.{field}') + r'\(?'
            )
            m = next_char_pattern.search(rule_text)
            is_func_call = m and m.group(0).endswith('(') if m else False
            if is_func_call and field in mod_info.get('functions', set()):
                continue
            if not is_func_call and field in mod_info.get('attributes', set()):
                continue
            issues.append({
                'id': 'MF1',
                'issue': f"Unknown '{mod_name}.{field}' - not a valid {mod_name} module field or function",
                'level': 'warning',
                'type': 'semantic',
            })
    return issues


def _check_modifier_conflicts(parsed):
    """Check for conflicting/impossible modifier combinations.
    Based on official docs: nocase cannot combine with xor, base64, base64wide.
    fullword cannot combine with base64/base64wide.
    """
    issues = []
    if 'strings' not in parsed:
        return issues
    IMMUTABLE_RULES = {
        'nocase': {'xor', 'base64', 'base64wide'},
        'xor': {'nocase', 'base64', 'base64wide'},
        'base64': {'nocase', 'xor', 'fullword'},
        'base64wide': {'nocase', 'xor', 'fullword'},
        'fullword': {'base64', 'base64wide'},
    }
    for s in parsed['strings']:
        mods = set(s.get('modifiers', []))
        for mod in mods:
            conflicts = IMMUTABLE_RULES.get(mod, set()) & mods
            if conflicts:
                issues.append({
                    'id': 'MC1',
                    'issue': f"'{mod}' modifier conflicts with '{' and '.join(sorted(conflicts))}' on string {s['name']}",
                    'level': 'error',
                    'type': 'semantic',
                    'element': f"{s['name']} = {s['value']}",
                })
        if 'base64' in mods or 'base64wide' in mods:
            if s['type'] != 'text':
                issues.append({
                    'id': 'MC2',
                    'issue': f"base64/base64wide only valid on text strings, not {s['type']}",
                    'level': 'error',
                    'type': 'semantic',
                    'element': f"{s['name']}",
                })
    return issues


def _check_deprecated(rule_text):
    """Check for deprecated features."""
    issues = []
    if re.search(r'\bentrypoint\b', rule_text):
        issues.append({
            'id': 'DP1',
            'issue': "'entrypoint' is deprecated since YARA 3.x - use 'pe.entry_point' instead",
            'level': 'warning',
            'type': 'version',
            'recommendation': "Replace 'entrypoint' with 'pe.entry_point' (requires import \"pe\")",
        })
    if re.search(r'\b0 of them\b', rule_text):
        issues.append({
            'id': 'DP2',
            'issue': "'0 of them' is ambiguous - use 'none of them' instead (YARA 4.3.0+)",
            'level': 'info',
            'type': 'version',
            'recommendation': "Replace '0 of them' with 'none of them' for clarity",
        })
    return issues


def _check_imports_structure(rule_text, parsed_rules):
    """Check import placement and missing module imports."""
    issues = []

    lines = rule_text.splitlines()
    first_rule_line = None
    for i, line in enumerate(lines):
        if re.match(r'^\s*rule\s+', line):
            first_rule_line = i
            break

    for i, line in enumerate(lines):
        m = re.match(r'^\s*import\s+"(\w+)"', line)
        if m:
            mod = m.group(1)
            if first_rule_line is not None and i > first_rule_line:
                issues.append({
                    'id': 'IS1',
                    'issue': f"import \"{mod}\" appears after first rule - YARA requires imports before rules",
                    'level': 'error',
                    'type': 'semantic',
                    'line': i + 1,
                })
            if mod not in ALL_MODULE_NAMES:
                issues.append({
                    'id': 'IS2',
                    'issue': f"import \"{mod}\" - unknown module (not one of: {', '.join(sorted(ALL_MODULE_NAMES))})",
                    'level': 'warning',
                    'type': 'semantic',
                    'line': i + 1,
                })

    imported = set()
    for i, line in enumerate(lines):
        m = re.match(r'^\s*import\s+"(\w+)"', line)
        if m:
            imported.add(m.group(1))

    module_uses = set()
    for mod_name, _ in _find_all_keywords(rule_text):
        if mod_name not in ALL_MODULE_NAMES:
            continue
        module_uses.add(mod_name)
    for mod in module_uses:
        if mod not in imported:
            issues.append({
                'id': 'IS3',
                'issue': f"Module '{mod}' used but not imported (missing: import \"{mod}\")",
                'level': 'error',
                'type': 'semantic',
                'recommendation': f"Add 'import \"{mod}\"' before any rule definitions",
            })

    return issues


def _check_string_references(parsed):
    """Check that all named strings are referenced in the condition
    (except $_ prefixed unreferenced strings).
    Accounts for implicit references via 'them', wildcard patterns ($grp*), etc."""
    issues = []
    if 'strings' not in parsed or 'condition_terms' not in parsed:
        return issues

    cond_text = ' '.join(parsed.get('condition_terms', []))

    if 'them' in cond_text:
        return issues

    all_refs = set(re.findall(r'[\$#@!][a-zA-Z_]\w*', cond_text))
    all_refs.add('$*')
    wildcard_refs = [r for r in re.findall(r'[\$#@!][a-zA-Z_]\w*\*', cond_text)]

    for s in parsed['strings']:
        sname = s['name']
        if sname.startswith('$_'):
            continue
        if sname in all_refs:
            continue
        matched_wildcard = any(
            sname.startswith(wc.rstrip('*'))
            for wc in wildcard_refs
        )
        if matched_wildcard:
            continue
        pattern = re.escape(sname) + r'\b'
        if not re.search(pattern, cond_text):
            issues.append({
                'id': 'SR1',
                'issue': f"String {sname} defined but never referenced in condition",
                'level': 'warning',
                'type': 'semantic',
                'element': f"{sname} = {s['value']}",
                'recommendation': "Either use it in the condition or prefix with '$_' for unreferenced strings",
            })
    return issues


def analyze_semantic(rule_text, parsed_rules):
    """Run all semantic analyses on the rule set.
    parsed_rules is a list of plyara-parsed rule dicts (may include imports)."""
    issues = []

    combined_text = rule_text

    imported = set()
    for i, line in enumerate(combined_text.splitlines()):
        m = re.match(r'^\s*import\s+"(\w+)"', line)
        if m:
            imported.add(m.group(1))

    issues.extend(_check_imports_structure(combined_text, parsed_rules))
    issues.extend(_check_deprecated(combined_text))
    issues.extend(_find_module_uses(combined_text, imported))

    for parsed in parsed_rules:
        if isinstance(parsed, dict) and 'rule_name' in parsed:
            issues.extend(_check_modifier_conflicts(parsed))
            issues.extend(_check_string_references(parsed))

    return issues


def analyze_cross_rule(rule_text, parsed_rules):
    """Cross-rule analysis - check rule ordering, rule references."""
    issues = []
    rule_names = []
    for p in parsed_rules:
        if isinstance(p, dict) and 'rule_name' in p:
            rule_names.append(p['rule_name'])

    for i, p in enumerate(parsed_rules):
        if not isinstance(p, dict):
            continue
        cond = ' '.join(p.get('condition_terms', []))
        refs = re.findall(r'(?<![\.\$\#\@\!])([A-Z]\w*)', cond)
        for ref in refs:
            if ref in YARA_4_5_KEYWORDS or ref in INTEGER_FUNCTIONS:
                continue
            if ref in rule_names:
                ref_idx = rule_names.index(ref)
                if ref_idx > i:
                    issues.append({
                        'id': 'CR1',
                        'issue': f"Rule '{p['rule_name']}' references '{ref}' which is defined later - YARA requires referenced rules to be defined first",
                        'level': 'error',
                        'type': 'semantic',
                        'recommendation': f"Move rule '{ref}' before '{p['rule_name']}'",
                    })
    return issues
