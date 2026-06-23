import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from yara_web.validator_engine import validate, HAS_YARA_PYTHON

print("HAS_YARA_PYTHON:", HAS_YARA_PYTHON)

# Valid rule
rule = '''rule Test {
    meta:
        description = "test"
    strings:
        $a = "foo"
    condition:
        $a
}'''
ok, errs, name = validate(rule)
print("Valid rule:", ok, errs, name)

# Invalid rule
rule2 = '''rule Bad {
    meta:
        description = "test"
    strings:
        $a = "foo"
    condishun:
        $a
}'''
ok2, errs2, name2 = validate(rule2)
print("Invalid rule:", ok2, errs2, name2)
