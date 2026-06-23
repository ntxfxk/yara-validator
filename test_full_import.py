"""Full import test simulating streamlit's loading order."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

modules = [
    "yara_web.validator_engine",
    "yara_web.quality_checks",
    "yara_web.semantic",
    "yara_web.performance",
    "yara_web.security",
]

for mname in modules:
    try:
        mod = __import__(mname, fromlist=[""])
        print(f"OK: {mname} -> {mod.__file__}")
        for name in ["validate", "parse_rule", "check_yara_quality",
                       "analyze_semantic", "analyze_performance", "analyze_security"]:
            if hasattr(mod, name):
                print(f"  has '{name}'")
    except Exception as e:
        print(f"FAIL: {mname}: {e}")
