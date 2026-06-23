import sys
sys.path.insert(0, r"C:\Users\vboxuser\Desktop\AI\Yara")
from yara_web.validator_engine import validate, parse_rule
print(f"validate imported: {validate}")
print(f"parse_rule imported: {parse_rule}")
