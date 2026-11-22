import sys
sys.path.insert(0, 'F:/New/integrityguard')
from integrityguard.network_classifier import FEATURE_VERSION, FEATURE_NAMES, ARCH_WIDE
print("FEATURE_VERSION=", FEATURE_VERSION)
print("ARCH=", ARCH_WIDE)
print("FEATURES len=", len(FEATURE_NAMES))
print("FEATURES=", list(FEATURE_NAMES))
# Check LABEL_SOURCE
try:
    from integrityguard.network_classifier import LABEL_SOURCE
    print("LABEL_SOURCE=", LABEL_SOURCE)
except ImportError:
    print("LABEL_SOURCE not defined")
# Check default checkpoint path
try:
    from integrityguard.network_classifier import _default_checkpoint_path
    print("checkpoint_path=", _default_checkpoint_path())
except Exception as e:
    print("checkpoint_path func not found:", e)
