"""Quick check of FEATURE_NAMES order and indices."""
import sys; sys.path.insert(0, r"F:\New\integrityguard")
from integrityguard.network_flow_schema import FEATURE_NAMES
for i, n in enumerate(FEATURE_NAMES[:20]):
    print(f"  idx {i:2d}: {n}")
