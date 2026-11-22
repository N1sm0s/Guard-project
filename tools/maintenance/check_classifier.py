import sys
sys.path.insert(0, r"F:\New\integrityguard")
from integrityguard.network_classifier import load_checkpoint, _MAIN_MODE_ENABLED, LABEL_SOURCE
from pathlib import Path

cp = load_checkpoint(Path(r"F:\New\integrityguard\data\models\network_classifier.pt"))
print("LABEL_SOURCE:", LABEL_SOURCE)
print("_MAIN_MODE_ENABLED:", _MAIN_MODE_ENABLED)
print("checkpoint loaded:", cp is not None)
if cp:
    print("arch:", cp.get("arch"))
    print("n_samples:", cp.get("n_samples"))
    print("trained_at_utc:", cp.get("trained_at_utc"))
    # Test inference on dummy snapshot
    from integrityguard.network_classifier import assess_network_with_classifier
    result = assess_network_with_classifier({}, {}, Path(r"F:\New\integrityguard\data\models\network_classifier.pt"))
    print("\n--- assess result ---")
    print("decision:", result["decision"])
    print("model_decision:", result["model_decision"])
    print("advisory_only:", result["advisory_only"])
    print("enforcement_applied:", result["enforcement_applied"])
    print("model:", result["model"])
    print("summary:", result["summary"][:120])
