"""Import real evidence into the versioned label registry and show coverage."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integrityguard.label_registry import LabelRegistry

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--registry', type=Path, required=True)
    args = parser.parse_args()
    registry = LabelRegistry(args.registry)
    print(json.dumps({'import': registry.import_catalog(args.catalog), 'coverage': registry.coverage()},
                     ensure_ascii=False, indent=2))
