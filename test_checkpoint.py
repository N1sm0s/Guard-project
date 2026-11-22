import sys
sys.path.insert(0, 'F:/New/integrityguard')
from pathlib import Path
from integrityguard.network_classifier import load_checkpoint, assess_network_with_classifier
import sqlite3, json

# Загружаем чекпойнт
ckpt_path = Path('F:/New/integrityguard/data/models/network_classifier.pt')
ckpt = load_checkpoint(ckpt_path)
if ckpt is None:
    print('FAIL: checkpoint not loaded (returned None)')
    sys.exit(1)
print('OK: checkpoint loaded successfully')
print('  trained_at_utc:', ckpt.get('trained_at_utc'))
print('  n_samples:', ckpt.get('n_samples'))
print('  classes:', ckpt.get('classes'))

# Берём последний снимок из БД
db_path = Path('F:/New/integrityguard/data/online/network_events.sqlite')
con = sqlite3.connect(str(db_path))
row = con.execute("SELECT snapshot_json FROM events ORDER BY captured_at_utc DESC LIMIT 1").fetchone()
con.close()

if not row:
    print('FAIL: no events in DB')
    sys.exit(1)

snap = json.loads(row[0])
result = assess_network_with_classifier(snap, {}, ckpt_path)
print('\nAssessment result:')
print('  decision:', result.get('decision'))
print('  class_probabilities:', result.get('class_probabilities'))
print('  risk_score:', result.get('risk_score'))
print('  summary:', result.get('summary', '')[:100])
