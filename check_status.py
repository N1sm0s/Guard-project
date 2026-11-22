import json, sqlite3, os

# Последний результат обучения
log = r"F:\New\integrityguard\data\models\retrain.log"
lines = [l for l in open(log, encoding="utf-8").readlines() if l.strip()]
d = json.loads(lines[-1])
print("=== Последнее обучение ===")
print(f"  Время:       {d.get('at_utc')}")
print(f"  Образцов:    {d.get('n_samples')}")
print(f"  Split:       {d.get('split_note')}")
print(f"  Val AUC:     {d.get('validation_metrics', {}).get('roc_auc')}")
print(f"  Test AUC:    {d.get('test_metrics', {}).get('roc_auc')}")
print(f"  Классы:      {d.get('class_counts')}")

# Текущие данные
db = r"F:\New\integrityguard\data\online\network_events.sqlite"
rev = r"F:\New\integrityguard\data\online\network_label_reviews.sqlite"
c = sqlite3.connect(db)
total_events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
c.close()
c = sqlite3.connect(rev)
total_reviews = c.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]
c.close()
print(f"\n=== Данные сейчас ===")
print(f"  Событий в БД:  {total_events}")
print(f"  Меток в БД:    {total_reviews}")
print(f"  Новых событий: {total_events - 1007} (с момента последнего обучения)")
