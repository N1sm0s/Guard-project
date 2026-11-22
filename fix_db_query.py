path = 'integrityguard/gui.py'
src = open(path, encoding='utf-8').read()

# Fix the SQL query in _check_load_events - columns are event_id, captured_at_utc, snapshot_json
old1 = '"SELECT id, timestamp, process_name, snapshot FROM events ORDER BY timestamp DESC LIMIT 50"'
new1 = '"SELECT event_id, captured_at_utc, \'\', snapshot_json FROM events ORDER BY captured_at_utc DESC LIMIT 50"'

# Fix the label building - process_name may be empty
old2 = '''            ts_short = str(ts)[:19] if ts else "?"
            proc_short = (proc or "unknown")[:30]
            label_txt = f"{ts_short}  {proc_short}"'''
new2 = '''            ts_short = str(ts)[:19] if ts else "?"
            label_txt = ts_short'''

if old1 in src:
    src = src.replace(old1, new1)
    print("Fixed SQL query")
else:
    print("ERROR: SQL query not found")

if old2 in src:
    src = src.replace(old2, new2)
    print("Fixed label building")
else:
    print("ERROR: label building not found")

open(path, 'w', encoding='utf-8').write(src)
print("Done.")
