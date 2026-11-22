$python = "F:\New\integrityguard\.venv\Scripts\python.exe"

Write-Output "=== Total events count ==="
& $python -c "
import sqlite3
con = sqlite3.connect('F:/New/integrityguard/data/online/network_events.sqlite')
cnt, last = con.execute('SELECT COUNT(*), MAX(captured_at_utc) FROM events').fetchone()
print(f'Total: {cnt}, Last: {last}')
"

Write-Output "=== Last 5 events with labels ==="
& $python -c "
import sqlite3, json
con = sqlite3.connect('F:/New/integrityguard/data/online/network_events.sqlite')
rows = con.execute('SELECT event_id, captured_at_utc, source, assessment_json FROM events ORDER BY captured_at_utc DESC LIMIT 5').fetchall()
for eid, ts, src, aj in rows:
    try:
        label = json.loads(aj).get('model_decision','?')
    except:
        label = 'parse_err'
    print(f'{eid} | {ts} | {src} | {label}')
"

Write-Output "=== Label distribution ==="
& $python -c "
import sqlite3, json, collections
con = sqlite3.connect('F:/New/integrityguard/data/online/network_events.sqlite')
rows = con.execute('SELECT assessment_json FROM events').fetchall()
counts = collections.Counter()
for (aj,) in rows:
    try:
        counts[json.loads(aj).get('model_decision','?')] += 1
    except:
        counts['parse_err'] += 1
for k,v in sorted(counts.items()): print(f'  {k}: {v}')
"

Write-Output "=== Retrain log last 5 lines ==="
Get-Content "F:\New\integrityguard\data\models\retrain.log" -Tail 5

Write-Output "=== Scheduled task ==="
Get-ScheduledTaskInfo -TaskName "IntegrityGuard NN Retrain" -ErrorAction SilentlyContinue | Select-Object LastRunTime,LastTaskResult,NextRunTime | Format-Table -AutoSize
