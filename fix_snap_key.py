path = 'integrityguard/gui.py'
src = open(path, encoding='utf-8').read()

# The _check_events_data dict maps event_id -> snap_json (4th column = snapshot_json)
# The SQL now returns: event_id, captured_at_utc, '', snapshot_json
# So self._check_events_data[eid] = snap_json is still correct (4th col = index 3)
# But we also need the combo label to show the timestamp properly
# Check what the current label text looks like in the combo store
import re
# Find the _check_load_events method area
idx = src.find('def _check_load_events')
snippet = src[idx:idx+600]
print(snippet)
